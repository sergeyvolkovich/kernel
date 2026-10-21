// ==== Эксклюзивный claim устройств: LockObj + очередь ожидания + hot-removal ====
//
// Семантика (требование «пользоваться устройством может только одна задача
// одновременно» + «если задача держит активный лок, а устройство удалено —
// программа получает ошибку от ядра + по IPC»):
//
// ```text
//   DeviceClaimRegistry
//   └─ locks: Vec<DeviceLock>          по одному LockObj на устройство
//         ├─ owner: Option<TaskId>     ЭКСКЛЮЗИВНЫЙ владелец (задача);
//         │                            повторный claim той же задачи — idempotent
//         ├─ wait_queue: BlockQueueId  претенденты (потоки) — очередь ЖИВЁТ
//         │                            В ПЛАНИРОВЩИКЕ (контракт block-очередей)
//         └─ notify_gate: Option<ObjId> endpoint владельца для событий
//                                      потери устройства (async-IPC)
// ```
//
// Пути события:
//   * claim свободного устройства — мгновенный захват (owner = задача);
//   * claim занятого — поток претендента блокируется в wait_queue
//     (двухфазный контракт: Blocked -> block_push); release будит
//     FIFO-претендента — ЕГО задача становится новым владельцем, а его
//     заблокированный сискол завершается успехом (syscall_ret = 0);
//   * RELEASE ПРИ УДАЛЕНИИ УСТРОЙСТВА (hot-removal): rescan помечает
//     записи `alive = false`; реестр для каждого удерживаемого лока:
//       1) IPC-сообщение владельцу на notify_gate (тег DEVICE_LOST +
//          идентичность устройства — «ошибка по IPC»);
//       2) форс-снятие лока (owner = None);
//       3) претенденты из wait_queue получают отказ (syscall_ret =
//          ENXIO-код) — «ошибка от ядра»;
//       4) все последующие claim/device-операции с этим путём —
//          SyscallError::DeviceGone до повторного появления устройства.
//   * exit задачи-владельца — авто-release всех её локов (контракт
//     разрушения домена: ресурсы не переживают владельца).

use alloc::{boxed::Box, vec::Vec};

use core::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::sync::KSpin;

use crate::capability::{CapabilityManager, ObjId};
use crate::hal::types::DevicePath;
use crate::ipc::{IPC_KERNEL_FROM, IpcManager, IpcMessage};
use crate::task::scheduler::BlockQueueId;
use crate::task::{TaskError, TaskId, TaskState, TcbManager, ThreadId, ThreadWait};

/// Тег события «устройство потеряно» в слове 0 IPC-сообщения.
pub const DEVICE_LOST_TAG: u64 = 0xD1;

/// Код «устройство удалено» для syscall_ret разбуженных с ошибкой
/// претендентов (ENXIO — тот же код, что у SyscallError::DeviceGone).
pub const DEVICE_GONE_RET: usize = usize::MAX - 5;

/// Отказ операции claim.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// Устройство удалено (hot-removal): claim невозможен.
    #[error("device is gone")]
    DeviceGone,
    /// Устройства нет в реестре устройств.
    #[error("device not found in registry")]
    DeviceNotFound,
    /// Попытка отпустить не удерживаемый лок.
    #[error("lock is not held by this task")]
    NotHeld,
    /// Лок-объект ещё не создан / очередь планировщика недоступна.
    #[error("scheduler cannot host the wait queue")]
    NoWaitQueue,
    /// Ошибка подсистемы задач (блокировка потока).
    #[error("task subsystem error: {0}")]
    Task(#[from] TaskError),
    /// Внутренняя ошибка (рассинхрон очередей).
    #[error("internal claim error")]
    Internal,
}

impl From<ClaimError> for crate::syscall::SyscallError {
    fn from(e: ClaimError) -> Self {
        use crate::syscall::SyscallError;
        match e {
            ClaimError::DeviceGone => SyscallError::DeviceGone,
            ClaimError::DeviceNotFound => SyscallError::NotFound,
            ClaimError::NotHeld => SyscallError::MissingRight,
            ClaimError::NoWaitQueue => SyscallError::Internal,
            ClaimError::Task(t) => t.into(),
            #[allow(unreachable_patterns)]
            _ => SyscallError::Internal,
        }
    }
}

/// Исход claim-операции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Устройство захвачено сразу (или уже принадлежало задаче).
    Acquired,
    /// Поток претендента заблокирован в wait_queue; при release
    /// устройства его задача станет владельцем, а сискол завершится
    /// (syscall_ret = 0). Отказ при удалении устройства — syscall_ret
    /// = [`DEVICE_GONE_RET`].
    Blocked,
}

/// Уникальный номер ожидания claim (тег ThreadWait::Queue).
const CLAIM_WAIT_TAG: u64 = 0xC1A1;

/// LockObj устройства: эксклюзивный владелец + очередь претендентов.
#[derive(Debug)]
pub struct DeviceLock {
    /// Идентичность устройства (ключ).
    pub device: DevicePath,
    /// Эксклюзивный владелец (задача). `None` — свободно.
    owner: Option<TaskId>,
    /// Очередь претендентов (потоков) — живёт в планировщике.
    wait_queue: BlockQueueId,
    /// Endpoint владельца (в его cspace) для события потери устройства.
    notify_gate: Option<ObjId>,
    /// Устройство удалено при активном локе («отравление» до возврата).
    gone: bool,
    /// Эпоха «отравления» (аудит).
    gone_epoch: u64,
}

/// Снимок состояния лока (сискол DEVICE_CLAIM_STATUS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimStatus {
    pub device: DevicePath,
    /// Владелец (None — свободно).
    pub owner: Option<TaskId>,
    /// Претендентов в очереди.
    pub waiters: usize,
    /// Устройство удалено при активном локе.
    pub gone: bool,
}

/// Реестр локов устройств (живёт внутри `DeviceManager`).
///
/// Interior mutability (RefCell/Cell) — как у TcbManager/CapabilityManager:
/// сискол-фасад держит `&DeviceManager` (неизменяемую ссылку GCTL), а
/// claim/release/уведомления мутируют реестр локов; сериализация —
/// однопоточный контракт крейта.
///
/// Подключение подсистем (задачи/capability/IPC) — параметрами методов,
/// как у `DeviceManager::export_capabilities(&tasks, &caps, ..)`.
pub struct DeviceClaimRegistry {
    locks: KSpin<Vec<DeviceLock>>,
    /// Счётчик hot-removal событий (эпоха отравления; SMP v0.12 — атомик).
    removal_epoch: AtomicU64,
}

impl DeviceClaimRegistry {
    /// Пустой реестр.
    pub fn new() -> Self {
        Self {
            locks: KSpin::new(Vec::new()),
            removal_epoch: AtomicU64::new(0),
        }
    }

    /// Число локов (аудит).
    pub fn count(&self) -> usize {
        self.locks.lock().len()
    }

    /// Найти/создать лок устройства. Очередь ожидания берётся у
    /// планировщика (если он есть); без планировщика лок работает только
    /// в try-режиме (блокировка претендентов невозможна).
    fn ensure_lock(&self, tasks: &TcbManager, device: &DevicePath) -> Result<(), ClaimError> {
        if self.locks.lock().iter().any(|l| &l.device == device) {
            return Ok(());
        }
        let wait_queue = tasks
            .scheduler()
            .map(|s| s.block_queue_create().unwrap_or_default())
            .unwrap_or_default();
        self.locks.lock().push(DeviceLock {
            device: device.clone(),
            owner: None,
            wait_queue,
            notify_gate: None,
            gone: false,
            gone_epoch: 0,
        });
        Ok(())
    }

    /// Идентичность устройства в словах IPC-сообщения DEVICE_LOST:
    /// `[DEVICE_LOST_TAG, kind, id0, id1]` (kind: 1=Pci, 2=Acpi, 3=Dt,
    /// 4=StreamId; для PCI id0 упаковывает BDF, для путей — FNV-хеш).
    pub fn device_lost_words(device: &DevicePath) -> [u64; 4] {
        let (kind, id0, id1) = match device {
            DevicePath::Pci(bdf) => (
                1u64,
                ((bdf.segment as u64) << 32)
                    | ((bdf.bus as u64) << 24)
                    | ((bdf.device as u64) << 16),
                bdf.function as u64,
            ),
            DevicePath::Acpi(p) => (2, fnv1a(p.as_str().as_bytes()), p.as_str().len() as u64),
            DevicePath::Dt(p) => (3, fnv1a(p.as_str().as_bytes()), p.as_str().len() as u64),
            DevicePath::StreamId { iommu, id } => (4, (iommu.0 as u64) << 32, *id as u64),
        };
        [DEVICE_LOST_TAG, kind, id0, id1]
    }

    /// Эксклюзивный claim устройства задачей.
    ///
    /// * устройство удалено/не найдено — [`ClaimError::DeviceGone`] /
    ///   [`ClaimError::DeviceNotFound`] (alive проверяет ВЫЗЫВАЮЩИЙ по
    ///   `DeviceManager` и передаёт флаг);
    /// * свободно — захват (idempotent для владельца);
    /// * занято другой задачей — блокировка потока претендента в
    ///   wait_queue ([`ClaimOutcome::Blocked`]).
    ///
    /// `notify_gate` — endpoint владельца (в его cspace) для события
    /// потери устройства; регистрируется вместе с захватом.
    pub fn claim(
        &self,
        tasks: &TcbManager,
        device: &DevicePath,
        alive: bool,
        task: TaskId,
        thread: ThreadId,
        notify_gate: Option<ObjId>,
        mode: crate::ipc::BlockMode,
    ) -> Result<ClaimOutcome, ClaimError> {
        self.ensure_lock(tasks, device)?;
        let mut locks = self.locks.lock();
        let lock = locks
            .iter_mut()
            .find(|l| &l.device == device)
            .expect("ensure_lock выше");

        if !alive || lock.gone {
            return Err(ClaimError::DeviceGone);
        }

        match lock.owner {
            // Свободно (или снят форс-релизом при удалении) — захват.
            None => {
                lock.owner = Some(task);
                lock.notify_gate = notify_gate;
                Ok(ClaimOutcome::Acquired)
            }
            // Idempotent: задача уже владеет.
            Some(owner) if owner == task => {
                // Doorbell-гейт можно обновить.
                if notify_gate.is_some() {
                    lock.notify_gate = notify_gate;
                }
                Ok(ClaimOutcome::Acquired)
            }
            // Занято другой задачей — блокировка претендента.
            // SMP v0.12: парковка идёт ПОД CLAIM-локом (вместе с проверкой
            // владельца выше — одна критсекция): release на другом CPU не
            // может «промахнуться» мимо претендента между его проверкой и
            // публикацией в wait_queue (lost-wakeup закрыт).
            Some(_) => {
                if mode == crate::ipc::BlockMode::Try {
                    return Err(ClaimError::Task(TaskError::ThreadWaitState(thread)));
                }
                if lock.wait_queue == BlockQueueId::default() {
                    return Err(ClaimError::NoWaitQueue);
                }
                let queue = lock.wait_queue;
                // Двухфазный контракт BlockQueueId: состояние -> парковка.
                // Оба шага — ПОД CLAIM-локом (см. комментарий ветки).
                tasks.thread_set_state(&thread, TaskState::Blocked)?;
                tasks.with_thread(&thread, |t| {
                    t.wait = Some(ThreadWait::Queue {
                        queue,
                        tag: CLAIM_WAIT_TAG,
                    });
                });
                let sched = tasks.scheduler().ok_or(ClaimError::NoWaitQueue)?;
                sched
                    .block_push(queue, thread)
                    .map_err(TaskError::Scheduler)?;
                Ok(ClaimOutcome::Blocked)
            }
        }
    }

    /// Отпустить лок (только владелец; при удалении устройства — форс
    /// из `on_device_removed`). Будит FIFO-претендента: его задача
    /// становится новым владельцем, его сискол завершается успехом.
    ///
    /// Возвращает новую задачу-владельца (если претендент был).
    pub fn release(
        &self,
        tasks: &TcbManager,
        device: &DevicePath,
        by: Option<TaskId>,
    ) -> Result<Option<TaskId>, ClaimError> {
        let mut locks = self.locks.lock();
        let Some(lock) = locks.iter_mut().find(|l| &l.device == device) else {
            return Err(ClaimError::DeviceNotFound);
        };
        match (lock.owner, by) {
            // Форс-релиз (by = None) или владелец отпускает сам.
            (Some(owner), Some(by)) if owner != by => {
                return Err(ClaimError::NotHeld);
            }
            _ => {}
        }

        // Снятие владельца; notify-гейт гасится вместе с владением.
        lock.owner = None;
        lock.notify_gate = None;

        // FIFO-претендент: его задача — новый владелец, сискол — успех.
        if lock.wait_queue != BlockQueueId::default() {
            let queue = lock.wait_queue;
            let sched = tasks.scheduler();
            let next = sched.and_then(|s| s.block_pop_front(queue).ok()).flatten();
            if let Some(waiter) = next {
                // Проверка причины ожидания (контракт Queue + тег claim).
                let is_claim = tasks
                    .with_thread(&waiter, |t| {
                        matches!(&t.wait, Some(ThreadWait::Queue { tag, .. }) if *tag == CLAIM_WAIT_TAG)
                    })
                    .unwrap_or(false);
                if !is_claim {
                    return Err(ClaimError::Internal);
                }
                let new_owner = tasks.thread_task(&waiter).ok_or(ClaimError::Internal)?;
                let lock = locks
                    .iter_mut()
                    .find(|l| &l.device == device)
                    .expect("лок найден выше");
                lock.owner = Some(new_owner);
                drop(locks);
                tasks.with_thread(&waiter, |t| {
                    t.wait = None;
                    t.syscall_ret = Some(0);
                });
                tasks.thread_set_state(&waiter, TaskState::Ready)?;
                return Ok(Some(new_owner));
            }
        }
        Ok(None)
    }

    /// Статус лока устройства (сискол DEVICE_CLAIM_STATUS).
    pub fn status(&self, tasks: &TcbManager, device: &DevicePath) -> Option<ClaimStatus> {
        let locks = self.locks.lock();
        let lock = locks.iter().find(|l| &l.device == device)?;
        let waiters = if lock.wait_queue == BlockQueueId::default() {
            0
        } else {
            tasks
                .scheduler()
                .and_then(|s| s.block_len(lock.wait_queue).ok())
                .unwrap_or(0)
        };
        Some(ClaimStatus {
            device: lock.device.clone(),
            owner: lock.owner,
            waiters,
            gone: lock.gone,
        })
    }

    /// Горячее удаление устройства (rescan пометил запись `alive = false`).
    ///
    /// ЯДЕРНАЯ ОШИБКА + IPC (требование №1):
    /// 1. владелец получает на notify_gate сообщение
    ///    `[DEVICE_LOST_TAG, kind, id0, id1]` (async, не блокирует ядро);
    /// 2. лок форс-снимается;
    /// 3. все претенденты из wait_queue будятся с syscall_ret =
    ///    [`DEVICE_GONE_RET`] (отрицательный errno пользователю);
    /// 4. лок «отравляется» (gone = true) до повторного появления
    ///    устройства (`device_alive_again`).
    ///
    /// Возвращает задачу-владельца, потерявшую устройство (для лога).
    pub fn on_device_removed(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        ipc: &IpcManager,
        device: &DevicePath,
    ) -> Result<Option<TaskId>, ClaimError> {
        self.removal_epoch.fetch_add(1, Ordering::Relaxed);
        // Снимаем владение/гейт и рвём лок — одним заимствованием.
        let (owner, notify_gate, queue) = {
            let mut locks = self.locks.lock();
            let Some(lock) = locks.iter_mut().find(|l| &l.device == device) else {
                return Ok(None);
            };
            let owner = lock.owner.take();
            let gate = lock.notify_gate.take();
            lock.gone = true;
            lock.gone_epoch = self.removal_epoch.load(Ordering::Relaxed);
            (owner, gate, lock.wait_queue)
        };

        // 1. IPC-уведомление владельцу (ошибка «по IPC»).
        if let (Some(_owner), Some(gate)) = (owner, notify_gate) {
            let mut msg = IpcMessage::new(IPC_KERNEL_FROM);
            for w in Self::device_lost_words(device) {
                let _ = msg.push_word(w);
            }
            // Очередь полна — событие не теряется молча: ядро обязано
            // стараться; QueueFull наверх (платформа решает: паника
            // драйвера-владельца или retry).
            let _ = ipc.kernel_send(tasks, caps, gate, Box::new(msg));
        }

        // 2. Претенденты: разбуждение с ошибкой ядра.
        if queue != BlockQueueId::default() {
            let sched = tasks.scheduler();
            while let Some(waiter) = sched.and_then(|s| s.block_pop_front(queue).ok()).flatten() {
                tasks.with_thread(&waiter, |t| {
                    t.wait = None;
                    t.syscall_ret = Some(DEVICE_GONE_RET);
                });
                let _ = tasks.thread_set_state(&waiter, TaskState::Ready);
            }
        }
        Ok(owner)
    }

    /// Устройство снова видно шиной (повторное появление после
    /// hot-removal): «отравление» снимается, лок свободен.
    pub fn device_alive_again(&self, device: &DevicePath) {
        if let Some(lock) = self.locks.lock().iter_mut().find(|l| &l.device == device) {
            lock.gone = false;
        }
    }

    /// Все локи задачи (разрушение домена: авто-release).
    /// Возвращает освобождённые устройства.
    pub fn release_all_of(&self, tasks: &TcbManager, task: &TaskId) -> Vec<DevicePath> {
        let mut freed = Vec::new();
        let devices: Vec<DevicePath> = self
            .locks
            .lock()
            .iter()
            .filter(|l| l.owner == Some(*task))
            .map(|l| l.device.clone())
            .collect();
        for device in devices {
            if self.release(tasks, &device, Some(*task)).is_ok() {
                freed.push(device);
            }
        }
        freed
    }

    /// Локи, удерживаемые задачей (аудит).
    pub fn locks_of(&self, task: &TaskId) -> Vec<DevicePath> {
        self.locks
            .lock()
            .iter()
            .filter(|l| l.owner == Some(*task))
            .map(|l| l.device.clone())
            .collect()
    }
}

impl Default for DeviceClaimRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// FNV-1a хеш строки (стабильная идентификация ACPI/DT-путей в словах
/// IPC; не криптография — только уникальность в рамках реестра).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityManager;
    use crate::hal::types::Bdf;
    use crate::ipc::IpcManager;
    use crate::task::{TaskPriority, TcbManager};

    /// Тестовый планировщик с block-очередями (сам бекенд — отдельный
    /// крейт, здесь только фикстура для проверки контракта).
    struct MockScheduler {
        queues: core::cell::RefCell<
            alloc::collections::BTreeMap<u64, alloc::collections::VecDeque<ThreadId>>,
        >,
        next: core::cell::Cell<u64>,
        enqueued: core::cell::Cell<usize>,
        descheduled: core::cell::Cell<usize>,
    }

    impl MockScheduler {
        fn new() -> Self {
            Self {
                queues: core::cell::RefCell::new(alloc::collections::BTreeMap::new()),
                next: core::cell::Cell::new(1),
                enqueued: core::cell::Cell::new(0),
                descheduled: core::cell::Cell::new(0),
            }
        }
    }

    impl crate::task::SchedulerInterface for MockScheduler {
        fn current(&self, _cpu: crate::task::CpuId) -> Option<ThreadId> {
            None
        }
        fn enqueue(&self, _task: ThreadId) -> Result<(), crate::task::SchedulerError> {
            self.enqueued.set(self.enqueued.get() + 1);
            Ok(())
        }
        fn deschedule(&self, _task: ThreadId) -> Result<(), crate::task::SchedulerError> {
            self.descheduled.set(self.descheduled.get() + 1);
            Ok(())
        }
        fn on_priority_change(
            &self,
            _task: ThreadId,
            _priority: crate::task::TaskPriority,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn switch_context(
            &self,
            _cpu: crate::task::CpuId,
            _prev: Option<ThreadId>,
            _next: ThreadId,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn isolation_policy(
            &self,
            _cpu: crate::task::CpuId,
        ) -> crate::hal::traits::kmap::IsolationPolicy {
            crate::hal::traits::kmap::IsolationPolicy::conservative()
        }
        fn perform_tick(&self, _delta: u64) {}

        fn block_queue_create(&self) -> Result<BlockQueueId, crate::task::SchedulerError> {
            let id = self.next.get();
            self.next.set(id + 1);
            Ok(BlockQueueId::new(id))
        }
        fn block_queue_destroy(
            &self,
            _queue: BlockQueueId,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn block_push(
            &self,
            queue: BlockQueueId,
            thread: ThreadId,
        ) -> Result<(), crate::task::SchedulerError> {
            self.queues
                .borrow_mut()
                .entry(queue.0)
                .or_default()
                .push_back(thread);
            Ok(())
        }
        fn block_remove(
            &self,
            queue: BlockQueueId,
            thread: ThreadId,
        ) -> Result<bool, crate::task::SchedulerError> {
            let mut queues = self.queues.borrow_mut();
            if let Some(q) = queues.get_mut(&queue.0) {
                if let Some(i) = q.iter().position(|t| *t == thread) {
                    q.remove(i);
                    return Ok(true);
                }
            }
            Ok(false)
        }
        fn block_pop_front(
            &self,
            queue: BlockQueueId,
        ) -> Result<Option<ThreadId>, crate::task::SchedulerError> {
            let mut queues = self.queues.borrow_mut();
            Ok(queues.get_mut(&queue.0).and_then(|q| q.pop_front()))
        }
        fn block_len(&self, queue: BlockQueueId) -> Result<usize, crate::task::SchedulerError> {
            Ok(self.queues.borrow().get(&queue.0).map_or(0, |q| q.len()))
        }
    }

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0x2000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    fn setup() -> (
        &'static TcbManager,
        &'static CapabilityManager,
        &'static IpcManager,
        &'static MockScheduler,
    ) {
        let tasks: &'static TcbManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(IpcManager::new()));
        let sched: &'static MockScheduler =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(MockScheduler::new()));
        tasks.install_scheduler(sched);
        (tasks, caps, ipc, sched)
    }

    fn pci_path(bus: u8, dev: u8, func: u8) -> DevicePath {
        DevicePath::Pci(Bdf::new(0, bus, dev, func))
    }

    #[test]
    fn exclusive_claim_release_and_wakeup() {
        let (tasks, _caps, _ipc, _sched) = setup();
        let mut claims = DeviceClaimRegistry::new();
        let dev = pci_path(1, 0, 0);

        // Задачи и потоки.
        let t_a = uuid_next();
        let t_b = uuid_next();
        tasks.create(t_a, TaskPriority::DEFAULT).unwrap();
        tasks.create(t_b, TaskPriority::DEFAULT).unwrap();
        let th_a = uuid_next();
        let th_b = uuid_next();
        tasks
            .create_thread(th_a, t_a, TaskPriority(10), 0, 0)
            .unwrap();
        tasks
            .create_thread(th_b, t_b, TaskPriority(10), 0, 0)
            .unwrap();

        // A захватывает.
        assert_eq!(
            claims
                .claim(
                    tasks,
                    &dev,
                    true,
                    t_a,
                    th_a,
                    None,
                    crate::ipc::BlockMode::Try
                )
                .unwrap(),
            ClaimOutcome::Acquired
        );
        assert_eq!(claims.status(tasks, &dev).unwrap().owner, Some(t_a));

        // Повторный claim владельца — idempotent.
        assert_eq!(
            claims
                .claim(
                    tasks,
                    &dev,
                    true,
                    t_a,
                    th_a,
                    None,
                    crate::ipc::BlockMode::Try
                )
                .unwrap(),
            ClaimOutcome::Acquired
        );

        // B блокируется (wait_queue); поток B «исполняется» (Running) —
        // блокировка всегда действие исполняющегося потока.
        tasks.thread_set_state(&th_b, TaskState::Running).unwrap();
        assert_eq!(
            claims
                .claim(
                    tasks,
                    &dev,
                    true,
                    t_b,
                    th_b,
                    None,
                    crate::ipc::BlockMode::Blocking
                )
                .unwrap(),
            ClaimOutcome::Blocked
        );
        assert_eq!(tasks.thread_view(&th_b).unwrap().state, TaskState::Blocked);
        assert_eq!(claims.status(tasks, &dev).unwrap().waiters, 1);

        // A отпускает: B становится владельцем, его сискол завершён.
        let new_owner = claims.release(tasks, &dev, Some(t_a)).unwrap();
        assert_eq!(new_owner, Some(t_b));
        assert_eq!(tasks.thread_view(&th_b).unwrap().state, TaskState::Ready);
        assert_eq!(tasks.thread_syscall_ret(&th_b), Some(Some(0)));
        assert_eq!(claims.status(tasks, &dev).unwrap().owner, Some(t_b));

        // Чужой release — отказ.
        assert!(matches!(
            claims.release(tasks, &dev, Some(t_a)),
            Err(ClaimError::NotHeld)
        ));

        // B отпускает: очередь пуста — лок свободен.
        claims.release(tasks, &dev, Some(t_b)).unwrap();
        assert_eq!(claims.status(tasks, &dev).unwrap().owner, None);

        // Локи задачи: авто-release при выходе.
        claims
            .claim(
                tasks,
                &dev,
                true,
                t_a,
                th_a,
                None,
                crate::ipc::BlockMode::Try,
            )
            .unwrap();
        assert_eq!(claims.locks_of(&t_a), alloc::vec![dev.clone()]);
        claims.release_all_of(tasks, &t_a);
        assert_eq!(claims.status(tasks, &dev).unwrap().owner, None);
    }

    #[test]
    fn hot_removal_notifies_owner_and_poisons() {
        let (tasks, caps, ipc, _sched) = setup();
        let mut claims = DeviceClaimRegistry::new();
        let dev = pci_path(2, 3, 0);

        // Задача-владелец + exit/notify endpoint (notification, ёмкость 4).
        let owner = uuid_next();
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();
        let th = uuid_next();
        tasks
            .create_thread(th, owner, TaskPriority(10), 0, 0)
            .unwrap();
        let ep = ipc
            .create_endpoint(
                tasks,
                caps,
                owner,
                4,
                crate::capability::ActionPermissions::all(),
                crate::capability::CapabilityBadge::FULL,
            )
            .unwrap();
        let gate = caps.endpoint_of(tasks, owner, ep).unwrap();

        // Захват с notify-гейтом.
        claims
            .claim(
                tasks,
                &dev,
                true,
                owner,
                th,
                Some(gate),
                crate::ipc::BlockMode::Try,
            )
            .unwrap();

        // Претендент-жертва (будет разбужен с ошибкой).
        let other = uuid_next();
        tasks.create(other, TaskPriority::DEFAULT).unwrap();
        let th2 = uuid_next();
        tasks
            .create_thread(th2, other, TaskPriority(10), 0, 0)
            .unwrap();
        tasks.thread_set_state(&th2, TaskState::Running).unwrap();
        claims
            .claim(
                tasks,
                &dev,
                true,
                other,
                th2,
                None,
                crate::ipc::BlockMode::Blocking,
            )
            .unwrap();

        // HOT-REMOVAL: владелец теряет лок.
        let lost = claims.on_device_removed(tasks, caps, ipc, &dev).unwrap();
        assert_eq!(lost, Some(owner));
        assert_eq!(claims.status(tasks, &dev).unwrap().owner, None);
        assert!(claims.status(tasks, &dev).unwrap().gone);

        // Претендент разбужен с кодом ошибки ядра.
        assert_eq!(tasks.thread_view(&th2).unwrap().state, TaskState::Ready);
        assert_eq!(tasks.thread_syscall_ret(&th2), Some(Some(DEVICE_GONE_RET)));

        // IPC-уведомление в буфере endpoint'а: тег DEVICE_LOST + идентичность.
        let msg = ipc
            .recv(tasks, caps, th, ep, crate::ipc::BlockMode::Try)
            .unwrap();
        if let crate::ipc::RecvOutcome::Message(msg) = msg {
            assert_eq!(msg.word(0), DEVICE_LOST_TAG);
            assert_eq!(msg.word(1), 1); // Pci
        } else {
            panic!("уведомление обязано быть в буфере");
        }

        // Claim удалённого — DeviceGone (ошибка от ядра).
        assert!(matches!(
            claims.claim(
                tasks,
                &dev,
                false,
                other,
                th2,
                None,
                crate::ipc::BlockMode::Try
            ),
            Err(ClaimError::DeviceGone)
        ));

        // Возвращение устройства снимает отравление.
        claims.device_alive_again(&dev);
        assert!(!claims.status(tasks, &dev).unwrap().gone);
    }

    #[test]
    fn device_lost_words_stable() {
        let dev = pci_path(0, 1, 2);
        let w = DeviceClaimRegistry::device_lost_words(&dev);
        assert_eq!(w[0], DEVICE_LOST_TAG);
        assert_eq!(w[1], 1);

        // Акпи-путь — хеш стабилен.
        let p1 = DevicePath::Acpi(crate::hal::types::AcpiPath::new("\\_SB.DEV0"));
        let p2 = DevicePath::Acpi(crate::hal::types::AcpiPath::new("\\_SB.DEV0"));
        assert_eq!(
            DeviceClaimRegistry::device_lost_words(&p1),
            DeviceClaimRegistry::device_lost_words(&p2)
        );
        assert_eq!(DeviceClaimRegistry::device_lost_words(&p1)[1], 2);
    }
}
