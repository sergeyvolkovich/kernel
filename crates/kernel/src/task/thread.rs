// ==== Потоки (L4: задача = protection domain, поток = единица планирования) ====
//
// Модель L4-Fiasco: ЗАДАЧА — домен защиты (cspace + адресное пространство,
// `TaskObj` в `TcbManager`), ПОТОК — сущность, которую диспетчирует
// планировщик. Потоки живут в задачах (у каждого — владелец-домен),
// разделяют её cspace и фасад памяти, но имеют собственные:
//   * состояние автомата (тот же словарь `TaskState`: Ready/Running/
//     Blocked/Suspended/Dead — конечный автомат потоковый по природе);
//   * приоритет (планировщик оперирует приоритетами ПОТОКОВ);
//   * точку старта (entry/stack — raw-слова; контекст строит arch-глюй);
//   * IPC-состояние: что поток ждёт ([`ThreadWait`]), почтовый ящик
//     доставленных сообщений, сообщение заблокированного отправителя и
//     парковочная очередь direct-IPC (L4-очередь приёмника).
//
// Идентификаторы: ThreadId разделяет пространство имён с TaskId (Uuid) —
// как глобальные номера L4, где задача адресуется зарезервированным
// «chief»-номером. Планировщик видит один тип.
//
// Таблица объектов — та же схема type-stable PagedTable: слоты не
// двигаются, generation защищает от ABA, TargetRef не нужен (capability
// на потоки пока не заводится — управление через TaskTCB домена).
//
// Каскад терминирования: перевод ЗАДАЧИ в Dead гасит все её живые потоки
// (каждый — через свой автомат состояний с хуками планировщика), поэтому
// `TcbManager::destroy` задачи не увидит осиротевших потоков.

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

use core::sync::atomic::{AtomicUsize, Ordering};

use intrusive_collections::{Bound, KeyAdapter, RBTree, RBTreeLink, UnsafeRef, intrusive_adapter};

use crate::capability::ObjId;
use crate::capability::paged::{KernelObj, ObjHeader, PagedTable};
use crate::ipc::IpcMessage;
use crate::task::scheduler::BlockQueueId;
use crate::task::types::{TaskError, TaskId, TaskPriority, TaskState, ThreadId, ThreadView};
use crate::task::{TaskObj, TcbInner, TcbManager, find_task};

/// Слотов на страницу таблицы потоков.
const THREAD_PAGE_SLOTS: usize = 8;
/// Страниц в каталоге: квота — 512 потоков на систему.
const THREAD_DIR_LEN: usize = 64;

// ==== Состояние ожидания ====

/// Что именно ждёт заблокированный поток (`ThreadObj::wait`).
///
/// Причина ожидания — ключ к правильному разбуждению: подсистема, которая
/// блокировала поток, знает, как его разбудить (IPC — очередь endpoint'а,
/// claim — очередь лок-объекта), и проверяет причину при пробуждении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadWait {
    /// Открытый приём (L4 open receive): от любого отправителя.
    /// Разбужен только `IpcManager::send_thread` (fast-path).
    RecvAny,
    /// Приём с endpoint'а (capability-адресованный).
    RecvEndpoint { gate: ObjId },
    /// Отправка в endpoint (сообщение — в `ThreadObj::blocked_msg`).
    /// `then_recv` — фаза L4 ipc_call: сразу после доставки сообщения
    /// поток переходит к приёму ответа на reply-гейте.
    SendEndpoint {
        gate: ObjId,
        then_recv: Option<ObjId>,
    },
    /// Универсальная очередь планировщика (claim устройства и т.п.):
    /// `tag` — идентификатор ожидания для подсистемы-владельца очереди.
    Queue { queue: BlockQueueId, tag: u64 },
}

// ==== Объект потока ====

/// Поток в глобальной таблице. Внутренность менеджера: наружу — только
/// копии-снимки ([`ThreadView`]) и операции через `TcbManager`.
#[repr(C)]
pub(crate) struct ThreadObj {
    /// Поколение объекта (первое поле — контракт [`KernelObj`]).
    pub(crate) hdr: ObjHeader,
    /// Членство в реестре `by_uuid` (редкий путь).
    link: RBTreeLink,
    /// Собственный индекс в таблице (для free без обратного маппинга).
    pub(crate) self_idx: u32,
    pub(crate) thread_id: ThreadId,
    /// Домен-владелец (cspace и фасад памяти общие с ним).
    pub(crate) owner: TaskId,

    pub(crate) state: TaskState,
    pub(crate) priority: TaskPriority,
    /// Точка старта: IP входа (raw-слово; контекст строит arch-глюй).
    pub(crate) entry: usize,
    /// Точка старта: вершина стека (raw-слово).
    pub(crate) stack_top: usize,

    /// Причина ожидания (`None` — поток не блокирован ожиданием).
    pub(crate) wait: Option<ThreadWait>,
    /// Доставленное сообщение (ждёт выгрузки в пользователя словами).
    pub(crate) mailbox: Option<Box<IpcMessage>>,
    /// Сообщение заблокированного отправителя (пока в send-очереди).
    pub(crate) blocked_msg: Option<Box<IpcMessage>>,
    /// Парковочная очередь direct-IPC (L4-очередь приёмника).
    pub(crate) parked: VecDeque<Box<IpcMessage>>,
    /// Материализованный возврат заблокированного сискола.
    pub(crate) syscall_ret: Option<usize>,
}

unsafe impl KernelObj for ThreadObj {
    fn hdr(&self) -> &ObjHeader {
        &self.hdr
    }
}
const _: () = assert!(core::mem::offset_of!(ThreadObj, hdr) == 0);

intrusive_adapter!(pub(crate) ThreadAdapter = UnsafeRef<ThreadObj>: ThreadObj { link => RBTreeLink });

impl<'a> KeyAdapter<'a> for ThreadAdapter {
    type Key = ThreadId;
    #[inline]
    fn get_key(&self, tcb: &'a ThreadObj) -> ThreadId {
        tcb.thread_id
    }
}

/// Таблица/реестр потоков внутри [`TcbManager`] (поле `TcbInner::threads`).
/// `pub(crate)`: менеджер собирает/дробит её вместе с таблицей задач под
/// одним KRwLock-контрактом менеджера (SMP v0.12).
pub(crate) struct ThreadInner {
    /// Порядок полей важен для дропа: реестр снимаем раньше таблицы.
    pub(crate) by_uuid: RBTree<ThreadAdapter>,
    pub(crate) threads: PagedTable<ThreadObj, THREAD_PAGE_SLOTS, THREAD_DIR_LEN>,
    /// Живые (не Dead) потоки ВСЕЙ системы — ленивый счётчик (v0.10).
    /// SMP v0.12: атомик — Dead-переходы на разных CPU идут параллельно,
    /// а транзакции IPC держат write-гард менеджера без &mut поля.
    pub(crate) total_live: AtomicUsize,
}

impl ThreadInner {
    pub(crate) fn new() -> Result<Self, TaskError> {
        Ok(Self {
            by_uuid: RBTree::new(ThreadAdapter::new()),
            threads: PagedTable::new().map_err(|_| TaskError::OutOfMemory)?,
            total_live: AtomicUsize::new(0),
        })
    }
}

// ==== Операции TcbManager над потоками ====
impl TcbManager {
    /// Создать поток в задаче-домене `owner` (состояние `Ready`).
    ///
    /// Идентификатор назначает вызывающий (внешний ключ, как у задач);
    /// коллизия в ОБЩЕМ пространстве с TaskId — [`TaskError::ThreadExists`].
    /// `entry`/`stack_top` — raw-слова старта: arch-глюй строит по ним
    /// контекст первого диспетчеризованного исполнения.
    ///
    /// Задача-владелец обязана быть живой (не Dead). При зарегистрированном
    /// планировщике поток ставится в очередь бекенда (`enqueue`); отказ
    /// бекенда полностью откатывает создание — поток, о котором не знает
    /// планировщик, не имеет права существовать.
    pub fn create_thread(
        &self,
        thread_id: ThreadId,
        owner: TaskId,
        priority: TaskPriority,
        entry: usize,
        stack_top: usize,
    ) -> Result<(), TaskError> {
        let mut inner = self.inner.write();

        // Владелец существует и жив?
        let owner_node = find_task(&inner, &owner).ok_or(TaskError::TaskNotFound(owner))?;
        // SAFETY: под write-гардом — эксклюзивный доступ.
        let owner_tcb = unsafe { &*UnsafeRef::into_raw(owner_node) };
        if owner_tcb.state == TaskState::Dead {
            return Err(TaskError::TaskNotFound(owner));
        }

        // Коллизия идентификаторов (потоки + задачи — одно пространство).
        if inner.threads.by_uuid.find(&thread_id).get().is_some()
            || inner.by_uuid.find(&thread_id).get().is_some()
        {
            return Err(TaskError::ThreadExists(thread_id));
        }

        // Песочница v0.9: предел живых потоков домена (атрибут GTCB).
        // Потоки, переведённые в Dead, не считаются — каскад смерти
        // уже погасил их. v0.10: ленивый счётчик GTCB `live_threads`
        // вместо O(n)-обхода реестра (спавн/флуд — горячий путь атак).
        let thread_limit = owner_tcb.limits.max_threads;
        if owner_tcb.live_threads >= thread_limit {
            return Err(TaskError::ThreadQuota {
                task: owner,
                limit: thread_limit,
            });
        }

        // SAFETY: слот неинициализирован; заполняется до любого разыменования.
        let slot = inner
            .threads
            .threads
            .alloc(|idx, generation| ThreadObj {
                hdr: ObjHeader::new(generation),
                link: RBTreeLink::new(),
                self_idx: idx,
                thread_id,
                owner,
                state: TaskState::Ready,
                priority,
                entry,
                stack_top,
                wait: None,
                mailbox: None,
                blocked_msg: None,
                parked: VecDeque::new(),
                syscall_ret: None,
            })
            .map_err(|_| TaskError::OutOfMemory)?;

        let node_ptr = {
            let node = inner
                .threads
                .threads
                .get_mut(slot.idx, slot.generation)
                .expect("слот только что выделен");
            core::ptr::from_mut(node)
        };
        // SAFETY: узел не отдан наружу, реестр — единственный контейнер.
        let node_ref = unsafe { UnsafeRef::from_raw(node_ptr) };
        inner.threads.by_uuid.insert(node_ref);

        // Хук планировщика (отказ — полный откат создания потока).
        if let Some(s) = inner.scheduler {
            if let Err(e) = s.enqueue(thread_id) {
                inner.threads.by_uuid.find_mut(&thread_id).remove();
                let freed = inner.threads.threads.free(slot.idx);
                debug_assert!(freed, "слот только что выделен");
                return Err(TaskError::Scheduler(e));
            }
        }
        // Успех: ленивые счётчики живых потоков (домен + система).
        // Свежая находка узла: первая (проверка квоты) уже отдала
        // UnsafeRef в into_raw — consuming-семантика.
        if let Some(owner_node) = find_task(&inner, &owner) {
            // SAFETY: эксклюзивный доступ под write-гардом; узел жив.
            let owner_tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(owner_node) };
            owner_tcb.live_threads += 1;
        }
        inner.threads.total_live.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Разрушить TCB потока. Контракт: поток завершён (`Dead`) и не ждёт.
    pub fn destroy_thread(&self, thread_id: ThreadId) -> Result<(), TaskError> {
        let mut inner = self.inner.write();

        let node = find_thread(&inner, &thread_id).ok_or(TaskError::ThreadNotFound(thread_id))?;
        let self_idx = {
            // SAFETY: под write-гардом — эксклюзивный доступ.
            let t: &ThreadObj = unsafe { &*UnsafeRef::into_raw(node) };
            if t.state != TaskState::Dead {
                return Err(TaskError::ThreadNotDead(thread_id));
            }
            t.self_idx
        };
        let removed = inner.threads.by_uuid.find_mut(&thread_id).remove();
        debug_assert!(removed.is_some(), "поток найден выше");
        let freed = inner.threads.threads.free(self_idx);
        debug_assert!(freed, "слот потока обязан быть живым");
        Ok(())
    }

    /// Снимок состояния потока.
    pub fn thread_view(&self, thread_id: &ThreadId) -> Option<ThreadView> {
        let inner = self.inner.read();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: под read-гардом — только чтение.
        let t: &ThreadObj = unsafe { &*UnsafeRef::into_raw(node) };
        Some(ThreadView {
            thread_id: t.thread_id,
            owner: t.owner,
            state: t.state,
            priority: t.priority,
            entry: t.entry,
            stack_top: t.stack_top,
        })
    }

    /// Владелец потока (задача-домен). `None` — потока нет.
    pub fn thread_task(&self, thread_id: &ThreadId) -> Option<TaskId> {
        let inner = self.inner.read();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: только чтение.
        let t: &ThreadObj = unsafe { &*UnsafeRef::into_raw(node) };
        Some(t.owner)
    }

    /// Снимки всех потоков задачи (порядок — по возрастанию ThreadId).
    pub fn threads_of(&self, owner: &TaskId) -> Vec<ThreadView> {
        let inner = self.inner.read();
        let mut out = Vec::new();
        for t in inner.threads.by_uuid.iter() {
            if &t.owner == owner {
                out.push(ThreadView {
                    thread_id: t.thread_id,
                    owner: t.owner,
                    state: t.state,
                    priority: t.priority,
                    entry: t.entry,
                    stack_top: t.stack_top,
                });
            }
        }
        out
    }

    /// Число живых (не Dead) потоков задачи.
    ///
    /// v0.10: O(1) — ленивый счётчик GTCB `live_threads` (точки его
    /// ведения: `create_thread` и Dead-переход потока).
    pub fn thread_count(&self, owner: &TaskId) -> usize {
        let inner = self.inner.read();
        match find_task(&inner, owner) {
            // SAFETY: только чтение под read-гардом.
            Some(node) => unsafe { (*UnsafeRef::into_raw(node)).live_threads },
            None => 0,
        }
    }

    /// Суммарное число живых потоков (аудит).
    ///
    /// v0.10: O(1) — ленивый системный счётчик `ThreadInner::total_live`.
    pub fn total_thread_count(&self) -> usize {
        let inner = self.inner.read();
        inner.threads.total_live.load(Ordering::Relaxed)
    }

    /// Перевести поток в `to` по автомату состояний (+ хуки планировщика).
    ///
    /// Зеркально `set_state` задач: `Ready` -> `enqueue`, `Blocked`/
    /// `Suspended`/`Dead` -> `deschedule`, `Running` — без хука.
    /// Переход в `Dead` гасит поколение объекта (защита от будущих
    /// ссылок) и сносит IPC-состояние (mailbox/parked/wait).
    pub fn thread_set_state(
        &self,
        thread_id: &ThreadId,
        to: TaskState,
    ) -> Result<TaskState, TaskError> {
        let inner = self.inner.write();
        thread_set_state_locked(&inner, thread_id, to)
    }

    /// Троттл-парковка потока квотой (SMP v0.12): Running -> Ready БЕЗ
    /// публикации в очередь готовности.
    ///
    /// Поток троттл-листа планировщика возвращается в готовность только
    /// на границе CPU-периода (`unthrottle_all`): enqueue-хук здесь НЕ
    /// звать — иначе поток оказался бы в кольце готовности, минуя
    /// троттл-парк. Убийство потока в троттл-листе корректно: Dead-переход
    /// вызывает `deschedule`, который вычищает троттл-лист бекенда.
    ///
    /// Возврат — прежнее состояние; `Err(InvalidTransition)` — поток
    /// уже не Running (убит в окне вытеснения): парковать нельзя,
    /// вызывающий (preempt-шаг) обязан бросить его без ре-очереди.
    pub fn thread_park_throttled(&self, thread_id: &ThreadId) -> Result<TaskState, TaskError> {
        let inner = self.inner.write();
        let node = find_thread(&inner, thread_id).ok_or(TaskError::ThreadNotFound(*thread_id))?;
        // SAFETY: эксклюзивный доступ под write-гардом менеджера.
        let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        let from = t.state;
        // Строго Running: троттл-парк — судьба ТОЛЬКО вытесненного
        // исполнителя. Blocked (успел заблокироваться) и Suspended
        // формально могут в Ready по автомату, но их готовность —
        // владение их собственных путей (wakeup/resume), не квоты.
        if from != TaskState::Running {
            return Err(TaskError::InvalidTransition {
                task: *thread_id,
                from,
                to: TaskState::Ready,
            });
        }
        // Без scheduler-хука: публикация — владение бекенда (троттл-лист).
        t.state = TaskState::Ready;
        Ok(from)
    }

    /// Транзакции IPC-парковки SMP v0.12 (зеркальные `recv_any_park` /
    /// `send_thread_offer`): переход автомата + публикация причины
    /// ожидания — ОДНА write-секция менеджера, чтобы встречная сторона
    /// (send/recv по тому же потоку) не видела промежуточных состояний.
    pub(crate) fn recv_any_park(
        &self,
        thread: &ThreadId,
        try_mode: bool,
    ) -> Result<RecvAnyPark, TaskError> {
        let inner = self.inner.write();
        {
            let node = find_thread(&inner, thread).ok_or(TaskError::ThreadNotFound(*thread))?;
            // SAFETY: эксклюзивный доступ под write-гардом.
            let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
            if let Some(m) = t.parked.pop_front() {
                return Ok(RecvAnyPark::Msg(m));
            }
            if try_mode {
                return Ok(RecvAnyPark::TryEmpty);
            }
        }
        // Парк: переход Blocked (хук deschedule) + причина — одна секция.
        thread_set_state_locked(&inner, thread, TaskState::Blocked)?;
        let node = find_thread(&inner, thread).ok_or(TaskError::ThreadNotFound(*thread))?;
        // SAFETY: эксклюзивный доступ под write-гардом.
        let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        t.wait = Some(ThreadWait::RecvAny);
        Ok(RecvAnyPark::Parked)
    }

    /// Зеркальная транзакция direct-IPC: [open-receive → claim] или
    /// [парковка в очередь потока] — одна write-секция.
    pub(crate) fn send_thread_offer(
        &self,
        to: &ThreadId,
        msg: Box<IpcMessage>,
    ) -> Result<SendThreadOffer, TaskError> {
        let inner = self.inner.write();
        let node = find_thread(&inner, to).ok_or(TaskError::ThreadNotFound(*to))?;
        // SAFETY: эксклюзивный доступ под write-гардом.
        let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        if t.state == TaskState::Blocked && matches!(t.wait, Some(ThreadWait::RecvAny)) {
            // Claim: причина ожидания снята, возврат материализован; поток
            // ещё Blocked — доставляющий переведёт его в Ready (вне локов
            // менеджера: map-элементы — KMEM, ранг не пересекается).
            t.wait = None;
            t.syscall_ret = Some(0);
            return Ok(SendThreadOffer::Claimed { msg });
        }
        if t.parked.len() >= crate::ipc::IPC_THREAD_PARK_MAX {
            return Ok(SendThreadOffer::Full);
        }
        t.parked.push_back(msg);
        Ok(SendThreadOffer::Parked)
    }

    /// Смена приоритета потока (хук `on_priority_change` планировщика).
    pub fn thread_set_priority(
        &self,
        thread_id: &ThreadId,
        priority: TaskPriority,
    ) -> Result<(), TaskError> {
        let inner = self.inner.write();

        let node = find_thread(&inner, thread_id).ok_or(TaskError::ThreadNotFound(*thread_id))?;
        // SAFETY: эксклюзивный доступ под write-гардом.
        let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };

        if let Some(s) = inner.scheduler {
            s.on_priority_change(*thread_id, priority)
                .map_err(TaskError::Scheduler)?;
        }
        t.priority = priority;
        Ok(())
    }

    /// Доступ к объекту потока для изменения (IPC-подсистема: mailbox,
    /// wait, blocked_msg, parked). `None` — потока нет. Реентери — паника.
    pub(crate) fn with_thread<R>(
        &self,
        thread_id: &ThreadId,
        f: impl FnOnce(&mut ThreadObj) -> R,
    ) -> Option<R> {
        let inner = self.inner.write();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: эксклюзивный доступ под write-гардом.
        let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        Some(f(t))
    }

    /// Снимок ожидания потока (аудит/отладка).
    pub fn thread_wait(&self, thread_id: &ThreadId) -> Option<Option<ThreadWait>> {
        self.with_thread(thread_id, |t| t.wait)
    }

    /// Материализованный возврат заблокированного сискола (arch-глюй
    /// читает после разбуждения; None — возврат ещё не готов).
    pub fn thread_syscall_ret(&self, thread_id: &ThreadId) -> Option<Option<usize>> {
        self.with_thread(thread_id, |t| t.syscall_ret)
    }

    /// Забрать материализованный возврат (владение; arch-гейт пишет его
    /// в rax пользователя при следующем входе). `None` — возврата нет.
    pub fn take_thread_syscall_ret(&self, thread_id: &ThreadId) -> Option<usize> {
        self.with_thread(thread_id, |t| t.syscall_ret.take())?
    }

    /// Первая пара (entry, stack) потока — стартовый контекст домена
    /// (главный поток задачи для протокола запуска L4).
    pub fn thread_start_info(&self, thread_id: &ThreadId) -> Option<(usize, usize)> {
        self.with_thread(thread_id, |t| (t.entry, t.stack_top))
    }

    /// L4 thread_ex_regs: сменить точку входа/стек потока (перезапуск,
    /// pager-протоколы, отладка). `None` в поле — не менять.
    ///
    /// Возвращает ПРЕЖНЮЮ пару (entry, stack) — arch-глюй восстанавливает
    /// контекст исполнения по новым значениям при следующей диспетчеризации.
    /// Мёртвый/несуществующий поток — [`TaskError::ThreadNotFound`];
    /// Dead не рестартуют (контракт автомата: воскрешение — новый поток).
    pub fn thread_ex_regs(
        &self,
        thread_id: &ThreadId,
        new_entry: Option<usize>,
        new_stack_top: Option<usize>,
    ) -> Result<(usize, usize), TaskError> {
        self.with_thread(thread_id, |t| {
            if t.state == TaskState::Dead {
                return None;
            }
            let old = (t.entry, t.stack_top);
            if let Some(e) = new_entry {
                t.entry = e;
            }
            if let Some(s) = new_stack_top {
                t.stack_top = s;
            }
            Some(old)
        })
        .ok_or(TaskError::ThreadNotFound(*thread_id))
        .and_then(|r| r.ok_or(TaskError::ThreadNotFound(*thread_id)))
    }
}

// ==== Транзакции IPC (SMP v0.12) ====

/// Исход `recv_any_park`: сообщение из парковочной очереди, парк в
/// open-receive или try-отказ (без парка).
pub(crate) enum RecvAnyPark {
    /// Сообщение из очереди потока (владение).
    Msg(Box<IpcMessage>),
    /// Поток переведён в Blocked + RecvAny (ждёт `send_thread`).
    Parked,
    /// Try-режим: очереди не было, парк не выполнялся.
    TryEmpty,
}

/// Исход `send_thread_offer`: claim открытого получателя (доставка —
/// на вызывающем, ВНЕ локов менеджера), парковка в очередь потока или
/// отказ по ёмкости.
pub(crate) enum SendThreadOffer {
    /// Получатель в open-receive и захвачен; сообщение возвращено
    /// вызывающему для доставки (map-элементы/mailbox/wake).
    Claimed { msg: Box<IpcMessage> },
    /// Сообщение припарковано в очередь потока-получателя.
    Parked,
    /// Очередь потока полна ([`crate::ipc::IPC_THREAD_PARK_MAX`]).
    Full,
}

/// Переход автомата состояний потока под УЖЕ взятым write-гардом
/// менеджера (транзакции `recv_any_park`/IPC-парковки: переход и
/// публикация причины ожидания — одна критсекция).
pub(crate) fn thread_set_state_locked(
    inner: &TcbInner,
    thread_id: &ThreadId,
    to: TaskState,
) -> Result<TaskState, TaskError> {
    let node = find_thread(inner, thread_id).ok_or(TaskError::ThreadNotFound(*thread_id))?;
    // SAFETY: эксклюзивный доступ под write-гардом менеджера.
    let t: &mut ThreadObj = unsafe { &mut *UnsafeRef::into_raw(node) };
    let from = t.state;

    if !from.can_transition_to(to) {
        return Err(TaskError::InvalidTransition {
            task: *thread_id,
            from,
            to,
        });
    }

    if let Some(s) = inner.scheduler {
        let notified = match to {
            TaskState::Ready => s.enqueue(*thread_id),
            TaskState::Blocked | TaskState::Suspended | TaskState::Dead => s.deschedule(*thread_id),
            TaskState::Running => Ok(()),
        };
        notified.map_err(TaskError::Scheduler)?;
    }

    if to == TaskState::Dead {
        t.hdr.kill();
        // IPC-состояние потока гасится вместе с ним.
        t.wait = None;
        t.mailbox = None;
        t.blocked_msg = None;
        t.parked.clear();
        t.syscall_ret = None;
        // v0.10: ленивые счётчики живых потоков (домен + система).
        // Каскад смерти задачи и одиночные завершения сходятся здесь.
        if from != TaskState::Dead {
            if let Some(owner_node) = find_task(inner, &t.owner) {
                // SAFETY: эксклюзивный доступ под write-гардом.
                let owner_tcb: &mut crate::task::TaskObj =
                    unsafe { &mut *UnsafeRef::into_raw(owner_node) };
                owner_tcb.live_threads = owner_tcb.live_threads.saturating_sub(1);
            }
            inner.threads.total_live.fetch_sub(1, Ordering::Relaxed);
        }
    }
    t.state = to;
    Ok(from)
}

// ==== Служебные ====

/// Поиск ThreadObj по Uuid (редкий путь — дерево). Возвращает невладеющую
/// ссылку: валидность гарантируется менеджером (узел жив, пока в реестре).
pub(crate) fn find_thread(inner: &TcbInner, thread_id: &ThreadId) -> Option<UnsafeRef<ThreadObj>> {
    let ptr = inner.threads.by_uuid.find(thread_id).get_ptr()?;
    // SAFETY: указатель на живой узел реестра.
    Some(unsafe { UnsafeRef::from_raw(ptr.as_ptr()) })
}

/// Первый поток реестра (курсорный обход без удержания гарда).
#[allow(dead_code)]
pub(crate) fn first_thread(inner: &TcbInner) -> Option<ThreadId> {
    inner.threads.by_uuid.front().get().map(|t| t.thread_id)
}

/// Следующий поток строго после `id` (обход без вложенных гардов).
#[allow(dead_code)]
pub(crate) fn next_thread_after(inner: &TcbInner, id: &ThreadId) -> Option<ThreadId> {
    let cursor = inner.threads.by_uuid.lower_bound(Bound::Excluded(id));
    cursor.get().map(|t| t.thread_id)
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use crate::task::{TaskError, TaskPriority, TaskState, TcbManager};

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0x1000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    fn manager() -> TcbManager {
        TcbManager::new().unwrap()
    }

    #[test]
    fn thread_lifecycle_in_task() {
        let tasks = manager();
        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();

        let t1 = uuid_next();
        let t2 = uuid_next();
        tasks
            .create_thread(t1, task, TaskPriority(10), 0x4000, 0x8000)
            .unwrap();
        tasks
            .create_thread(t2, task, TaskPriority(20), 0x5000, 0x9000)
            .unwrap();

        // Снимки: оба Ready, владельцы корректны, стартовая пара на месте.
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Ready);
        assert_eq!(tasks.thread_view(&t1).unwrap().owner, task);
        assert_eq!(tasks.thread_start_info(&t1), Some((0x4000, 0x8000)));
        assert_eq!(tasks.thread_view(&t2).unwrap().priority, TaskPriority(20));

        // Счётчики.
        assert_eq!(tasks.thread_count(&task), 2);
        assert_eq!(tasks.total_thread_count(), 2);
        assert_eq!(tasks.threads_of(&task).len(), 2);

        // Коллизия ID с задачей — ThreadExists (общее пространство имён).
        assert!(matches!(
            tasks.create_thread(task, task, TaskPriority(1), 0, 0),
            Err(TaskError::ThreadExists(_))
        ));

        // Автомат состояний потока: Ready -> Running (диспетчеризация)
        // -> Blocked (IPC/claim) -> Ready (wakeup) -> Dead.
        tasks.thread_set_state(&t1, TaskState::Running).unwrap();
        tasks.thread_set_state(&t1, TaskState::Blocked).unwrap();
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Blocked);
        tasks.thread_set_state(&t1, TaskState::Ready).unwrap();
        tasks.thread_set_state(&t1, TaskState::Dead).unwrap();
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Dead);

        // Ready -> Blocked напрямую запрещён автоматом (блокировка —
        // действие ИСПОЛНЯЮЩЕГОСЯ потока, см. can_transition_to).
        assert!(matches!(
            tasks.thread_set_state(&t2, TaskState::Blocked),
            Err(TaskError::InvalidTransition { .. })
        ));

        // Мёртвый поток не считается живым; разрушается по контракту.
        assert_eq!(tasks.thread_count(&task), 1);
        tasks.destroy_thread(t1).unwrap();

        // Destroy живого — отказ.
        assert!(matches!(
            tasks.destroy_thread(t2),
            Err(TaskError::ThreadNotDead(_))
        ));

        // Поток в чужой/несуществующей задаче — отказ.
        let ghost = uuid_next();
        assert!(matches!(
            tasks.create_thread(ghost, ghost, TaskPriority(1), 0, 0),
            Err(TaskError::TaskNotFound(_))
        ));
    }

    /// SMP v0.12: троттл-парковка — Running -> Ready БЕЗ enqueue-хука
    /// (поток уходит в троттл-лист бекенда, НЕ в очередь готовности),
    /// и отказ для потока, уже не Running (убит в окне вытеснения).
    #[test]
    fn thread_park_throttled_ready_without_enqueue() {
        let tasks = manager();
        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();
        let t1 = uuid_next();
        tasks
            .create_thread(t1, task, TaskPriority(10), 0x4000, 0x8000)
            .unwrap();

        // Диспетчеризация -> вытеснение по квоте: троттл-парк.
        tasks.thread_set_state(&t1, TaskState::Running).unwrap();
        let from = tasks.thread_park_throttled(&t1).unwrap();
        assert_eq!(from, TaskState::Running);
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Ready);

        // Возобновление с границы периода: Ready -> Running легально
        // (готовность возвращает бекенд — unthrottle_all).
        tasks.thread_set_state(&t1, TaskState::Running).unwrap();

        // Не-Running поток (Blocked) троттл-парковать нельзя — окно
        // вытеснения закрыло убийство/блокировку на другом CPU.
        tasks.thread_set_state(&t1, TaskState::Blocked).unwrap();
        assert!(matches!(
            tasks.thread_park_throttled(&t1),
            Err(TaskError::InvalidTransition { .. })
        ));
        // Состояние не тронуто отказом.
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Blocked);
    }

    #[test]
    fn task_death_cascades_to_threads() {
        let tasks = manager();
        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();
        let t1 = uuid_next();
        let t2 = uuid_next();
        tasks
            .create_thread(t1, task, TaskPriority(1), 0, 0)
            .unwrap();
        tasks
            .create_thread(t2, task, TaskPriority(2), 0, 0)
            .unwrap();

        // Терминирование задачи гасит потоки (каскад внутри менеджера).
        tasks.set_state(&task, TaskState::Dead).unwrap();
        assert_eq!(tasks.thread_view(&t1).unwrap().state, TaskState::Dead);
        assert_eq!(tasks.thread_view(&t2).unwrap().state, TaskState::Dead);
        assert_eq!(tasks.thread_count(&task), 0);

        // Потоки в мёртвой задаче не создаются.
        let t3 = uuid_next();
        assert!(matches!(
            tasks.create_thread(t3, task, TaskPriority(1), 0, 0),
            Err(TaskError::TaskNotFound(_))
        ));
    }
}
