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

use intrusive_collections::{Bound, KeyAdapter, RBTree, RBTreeLink, UnsafeRef, intrusive_adapter};

use crate::capability::ObjId;
use crate::capability::paged::{KernelObj, ObjHeader, PagedTable};
use crate::ipc::IpcMessage;
use crate::task::scheduler::BlockQueueId;
use crate::task::types::{TaskError, TaskId, TaskPriority, TaskState, ThreadId, ThreadView};
use crate::task::{TcbInner, TcbManager, find_task};

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
/// одним RefCell-контрактом однопоточности.
pub(crate) struct ThreadInner {
    /// Порядок полей важен для дропа: реестр снимаем раньше таблицы.
    pub(crate) by_uuid: RBTree<ThreadAdapter>,
    pub(crate) threads: PagedTable<ThreadObj, THREAD_PAGE_SLOTS, THREAD_DIR_LEN>,
}

impl ThreadInner {
    pub(crate) fn new() -> Result<Self, TaskError> {
        Ok(Self {
            by_uuid: RBTree::new(ThreadAdapter::new()),
            threads: PagedTable::new().map_err(|_| TaskError::OutOfMemory)?,
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
        let mut inner = self.inner.borrow_mut();

        // Владелец существует и жив?
        let owner_node = find_task(&inner, &owner).ok_or(TaskError::TaskNotFound(owner))?;
        // SAFETY: под borrow_mut — эксклюзивный доступ.
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
        Ok(())
    }

    /// Разрушить TCB потока. Контракт: поток завершён (`Dead`) и не ждёт.
    pub fn destroy_thread(&self, thread_id: ThreadId) -> Result<(), TaskError> {
        let mut inner = self.inner.borrow_mut();

        let node = find_thread(&inner, &thread_id).ok_or(TaskError::ThreadNotFound(thread_id))?;
        let self_idx = {
            // SAFETY: под borrow_mut — эксклюзивный доступ.
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
        let inner = self.inner.borrow();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: под borrow — только чтение.
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
        let inner = self.inner.borrow();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: только чтение.
        let t: &ThreadObj = unsafe { &*UnsafeRef::into_raw(node) };
        Some(t.owner)
    }

    /// Снимки всех потоков задачи (порядок — по возрастанию ThreadId).
    pub fn threads_of(&self, owner: &TaskId) -> Vec<ThreadView> {
        let inner = self.inner.borrow();
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
    pub fn thread_count(&self, owner: &TaskId) -> usize {
        let inner = self.inner.borrow();
        inner
            .threads
            .by_uuid
            .iter()
            .filter(|t| &t.owner == owner && t.state != TaskState::Dead)
            .count()
    }

    /// Суммарное число живых потоков (аудит).
    pub fn total_thread_count(&self) -> usize {
        let inner = self.inner.borrow();
        inner
            .threads
            .by_uuid
            .iter()
            .filter(|t| t.state != TaskState::Dead)
            .count()
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
        let inner = self.inner.borrow_mut();

        let node = find_thread(&inner, thread_id).ok_or(TaskError::ThreadNotFound(*thread_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
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
                TaskState::Blocked | TaskState::Suspended | TaskState::Dead => {
                    s.deschedule(*thread_id)
                }
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
        }
        t.state = to;
        Ok(from)
    }

    /// Смена приоритета потока (хук `on_priority_change` планировщика).
    pub fn thread_set_priority(
        &self,
        thread_id: &ThreadId,
        priority: TaskPriority,
    ) -> Result<(), TaskError> {
        let inner = self.inner.borrow_mut();

        let node = find_thread(&inner, thread_id).ok_or(TaskError::ThreadNotFound(*thread_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
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
        let inner = self.inner.borrow_mut();
        let node = find_thread(&inner, thread_id)?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
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

// ==== Служебные ====

/// Поиск ThreadObj по Uuid (редкий путь — дерево). Возвращает невладеющую
/// ссылку: валидность гарантируется менеджером (узел жив, пока в реестре).
pub(crate) fn find_thread(inner: &TcbInner, thread_id: &ThreadId) -> Option<UnsafeRef<ThreadObj>> {
    let ptr = inner.threads.by_uuid.find(thread_id).get_ptr()?;
    // SAFETY: указатель на живой узел реестра.
    Some(unsafe { UnsafeRef::from_raw(ptr.as_ptr()) })
}

/// Первый поток реестра (курсорный обход без удержания borrow).
#[allow(dead_code)]
pub(crate) fn first_thread(inner: &TcbInner) -> Option<ThreadId> {
    inner.threads.by_uuid.front().get().map(|t| t.thread_id)
}

/// Следующий поток строго после `id` (обход без вложенных borrow).
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
