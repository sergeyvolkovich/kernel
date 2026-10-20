// ==== Менеджер задач (TCB) + потоки (L4: домен защиты + единицы планирования) ====
//
// Двухуровневая схема (шаги 1–3 из плана):
//
// ```text
//   TcbManager
//   ├─ tasks: PagedTable<TaskObj>         глобальная таблица задач (домены):
//   │        + by_uuid: RBTree            страницы из slab, адреса стабильны,
//   │                                      у каждого объекта ObjHeader с поколением
//   ├─ threads: PagedTable<ThreadObj>     таблица потоков (планируемые сущности,
//   │        + threads_by_uuid: RBTree    см. task::thread — L4-модель)
//   └─ scheduler: Option<&dyn>            бекенд планировщика (контракт)
// ```
//
// Задача-объект — type-stable: слот в страничной таблице не двигается и не
// переиспользуется без смены поколения. Поэтому capability на задачу держат
// `TargetRef` (указатель на заголовок + generation) и проверяют живость одним
// атомарным чтением — спускаться по дереву не нужно (ленивая схема).
//
// Смерть задачи: переход в `Dead` инкрементирует поколение (`hdr.kill()`)
// ДО смены состояния (порядок из плана: сначала generation, потом ресурсы).
// Все TargetRef на задачу гаснут немедленно; слот объекта освобождается позже,
// в `destroy` (контракт «revoke_all → terminate → destroy» не изменился).
// Каскад: перевод задачи в Dead гасит и все её живые потоки (каждый — через
// свой автомат состояний с хуками планировщика).
//
// CSpace задачи — локальная таблица хендлов (уровень 2), см.
// `crate::capability::HandleTable`. Доступ к ней — только через
// `with_caps` / `with_caps_mut` (RefCell-контракт однопоточности).

pub mod scheduler;
pub mod thread;
pub mod types;

use alloc::boxed::Box;
use core::cell::RefCell;

use intrusive_collections::{Bound, KeyAdapter, RBTree, RBTreeLink, UnsafeRef, intrusive_adapter};

use crate::capability::{
    HandleTable, ObjId,
    paged::{KernelObj, ObjHeader, PagedTable, SlotRef, TargetRef},
};

pub use scheduler::{BLOCK_QUEUE_NONE, BlockQueueId, CpuId, SchedulerError, SchedulerInterface};
use thread::ThreadInner;
pub use thread::ThreadWait;
pub use types::{
    TaskError, TaskId, TaskLimits, TaskPriority, TaskSecView, TaskState, TaskUsage, TaskView,
    ThreadId, ThreadView,
};

/// Слотов на страницу таблицы задач (страница ~600 Б).
const TASK_PAGE_SLOTS: usize = 8;
/// Страниц в каталоге: квота — 256 задач на систему (подгони под ядро).
const TASK_DIR_LEN: usize = 32;

// ==== TaskObj ====

/// Объект задачи в глобальной таблице. Внутренность менеджера: наружу
/// отдаются только копии-снимки (`TaskView`) и `SlotRef`/`TargetRef`.
#[repr(C)]
pub(crate) struct TaskObj {
    /// Поколение объекта (первое поле — контракт [`KernelObj`]).
    hdr: ObjHeader,
    /// Членство в реестре `by_uuid` (редкий путь).
    link: RBTreeLink,
    /// Собственный индекс в `tasks` (для free без обратного маппинга).
    self_idx: u32,
    task_id: TaskId,

    state: TaskState,
    priority: TaskPriority,
    /// CSpace: локальная таблица хендлов (уровень 2). Box — стабильный
    /// адрес (slab-слот объекта не должен переезжать), создаётся вместе
    /// с задачей. Доступ менеджера capability — через with_caps[_mut].
    pub(crate) caps: Box<HandleTable>,
    /// Exit-endpoint задачи (гейт [`ObjId`]), куда ядро доставляет
    /// `crate::ipc::ExitPayload` при её завершении. `None` — родитель
    /// не регистрировал (доставка — тихий no-op).
    pub(crate) exit_ep: Option<ObjId>,
    /// Атрибуты песочницы v0.9: пределы домена + текущее потребление.
    /// Дефолт — [`TaskLimits::UNLIMITED`] (доверенная задача); лимиты
    /// назначает держатель TaskTCB-права через `set_limits` (трещотка).
    pub(crate) limits: TaskLimits,
    /// Учёт потребления для пределов (точки зарядки — сисколы памяти;
    /// CPU — гейт планировщика при вытеснении, v0.10).
    pub(crate) usage: TaskUsage,
    /// Живые (не Dead) потоки домена — ленивый счётчик GTCB (v0.10):
    /// инкремент в `create_thread`, декремент в Dead-переходе потока.
    /// Заменяет O(n)-обход реестра в проверке `max_threads` спавна.
    pub(crate) live_threads: usize,
}

unsafe impl KernelObj for TaskObj {
    fn hdr(&self) -> &ObjHeader {
        &self.hdr
    }
}
const _: () = assert!(core::mem::offset_of!(TaskObj, hdr) == 0);

intrusive_adapter!(pub(crate) TaskAdapter = UnsafeRef<TaskObj>: TaskObj { link => RBTreeLink });

impl<'a> KeyAdapter<'a> for TaskAdapter {
    type Key = TaskId;
    #[inline]
    fn get_key(&self, tcb: &'a TaskObj) -> TaskId {
        tcb.task_id
    }
}

// ==== Менеджер ====

/// Полное внутреннее состояние менеджера (задачи + потоки + планировщик).
/// `pub(crate)`: потоковые операции живут в сиблинг-модуле `task::thread`
/// и работают с теми же таблицами под одним контрактом RefCell.
pub(crate) struct TcbInner {
    /// Порядок полей важен для дропа: реестры снимаем раньше таблиц.
    pub(crate) by_uuid: RBTree<TaskAdapter>,
    pub(crate) tasks: PagedTable<TaskObj, TASK_PAGE_SLOTS, TASK_DIR_LEN>,
    /// Таблица/реестр потоков (L4-модель; см. `task::thread`).
    pub(crate) threads: ThreadInner,
    /// Планировщик-бекенд (контракт — `scheduler::SchedulerInterface`).
    /// `None` — планировщик не зарегистрирован: хуки не вызываются, и
    /// менеджер остаётся совместим с платформами без планировщика.
    pub(crate) scheduler: Option<&'static dyn SchedulerInterface>,
}

/// Менеджер задач: глобальные таблицы объектов (задачи-домены + потоки)
/// + uuid-индексы (редкий путь) + cspace-якорь каждой задачи.
///
/// Все методы принимают `&self`; сериализация — внутренним `RefCell`
/// (однопоточный контракт, см. тест `reentrancy_is_caught`).
pub struct TcbManager {
    inner: RefCell<TcbInner>,
}

impl TcbManager {
    /// Пустой реестр. Страницы таблиц выделяются лениво.
    pub fn new() -> Result<Self, TaskError> {
        Ok(Self {
            inner: RefCell::new(TcbInner {
                by_uuid: RBTree::new(TaskAdapter::new()),
                tasks: PagedTable::new().map_err(|_| TaskError::OutOfMemory)?,
                threads: ThreadInner::new()?,
                scheduler: None,
            }),
        })
    }

    // ==== Планировщик ====

    /// Регистрирует планировщик-бекенд (`&'static`: планировщик — глобальный
    /// сервис ядра со временем жизни программы).
    ///
    /// После регистрации менеджер уведомляет бекенд о переходах автомата
    /// состояний ЗАДАЧ (легаси-модель, для платформ без потоков) и ПОТОКОВ
    /// (L4-модель; см. `thread::TcbManager::create_thread`):
    ///
    /// | переход в        | хук                            |
    /// |------------------|--------------------------------|
    /// | `Ready` (create, из Blocked/Suspended) | `enqueue`      |
    /// | `Blocked`/`Suspended`/`Dead`           | `deschedule`   |
    /// | `Running`        | (без хука — диспетчеризация и есть событие планировщика) |
    ///
    /// Хуки вызываются ДО фиксации перехода: отказ бекенда
    /// ([`TaskError::Scheduler`]) оставляет автомат состояний нетронутым,
    /// а при создании задачи/потока — полностью откатывает регистрацию.
    ///
    /// Контракт реентерабельности: хуки вызываются под `borrow_mut`
    /// менеджера — синхронный реентери в методы `TcbManager` из бекенда
    /// паникует заимствованием (тот же контракт, что у `for_each`).
    /// Замена бекенда «на живую» — ответственность вызывающего: уже
    /// зарегистрированные сущности новому бекенду НЕ переются, его
    /// обязанность — синхронизировать состояние (или регистрировать
    /// бекенд до создания задач/потоков).
    pub fn install_scheduler(&self, scheduler: &'static dyn SchedulerInterface) {
        self.inner.borrow_mut().scheduler = Some(scheduler);
    }

    /// Зарегистрированный планировщик-бекенд, если есть.
    pub fn scheduler(&self) -> Option<&'static dyn SchedulerInterface> {
        self.inner.borrow().scheduler
    }

    // ==== Жизненный цикл задачи ====

    /// Создаёт задачу с уникальным `task_id` в состоянии `Ready`.
    ///
    /// Идентификатор назначает вызывающая сторона; повторная регистрация —
    /// [`TaskError::TaskExists`] (коллизия с ThreadId — тоже, общее
    /// пространство имён L4). При зарегистрированном планировщике задача
    /// ставится в очередь бекенда (`enqueue`; легаси-модель платформ без
    /// потоков); отказ бекенда откатывает создание целиком.
    pub fn create(&self, task_id: TaskId, priority: TaskPriority) -> Result<(), TaskError> {
        let mut inner = self.inner.borrow_mut();

        if inner.by_uuid.find(&task_id).get().is_some()
            || inner.threads.by_uuid.find(&task_id).get().is_some()
        {
            return Err(TaskError::TaskExists(task_id));
        }

        let caps = Box::new(HandleTable::new().map_err(|_| TaskError::OutOfMemory)?);
        // SAFETY: слот неинициализирован; заполняется здесь же, до любого
        // разыменования. Съёмка self_idx нужна для последующего free.
        let slot = inner
            .tasks
            .alloc(|idx, generation| TaskObj {
                hdr: ObjHeader::new(generation),
                link: RBTreeLink::new(),
                self_idx: idx,
                task_id,
                state: TaskState::Ready,
                priority,
                caps,
                exit_ep: None,
                limits: TaskLimits::UNLIMITED,
                usage: TaskUsage::default(),
                live_threads: 0,
            })
            .map_err(|_| TaskError::OutOfMemory)?;

        // Снимаем сырой указатель, пока borrow_mut таблицы жив, и вставляем
        // в реестр (нода не двигается — slab-слот страничной таблицы).
        let node_ptr = {
            let node = inner
                .tasks
                .get_mut(slot.idx, slot.generation)
                .expect("слот только что выделен");
            core::ptr::from_mut(node)
        };
        // SAFETY: узел никому снаружи не отдан, реестр — единственный
        // контейнер; вставка до любого возврата ошибки.
        let node_ref = unsafe { UnsafeRef::from_raw(node_ptr) };
        inner.by_uuid.insert(node_ref);

        // Хук планировщика после успешной регистрации TCB: бекенд получает
        // id уже существующей Ready-задачи. Отказ — полный откат создания
        // (снятие с реестра, освобождение слота с уничтожением TCB).
        if let Some(s) = inner.scheduler {
            if let Err(e) = s.enqueue(task_id) {
                inner.by_uuid.find_mut(&task_id).remove();
                let freed = inner.tasks.free(slot.idx);
                debug_assert!(freed, "слот только что выделен");
                return Err(TaskError::Scheduler(e));
            }
        }
        Ok(())
    }

    /// Разрушает TCB. Контракт вызова:
    /// 1. задача завершена (`state == Dead`), иначе [`TaskError::TaskNotDead`];
    /// 2. cspace пуст — сначала `CapabilityManager::revoke_all(task)`,
    ///    иначе [`TaskError::TaskHasCaps`];
    /// 3. живых потоков нет (каскад `set_state(Dead)` гасит их; остаток —
    ///    [`TaskError::TaskHasThreads`] на злоупотреблении API).
    ///
    /// Порядок «revoke_all → terminate → destroy» — ответственность
    /// вызывающего кода: менеджеры не вызывают друг друга в цикле.
    pub fn destroy(&self, task_id: TaskId) -> Result<(), TaskError> {
        let mut inner = self.inner.borrow_mut();

        let node = find_task(&inner, &task_id).ok_or(TaskError::TaskNotFound(task_id))?;
        let (self_idx, live) = {
            // SAFETY: под borrow_mut менеджера доступ к объекту эксклюзивен.
            let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(node) };
            if tcb.state != TaskState::Dead {
                return Err(TaskError::TaskNotDead(task_id));
            }
            if tcb.caps.live_count() != 0 {
                return Err(TaskError::TaskHasCaps {
                    task: task_id,
                    caps: tcb.caps.live_count(),
                });
            }
            (tcb.self_idx, tcb.live_threads)
        };
        // Осиротевшие живые потоки — отказ (каскад должен был погасить).
        // v0.10: ленивый счётчик GTCB вместо O(n)-обхода реестра.
        if live != 0 {
            return Err(TaskError::TaskHasThreads {
                task: task_id,
                threads: live,
            });
        }

        // Снятие с реестра и освобождение слота объекта: free сначала
        // бьёт поколение (все оставшиеся TargetRef гаснут), потом дропает.
        let removed = inner.by_uuid.find_mut(&task_id).remove();
        debug_assert!(removed.is_some(), "TCB найден выше");
        let freed = inner.tasks.free(self_idx);
        debug_assert!(freed, "слот объекта обязан быть живым");
        Ok(())
    }

    // ==== Атрибуты песочницы v0.9 (пределы GTCB + учёт) ====

    /// Назначить пределы задаче (трещотка: новые значения УЖЕСТОЧАЮТ
    /// текущие — `TaskLimits::tighten`, см. документацию типа). Право
    /// контролирует хендлер сискола (TaskTCB на цель), менеджер лишь
    /// хранит и применяет атомарно.
    pub fn set_limits(&self, task_id: &TaskId, tighten_to: TaskLimits) -> Result<(), TaskError> {
        let inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        tcb.limits = tcb.limits.tighten(&tighten_to);
        Ok(())
    }

    /// Снимок атрибутов безопасности задачи (пределы + потребление).
    pub fn sec_view(&self, task_id: &TaskId) -> Option<TaskSecView> {
        let inner = self.inner.borrow();
        let node = find_task(&inner, task_id)?;
        // SAFETY: только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(node) };
        Some(TaskSecView {
            limits: tcb.limits,
            usage: tcb.usage,
        })
    }

    /// Зарядить домену `pages` страниц (превышение max_pages — отказ
    /// [`TaskError::PageQuota`]; зарядка атомарна: при отказе счётчик не
    /// меняется). Вызов ДО фактической аллокации/отображения, откат —
    /// `refund_pages` при отказе подсистемы.
    pub fn charge_pages(&self, task_id: &TaskId, pages: usize) -> Result<(), TaskError> {
        let mut inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        let used = tcb.usage.pages;
        let limit = tcb.limits.max_pages;
        match used.checked_add(pages) {
            Some(total) if total <= limit => {
                tcb.usage.pages = total;
                Ok(())
            }
            _ => Err(TaskError::PageQuota {
                task: *task_id,
                used,
                limit,
            }),
        }
    }

    /// Вернуть `pages` страниц в учёт домена (MEM_FREE, grant-исход,
    /// откат неудачной зарядки). Счётчик не уходит ниже нуля.
    pub fn refund_pages(&self, task_id: &TaskId, pages: usize) {
        let mut inner = self.inner.borrow_mut();
        if let Some(node) = find_task(&inner, task_id) {
            // SAFETY: эксклюзивный доступ под borrow_mut.
            let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
            tcb.usage.pages = tcb.usage.pages.saturating_sub(pages);
        }
    }

    /// Зарядить домену один SHM-регион (предел max_shm).
    pub fn charge_shm(&self, task_id: &TaskId) -> Result<(), TaskError> {
        let mut inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        if tcb.usage.shm >= tcb.limits.max_shm {
            return Err(TaskError::ShmQuota {
                task: *task_id,
                limit: tcb.limits.max_shm,
            });
        }
        tcb.usage.shm += 1;
        Ok(())
    }

    /// Снять один SHM-регион с учёта домена (SHM_DESTROY).
    pub fn refund_shm(&self, task_id: &TaskId) {
        let mut inner = self.inner.borrow_mut();
        if let Some(node) = find_task(&inner, task_id) {
            // SAFETY: эксклюзивный доступ под borrow_mut.
            let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
            tcb.usage.shm = tcb.usage.shm.saturating_sub(1);
        }
    }

    // ==== CPU-квоты v0.10 (учёт троттлинга песочницы) ====

    /// Зарядить домену `ticks` тиков CPU (вытеснение потока гейтом
    /// планировщика; минимум 1 за проход — анти-спин для yield-циклов).
    ///
    /// Потреблённое не отказываем — счётчик клампится в квоту. Возврат
    /// `Ok(true)` — домен за пределом `cpu_quota`: планировщик обязан
    /// запарковать вытеснённый поток до границы периода (троттлинг).
    /// Первый вход за предел (и каждый после сброса периода) — аудит
    /// песочницы + `cpu_throttle_events += 1`. Квота `usize::MAX`
    /// (доверенный домен) — быстрый путь без бухгалтерии.
    pub fn charge_cpu(&self, task_id: &TaskId, ticks: usize) -> Result<bool, TaskError> {
        if ticks == 0 {
            return Ok(false);
        }
        let mut inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        let quota = tcb.limits.cpu_quota;
        if quota == usize::MAX {
            return Ok(false);
        }
        let total = tcb.usage.cpu_used.saturating_add(ticks);
        if total < quota {
            tcb.usage.cpu_used = total;
            return Ok(false);
        }
        // За пределом: счётчик клампится, флаг один раз логируется.
        tcb.usage.cpu_used = quota;
        if !tcb.usage.cpu_throttled {
            tcb.usage.cpu_throttled = true;
            tcb.usage.cpu_throttle_events = tcb.usage.cpu_throttle_events.saturating_add(1);
            sandbox_audit(&alloc::format!(
                "cpu quota: domain {} throttled (charged {} ticks, limit {} per period)",
                tcb.task_id,
                total,
                quota
            ));
        }
        Ok(true)
    }

    /// Граница CPU-периода: сбросить учёт всех доменов (вызывает бекенд
    /// планировщика через glue; потоки из троттл-листа возвращает в
    /// готовность сам бекенд). Возврат — число доменов, которые
    /// находились в троттлинге (аудит границы периода).
    pub fn on_cpu_period(&self) -> usize {
        let mut inner = self.inner.borrow_mut();
        // Реестр (KeyAdapter-RBTree) даёт только &TaskObj — два прохода:
        // снимок идентификаторов, затем точечные мутации через find_task
        // (свежая UnsafeRef; consuming-into_raw — без переиспользования).
        // Период редкий (~100 мс) — цена мала.
        let ids: alloc::vec::Vec<TaskId> = inner.by_uuid.iter().map(|t| t.task_id).collect();
        let mut unthrottled = 0;
        for id in ids {
            let Some(node) = find_task(&inner, &id) else {
                continue;
            };
            // SAFETY: эксклюзивный доступ под borrow_mut; узел жив в реестре.
            let t: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
            if t.usage.cpu_throttled {
                unthrottled += 1;
                t.usage.cpu_throttled = false;
            }
            t.usage.cpu_used = 0;
        }
        unthrottled
    }

    /// Предел `may_spawn` задачи (право творца; TASK_CREATE-хендлер).
    pub fn may_spawn(&self, task_id: &TaskId) -> Result<bool, TaskError> {
        let inner = self.inner.borrow();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(node) };
        Ok(tcb.limits.may_spawn)
    }

    // ==== Exit-endpoint (протокол завершения дочерних задач) ====

    /// Зарегистрировать exit-endpoint задачи (см. `crate::ipc` —
    /// три вида данных: код выхода / исключение / кем убита).
    pub(crate) fn set_exit_endpoint(&self, task_id: &TaskId, gate: ObjId) -> Result<(), TaskError> {
        let inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        tcb.exit_ep = Some(gate);
        Ok(())
    }

    /// Зарегистрированный exit-endpoint задачи (`None` — не регистрировался
    /// или задачи нет).
    pub(crate) fn exit_endpoint(&self, task_id: &TaskId) -> Option<ObjId> {
        let inner = self.inner.borrow();
        let node = find_task(&inner, task_id)?;
        // SAFETY: только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(node) };
        tcb.exit_ep
    }

    // ==== Чтение ====

    /// Зарегистрирована ли задача.
    pub fn contains(&self, task_id: &TaskId) -> bool {
        let inner = self.inner.borrow();
        inner.by_uuid.find(task_id).get().is_some()
    }

    /// Снимок состояния задачи.
    pub fn get(&self, task_id: &TaskId) -> Option<TaskView> {
        let inner = self.inner.borrow();
        let tcb = find_task(&inner, task_id)?;
        // SAFETY: под borrow — только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(tcb) };
        Some(TaskView {
            task_id: tcb.task_id,
            state: tcb.state,
            priority: tcb.priority,
        })
    }

    /// Стабильная ссылка задачи на себя в таблице объектов: `(idx, generation)`.
    /// Кэшируется планировщиком — горячий путь не ищет задачу по Uuid.
    pub fn self_slot(&self, task_id: &TaskId) -> Option<SlotRef> {
        let inner = self.inner.borrow();
        let tcb = find_task(&inner, task_id)?;
        // SAFETY: только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(tcb) };
        Some(SlotRef {
            idx: tcb.self_idx,
            generation: tcb.hdr.generation(),
        })
    }

    /// TargetRef на живую (не Dead) задачу — цель для capability.
    /// `None` — задача не существует или уже мертва (поколение побито).
    pub(crate) fn target_ref(&self, task_id: &TaskId) -> Option<TargetRef> {
        let inner = self.inner.borrow();
        let tcb = find_task(&inner, task_id)?;
        // SAFETY: только чтение.
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(tcb) };
        if tcb.state == TaskState::Dead {
            return None;
        }
        Some(TargetRef::from_obj(tcb))
    }

    /// Число живых задач.
    pub fn count(&self) -> usize {
        let inner = self.inner.borrow();
        inner.by_uuid.iter().count()
    }

    /// Обход всех задач в порядке возрастания `task_id` (редкий путь:
    /// uuid-дерево). Callback получает копии, TCB наружу не утекает.
    /// Вызов методов менеджера из callback — паника RefCell.
    pub fn for_each(&self, mut f: impl FnMut(TaskView)) {
        let inner = self.inner.borrow();
        for tcb in inner.by_uuid.iter() {
            f(TaskView {
                task_id: tcb.task_id,
                state: tcb.state,
                priority: tcb.priority,
            });
        }
    }

    /// Первая задача реестра (курсорный обход без удержания borrow).
    pub(crate) fn first_task(&self) -> Option<TaskId> {
        let inner = self.inner.borrow();
        inner.by_uuid.front().get().map(|t| t.task_id)
    }

    /// Следующая задача строго после `task_id` (для дроп-обхода менеджера
    /// capability без аллокаций и без вложенных borrow).
    pub(crate) fn next_task_after(&self, task_id: &TaskId) -> Option<TaskId> {
        let inner = self.inner.borrow();
        let cursor = inner.by_uuid.lower_bound(Bound::Excluded(task_id));
        cursor.get().map(|t| t.task_id)
    }

    // ==== Изменение состояния ====

    /// Переводит задачу в `to`, проверяя переход по автомату состояний.
    /// Возвращает прежнее состояние.
    ///
    /// Переход в `Dead` сначала инкрементирует поколение объекта (все
    /// TargetRef на задачу гаснут немедленно), затем меняет состояние —
    /// порядок «generation, потом ресурсы» из плана. КАСКАД: смерть задачи
    /// гасит все её живые потоки (каждый — через свой автомат с хуками
    /// планировщика; сбор потока идёт без удержания borrow, чтобы
    /// `thread_set_state` не реентерил RefCell).
    ///
    /// При зарегистрированном планировщике переход сначала уведомляет бекенд
    /// (`enqueue` в `Ready`, `deschedule` в `Blocked`/`Suspended`/`Dead`; в
    /// `Running` хука нет — диспетчеризация и есть событие планировщика,
    /// состояние выставляет платформенный glue после `switch_context`).
    /// Отказ бекенда ([`TaskError::Scheduler`]) НЕ фиксирует переход:
    /// состояние и поколение остаются прежними.
    pub fn set_state(&self, task_id: &TaskId, to: TaskState) -> Result<TaskState, TaskError> {
        // Фаза 1: перевод задачи под borrow + сбор живых потоков для каскада.
        let (from, live_threads) = {
            let inner = self.inner.borrow_mut();

            let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
            // SAFETY: эксклюзивный доступ под borrow_mut.
            let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
            let from = tcb.state;

            if !from.can_transition_to(to) {
                return Err(TaskError::InvalidTransition {
                    task: *task_id,
                    from,
                    to,
                });
            }

            // Хук планировщика ДО фиксации: отказ бекенда оставляет автомат
            // состояний и поколение объекта нетронутыми.
            if let Some(s) = inner.scheduler {
                let notified = match to {
                    TaskState::Ready => s.enqueue(*task_id),
                    TaskState::Blocked | TaskState::Suspended | TaskState::Dead => {
                        s.deschedule(*task_id)
                    }
                    // Диспетчеризация — событие самого планировщика: в Running
                    // задачу переводит платформенный код после switch_context.
                    TaskState::Running => Ok(()),
                };
                notified.map_err(TaskError::Scheduler)?;
            }

            if to == TaskState::Dead {
                tcb.hdr.kill();
            }
            tcb.state = to;

            // Сбор живых потоков для каскада (borrow ещё жив — читаем дерево).
            let threads: alloc::vec::Vec<ThreadId> = if to == TaskState::Dead {
                inner
                    .threads
                    .by_uuid
                    .iter()
                    .filter(|t| t.owner == *task_id && t.state != TaskState::Dead)
                    .map(|t| t.thread_id)
                    .collect()
            } else {
                alloc::vec::Vec::new()
            };
            (from, threads)
        };

        // Фаза 2: каскад на потоках (borrow отпущен — thread_set_state
        // заимствует менеджер легально).
        if to == TaskState::Dead {
            for tid in live_threads {
                // Отказ отдельного потока не откатывает смерть задачи:
                // домен мёртв, потоки в нём не исполняемы по построению.
                let _ = self.thread_set_state(&tid, TaskState::Dead);
            }
        }
        Ok(from)
    }

    /// Меняет приоритет задачи.
    ///
    /// При зарегистрированном планировщике бекенд уведомляется ДО применения
    /// (`on_priority_change`); отказ откатывает смену приоритета.
    pub fn set_priority(&self, task_id: &TaskId, priority: TaskPriority) -> Result<(), TaskError> {
        let inner = self.inner.borrow_mut();

        let node = find_task(&inner, task_id).ok_or(TaskError::TaskNotFound(*task_id))?;
        // SAFETY: эксклюзивный доступ под borrow_mut.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };

        if let Some(s) = inner.scheduler {
            s.on_priority_change(*task_id, priority)
                .map_err(TaskError::Scheduler)?;
        }
        tcb.priority = priority;
        Ok(())
    }

    // ==== CSpace-якорь (используется менеджером capability) ====

    /// Количество хендлов задачи (аудит/тесты).
    pub fn cap_count(&self, task_id: &TaskId) -> Option<usize> {
        self.with_caps(task_id, |t| t.live_count())
    }

    /// Доступ к таблице хендлов задачи для чтения. `None` — задачи нет.
    ///
    /// Реентери (вызов методов `TcbManager` из замыкания) — паника.
    pub(crate) fn with_caps<R>(
        &self,
        task_id: &TaskId,
        f: impl FnOnce(&HandleTable) -> R,
    ) -> Option<R> {
        let inner = self.inner.borrow();
        let node = find_task(&inner, task_id)?;
        // SAFETY: под borrow — совместный доступ; мутации только через
        // with_caps_mut (контракт менеджера).
        let tcb: &TaskObj = unsafe { &*UnsafeRef::into_raw(node) };
        Some(f(&tcb.caps))
    }

    /// Доступ к таблице хендлов задачи для изменения. `None` — задачи нет.
    ///
    /// Реентери — паника заимствования (контракт однопоточности).
    pub(crate) fn with_caps_mut<R>(
        &self,
        task_id: &TaskId,
        f: impl FnOnce(&mut HandleTable) -> R,
    ) -> Option<R> {
        let inner = self.inner.borrow_mut();
        let node = find_task(&inner, task_id)?;
        // SAFETY: под borrow_mut — эксклюзивный доступ к объекту задачи.
        let tcb: &mut TaskObj = unsafe { &mut *UnsafeRef::into_raw(node) };
        Some(f(&mut tcb.caps))
    }

    /// Объект задачи по стабильной ссылке `(idx, generation)` — O(1), без
    /// uuid-дерева (горячий путь `CapabilityManager::resolve_slot`).
    /// `None` — ссылка протухла (поколение побито) или вне квоты.
    pub(crate) fn with_task_obj<R>(
        &self,
        slot: SlotRef,
        f: impl FnOnce(&TaskObj) -> R,
    ) -> Option<R> {
        let inner = self.inner.borrow();
        let tcb = inner.tasks.get(slot.idx, slot.generation)?;
        Some(f(tcb))
    }
}

impl Drop for TcbManager {
    /// Освобождает все ThreadObj и TaskObj: слоты гасятся в таблицах
    /// (generation вверх, потом drop). Порядок разрушения ядра: менеджер
    /// capability обязан быть разрушен раньше менеджера задач
    /// (гарантируется lifetime-ссылкой `CapabilityManager<'tasks>`),
    /// поэтому cspace задач здесь пусты.
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        debug_assert!(
            inner.by_uuid.iter().all(|t| t.caps.is_empty()),
            "TcbManager::drop: у задачи остались capability — отзовите их до разрушения менеджера задач"
        );
        // Потоки гасим первыми: они принадлежат задачам.
        while let Some(node) = inner.threads.by_uuid.front_mut().remove() {
            // SAFETY: узел снят с реестра, память принадлежит таблице.
            let self_idx = unsafe { &*UnsafeRef::into_raw(node) }.self_idx;
            let freed = inner.threads.threads.free(self_idx);
            debug_assert!(freed, "слот потока обязан быть живым");
        }
        while let Some(node) = inner.by_uuid.front_mut().remove() {
            // SAFETY: узел снят с реестра, память принадлежит таблице.
            let self_idx = unsafe { &*UnsafeRef::into_raw(node) }.self_idx;
            let freed = inner.tasks.free(self_idx);
            debug_assert!(freed, "слот объекта обязан быть живым");
        }
    }
}

// ==== Служебные ====

/// Аудит песочницы: строка в консоль отладки ядра (каждая блокировка
/// операции домена-песочницы видна оператору; v0.9 — сисколы, v0.10 —
/// CPU-троттлинг). Живёт здесь, чтобы и подсистема задач (учёт квот),
/// и сискол-фасад печатали единым префиксом «[kernel: sandbox] ».
pub(crate) fn sandbox_audit(line: &str) {
    use alloc::fmt::Write;
    if let Some(sink) = crate::syscall::debug::debug_sink() {
        let mut s = alloc::string::String::with_capacity(line.len() + 24);
        let _ = write!(s, "\r\n[kernel: sandbox] {line}\r\n");
        sink.write(s.as_bytes());
    }
}

/// Поиск TaskObj по Uuid (редкий путь — дерево). Возвращает невладеющую
/// ссылку: валидность гарантируется менеджером (узел жив, пока в реестре).
pub(crate) fn find_task(inner: &TcbInner, task_id: &TaskId) -> Option<UnsafeRef<TaskObj>> {
    let ptr = inner.by_uuid.find(task_id).get_ptr()?;
    // SAFETY: указатель на живой узел реестра.
    Some(unsafe { UnsafeRef::from_raw(ptr.as_ptr()) })
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use crate::task::{TaskLimits, TaskPriority, TcbManager};

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0x3000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    #[test]
    fn cpu_quota_charge_throttle_and_period_refill() {
        let tasks = TcbManager::new().unwrap();
        let dom = uuid_next();
        tasks.create(dom, TaskPriority::DEFAULT).unwrap();

        // Доверенный домен (UNLIMITED): зарядка — без бухгалтерии.
        assert!(!tasks.charge_cpu(&dom, 10_000).unwrap());
        assert_eq!(tasks.sec_view(&dom).unwrap().usage.cpu_used, 0);

        // Квота 10 тиков; трещотка не даёт её расширить.
        tasks
            .set_limits(
                &dom,
                TaskLimits {
                    cpu_quota: 10,
                    ..TaskLimits::UNLIMITED
                },
            )
            .unwrap();
        tasks.set_limits(&dom, TaskLimits::UNLIMITED).unwrap();
        assert_eq!(tasks.sec_view(&dom).unwrap().limits.cpu_quota, 10);

        // В пределах — копится, троттлинга нет.
        assert!(!tasks.charge_cpu(&dom, 4).unwrap());
        assert!(!tasks.charge_cpu(&dom, 5).unwrap());
        let sec = tasks.sec_view(&dom).unwrap();
        assert_eq!(sec.usage.cpu_used, 9);
        assert!(!sec.usage.cpu_throttled);

        // Перебор: троттл (кламп счётчика + один ивент на вход).
        assert!(tasks.charge_cpu(&dom, 5).unwrap());
        let sec = tasks.sec_view(&dom).unwrap();
        assert_eq!(sec.usage.cpu_used, 10, "счётчик клампится в квоту");
        assert!(sec.usage.cpu_throttled);
        assert_eq!(sec.usage.cpu_throttle_events, 1);

        // Повторные заряды внутри троттлинга — ивент не растёт.
        assert!(tasks.charge_cpu(&dom, 7).unwrap());
        assert_eq!(tasks.sec_view(&dom).unwrap().usage.cpu_throttle_events, 1);

        // Нулевой заряд — no-op.
        assert!(!tasks.charge_cpu(&dom, 0).unwrap());

        // Граница периода: сброс всем, счётчик ивентов — живёт.
        assert_eq!(tasks.on_cpu_period(), 1);
        let sec = tasks.sec_view(&dom).unwrap();
        assert_eq!(sec.usage.cpu_used, 0);
        assert!(!sec.usage.cpu_throttled);
        assert_eq!(sec.usage.cpu_throttle_events, 1, "история не стирается");

        // Новый период: снова троттл — второй ивент.
        assert!(!tasks.charge_cpu(&dom, 9).unwrap());
        assert!(tasks.charge_cpu(&dom, 9).unwrap());
        assert_eq!(tasks.sec_view(&dom).unwrap().usage.cpu_throttle_events, 2);

        // Несуществующий домен — ошибка, а не false.
        let ghost = uuid_next();
        assert!(tasks.charge_cpu(&ghost, 1).is_err());
    }

    #[test]
    fn lazy_thread_counters_match_reality() {
        let tasks = TcbManager::new().unwrap();
        let a = uuid_next();
        let b = uuid_next();
        tasks.create(a, TaskPriority::DEFAULT).unwrap();
        tasks.create(b, TaskPriority::DEFAULT).unwrap();

        // Пять живых потоков в двух доменах: счётчики O(1) обязаны
        // совпадать с фактическим состоянием реестра.
        let mut ids = alloc::vec::Vec::new();
        for i in 0..3 {
            let t = uuid_next();
            tasks
                .create_thread(t, a, TaskPriority(1), 0x1000, 0x9000)
                .unwrap();
            ids.push(t);
            let _ = i;
        }
        let tb = uuid_next();
        tasks
            .create_thread(tb, b, TaskPriority(1), 0x1000, 0x9000)
            .unwrap();
        let tb2 = uuid_next();
        tasks
            .create_thread(tb2, b, TaskPriority(1), 0x1000, 0x9000)
            .unwrap();

        assert_eq!(tasks.thread_count(&a), 3);
        assert_eq!(tasks.thread_count(&b), 2);
        assert_eq!(tasks.total_thread_count(), 5);

        // Гасим по одному: декременты идут и в домен, и в систему.
        tasks
            .thread_set_state(&ids[0], crate::task::types::TaskState::Running)
            .unwrap();
        tasks
            .thread_set_state(&ids[0], crate::task::types::TaskState::Dead)
            .unwrap();
        assert_eq!(tasks.thread_count(&a), 2);
        assert_eq!(tasks.total_thread_count(), 4);

        // Каскад смерти домена: все его потоки — в один Dead-переход.
        tasks
            .set_state(&b, crate::task::types::TaskState::Dead)
            .unwrap();
        assert_eq!(tasks.thread_count(&b), 0, "каскад обнулил счётчик домена");
        assert_eq!(tasks.total_thread_count(), 2);
    }
}
