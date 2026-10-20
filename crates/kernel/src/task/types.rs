// ==== Типы подсистемы задач (TCB) ====
//
// TCB (Thread Control Block) — блок управления задачей. Ссылка на задачу в
// capability-модели — `ContainerACCCapability::TaskTCB { task_id: Uuid }`,
// поэтому идентификатором задачи остаётся `Uuid` (см. совместимость с
// `crate::capability::types`).

use uuid::Uuid;

use thiserror::Error;

/// Идентификатор задачи. Совпадает с `task_id` из
/// `ContainerACCCapability::TaskTCB`.
pub type TaskId = Uuid;

/// Идентификатор потока (L4: global thread ID).
///
/// Разделяет пространство имён с [`TaskId`] — как в L4-Fiasco, где задача
/// (protection domain) адресуется зарезервированным «chief»-ID из того же
/// глобального пространства номеров потоков. Планировщик оперирует
/// ИМЕННО потоками: `SchedulerInterface::enqueue/deschedule` получают
/// ThreadId (тип-алиас — сознательно: единое пространство имён L4 не
/// разводится на два несовместимых типа).
pub type ThreadId = TaskId;

/// Приоритет задачи: 0 — наименьший, 255 — наивысший (как в seL4).
///
/// Планировщика в этом слое нет: менеджер только хранит и валидирует
/// значение, а порядок исполнения выбирает бекенд планировщика.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskPriority(pub u8);

impl TaskPriority {
    /// Приоритет по умолчанию для «обычных» задач.
    pub const DEFAULT: Self = Self(100);

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Состояние задачи. `Dead` — терминальное: из него нет переходов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Готова к исполнению, ждёт процессор.
    Ready,
    /// Исполняется на процессоре (для будущей SMP — их может быть несколько).
    Running,
    /// Заблокирована на синхронизации (IPC, мьютекс, ожидание IRQ).
    Blocked,
    /// Приостановлена извне (suspend): в очередь планировщика не попадает.
    Suspended,
    /// Завершена. Только из этого состояния можно разрушить TCB.
    Dead,
}

impl TaskState {
    /// Допустимые переходы (конечный автомат задачи):
    ///
    /// ```text
    ///            yield/preempt                suspend
    ///   Ready ───────────────▶ Running ───────────────▶ Suspended
    ///     ▲                      │  ▲                       │
    ///     │ wakeup               │  │ dispatch              │ resume
    ///     │                      ▼  │                       ▼
    ///   Blocked ◀────────────────  ┘                     Ready
    ///            block
    ///
    ///   любое состояние ──▶ Dead (terminate)
    /// ```
    ///
    /// Правила:
    /// * `Dead` терминально — переходов из него нет;
    /// * в `Blocked` можно попасть только из `Running` (блокировка —
    ///   всегда действие исполняющейся задачи);
    /// * `Suspended` допустима из `Ready`/`Running`/`Blocked`, возврат —
    ///   только в `Ready`.
    pub fn can_transition_to(self, to: TaskState) -> bool {
        use TaskState::*;
        match self {
            Ready => matches!(to, Running | Suspended | Dead),
            Running => matches!(to, Ready | Blocked | Suspended | Dead),
            Blocked => matches!(to, Ready | Suspended | Dead),
            Suspended => matches!(to, Ready | Dead),
            Dead => false,
        }
    }
}

/// Снимок состояния задачи для аудита (копия, не ссылка: TCB остаётся
/// внутренностью менеджера).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskView {
    pub task_id: TaskId,
    pub state: TaskState,
    pub priority: TaskPriority,
}

// ==== Атрибуты песочницы v0.9 (rlimit-стиль в GTCB) ====
//
// Песочница задачи — это НАБОР ПРЕДЕЛОВ в её TCB (задача-домен = GTCB
// rust-l4: cspace + адресное пространство + атрибуты защиты). Лимиты
// назначает держатель TaskTCB-права на домен (родитель — порождённому),
// семантика изменения — «трещотка»: значения можно только УЖЕСТОЧАТЬ
// (уменьшить предел, снять право), поэтому даже задача, владеющая
// TaskTCB на САМУЮ СЕБЯ, не может расширить собственную песочницу.
// usize::MAX — «без предела» (дефолт: доверенные службы ядра).

/// Пределы задачи (атрибуты песочницы в GTCB). `usize::MAX` = без лимита.
///
/// Поля-числа — верхние границы потребления; `may_spawn` — право творца
/// (L4: holder TaskTCB на себя) — НЕ наследуется порождёнными доменами
/// автоматически, гасится родителем явно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskLimits {
    /// Память: максимум страниц (MEM_ALLOC + входящие map/transfer/SHM).
    pub max_pages: usize,
    /// Потоки: максимум живых потоков домена (THREAD_CREATE).
    pub max_threads: usize,
    /// Endpoint'ы: максимум живых Gate-capability (EP_CREATE).
    pub max_endpoints: usize,
    /// SHM-регионы: максимум одновременных (SHM_CREATE).
    pub max_shm: usize,
    /// Capability: максимум живых хендлов в cspace (grant/mint/send).
    pub max_caps: usize,
    /// Приоритет: потолок для THREAD_SET_PRIO/TASK приоритета (0..=255).
    pub max_prio: u8,
    /// Право творца: разрешено ли TASK_CREATE (создание новых доменов).
    pub may_spawn: bool,
    /// CPU: максимум тиков планировщика за период (v0.10).
    ///
    /// Период — политика бекенда планировщика (x86_64: `CPU_PERIOD_TICKS`
    /// глобальных тиков всех CPU; тик = 1/SCHED_HZ сек). Тики зарядуются
    /// домену на КАЖДОМ конце отрезка исполнения потока — вытеснение
    /// (квант/yield/IPI) и блокировка (IPC/claim): минимум 1 тик за
    /// проход (анти-спин: yield-цикл и «вычислить-и-заблокироваться»
    /// не дешевле честного кванта) плюс фактически потреблённые тики.
    /// `usize::MAX` — без лимита.
    pub cpu_quota: usize,
}

impl TaskLimits {
    /// Доверенная задача: без песочницы (все пределы сняты).
    pub const UNLIMITED: Self = Self {
        max_pages: usize::MAX,
        max_threads: usize::MAX,
        max_endpoints: usize::MAX,
        max_shm: usize::MAX,
        max_caps: usize::MAX,
        max_prio: u8::MAX,
        may_spawn: true,
        cpu_quota: usize::MAX,
    };

    /// Ужесточение (трещотка): каждое числовое поле — минимум из пары,
    /// `may_spawn` — логическое И. Итог никогда слабее текущего не будет.
    pub const fn tighten(&self, other: &Self) -> Self {
        Self {
            max_pages: if other.max_pages < self.max_pages {
                other.max_pages
            } else {
                self.max_pages
            },
            max_threads: if other.max_threads < self.max_threads {
                other.max_threads
            } else {
                self.max_threads
            },
            max_endpoints: if other.max_endpoints < self.max_endpoints {
                other.max_endpoints
            } else {
                self.max_endpoints
            },
            max_shm: if other.max_shm < self.max_shm {
                other.max_shm
            } else {
                self.max_shm
            },
            max_caps: if other.max_caps < self.max_caps {
                other.max_caps
            } else {
                self.max_caps
            },
            max_prio: if other.max_prio < self.max_prio {
                other.max_prio
            } else {
                self.max_prio
            },
            cpu_quota: if other.cpu_quota < self.cpu_quota {
                other.cpu_quota
            } else {
                self.cpu_quota
            },
            may_spawn: self.may_spawn && other.may_spawn,
        }
    }
}

/// Текущее потребление задачи (учёт для пределов; копия-снимок для аудита).
///
/// Поля-счётчики ведёт ядро в точках зарядки (сисколы памяти/IPC; CPU —
/// гейт планировщика при вытеснении); категория «endpoints» не хранится —
/// она вычисляется по живым Gate-capability cspace (cчётчик разошёлся бы
/// с реальностью при CAP_DELETE/CAP_REVOKE гейта).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaskUsage {
    /// Заряжено страниц (MEM_ALLOC + входящие окна map/transfer/SHM).
    pub pages: usize,
    /// Живые SHM-регионы (SHM_CREATE − SHM_DESTROY).
    pub shm: usize,
    /// CPU: тики, потреблённые доменом в текущем периоде (v0.10).
    /// На границе периода счётчик сбрасывает `TcbManager::on_cpu_period`.
    pub cpu_used: usize,
    /// CPU: домен сейчас за пределом квоты (потоки паркует планировщик
    /// до границы периода) — зеркало решения `charge_cpu`.
    pub cpu_throttled: bool,
    /// CPU: сколько раз домен входил за предел квоты (каждое повторное
    /// включение троттлинга — +1; аудит песочницы).
    pub cpu_throttle_events: usize,
}

/// Снимок атрибутов безопасности задачи (аудит песочницы, TASK_LIMITS_INFO).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskSecView {
    pub limits: TaskLimits,
    pub usage: TaskUsage,
}

/// Снимок состояния потока для аудита (копия): L4-модель, поток —
/// единица планирования, живущая в задаче-домене `owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadView {
    pub thread_id: ThreadId,
    /// Задача-домен (cspace и адресное пространство общие с ней).
    pub owner: TaskId,
    pub state: TaskState,
    pub priority: TaskPriority,
    /// Точка старта: IP входа (raw-слово, смысл — платформенный).
    pub entry: usize,
    /// Точка старта: вершина стека (raw-слово).
    pub stack_top: usize,
}

/// Ошибка операции над задачей.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TaskError {
    #[error("task {0} not found")]
    TaskNotFound(TaskId),
    #[error("task {0} already exists")]
    TaskExists(TaskId),
    /// Разрушение TCB до перехода в `Dead`.
    #[error("task {0} must be terminated (Dead) before destroy")]
    TaskNotDead(TaskId),
    /// Разрушение TCB при непустом cspace: сначала отзовите capability
    /// (`CapabilityManager::revoke_all`).
    #[error("task {task} still holds {caps} capabilities")]
    TaskHasCaps { task: TaskId, caps: usize },
    #[error("invalid transition of task {task}: {from:?} -> {to:?}")]
    InvalidTransition {
        task: TaskId,
        from: TaskState,
        to: TaskState,
    },
    /// Сбой slab-аллокатора или страничной таблицы (память под TCB).
    #[error("out of memory")]
    OutOfMemory,
    // ==== Потоки (L4: задача = protection domain, потоки = единицы планирования) ====
    /// Поток не найден в реестре.
    #[error("thread {0} not found")]
    ThreadNotFound(ThreadId),
    /// Поток с таким ThreadId уже существует (общее пространство имён
    /// с задачами — коллизия и с задачей даёт этот же вариант).
    #[error("thread {0} already exists")]
    ThreadExists(ThreadId),
    /// Поток принадлежит другой задаче (создание потока в чужом домене
    /// или операция поверх чужого потока).
    #[error("thread {thread} does not belong to task {task}")]
    ThreadForeign { thread: ThreadId, task: TaskId },
    /// Разрушение задачи при живых потоках: сначала погасите потоки
    /// (`thread_terminate` каждого) — как cspace до destroy TCB.
    #[error("task {task} still has {threads} live threads")]
    TaskHasThreads { task: TaskId, threads: usize },
    /// Разрушение TCB потока до перехода в `Dead`.
    #[error("thread {0} must be terminated (Dead) before destroy")]
    ThreadNotDead(ThreadId),
    /// Операция над потоком в непригодном состоянии (например, ожидание
    /// IPC-ответа у потока, который ничего не ждёт).
    #[error("thread {0} is in an unexpected wait state")]
    ThreadWaitState(ThreadId),
    /// Отказ хука планировщика-бекенда (см. `crate::task::scheduler`).
    ///
    /// Переход автомата состояний / создание задачи при этом НЕ
    /// фиксируются: хуки вызываются до записи нового состояния.
    #[error("scheduler backend error: {0}")]
    Scheduler(#[from] crate::task::scheduler::SchedulerError),
    // ==== Песочница v0.9 (атрибуты GTCB) ====
    /// Предел памяти домена исчерпан (зарядка страниц сверх max_pages).
    #[error("task {task} page quota exceeded (used {used}, limit {limit})")]
    PageQuota {
        task: TaskId,
        used: usize,
        limit: usize,
    },
    /// Предел потоков домена исчерпан (max_threads).
    #[error("task {task} thread quota exceeded (limit {limit})")]
    ThreadQuota { task: TaskId, limit: usize },
    /// Предел SHM-регионов домена исчерпан (max_shm).
    #[error("task {task} shm quota exceeded (limit {limit})")]
    ShmQuota { task: TaskId, limit: usize },
    /// Право творца погашено атрибутом песочницы (may_spawn = false).
    #[error("task {0} is not allowed to spawn domains")]
    SpawnDenied(TaskId),
}
