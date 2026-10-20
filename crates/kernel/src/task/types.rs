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
}
