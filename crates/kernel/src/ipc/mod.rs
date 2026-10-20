// ==== IPC в стиле L4-Fiasco (гибрид: endpoint-объекты + fast-path по ThreadID) ====
//
// Архитектура (выбор «гибрид» при проектировании):
//
// ```text
//   Синхронный IPC (rendezvous, L4-семантика)
//   ├─ endpoint-объекты (GateObj в CapabilityManager, состояние —
//   │  [`EndpointState`]): буфер сообщений (ёмкость) + две очереди
//   │  блокировки В ПЛАНИРОВЩИКЕ (отправители/получатели, FIFO);
//   │  адресация — capability `Gate` (seL4-подобный слой);
//   └─ fast-path по глобальному ThreadID (L4 v2): прямая отправка потоку
//      (`send_thread`): получатель в open-receive — доставка в почтовый
//      ящик без единого обращения к endpoint; иначе сообщение паркуется
//      в очереди ПОТОКА (L4-очередь приёмника, ограничена).
//
//   Асинхронные события (notification-канал)
//   └─ endpoint с ёмкостью > 0: signal = постановка слова в буфер —
//      doorbell SHM-колец, доставка exit-состояний, события потери
//      устройства. Ядро-отправитель НИКОГДА не блокируется.
// ```
//
// Блокировка потока — двухфазная (контракт `task::scheduler::BlockQueueId`):
//   1) `TcbManager::thread_set_state(Blocked)` — хук `deschedule`;
//   2) `SchedulerInterface::block_push` — парковка в очереди бекенда.
// Разбуждение — зеркально: `block_pop_front` -> доставка -> `Ready`
// (хук `enqueue`). Сискол, заблокировавший поток, «возвращается» в
// пользователя только в момент разбуждения: arch-глюй после хендлера
// проверяет состояние потока и вместо возврата переключает контекст;
// материализованное значение — `ThreadObj::syscall_ret`.
//
// Элементы сообщения (map/grant, аналог flexpage L4): при доставке
// ядро переносит физические кадры окна отправителя в пространство
// получателя (через [`crate::mem::MemRouter`]). Ошибки переноса НЕ
// роняют сообщение: бит `ITEM_ERRORS` в `IpcStatus` сообщает пользователю,
// что часть элементов пропущена.

use alloc::{boxed::Box, collections::VecDeque};
use core::cell::Cell;

use uuid::Uuid;

use thiserror::Error;

use crate::capability::{
    ActionPermissions, CapHandle, CapabilityBadge, CapabilityError, CapabilityManager,
    ContainerACCCapability, ObjId,
};
use crate::mem::MemRouter;
use crate::task::scheduler::BlockQueueId;
use crate::task::{TaskError, TaskId, TaskState, TcbManager, ThreadId, ThreadWait};

pub mod shm;

pub use shm::{RingLayout, ShmError, ShmId, ShmInfo, ShmManager};

// ==== Константы протокола ====

/// Inline-слова сообщения (L4 short IPC: dword-регистры).
pub const IPC_INLINE_WORDS: usize = 8;
/// Map/grant-элементов на сообщение (flexpage-передачи L4).
pub const IPC_MAX_ITEMS: usize = 4;
/// Ёмкость парковочной очереди ПОТОКА (direct-IPC fast-path).
pub const IPC_THREAD_PARK_MAX: usize = 8;
/// Синтетический «отправитель — ядро» (nil-UUID): signal/exit-доставка.
pub const IPC_KERNEL_FROM: ThreadId = Uuid::nil();

// ==== Ошибки IPC ====

/// Отказ операции IPC.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IpcError {
    /// Операция потребовала бы блокировки, а режим — try (EAGAIN-аналог).
    #[error("operation would block")]
    TryAgain,
    /// Буфер endpoint'а заполнен (signal/ядерная доставка без блокировки).
    #[error("endpoint queue is full")]
    QueueFull,
    /// Capability не является Gate/endpoint'ом.
    #[error("capability is not an endpoint")]
    NotEndpoint,
    /// Планировщик не зарегистрирован / не поддерживает очереди блокировки.
    #[error("scheduler cannot park threads (no backend or no block queues)")]
    NoBlockQueues,
    /// Владелец endpoint'а мёртв (гейт погашен).
    #[error("endpoint owner is dead")]
    OwnerDead,
    /// Ошибка подсистемы задач (состояния потоков).
    #[error("task subsystem error: {0}")]
    Task(#[from] TaskError),
    /// Ошибка подсистемы capability.
    #[error("capability error: {0}")]
    Cap(#[from] CapabilityError),
    /// Нарушение внутреннего инварианта (несогласованные очереди).
    #[error("internal ipc error")]
    Internal,
}

impl From<IpcError> for crate::syscall::SyscallError {
    fn from(e: IpcError) -> Self {
        use crate::syscall::SyscallError;
        match e {
            IpcError::TryAgain => SyscallError::TryAgain,
            IpcError::QueueFull => SyscallError::Busy,
            IpcError::NotEndpoint => SyscallError::InvalidArgument,
            IpcError::NoBlockQueues => SyscallError::Internal,
            IpcError::OwnerDead => SyscallError::InvalidHandle,
            IpcError::Task(t) => t.into(),
            IpcError::Cap(c) => c.into(),
            #[allow(unreachable_patterns)]
            _ => SyscallError::Internal,
        }
    }
}

// ==== Сообщение ====

bitflags::bitflags! {
    /// Статус доставки сообщения.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IpcStatus: u32 {
        /// Часть map/grant-элементов не удалось применить (окна получателя
        /// или источника некорректны); сообщение доставлено, элементы пропущены.
        const ITEM_ERRORS = 1;
        /// Сообщение доставлено без блокировки получателя (fast-path/буфер).
        const FAST_PATH = 1 << 1;
    }
}

/// Элемент flexpage-переноса (map/grant L4).
///
/// `map` — отобразить окно отправителя в пространство получателя (кадры
/// остаются у отправителя, разделяемое отображение); `grant` — передать
/// владение: у отправителя окно снимается, получатель получает кадры.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    /// База окна в пространстве ОТПРАВИТЕЛЯ (источник кадров).
    pub src_base: usize,
    /// База окна в пространстве ПОЛУЧАТЕЛЯ (0 — выбрать автоматически).
    pub dst_base: usize,
    /// Размер в страницах (степень двойки — гранулярность flexpage).
    pub pages: usize,
    /// grant: передать владение кадрами (map — разделяемое отображение).
    pub grant: bool,
    /// Права отображения (`MMAPMemoryFlags::bits`).
    pub flags: u8,
}

/// Сообщение L4-стиля: inline-слова + flexpage-элементы + длинный payload.
///
/// `words` — регистровая часть (аналог dword-сообщений L4 short IPC);
/// `items` — map/grant-передачи, применяются ядром при доставке;
/// `payload` — длинные данные (снимки регистров исключения, argv-строки),
/// выгружаются получателем по словам сисколом чтения сообщения.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    words: heapless::Vec<u64, IPC_INLINE_WORDS>,
    items: heapless::Vec<MapItem, IPC_MAX_ITEMS>,
    payload: Option<Box<[u64]>>,
    from: ThreadId,
    status: IpcStatus,
}

impl IpcMessage {
    /// Пустое сообщение от `from`.
    pub fn new(from: ThreadId) -> Self {
        Self {
            words: heapless::Vec::new(),
            items: heapless::Vec::new(),
            payload: None,
            from,
            status: IpcStatus::empty(),
        }
    }

    /// Однословное сообщение (signal/уведомление).
    pub fn signal(from: ThreadId, w0: u64) -> Self {
        let mut m = Self::new(from);
        let _ = m.words.push(w0);
        m
    }

    /// Добавить inline-слово (сверх лимита — молча игнорируется: ABI
    /// фиксирует `IPC_INLINE_WORDS`, длинные данные — payload).
    pub fn push_word(&mut self, w: u64) -> &mut Self {
        let _ = self.words.push(w);
        self
    }

    /// Собрать из среза слов (лишние — отброшены).
    pub fn with_words(mut self, ws: &[u64]) -> Self {
        for &w in ws {
            let _ = self.words.push(w);
        }
        self
    }

    /// Добавить flexpage-элемент (сверх лимита — игнорируется).
    pub fn push_item(&mut self, item: MapItem) -> &mut Self {
        let _ = self.items.push(item);
        self
    }

    /// Длинный payload (регистры исключения, argv-строки).
    pub fn with_payload(mut self, payload: Box<[u64]>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Стартовое сообщение протокола запуска (argc/argv через IPC, L4):
    /// слова = [argc, argv_ptr, argv_bytes, envp_ptr, envp_bytes, резерв].
    /// Указатели адресуют буферы, переданные map-элементом.
    pub fn start_args(from: ThreadId, argc: u64, argv_ptr: u64, argv_bytes: u64) -> Self {
        let mut m = Self::new(from);
        let _ = m.words.push(argc);
        let _ = m.words.push(argv_ptr);
        let _ = m.words.push(argv_bytes);
        let _ = m.words.push(0); // envp_ptr (резерв протокола)
        let _ = m.words.push(0); // envp_bytes
        m
    }

    /// Inline-слова.
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Слово по индексу (вне диапазона — 0, как у `SyscallArgs`).
    pub fn word(&self, idx: usize) -> u64 {
        self.words.get(idx).copied().unwrap_or(0)
    }

    /// Flexpage-элементы.
    pub fn items(&self) -> &[MapItem] {
        &self.items
    }

    /// Взять payload (владение; повторный вызов — None).
    pub fn take_payload(&mut self) -> Option<Box<[u64]>> {
        self.payload.take()
    }

    /// Payload по ссылке.
    pub fn payload(&self) -> Option<&[u64]> {
        self.payload.as_deref()
    }

    /// Отправитель (глобальный ThreadID; [`IPC_KERNEL_FROM`] — ядро).
    pub fn from(&self) -> ThreadId {
        self.from
    }

    /// Переименовать отправителя (ядро подменяет источник на
    /// [`IPC_KERNEL_FROM`] при ядерной доставке).
    pub(crate) fn set_from(&mut self, from: ThreadId) {
        self.from = from;
    }

    /// Статус доставки.
    pub fn status(&self) -> IpcStatus {
        self.status
    }

    pub(crate) fn set_status(&mut self, status: IpcStatus) {
        self.status = status;
    }
}

// ==== Состояние endpoint'а (живёт в GateObj) ====

/// Состояние IPC-endpoint'а: буфер сообщений + две очереди блокировки.
///
/// Ёмкость `capacity` задаёт режим:
/// * `0` — строгий rendezvous (L4 sync IPC): сообщения не буферизуются,
///   отправитель и получатель встречаются в очередях планировщика;
/// * `> 0` — буферизация (notification-режим): signal-слова копятся в
///   `queue`, отправители блокируются только при переполнении.
///
/// Очереди блокировки `send_q`/`recv_q` создаются у планировщика-бекенда
/// при создании endpoint'а ([`IpcManager::create_endpoint`]);
/// `BlockQueueId::default()` — планировщика нет: endpoint работает только
/// в try-режиме и на буферизованных сообщениях.
#[derive(Debug, Default)]
pub struct EndpointState {
    capacity: usize,
    queue: VecDeque<Box<IpcMessage>>,
    send_q: BlockQueueId,
    recv_q: BlockQueueId,
}

impl EndpointState {
    /// Полное состояние (очереди от планировщика).
    pub fn new(capacity: usize, send_q: BlockQueueId, recv_q: BlockQueueId) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
            send_q,
            recv_q,
        }
    }

    /// Ёмкость буфера сообщений (0 — строгий rendezvous).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Сообщений в буфере.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Очередь заблокированных отправителей (в планировщике).
    pub fn send_queue(&self) -> BlockQueueId {
        self.send_q
    }

    /// Очередь заблокированных получателей (в планировщике).
    pub fn recv_queue(&self) -> BlockQueueId {
        self.recv_q
    }

    fn has_room(&self) -> bool {
        self.queue.len() < self.capacity
    }
}

// ==== Исходы операций ====

/// Исход отправки: что произошло с сообщением и потоком-отправителем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Доставлено напрямую ждущему получателю (fast-path/rendezvous).
    Delivered,
    /// Поставлено в буфер endpoint'а (notification-режим).
    Queued,
    /// Припарковано в очереди ПОТОКА-получателя (direct-IPC).
    Parked,
    /// Отправитель заблокирован (в очереди endpoint'а); сискол
    /// «вернётся» при встрече — значение в `ThreadObj::syscall_ret`.
    Blocked,
}

/// Исход приёма.
#[derive(Debug)]
pub enum RecvOutcome {
    /// Сообщение получено (владение Box'ом).
    Message(Box<IpcMessage>),
    /// Поток заблокирован на ожидании; при разбуждении сообщение будет
    /// в `ThreadObj::mailbox`, возврат сискола — в `syscall_ret`.
    Blocked,
}

/// Режим блокировки операции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    /// Блокировать поток до события (L4-семантика по умолчанию).
    Blocking,
    /// Только неблокирующая попытка: отказ [`IpcError::TryAgain`].
    Try,
}

// ==== Exit-протокол: три вида данных на exit endpoint ====

/// Снимок регистров потока на момент исключения.
///
/// Формат слов — платформенное знание (arch-глюй заполняет по своей
/// разладке регистра); ядро только переносит массив. Размер не
/// фиксируется жёстко, типовой объём — 16–32 слова.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterSnapshot(pub Box<[u64]>);

impl RegisterSnapshot {
    /// Пустой снимок (данные недоступны — например, fault вне потока).
    pub fn empty() -> Self {
        Self(Box::from([0u64; 0]))
    }

    /// Снимок из среза слов.
    pub fn from_words(words: &[u64]) -> Self {
        Self(Box::from(words))
    }

    /// Слова снимка.
    pub fn words(&self) -> &[u64] {
        &self.0
    }
}

/// Указатели сбоя: адрес и точка возникновения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultInfo {
    /// Адрес, вызвавший сбой (fault address, CR2/FAR-аналог).
    pub fault_addr: usize,
    /// Инструкция, на которой произошёл сбой.
    pub ip: usize,
    /// Класс сбоя.
    pub kind: FaultKind,
}

/// Класс аппаратного сбоя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultKind {
    /// Чтение отсутствующей/запрещённой страницы.
    PageRead,
    /// Запись в отсутствующую/запрещённую страницу.
    PageWrite,
    /// Исполнение запрещённой страницы (W^X).
    PageExec,
    /// Общая защита (x86 #GP и аналоги).
    GeneralProtection,
    /// Выравнивание.
    Alignment,
    /// Арифметика (div-by-zero и т.п.).
    Arithmetic,
    /// Прочее (платформа уточняет словами payload).
    Other,
}

impl FaultKind {
    /// Кодировка для слова сообщения (стабильный ABI).
    pub const fn as_word(self) -> u64 {
        match self {
            Self::PageRead => 1,
            Self::PageWrite => 2,
            Self::PageExec => 3,
            Self::GeneralProtection => 4,
            Self::Alignment => 5,
            Self::Arithmetic => 6,
            Self::Other => 7,
        }
    }

    /// Обратное преобразование (неизвестный код — Other).
    pub const fn from_word(w: u64) -> Self {
        match w {
            1 => Self::PageRead,
            2 => Self::PageWrite,
            3 => Self::PageExec,
            4 => Self::GeneralProtection,
            5 => Self::Alignment,
            6 => Self::Arithmetic,
            _ => Self::Other,
        }
    }
}

/// Источник терминирования (третий вид exit-данных — «кем убита»).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KillSource {
    /// Задача завершилась сама (syscall exit): payload несёт код.
    SelfExit,
    /// Ядро (нарушение инварианта, OOM-kill, паника надзирателя).
    Kernel,
    /// Родительская/другая задача через terminate-capability.
    Task(TaskId),
}

impl KillSource {
    /// Кодировка для слов сообщения: [тег, task_lo, task_hi].
    pub const fn to_words(self) -> [u64; 3] {
        match self {
            Self::SelfExit => [1, 0, 0],
            Self::Kernel => [2, 0, 0],
            // Тег 3; UUID задачи — младшее/старшее 64 бита.
            Self::Task(t) => [3, t.as_u128() as u64, (t.as_u128() >> 64) as u64],
        }
    }

    /// Обратное преобразование.
    pub fn from_words(tag: u64, lo: u64, hi: u64) -> Self {
        match tag {
            1 => Self::SelfExit,
            2 => Self::Kernel,
            _ => Self::Task(Uuid::from_u128(((hi as u128) << 64) | lo as u128)),
        }
    }
}

/// Payload выхода дочерней задачи — ТРИ вида данных на exit endpoint.
///
/// Сериализация в слова сообщения (стабильный протокол v1):
/// ```text
///  w0 = тег: 1 = Exit, 2 = Exception, 3 = Killed
///  w1..2 = TaskId (lo, hi) завершённой задачи
///  Exit:      w3 = код выхода,
///             w4 = cpu_used — тики CPU последнего периода (v0.10),
///             w5 = cpu_throttle_events — сколько раз домен входил
///                  за предел CPU-квоты (вердикт песочницы)
///  Exception: w3 = fault_addr, w4 = ip, w5 = kind (FaultKind::as_word),
///             payload = снимок регистров (RegisterSnapshot)
///  Killed:    w3..5 = KillSource::to_words()
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitPayload {
    /// 1) Обычный выход: код возврата + CPU-статистика домена (v0.10:
    ///    вердикт песочницы — квота держала домен, пока он не сдался).
    Exit {
        code: usize,
        cpu_used: usize,
        cpu_throttle_events: usize,
    },
    /// 2) Исключение: снимок регистров процесса + указатели фолта.
    Exception {
        snapshot: RegisterSnapshot,
        fault: FaultInfo,
    },
    /// 3) Убита: источник терминирования.
    Killed { by: KillSource },
}

impl ExitPayload {
    /// Тег вида (w0 протокола).
    pub const fn tag(&self) -> u64 {
        match self {
            Self::Exit { .. } => 1,
            Self::Exception { .. } => 2,
            Self::Killed { .. } => 3,
        }
    }

    /// Упаковать в сообщение exit-endpoint'а.
    pub fn into_message(self, task: TaskId) -> Box<IpcMessage> {
        let v = task.as_u128();
        let mut m = IpcMessage::new(IPC_KERNEL_FROM);
        let _ = m.words.push(self.tag());
        let _ = m.words.push(v as u64);
        let _ = m.words.push((v >> 64) as u64);
        match self {
            Self::Exit {
                code,
                cpu_used,
                cpu_throttle_events,
            } => {
                let _ = m.words.push(code as u64);
                let _ = m.words.push(cpu_used as u64);
                let _ = m.words.push(cpu_throttle_events as u64);
            }
            Self::Exception { snapshot, fault } => {
                let _ = m.words.push(fault.fault_addr as u64);
                let _ = m.words.push(fault.ip as u64);
                let _ = m.words.push(fault.kind.as_word());
                m = m.with_payload(snapshot.0);
            }
            Self::Killed { by } => {
                for w in by.to_words() {
                    let _ = m.words.push(w);
                }
            }
        }
        Box::new(m)
    }

    /// Распаковать из сообщения (None — слова не соответствуют протоколу).
    pub fn from_message(msg: &IpcMessage) -> Option<Self> {
        let tag = msg.word(0);
        let _lo = msg.word(1);
        let _hi = msg.word(2);
        match tag {
            1 => Some(Self::Exit {
                code: msg.word(3) as usize,
                cpu_used: msg.word(4) as usize,
                cpu_throttle_events: msg.word(5) as usize,
            }),
            2 => Some(Self::Exception {
                snapshot: RegisterSnapshot(Box::from(msg.payload().unwrap_or(&[]))),
                fault: FaultInfo {
                    fault_addr: msg.word(3) as usize,
                    ip: msg.word(4) as usize,
                    kind: FaultKind::from_word(msg.word(5)),
                },
            }),
            3 => Some(Self::Killed {
                by: KillSource::from_words(msg.word(3), msg.word(4), msg.word(5)),
            }),
            _ => None,
        }
    }
}

// ==== Менеджер IPC ====

/// Оркестратор IPC: тонкий слой над состоянием в GateObj/ThreadObj.
///
/// Сам менеджер почти бессостоятелен (всё живёт в объектах ядра —
/// endpoint'ы в `CapabilityManager`, ожидания в `TcbManager`): он владеет
/// только счётчиками аудита. Методы принимают менеджеры параметрами —
/// тот же паттерн, что `DeviceManager::export_capabilities(&tasks, &caps)`.
pub struct IpcManager {
    delivered: Cell<usize>,
    fast_path: Cell<usize>,
    blocked_ops: Cell<usize>,
}

impl IpcManager {
    /// Пустой менеджер.
    pub fn new() -> Self {
        Self {
            delivered: Cell::new(0),
            fast_path: Cell::new(0),
            blocked_ops: Cell::new(0),
        }
    }

    /// Счётчики аудита: (доставлено, из них fast-path, заблокировано).
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.delivered.get(),
            self.fast_path.get(),
            self.blocked_ops.get(),
        )
    }

    // ==== Создание endpoint'ов ====

    /// Создать endpoint и выдать владельцу корневую capability.
    ///
    /// `capacity` — режим: 0 = строгий rendezvous, > 0 = буферизация
    /// (notification-канал: doorbell-и, exit-доставка, события устройств).
    /// Очереди блокировки берутся у зарегистрированного планировщика;
    /// если его нет (или он без block-очередей), endpoint создаётся с
    /// пустыми очередями — блокирующие операции на нём будут отказывать
    /// [`IpcError::NoBlockQueues`], try-режим и буфер работают.
    pub fn create_endpoint(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        owner: TaskId,
        capacity: usize,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Result<CapHandle, IpcError> {
        let (send_q, recv_q) = match tasks.scheduler() {
            Some(s) => (
                s.block_queue_create().unwrap_or_default(),
                s.block_queue_create().unwrap_or_default(),
            ),
            None => (BlockQueueId::default(), BlockQueueId::default()),
        };
        caps.create_endpoint(tasks, owner, capacity, send_q, recv_q, perms, badge)
            .map_err(IpcError::Cap)
    }

    // ==== Отправка в endpoint ====

    /// Отправить сообщение в endpoint по capability вызывающего.
    ///
    /// Порядок (L4-rendezvous + буферизация):
    /// 1. ждущий получатель (recv-очередь endpoint'а) — прямая доставка;
    /// 2. буфер (если есть место) — постановка в очередь;
    /// 3. try-режим — [`IpcError::TryAgain`];
    /// 4. блокировка отправителя в send-очереди (сообщение — в
    ///    `ThreadObj::blocked_msg`, возврат сискола — при встрече).
    pub fn send(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        router: Option<&dyn MemRouter>,
        from_thread: ThreadId,
        ep: CapHandle,
        msg: Box<IpcMessage>,
        mode: BlockMode,
    ) -> Result<SendOutcome, IpcError> {
        let owner = thread_task(tasks, from_thread)?;
        let view = caps
            .get(tasks, owner, ep)
            .ok_or(CapabilityError::InvalidHandle(ep))?;
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            return Err(IpcError::NotEndpoint);
        };
        self.send_to_gate(tasks, caps, router, from_thread, gate_id, msg, mode, None)
    }

    /// Отправка в гейт (ядро/фасад — без проверки capability).
    ///
    /// `then_recv` — фаза call: после доставки сообщения отправитель
    /// переходит к приёму ответа на этом гейте, не возвращаясь в
    /// пользователя (L4 ipc_call).
    #[allow(clippy::too_many_arguments)]
    pub fn send_to_gate(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        router: Option<&dyn MemRouter>,
        from_thread: ThreadId,
        gate: ObjId,
        msg: Box<IpcMessage>,
        mode: BlockMode,
        then_recv: Option<ObjId>,
    ) -> Result<SendOutcome, IpcError> {
        // 1. Ждущий получатель (recv-очередь endpoint'а) — прямая доставка.
        let mut slot = Some(msg);
        if let Some(outcome) =
            self.try_deliver_to_waiter(tasks, caps, router, from_thread, gate, &mut slot)?
        {
            return Ok(outcome);
        }

        // 2. Буфер endpoint'а.
        let queued = caps
            .with_endpoint(gate, |ep| {
                if ep.has_room() {
                    if let Some(m) = slot.take() {
                        ep.queue.push_back(m);
                    }
                    true
                } else {
                    false
                }
            })
            .ok_or(IpcError::OwnerDead)?;
        if queued {
            return Ok(SendOutcome::Queued);
        }

        // 3. Буфера нет/полон: try-режим отказывает, блокирующий — паркует
        //    отправителя (сообщение переносится в ThreadObj::blocked_msg).
        if mode == BlockMode::Try {
            return Err(IpcError::TryAgain);
        }
        // Сообщение всё ещё в слоте (буфер его не взял).
        let msg = slot.take().expect("message stays in slot when not queued");
        self.block_sender(tasks, caps, from_thread, gate, msg, then_recv)?;
        self.blocked_ops.set(self.blocked_ops.get() + 1);
        Ok(SendOutcome::Blocked)
    }

    /// Ядерная (неблокирующая) отправка: signal/exit/потеря устройства.
    ///
    /// Отправитель — ядро ([`IPC_KERNEL_FROM`]), блокировки никогда нет:
    /// ждущий получатель получает сообщение сразу, иначе — буфер; полный
    /// буфер — [`IpcError::QueueFull`] (событие не теряется молча).
    pub fn kernel_send(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        gate: ObjId,
        msg: Box<IpcMessage>,
    ) -> Result<SendOutcome, IpcError> {
        let mut msg = msg;
        msg.set_from(IPC_KERNEL_FROM);
        let mut slot = Some(msg);
        if let Some(outcome) =
            self.try_deliver_to_waiter(tasks, caps, None, IPC_KERNEL_FROM, gate, &mut slot)?
        {
            return Ok(outcome);
        }
        let msg = slot
            .take()
            .expect("сообщение у вызывающего, если доставки не было");
        enqueue_or_full(caps, gate, msg)
    }

    /// Однословный signal (doorbell SHM-колец, события устройств).
    pub fn signal(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        gate: ObjId,
        word: u64,
    ) -> Result<SendOutcome, IpcError> {
        self.kernel_send(
            tasks,
            caps,
            gate,
            Box::new(IpcMessage::signal(IPC_KERNEL_FROM, word)),
        )
    }

    /// Доставка ждущему получателю, если он есть. `Ok(None)` — получателя
    /// нет (сообщение остаётся во владении вызывающего — слот не тронут).
    fn try_deliver_to_waiter(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        router: Option<&dyn MemRouter>,
        from_thread: ThreadId,
        gate: ObjId,
        msg: &mut Option<Box<IpcMessage>>,
    ) -> Result<Option<SendOutcome>, IpcError> {
        // Первый поток из recv-очереди endpoint'а (FIFO планировщика).
        let Some(waiter) = self.pop_waiter(tasks, caps, gate, WaitSide::Recv)? else {
            return Ok(None);
        };
        // Защита: поток обязан ждать именно этот гейт.
        let expects_gate = tasks
            .with_thread(
                &waiter,
                |t| matches!(&t.wait, Some(ThreadWait::RecvEndpoint { gate: g }) if *g == gate),
            )
            .unwrap_or(false);
        if !expects_gate {
            return Err(IpcError::Internal);
        }
        let msg = msg.take().expect("вызывающий держит сообщение");
        self.deliver(tasks, router, from_thread, waiter, msg)?;
        self.delivered.set(self.delivered.get() + 1);
        Ok(Some(SendOutcome::Delivered))
    }

    /// Блокировка отправителя: сообщение — в blocked_msg, поток — в send_q.
    fn block_sender(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        from_thread: ThreadId,
        gate: ObjId,
        msg: Box<IpcMessage>,
        then_recv: Option<ObjId>,
    ) -> Result<(), IpcError> {
        let queue = caps
            .with_endpoint(gate, |ep| ep.send_queue())
            .ok_or(IpcError::OwnerDead)?;
        if queue == BlockQueueId::default() {
            return Err(IpcError::NoBlockQueues);
        }

        // Шаг 1 контракта BlockQueueId: состояние Blocked (хук deschedule).
        tasks.thread_set_state(&from_thread, TaskState::Blocked)?;
        // Шаг 2: парковка в очереди планировщика + сохранение сообщения.
        tasks.with_thread(&from_thread, |t| {
            t.wait = Some(ThreadWait::SendEndpoint { gate, then_recv });
            t.blocked_msg = Some(msg);
        });
        let sched = tasks.scheduler().ok_or(IpcError::NoBlockQueues)?;
        sched
            .block_push(queue, from_thread)
            .map_err(TaskError::Scheduler)?;
        Ok(())
    }

    // ==== Приём ====

    /// Принять сообщение из endpoint'а по capability вызывающего.
    ///
    /// Порядок: буфер -> заблокированный отправитель (rendezvous) ->
    /// try-отказ -> блокировка получателя (recv-очередь).
    pub fn recv(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        thread: ThreadId,
        ep: CapHandle,
        mode: BlockMode,
    ) -> Result<RecvOutcome, IpcError> {
        let owner = thread_task(tasks, thread)?;
        let view = caps
            .get(tasks, owner, ep)
            .ok_or(CapabilityError::InvalidHandle(ep))?;
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            return Err(IpcError::NotEndpoint);
        };
        self.recv_from_gate(tasks, caps, thread, gate_id, mode, false)
    }

    /// Приём с гейта (ядро/фасад). `already_blocked` — поток уже Blocked
    /// (фаза call: переход Blocked->Blocked недопустим автоматом состояний).
    pub fn recv_from_gate(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        thread: ThreadId,
        gate: ObjId,
        mode: BlockMode,
        already_blocked: bool,
    ) -> Result<RecvOutcome, IpcError> {
        // 1. Буфер endpoint'а.
        let from_queue: Option<Box<IpcMessage>> = caps
            .with_endpoint(gate, |ep| ep.queue.pop_front())
            .flatten();
        if let Some(mut msg) = from_queue {
            // Освободился слот: FIFO-отправитель занимает его из send_q.
            self.refill_from_senders(tasks, caps, gate)?;
            msg.set_status(msg.status() | IpcStatus::FAST_PATH);
            self.delivered.set(self.delivered.get() + 1);
            return Ok(RecvOutcome::Message(msg));
        }

        // 2. Rendezvous: заблокированный отправитель с сообщением.
        if let Some(sender) = self.pop_waiter(tasks, caps, gate, WaitSide::Send)? {
            let expects_gate = tasks
                .with_thread(&sender, |t| {
                    matches!(&t.wait, Some(ThreadWait::SendEndpoint { gate: g, .. }) if *g == gate)
                })
                .unwrap_or(false);
            if !expects_gate {
                return Err(IpcError::Internal);
            }
            let taken = tasks
                .with_thread(&sender, |t| {
                    let msg = t.blocked_msg.take();
                    let wait = t.wait.take();
                    msg.map(|m| (m, wait))
                })
                .flatten();
            let Some((msg, wait)) = taken else {
                return Err(IpcError::Internal);
            };
            // Отправитель доставлен: вернуть его в пользователя или перевести
            // в фазу call-приёма (then_recv).
            self.complete_sender(tasks, caps, sender, wait)?;
            self.delivered.set(self.delivered.get() + 1);
            return Ok(RecvOutcome::Message(msg));
        }

        // 3. Принимать нечего: try-отказ или блокировка получателя.
        if mode == BlockMode::Try {
            return Err(IpcError::TryAgain);
        }
        self.block_receiver(tasks, caps, thread, gate, already_blocked)?;
        self.blocked_ops.set(self.blocked_ops.get() + 1);
        Ok(RecvOutcome::Blocked)
    }

    /// Освободившийся слот буфера занимает FIFO-отправитель из send_q.
    fn refill_from_senders(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        gate: ObjId,
    ) -> Result<(), IpcError> {
        let Some(sender) = self.pop_waiter(tasks, caps, gate, WaitSide::Send)? else {
            return Ok(());
        };
        let taken = tasks
            .with_thread(&sender, |t| {
                let msg = t.blocked_msg.take();
                t.wait = None;
                t.syscall_ret = Some(0);
                msg
            })
            .flatten();
        if let Some(msg) = taken {
            let queued = enqueue_or_full(caps, gate, msg);
            debug_assert!(
                matches!(queued, Ok(SendOutcome::Queued)),
                "слот освободился только что"
            );
            // Отправитель разбужен выше (wait = None, ret = 0): перевести в Ready.
            tasks.thread_set_state(&sender, TaskState::Ready)?;
        }
        Ok(())
    }

    /// Завершение фазы отправки заблокированного отправителя: возврат в
    /// пользователя или переход к фазе приёма (ipc_call, L4).
    fn complete_sender(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        sender: ThreadId,
        wait: Option<ThreadWait>,
    ) -> Result<(), IpcError> {
        // Фаза call: сразу приём ответа на reply-гейте (поток не выходит
        // в пользователя между фазами — семантика L4 ipc_call).
        if let Some(ThreadWait::SendEndpoint {
            then_recv: Some(reply),
            ..
        }) = wait
        {
            return match self.recv_from_gate(tasks, caps, sender, reply, BlockMode::Blocking, true)
            {
                Ok(RecvOutcome::Message(msg)) => {
                    // Ответ уже пришёл: положить в ящик и разбудить.
                    tasks.with_thread(&sender, |t| {
                        t.mailbox = Some(msg);
                        t.syscall_ret = Some(0);
                    });
                    tasks.thread_set_state(&sender, TaskState::Ready)?;
                    Ok(())
                }
                // Поток переблокирован на recv-очереди reply-гейта.
                Ok(RecvOutcome::Blocked) => Ok(()),
                Err(e) => Err(e),
            };
        }
        // Обычная отправка: возврат в пользователя с кодом 0.
        tasks.with_thread(&sender, |t| {
            t.wait = None;
            t.syscall_ret = Some(0);
        });
        tasks.thread_set_state(&sender, TaskState::Ready)?;
        Ok(())
    }

    /// Блокировка получателя на гейте.
    fn block_receiver(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        thread: ThreadId,
        gate: ObjId,
        already_blocked: bool,
    ) -> Result<(), IpcError> {
        let queue = caps
            .with_endpoint(gate, |ep| ep.recv_queue())
            .ok_or(IpcError::OwnerDead)?;
        if queue == BlockQueueId::default() {
            return Err(IpcError::NoBlockQueues);
        }
        if !already_blocked {
            tasks.thread_set_state(&thread, TaskState::Blocked)?;
        }
        tasks.with_thread(&thread, |t| {
            t.wait = Some(ThreadWait::RecvEndpoint { gate });
        });
        let sched = tasks.scheduler().ok_or(IpcError::NoBlockQueues)?;
        sched
            .block_push(queue, thread)
            .map_err(TaskError::Scheduler)?;
        Ok(())
    }

    // ==== Fast-path: прямая отправка потоку (L4) ====

    /// Прямая отправка потоку по глобальному ThreadID (без endpoint).
    ///
    /// * получатель в open-receive ([`ThreadWait::RecvAny`]) — мгновенная
    ///   доставка в почтовый ящик + разбуждение (L4 fast path);
    /// * иначе — сообщение паркуется в очереди ПОТОКА (до
    ///   [`IPC_THREAD_PARK_MAX`]); переполнение — [`IpcError::TryAgain`].
    ///
    /// Отправитель НИКОГДА не блокируется: это асинхронный канал к
    /// конкретному потоку (стартовые argc/argv, короткие команды).
    pub fn send_thread(
        &self,
        tasks: &TcbManager,
        router: Option<&dyn MemRouter>,
        from_thread: ThreadId,
        to_thread: ThreadId,
        mut msg: Box<IpcMessage>,
    ) -> Result<SendOutcome, IpcError> {
        let receiver_open = tasks
            .with_thread(&to_thread, |t| {
                t.state == TaskState::Blocked && matches!(t.wait, Some(ThreadWait::RecvAny))
            })
            .unwrap_or(false);

        if receiver_open {
            msg.set_status(msg.status() | IpcStatus::FAST_PATH);
            self.deliver(tasks, router, from_thread, to_thread, msg)?;
            self.fast_path.set(self.fast_path.get() + 1);
            self.delivered.set(self.delivered.get() + 1);
            return Ok(SendOutcome::Delivered);
        }

        // Парковка в очереди потока-получателя.
        let parked = tasks
            .with_thread(&to_thread, |t| {
                if t.parked.len() >= IPC_THREAD_PARK_MAX {
                    false
                } else {
                    t.parked.push_back(msg);
                    true
                }
            })
            .ok_or(TaskError::ThreadNotFound(to_thread))?;
        if parked {
            Ok(SendOutcome::Parked)
        } else {
            Err(IpcError::TryAgain)
        }
    }

    /// Открытый приём (L4 open receive): от любого отправителя.
    ///
    /// Сначала — парковочная очередь самого потока, затем блокировка в
    /// open-receive (разбужит `send_thread`).
    pub fn recv_any(
        &self,
        tasks: &TcbManager,
        thread: ThreadId,
        mode: BlockMode,
    ) -> Result<RecvOutcome, IpcError> {
        let parked: Option<Box<IpcMessage>> = tasks
            .with_thread(&thread, |t| t.parked.pop_front())
            .flatten();
        if let Some(mut msg) = parked {
            msg.set_status(msg.status() | IpcStatus::FAST_PATH);
            self.delivered.set(self.delivered.get() + 1);
            return Ok(RecvOutcome::Message(msg));
        }
        if mode == BlockMode::Try {
            return Err(IpcError::TryAgain);
        }
        tasks.thread_set_state(&thread, TaskState::Blocked)?;
        tasks.with_thread(&thread, |t| {
            t.wait = Some(ThreadWait::RecvAny);
        });
        self.blocked_ops.set(self.blocked_ops.get() + 1);
        Ok(RecvOutcome::Blocked)
    }

    // ==== Доставка в почтовый ящик ====

    /// Доставить сообщение потоку: применить flexpage-элементы, положить в
    /// mailbox, разбудить (если был Blocked).
    fn deliver(
        &self,
        tasks: &TcbManager,
        router: Option<&dyn MemRouter>,
        from_thread: ThreadId,
        receiver: ThreadId,
        mut msg: Box<IpcMessage>,
    ) -> Result<(), IpcError> {
        // Flexpage-элементы: кадры окна отправителя -> получателю.
        if !msg.items().is_empty() {
            if let Some(router) = router {
                let sender_owner = tasks.thread_task(&from_thread);
                let receiver_owner = tasks.thread_task(&receiver);
                if let (Some(src), Some(dst)) = (sender_owner, receiver_owner) {
                    apply_map_items(router, src, dst, &mut msg);
                } else {
                    msg.set_status(msg.status() | IpcStatus::ITEM_ERRORS);
                }
            } else {
                // Роутера нет (например, ядерная доставка) — элементы пропущены.
                msg.set_status(msg.status() | IpcStatus::ITEM_ERRORS);
            }
        }

        let was_blocked = tasks
            .with_thread(&receiver, |t| {
                let was = t.state == TaskState::Blocked;
                t.mailbox = Some(msg);
                t.wait = None;
                t.syscall_ret = Some(0);
                was
            })
            .ok_or(TaskError::ThreadNotFound(receiver))?;
        if was_blocked {
            tasks.thread_set_state(&receiver, TaskState::Ready)?;
        }
        Ok(())
    }

    // ==== Выгрузка почтового ящика (сисколы чтения) ====

    /// Слово сообщения из почтового ящика потока (None — ящик пуст).
    /// Индексация сквозная: inline-слова, затем payload.
    pub fn mailbox_word(&self, tasks: &TcbManager, thread: ThreadId, index: usize) -> Option<u64> {
        tasks
            .with_thread(&thread, |t| {
                let m = t.mailbox.as_ref()?;
                if index < m.words().len() {
                    Some(m.word(index))
                } else {
                    m.payload()
                        .and_then(|p| p.get(index - m.words().len()).copied())
                }
            })
            .flatten()
    }

    /// Число слов в почтовом ящике (inline + payload; 0 — ящик пуст).
    pub fn mailbox_len(&self, tasks: &TcbManager, thread: ThreadId) -> usize {
        tasks
            .with_thread(&thread, |t| {
                t.mailbox
                    .as_ref()
                    .map(|m| m.words().len() + m.payload().map_or(0, |p| p.len()))
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    /// Статус доставки сообщения в ящике (0 — пусто).
    pub fn mailbox_status(&self, tasks: &TcbManager, thread: ThreadId) -> IpcStatus {
        tasks
            .with_thread(&thread, |t| {
                t.mailbox
                    .as_ref()
                    .map_or(IpcStatus::empty(), |m| m.status())
            })
            .unwrap_or(IpcStatus::empty())
    }

    /// Очистить почтовый ящик (следующее recv начнётся с чистого).
    pub fn mailbox_clear(&self, tasks: &TcbManager, thread: ThreadId) {
        let _ = tasks.with_thread(&thread, |t| {
            t.mailbox = None;
            t.syscall_ret = None;
        });
    }

    /// Положить сообщение в почтовый ящик потока.
    ///
    /// Для НЕ-блокирующего приёма: `recv`/`recv_any` уже вернули слово 0
    /// пользователю, а слова 1.. читаются `IPC_MSG_WORD` из ящика. Раньше
    /// (баг v0.5.2) `recv_any` на parked-pop-пути возвращал `msg.word(0)`
    /// и ВЫБРАСЫВАЛ сообщение: ящик оставался пустым, `IPC_MSG_WORD` дал
    /// NotFound, первый init получал мусорный argv_ptr и умирал на #PF.
    /// `deliver` (fast-path) ящик уже ставил — единая семантика теперь тут.
    pub fn mailbox_set(&self, tasks: &TcbManager, thread: ThreadId, msg: Box<IpcMessage>) {
        let _ = tasks.with_thread(&thread, |t| {
            t.mailbox = Some(msg);
        });
    }

    // ==== Exit-протокол ====

    /// Зарегистрировать exit-endpoint задачи (гейт, в который ядро
    /// доставляет [`ExitPayload`] при её завершении).
    pub fn set_exit_endpoint(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        gate: ObjId,
    ) -> Result<(), IpcError> {
        tasks.set_exit_endpoint(&task, gate).map_err(IpcError::Task)
    }

    /// Доставить exit-состояние дочерней задачи на её exit endpoint.
    ///
    /// Ядерная отправка (без блокировки): ждущий родитель получает сразу,
    /// иначе — буфер; отсутствие зарегистрированного endpoint'а — тихий
    /// no-op (родитель не просил уведомлений).
    pub fn deliver_exit(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        child: TaskId,
        payload: ExitPayload,
    ) -> Result<Option<SendOutcome>, IpcError> {
        let Some(gate) = tasks.exit_endpoint(&child) else {
            return Ok(None);
        };
        let msg = payload.into_message(child);
        self.kernel_send(tasks, caps, gate, msg).map(Some)
    }

    // ==== Вспомогательное ====

    /// Достать поток из очереди блокировки endpoint'а (сторона Send/Recv).
    fn pop_waiter(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        gate: ObjId,
        side: WaitSide,
    ) -> Result<Option<ThreadId>, IpcError> {
        let queue = caps
            .with_endpoint(gate, |ep| match side {
                WaitSide::Send => ep.send_queue(),
                WaitSide::Recv => ep.recv_queue(),
            })
            .ok_or(IpcError::OwnerDead)?;
        if queue == BlockQueueId::default() {
            return Ok(None);
        }
        let sched = tasks.scheduler().ok_or(IpcError::NoBlockQueues)?;
        sched
            .block_pop_front(queue)
            .map_err(TaskError::Scheduler)
            .map_err(IpcError::Task)
    }
}

#[derive(Clone, Copy)]
enum WaitSide {
    Send,
    Recv,
}

impl Default for IpcManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Владелец потока (задача). `Err` — потока нет.
fn thread_task(tasks: &TcbManager, thread: ThreadId) -> Result<TaskId, IpcError> {
    tasks
        .thread_task(&thread)
        .ok_or(TaskError::ThreadNotFound(thread))
        .map_err(IpcError::Task)
}

/// Поставить сообщение в буфер endpoint'а или отказать QueueFull.
fn enqueue_or_full(
    caps: &CapabilityManager,
    gate: ObjId,
    msg: Box<IpcMessage>,
) -> Result<SendOutcome, IpcError> {
    let mut slot = Some(msg);
    let queued = caps
        .with_endpoint(gate, |ep| {
            if ep.has_room() {
                if let Some(m) = slot.take() {
                    ep.queue.push_back(m);
                }
                true
            } else {
                false
            }
        })
        .ok_or(IpcError::OwnerDead)?;
    if queued {
        Ok(SendOutcome::Queued)
    } else {
        Err(IpcError::QueueFull)
    }
}

/// Применить flexpage-элементы сообщения: кадры отправителя -> получателю.
fn apply_map_items(router: &dyn MemRouter, src: TaskId, dst: TaskId, msg: &mut IpcMessage) {
    let mut failed = false;
    for item in msg.items() {
        let res = router.transfer(
            dst,
            item.dst_base,
            src,
            item.src_base,
            item.pages,
            item.grant,
            crate::hal::traits::mmap::MMAPMemoryFlags::from_bits_retain(item.flags),
        );
        if res.is_err() {
            failed = true;
        }
    }
    if failed {
        msg.set_status(msg.status() | IpcStatus::ITEM_ERRORS);
    }
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_builders_and_limits() {
        let mut m = IpcMessage::new(IPC_KERNEL_FROM);
        for i in 0..16 {
            m.push_word(i);
        }
        // Лимит inline-слов — 8, остальное отброшено.
        assert_eq!(m.words().len(), IPC_INLINE_WORDS);
        assert_eq!(m.word(0), 0);
        assert_eq!(m.word(7), 7);
        assert_eq!(m.word(100), 0);

        // Элементы.
        let item = MapItem {
            src_base: 0x1000,
            dst_base: 0,
            pages: 1,
            grant: false,
            flags: 0,
        };
        m.push_item(item);
        assert_eq!(m.items().len(), 1);

        // Payload.
        let m = m.with_payload(Box::from([42u64, 43]));
        assert_eq!(m.payload(), Some(&[42u64, 43][..]));
    }

    #[test]
    fn exit_payload_roundtrip_all_three_kinds() {
        let task = Uuid::from_u128(0xABCD_1234_5678);

        // 1. Код выхода.
        let msg = ExitPayload::Exit {
            code: 7,
            cpu_used: 3,
            cpu_throttle_events: 1,
        }
        .into_message(task);
        assert_eq!(msg.word(0), 1);
        let back = ExitPayload::from_message(&msg).unwrap();
        assert!(
            back == ExitPayload::Exit {
                code: 7,
                cpu_used: 3,
                cpu_throttle_events: 1,
            }
        );

        // 2. Исключение: снимок регистров + указатели фолта.
        let payload = ExitPayload::Exception {
            snapshot: RegisterSnapshot::from_words(&[1, 2, 3, 4, 5, 6, 7, 8]),
            fault: FaultInfo {
                fault_addr: 0xDEAD_1000,
                ip: 0x4000,
                kind: FaultKind::PageWrite,
            },
        };
        let msg = payload.clone().into_message(task);
        assert_eq!(msg.word(0), 2);
        assert_eq!(msg.words().len(), 6);
        assert_eq!(msg.payload().unwrap().len(), 8);
        let back = ExitPayload::from_message(&msg).unwrap();
        assert_eq!(back, payload);

        // 3. Убита: источник.
        let killer = Uuid::from_u128(0xFEED);
        let msg = ExitPayload::Killed {
            by: KillSource::Task(killer),
        }
        .into_message(task);
        assert_eq!(msg.word(0), 3);
        let back = ExitPayload::from_message(&msg).unwrap();
        assert_eq!(
            back,
            ExitPayload::Killed {
                by: KillSource::Task(killer)
            }
        );

        // Само-выход и ядро.
        assert_eq!(
            ExitPayload::from_message(
                &ExitPayload::Killed {
                    by: KillSource::Kernel
                }
                .into_message(task)
            ),
            Some(ExitPayload::Killed {
                by: KillSource::Kernel
            })
        );
        assert_eq!(
            ExitPayload::from_message(
                &ExitPayload::Killed {
                    by: KillSource::SelfExit
                }
                .into_message(task)
            ),
            Some(ExitPayload::Killed {
                by: KillSource::SelfExit
            })
        );

        // Незнакомый тег — None.
        let bad = IpcMessage::signal(IPC_KERNEL_FROM, 99);
        assert!(ExitPayload::from_message(&bad).is_none());
    }

    #[test]
    fn fault_kind_and_kill_source_coding_stable() {
        for kind in [
            FaultKind::PageRead,
            FaultKind::PageWrite,
            FaultKind::PageExec,
            FaultKind::GeneralProtection,
            FaultKind::Alignment,
            FaultKind::Arithmetic,
            FaultKind::Other,
        ] {
            assert_eq!(FaultKind::from_word(kind.as_word()), kind);
        }
        assert_eq!(FaultKind::from_word(9999), FaultKind::Other);

        let src = KillSource::Task(Uuid::from_u128(u128::MAX));
        let [t, lo, hi] = src.to_words();
        assert_eq!(KillSource::from_words(t, lo, hi), src);
        assert_eq!(KillSource::from_words(1, 0, 0), KillSource::SelfExit);
        assert_eq!(KillSource::from_words(2, 0, 0), KillSource::Kernel);
    }

    #[test]
    fn start_args_message_format() {
        let m = IpcMessage::start_args(IPC_KERNEL_FROM, 3, 0x5000, 0x100);
        assert_eq!(m.word(0), 3); // argc
        assert_eq!(m.word(1), 0x5000); // argv ptr
        assert_eq!(m.word(2), 0x100); // argv bytes
    }

    #[test]
    fn endpoint_state_defaults_and_capacity() {
        let ep = EndpointState::default();
        assert_eq!(ep.capacity(), 0);
        assert_eq!(ep.queued(), 0);
        assert_eq!(ep.send_queue(), BlockQueueId::default());
        assert_eq!(ep.recv_queue(), BlockQueueId::default());

        let ep = EndpointState::new(4, BlockQueueId::new(1), BlockQueueId::new(2));
        assert_eq!(ep.capacity(), 4);
        assert_eq!(ep.send_queue(), BlockQueueId::new(1));
        assert_eq!(ep.recv_queue(), BlockQueueId::new(2));
    }
}
