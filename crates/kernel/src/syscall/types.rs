// ==== Типы syscall-слоя: номера, аргументы, коды возврата ====
//
// Здесь — ТОЛЬКО словарь ABI-уровня: как сисколы адресуются, какие аргументы
// приходят и как возвращаются результаты. Никакой логики: семантика конкретных
// сисколов живёт в хендлерах (вне крейта) и в менеджерах подсистем.
//
// Контракт «фасад без логики» (см. mod.rs): слой сисколов НЕ решает, ЧТО
// делает операция, он решает, КАК вызов доходит до менеджера и как ошибка
// менеджера превращается в код возврата пользователя.

use core::fmt;

use thiserror::Error;

use crate::capability::{CapHandle, CapabilityError, CapabilityManager, CapabilityView};
use crate::hal::device::{DeviceManager, IrqRouter};
use crate::hal::traits::mmap::MemErrorCode;
use crate::ipc::{IpcManager, ShmManager};
use crate::mem::MemRouter;
use crate::task::{CpuId, TaskError, TaskId, TcbManager, ThreadId};

// ───────────────────────────── Номер и аргументы ─────────────────────────────

/// Номер сискола. Голое число: конкретная нумерация (BSD/POSIX-подобная,
/// seL4-подобная, своя) — соглашение платформы; крейт адресует хендлеры
/// по [`Self`] без придания номерам смысла.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct SyscallNumber(pub u64);

impl SyscallNumber {
    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SyscallNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syscall({})", self.0)
    }
}

/// Число аргументов сискола (регистры a0..a5 у RISC-V/ARM, rdi..r9 у x86-64).
pub const SYSCALL_ARG_COUNT: usize = 6;

/// Аргументы сискола: до [`SYSCALL_ARG_COUNT`] машинных слов.
///
/// Значения — «сырые» (usize): интерпретация (числа, хендлы, флаги, биты
/// по маске) — право хендлера, не фасада.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SyscallArgs {
    regs: [usize; SYSCALL_ARG_COUNT],
}

impl SyscallArgs {
    /// Аргументы из машинных слов (порядок — как в ABI платформы).
    #[inline]
    pub const fn new(regs: [usize; SYSCALL_ARG_COUNT]) -> Self {
        Self { regs }
    }

    /// Без аргументов (все нули).
    #[inline]
    pub const fn none() -> Self {
        Self {
            regs: [0; SYSCALL_ARG_COUNT],
        }
    }

    /// Аргумент по индексу (0..SYSCALL_ARG_COUNT); вне диапазона — 0
    /// (защита от кривого glue: хендлер получит детерминированный 0,
    /// а не чтение чужой памяти).
    #[inline]
    pub const fn arg(&self, idx: usize) -> usize {
        if idx < SYSCALL_ARG_COUNT {
            self.regs[idx]
        } else {
            0
        }
    }

    /// Сырой срез аргументов (аудит/трейс).
    #[inline]
    pub const fn regs(&self) -> &[usize; SYSCALL_ARG_COUNT] {
        &self.regs
    }
}

impl Default for SyscallArgs {
    fn default() -> Self {
        Self::none()
    }
}

// ───────────────────────────── Коды возврата ─────────────────────────────

/// Ошибка сискола на уровне фасада: перевод ошибок менеджеров подсистем
/// в единый код возврата пользователя (errno-подобный).
///
/// Нумерация кодов ([`Self::code`]) — Linux-конвенция как дефолт ИЗВЕСТНОЙ
/// величины для отладки; финальную нумерацию ABI задаёт платформа
/// (перевод `SyscallRet::to_raw` — единственная точка, где коды становятся
/// числами). Анти-side-channel политика крейта сохраняется: «хендла нет» и
/// «хендл протух» — один [`Self::InvalidHandle`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyscallError {
    /// Нет хендлера номера / операция не поддержана (ENOSYS-аналог).
    #[error("syscall not supported")]
    NotSupported,

    /// Некорректный аргумент (EINVAL-аналог).
    #[error("invalid argument")]
    InvalidArgument,

    /// Хендл не найден ИЛИ протух — намеренно неразличимо (EBADF-аналог).
    #[error("invalid handle")]
    InvalidHandle,

    /// Недостаточно прав у capability (EPERM-аналог).
    #[error("missing capability right")]
    MissingRight,

    /// Нет памяти под операцию (ENOMEM-аналог).
    #[error("out of memory")]
    OutOfMemory,

    /// Объект операции не найден (ENOENT-аналог).
    #[error("object not found")]
    NotFound,

    /// Объект уже существует (EEXIST-аналог).
    #[error("object already exists")]
    AlreadyExists,

    /// Объект занят/жив и не может быть разрушен (EBUSY-аналог).
    #[error("object is busy")]
    Busy,

    /// Пул тегов ASID/PCID исчерпан (ENOSPC-аналог).
    #[error("ASID/PCID pool exhausted")]
    AsidExhausted,

    /// Гейт сисколов не установлен на CPU (ENODEV-аналог).
    #[error("syscall gate/platform not installed")]
    GateNotInstalled,

    /// Операция потребовала бы блокировки, а режим — неблокирующий
    /// (try-варианты IPC/claim; EAGAIN-аналог).
    #[error("operation would block")]
    TryAgain,

    /// Устройство, на которое ссылалась capability, удалено из системы
    /// (hot-removal). Держатель лока уже уведомлён по IPC (ENXIO-аналог).
    #[error("device is gone (removed)")]
    DeviceGone,

    /// Внутренняя ошибка ядра (EIO-аналог): инвариант, протокол, slab.
    #[error("internal kernel error")]
    Internal,
}

impl SyscallError {
    /// errno-подобный код (Linux-конвенция; см. документацию типа).
    pub const fn code(self) -> i32 {
        match self {
            Self::NotSupported => 38,     // ENOSYS
            Self::InvalidArgument => 22,  // EINVAL
            Self::InvalidHandle => 9,     // EBADF
            Self::MissingRight => 1,      // EPERM
            Self::OutOfMemory => 12,      // ENOMEM
            Self::NotFound => 2,          // ENOENT
            Self::AlreadyExists => 17,    // EEXIST
            Self::Busy => 16,             // EBUSY
            Self::AsidExhausted => 28,    // ENOSPC
            Self::GateNotInstalled => 19, // ENODEV
            Self::TryAgain => 11,         // EAGAIN
            Self::DeviceGone => 6,        // ENXIO (ENODEV занят гейтом)
            Self::Internal => 5,          // EIO
        }
    }
}

/// Результат сискола: `usize` (успех) или код ошибки.
pub type SyscallRet = Result<usize, SyscallError>;

/// Перевод результата в машинное слово ABI: успех — значение, отказ —
/// `-(errno)` (конвенция «отрицательный errno», как у Linux raw syscalls;
/// платформа вправе кодировать иначе — это единственная точка кодирования).
#[inline]
pub fn syscall_ret_to_raw(ret: SyscallRet) -> isize {
    match ret {
        Ok(v) => v as isize,
        Err(e) => -(e.code() as isize),
    }
}

// ───────────────────────────── Перевод ошибок менеджеров ─────────────────────────────

impl From<CapabilityError> for SyscallError {
    fn from(e: CapabilityError) -> Self {
        match e {
            CapabilityError::InvalidHandle(_) => Self::InvalidHandle,
            CapabilityError::MissingRight { .. } => Self::MissingRight,
            CapabilityError::TaskNotFound(_) | CapabilityError::UnknownTaskTarget(_) => {
                Self::NotFound
            }
            CapabilityError::OutOfMemory => Self::OutOfMemory,
            CapabilityError::Internal => Self::Internal,
            // non_exhaustive-перечисление: будущие варианты — внутренняя ошибка.
            #[allow(unreachable_patterns)]
            _ => Self::Internal,
        }
    }
}

impl From<TaskError> for SyscallError {
    fn from(e: TaskError) -> Self {
        match e {
            TaskError::TaskNotFound(_) => Self::NotFound,
            TaskError::TaskExists(_) => Self::AlreadyExists,
            TaskError::TaskNotDead(_) => Self::Busy,
            TaskError::TaskHasCaps { .. } => Self::Busy,
            TaskError::InvalidTransition { .. } => Self::InvalidArgument,
            TaskError::OutOfMemory => Self::OutOfMemory,
            // Потоки: тот же словарь errno (общее пространство имён L4).
            TaskError::ThreadNotFound(_) => Self::NotFound,
            TaskError::ThreadExists(_) => Self::AlreadyExists,
            TaskError::ThreadForeign { .. } => Self::MissingRight,
            TaskError::TaskHasThreads { .. } => Self::Busy,
            TaskError::ThreadNotDead(_) => Self::Busy,
            TaskError::ThreadWaitState(_) => Self::InvalidArgument,
            TaskError::Scheduler(_) => Self::Internal,
        }
    }
}

impl From<crate::task::SchedulerError> for SyscallError {
    fn from(_: crate::task::SchedulerError) -> Self {
        // Отказ бекенда планировщика (yield/очереди): внутренняя ошибка
        // ядра — юзерспейс не может её ни исправить, ни различить.
        Self::Internal
    }
}

impl From<MemErrorCode> for SyscallError {
    fn from(e: MemErrorCode) -> Self {
        match e {
            MemErrorCode::NoMemoryLeft | MemErrorCode::PageAllocator(_) => Self::OutOfMemory,
            MemErrorCode::InvalADDR | MemErrorCode::Unaligned => Self::InvalidArgument,
            MemErrorCode::InvalidArgument(_) => Self::InvalidArgument,
            MemErrorCode::NotFound => Self::NotFound,
            MemErrorCode::AlreadyMapped => Self::AlreadyExists,
            MemErrorCode::NotMapped => Self::NotFound,
            MemErrorCode::SlabError(_) | MemErrorCode::InternalError => Self::Internal,
            MemErrorCode::AlignBoxError(_) => Self::Internal,
            MemErrorCode::Asid(crate::hal::traits::asid::ASIDError::Exhausted) => {
                Self::AsidExhausted
            }
            MemErrorCode::Asid(_) => Self::Internal,
        }
    }
}

// ───────────────────────────── Контекст исполнения ─────────────────────────────

/// Контекст исполнения сискола: что хендлеру нужно от ядра.
///
/// Строится фасадом на каждый вызов ([`crate::syscall::SyscallFacade::dispatch`])
/// и передаётся хендлеру по `&mut`. Содержит ссылки на менеджеры и
/// идентификацию вызова: собственное состояние хендлер держит у себя
/// (глобальный сервис — как планировщик у `TcbManager`).
///
/// Базовое ядро (v0.2): `cpu` / `task` / `tasks` / `caps`. Расширение L4:
/// `thread` — исполняющийся поток (блокирующие операции IPC/claim паркуют
/// именно его), `ipc`/`shm`/`devices`/`memory` — подсистемы, подключенные
/// владельцем фасада (`Option`: платформа без подсистемы получает
/// детерминированный `NotSupported` вместо паники).
///
/// Однопоточный контракт крейта распространяется и сюда: менеджеры
/// сериализуются RefCell, реентери из хендлера в фасад — паника
/// заимствования (та же политика, что у `TcbManager::with_caps`).
pub struct SyscallCtx<'a> {
    /// CPU, на котором пришёл вызов (для гейта/планировщика).
    pub cpu: CpuId,
    /// Задача-источник вызова (владелец cspace, чьи хендлы валидны).
    pub task: TaskId,
    /// Исполняющийся поток (L4: сискол всегда на потоке; блокировки
    /// переводят ЕГО в Blocked, пробуждение пишет `syscall_ret`).
    pub thread: ThreadId,
    /// Реестр задач (жизненный цикл, приоритеты, состояния).
    pub tasks: &'a TcbManager,
    /// Менеджер capability (гранты, деривация, отзыв).
    pub caps: &'a CapabilityManager,
    /// IPC-подсистема (endpoint'ы, доставка, exit-протокол).
    pub ipc: Option<&'a IpcManager>,
    /// SHM/кольца io_uring.
    pub shm: Option<&'a ShmManager>,
    /// Реестр устройств (claim/статусы/живость).
    pub devices: Option<&'a DeviceManager>,
    /// Роутер памяти (аллокация регионов, flexpage-переносы).
    pub memory: Option<&'a dyn MemRouter>,
    /// IRQ-роутер (привязки прерываний драйверов к endpoint'ам).
    pub irq: Option<&'a IrqRouter>,
}

impl<'a> SyscallCtx<'a> {
    /// Минимальный контекст (ядро без расширенных подсистем — обратная
    /// совместимость с прямыми конструкциями тестов v0.2).
    pub fn core(
        cpu: CpuId,
        task: TaskId,
        tasks: &'a TcbManager,
        caps: &'a CapabilityManager,
    ) -> Self {
        Self {
            cpu,
            task,
            // Легаси-платформы без потоков: «поток» = сама задача.
            thread: task,
            tasks,
            caps,
            ipc: None,
            shm: None,
            devices: None,
            memory: None,
            irq: None,
        }
    }

    /// Исполняющийся поток (L4-модель).
    pub fn with_thread(mut self, thread: ThreadId) -> Self {
        self.thread = thread;
        self
    }

    /// Подключить IPC-подсистему.
    pub fn with_ipc(mut self, ipc: &'a IpcManager) -> Self {
        self.ipc = Some(ipc);
        self
    }

    /// Подключить SHM-подсистему.
    pub fn with_shm(mut self, shm: &'a ShmManager) -> Self {
        self.shm = Some(shm);
        self
    }

    /// Подключить реестр устройств.
    pub fn with_devices(mut self, devices: &'a DeviceManager) -> Self {
        self.devices = Some(devices);
        self
    }

    /// Подключить роутер памяти.
    pub fn with_memory(mut self, memory: &'a dyn MemRouter) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Подключить IRQ-роутер (привязки прерываний драйверов).
    pub fn with_irq(mut self, irq: &'a IrqRouter) -> Self {
        self.irq = Some(irq);
        self
    }

    /// Снимок capability вызывающего по хендлу (без RAII — чистое чтение;
    /// для транзитных capability — `crate::syscall::SyscallFacade::mint_transient`).
    pub fn resolve(&self, handle: CapHandle) -> Result<CapabilityView, SyscallError> {
        // Владелец — вызывающая задача; чужие хендлы неотличимы от битых.
        self.caps
            .get(self.tasks, self.task, handle)
            .ok_or(SyscallError::InvalidHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_bounds_and_defaults() {
        let args = SyscallArgs::new([1, 2, 3, 4, 5, 6]);
        assert_eq!(args.arg(0), 1);
        assert_eq!(args.arg(5), 6);
        // Вне диапазона — детерминированный 0, не чужая память.
        assert_eq!(args.arg(6), 0);
        assert_eq!(args.arg(usize::MAX), 0);
        assert_eq!(SyscallArgs::none().regs(), &[0; SYSCALL_ARG_COUNT]);
        assert_eq!(SyscallArgs::default().arg(0), 0);
    }

    #[test]
    fn errno_mapping_is_stable() {
        // Коды обязаны совпадать с Linux-конвенцией (документация типа).
        assert_eq!(SyscallError::NotSupported.code(), 38);
        assert_eq!(SyscallError::InvalidHandle.code(), 9);
        assert_eq!(SyscallError::OutOfMemory.code(), 12);
        assert_eq!(SyscallError::MissingRight.code(), 1);

        // to_raw: успех — значение, отказ — отрицательный errno.
        assert_eq!(syscall_ret_to_raw(Ok(42)), 42);
        assert_eq!(syscall_ret_to_raw(Err(SyscallError::NotSupported)), -38);

        // Переводы ошибок менеджеров — детерминированные варианты.
        let e: SyscallError = MemErrorCode::NoMemoryLeft.into();
        assert_eq!(e, SyscallError::OutOfMemory);
        let e: SyscallError = MemErrorCode::AlreadyMapped.into();
        assert_eq!(e, SyscallError::AlreadyExists);
        let e: SyscallError =
            MemErrorCode::Asid(crate::hal::traits::asid::ASIDError::Exhausted).into();
        assert_eq!(e, SyscallError::AsidExhausted);
        let e: SyscallError = TaskError::TaskExists(UuidHelper::zero()).into();
        assert_eq!(e, SyscallError::AlreadyExists);
    }

    /// Нуленый Uuid для тестов перевода ошибок (uuid в no_std-режиме
    /// без v4-генератора — константа проще).
    struct UuidHelper;
    impl UuidHelper {
        fn zero() -> uuid::Uuid {
            uuid::Uuid::from_bytes([0; 16])
        }
    }

    #[test]
    fn syscall_number_identity() {
        let n = SyscallNumber::new(7);
        assert_eq!(n.as_u64(), 7);
        assert_eq!(n, SyscallNumber(7));
        assert!(SyscallNumber::new(1) < SyscallNumber::new(2));
        assert_eq!(SyscallNumber::default().as_u64(), 0);
    }
}
