// ==== ФАСАД СИСКОЛОВ: гейт входа, реестр хендлеров, диспетчер ====
//
// Слой сисколов крейта — ФАСАД, НЕ ЛОГИКА:
//   * ЧТО делает операция — решают менеджеры подсистем (task, capability,
//     mem) и хендлеры платформы ВНЕ крейта;
//   * КАК вызов доходит до них — здесь: гейт входа (per-CPU стеки и
//     позиции возврата), реестр хендлеров (ПЛОСКАЯ таблица слотов —
//     вектор прерываний), контекст вызова и перевод ошибок в
//     errno-подобные коды (`syscall::types`).
//
// Архитектурная точка Meltdown/Spectre — гейт: вход в ядро и выход из него
// обязаны переключать таблицы страниц по политике KPTI (см.
// `hal::traits::kmap::IsolationPolicy`), а при наличии PCID/ASID —
// тегированно, без сброса TLB (`hal::traits::asid`). Крейт ведёт per-CPU
// состояние (какое пространство активно на CPU), переключение исполняет
// арх-бекенд через контракт [`SyscallPlatform`] — прямой аналог
// `MMAPInterface`/`KMAPInterface`/`SchedulerInterface`:
//
// ```text
//   user code ──syscall──▶ [arch trampoline]
//                             │ gate stack + enter position (SyscallGate)
//                             │ KPTI: user CR3 | tag U ──▶ kernel CR3 | tag K
//                             ▼
//                       SyscallFacade::dispatch
//                             │ table[number]: bounds-check + чтение слота,
//                             │ ноль аллокаций (вектор прерываний)
//                             ▼
//                       handler(ctx) ──▶ менеджеры подсистем
//                             │
//   user code ◀──ret──────── [arch exit: позиция возврата + user CR3 | tag U]
// ```
//
// Направления вызовов:
//   arch glue -> гейт: `set_enter_position` / `set_user_space` (учёт),
//                `SyscallPlatform::enter/exit` исполняет само железо;
//   arch glue -> фасад: `dispatch` (после входа, на стеке гейта);
//   платформа -> реестр: `install_default_table` / `register` /
//                `reregister` / `unregister` (статические хендлеры);
//   фасад -> менеджеры: только через ctx хендлеров (task.rs — примеры
//                тонкой маршрутизации без собственной логики).

use crate::sync::KRwLock;
use core::fmt;

use spin::Once;
use thiserror::Error;

use crate::capability::{CapHandle, CapabilityManager, MintSpec};
use crate::hal::irq::IrqRouter;
use crate::hal::traits::asid::AsidPair;
use crate::hal::traits::mmap::PhysADDR;
use crate::task::{CpuId, TaskId, TcbManager};

pub mod debug;
pub mod futex;
pub mod handle_guard;
pub mod io;
pub mod iommu;
pub mod ipc;
pub mod mem;
pub mod nums;
pub mod system;
pub mod task;
pub mod types;

pub use debug::{DebugSink, install_debug_sink, trace_enabled};
pub use handle_guard::HandleGuard;
pub use types::{
    SYSCALL_ARG_COUNT, SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet,
};

use crate::ipc::{IpcManager, ShmManager};
use crate::mem::MemRouter;
use crate::task::ThreadId;

// ───────────────────── SMP v0.12: защёлка исхода диспетчера ─────────────────────

/// Потолок защёлок (диагностический: MADT-топология демонстрационных
/// платформ много меньше; переполнение индекса — clamp без паники).
const BLOCK_LATCH_CPUS: usize = 64;

/// Per-CPU защёлка «ЭТОТ диспетч заблокировал вызывающий поток».
///
/// Проблема (бывший BKL закрывал её глобальной сериализацией): хендлер
/// блокировки возвращает `Ok(0)` — неотличимо от обычного успеха, и гейт
/// после диспетча решал «парковать или вернуть» повторным чтением TCB.
/// Между диспетчем и чтением поток мог быть уже разбужен с другого CPU,
/// снова стать Running — чтение дало бы «не блокирован» и sysret вошёл бы
/// в поток ПОВТОРНО, пока его исполняет другой CPU (двойной запуск).
///
/// Решение: решение гейта — по данным СВОЕГО CPU. Хендлер блокирующей
/// операции ставит защёлку до возврата; гейт забирает её после диспетча.
/// Запись и чтение — только с одного и того же CPU (program order);
/// атомики — от переупорядочивания компилятором, не для cross-CPU.
static BLOCK_LATCH: [core::sync::atomic::AtomicBool; BLOCK_LATCH_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; BLOCK_LATCH_CPUS];

/// Хендлер заблокировал вызывающий поток (IPC send/recv/call/recv_any,
/// DEVICE_CLAIM): гейт после диспетча обязан уйти в диспетчеризацию.
#[inline]
pub fn record_block_latch(cpu: CpuId) {
    BLOCK_LATCH[cpu.min(BLOCK_LATCH_CPUS - 1)].store(true, core::sync::atomic::Ordering::Release);
}

/// Забрать защёлку своего CPU (гейт после диспетча; чтение сбрасывает).
#[inline]
pub fn take_block_latch(cpu: CpuId) -> bool {
    BLOCK_LATCH[cpu.min(BLOCK_LATCH_CPUS - 1)].swap(false, core::sync::atomic::Ordering::AcqRel)
}

// ───────────────────────────── Позиция возврата ─────────────────────────────

/// Позиция возврата в пользователя: IP/SP прерванной инструкции.
///
/// Пишется арх-глюем при входе (куда возвращаться), читается при выходе.
/// Голые машинные слова: формат регистров/стека — знание платформы.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnterPosition {
    ip: usize,
    sp: usize,
}

impl EnterPosition {
    #[inline]
    pub const fn new(ip: usize, sp: usize) -> Self {
        Self { ip, sp }
    }

    /// Адрес возврата (instruction pointer).
    #[inline]
    pub const fn ip(&self) -> usize {
        self.ip
    }

    /// Указатель стека пользователя на момент входа.
    #[inline]
    pub const fn sp(&self) -> usize {
        self.sp
    }
}

// ───────────────────────────── Гейт: ошибки и состояние ─────────────────────────────

/// Отказ гейта сисколов (учёт и валидация, не железо).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateError {
    /// `cpu` вне границ гейта (CPU_COUNT).
    #[error("cpu {0} is out of gate bounds")]
    InvalidCpu(CpuId),
    /// Платформа сисколов не установлена (см. [`GateManager::install`]).
    #[error("syscall platform is not installed")]
    PlatformNotInstalled,
}

/// Активное пользовательское пространство на CPU (запись гейта).
///
/// Части KPTI-картины: корень пользовательской таблицы + её пара тегов
/// (`None` — нетегированное пространство / политика полного ядра).
/// Обновляется арх-глюем при переключении контекста и на входе сискола.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct UserSpace {
    pub root: Option<PhysADDR>,
    pub asid: Option<AsidPair>,
}

impl UserSpace {
    /// Тегированное пространство.
    #[inline]
    pub const fn tagged(root: PhysADDR, asid: AsidPair) -> Self {
        Self {
            root: Some(root),
            asid: Some(asid),
        }
    }
}

/// Вектор входа одного CPU: стек сисколов + позиция возврата + активное
/// пользовательское пространство.
///
/// Стек лежит inline (массив машинного размера, как в платформенных
/// гейтах): адрес стабилен, пока [`SyscallGate`] живёт в статике/Box
/// владельца-платформы. Выравнивание вершины стека под ABI (16 байт у
/// x86-64/SysV) — обязанность арх-глюя, использующего
/// [`SyscallGate::stack_top`].
pub struct GateCpu<const SYSCALL_STACK: usize> {
    stack: [u8; SYSCALL_STACK],
    enter: Option<EnterPosition>,
    user: UserSpace,
}

impl<const SYSCALL_STACK: usize> GateCpu<SYSCALL_STACK> {
    /// Нулевой вектор (стек занулён, позиций нет).
    pub const EMPTY: Self = Self {
        stack: [0; SYSCALL_STACK],
        enter: None,
        user: UserSpace {
            root: None,
            asid: None,
        },
    };

    /// Позиция возврата, записанная последним входом.
    #[inline]
    pub fn enter_position(&self) -> Option<EnterPosition> {
        self.enter
    }

    /// Активное пользовательское пространство CPU.
    #[inline]
    pub const fn user_space(&self) -> UserSpace {
        self.user
    }

    /// Стек сисколов CPU (сырые байты; см. [`SyscallGate::stack_top`]).
    #[inline]
    pub fn stack(&self) -> &[u8; SYSCALL_STACK] {
        &self.stack
    }
}

/// Гейт сисколов: per-CPU векторы входа, `CPU_COUNT` штук.
///
/// Это УЧЁТ, не железо: кто на каком CPU, куда возвращаться, какое
/// пространство активно. Само переключение таблиц/стеков — арх-бекенд
/// ([`SyscallPlatform`]), крейт лишь хранит и выдаёт состояние. Размер
/// стека и число CPU — константы сборки (как в векторах входа seL4).
///
/// KPTI-контракт гейта (см. `hal::traits::kmap`): при политике
/// `UserTableIsolation` бекенд на `enter` активирует ядровую таблицу
/// (тег `kernel` пары), на `exit` — пользовательскую (тег `user`), с
/// `FlushMode::NoFlush` при живых тегах. Гейт подсказывает бекенду пару
/// тегов текущего пространства ([`Self::user_space`]) — та же пара, под
/// которую создавался фасад задачи (`MemoryManager::create_ufacade_asid`).
pub struct SyscallGate<const SYSCALL_STACK: usize, const CPU_COUNT: usize> {
    cpus: [GateCpu<SYSCALL_STACK>; CPU_COUNT],
}

impl<const SYSCALL_STACK: usize, const CPU_COUNT: usize> SyscallGate<SYSCALL_STACK, CPU_COUNT> {
    /// Гейт с нулевыми векторами (платформа заполняет стеки/позиции сама).
    pub fn new() -> Self {
        Self {
            cpus: [const { GateCpu::EMPTY }; CPU_COUNT],
        }
    }

    /// Число CPU гейта (для валидации у бекенда).
    #[inline]
    pub const fn cpu_count(&self) -> usize {
        CPU_COUNT
    }

    /// Размер стека сисколов одного CPU.
    #[inline]
    pub const fn stack_size(&self) -> usize {
        SYSCALL_STACK
    }

    fn cpu(&self, cpu: CpuId) -> Result<&GateCpu<SYSCALL_STACK>, GateError> {
        self.cpus.get(cpu).ok_or(GateError::InvalidCpu(cpu))
    }

    fn cpu_mut(&mut self, cpu: CpuId) -> Result<&mut GateCpu<SYSCALL_STACK>, GateError> {
        self.cpus.get_mut(cpu).ok_or(GateError::InvalidCpu(cpu))
    }

    /// Записать позицию возврата для CPU (арх-глюй на входе).
    pub fn set_enter_position(&mut self, cpu: CpuId, pos: EnterPosition) -> Result<(), GateError> {
        self.cpu_mut(cpu)?.enter = Some(pos);
        Ok(())
    }

    /// Прочитать позицию возврата CPU (арх-глюй на выходе).
    pub fn enter_position(&self, cpu: CpuId) -> Result<Option<EnterPosition>, GateError> {
        Ok(self.cpu(cpu)?.enter_position())
    }

    /// Записать активное пользовательское пространство CPU (арх-глюй при
    /// переключении контекста / входе). Пара тегов обязана быть парой
    /// фасада активной задачи — иначе выход в пользователя разъедется с
    /// компоновкой её таблиц.
    pub fn set_user_space(&mut self, cpu: CpuId, user: UserSpace) -> Result<(), GateError> {
        self.cpu_mut(cpu)?.user = user;
        Ok(())
    }

    /// Активное пользовательское пространство CPU.
    pub fn user_space(&self, cpu: CpuId) -> Result<UserSpace, GateError> {
        Ok(self.cpu(cpu)?.user_space())
    }

    /// Вершина стека сисколов CPU (адрес для арх-глюя: RSP на входе;
    /// стек растёт вниз, вершина — конец массива).
    ///
    /// # Safety-контракт для вызывающего
    /// Гейт обязан жить по стабильному адресу (статика/leak), пока arch-глюй
    /// использует адрес: передвинутый гейт делает все вершины невалидными.
    pub fn stack_top(&self, cpu: CpuId) -> Result<usize, GateError> {
        let cpu_ref = self.cpu(cpu)?;
        Ok(cpu_ref.stack.as_ptr() as usize + SYSCALL_STACK)
    }
}

impl<const SYSCALL_STACK: usize, const CPU_COUNT: usize> Default
    for SyscallGate<SYSCALL_STACK, CPU_COUNT>
{
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────────── Контракт арх-бекенда ─────────────────────────────

/// Архитектурный бекенд syscall-входа/выхода (KPTI-переключение таблиц).
///
/// Реализуется платформенным кодом ВНЕ крейта — тот же исполнитель, что у
/// `MMAPInterface`/`KMAPInterface`/`SchedulerInterface`. Все методы — `&self`:
/// бекенд глобальный (`&'static`, как планировщик), синхронизация — его забота.
///
/// # Контракт Meltdown/Spectre (обязателен для реализации)
///
/// 1. `enter` — переключение на ядровый контекст CPU: стек гейта
///    (адрес выдаёт `SyscallGate::stack_top`) и, при KPTI, ядровая таблица
///    страниц (тег `kernel` пары активного пространства). Активация —
///    ТОЛЬКО через фасадный слой памяти (`ASIDInterface::activate`):
///    прямые записи CR3/TTBR в обход контракта запрещены — там живёт
///    физика и семантика изоляции.
/// 2. `exit` — возврат в пользователя: позиция входа + пользовательская
///    таблица (тег `user`). При живых тегах — `FlushMode::NoFlush`: TLB
///    остаётся тёплым, в этом смысл PCID. Пользовательская таблица при
///    `UserTableIsolation` не содержит ядра сверх EntryTrampoline/UserShared.
/// 3. Политика изоляции обязана совпадать с `MemoryManager::kmap().policy()`
///    (контракт зеркалит `SchedulerInterface::switch_context`).
/// 4. Трамплин входа (код, вызывающий эти хуки) — W^X и не записываем
///    (см. `KernelRegionKind::EntryTrampoline`): поверхность Spectre-класса
///    на входе в ядро обязана быть минимальной.
///
/// `Err` — переключение не выполнено; CPU остаётся в текущем режиме
/// (бекенд приводит себя в согласованное состояние до возврата ошибки).
pub trait SyscallPlatform {
    /// Число CPU, которое обслуживает бекенд (валидация `cpu`).
    fn cpu_count(&self) -> usize;

    /// Вход в ядро на CPU: стек сисколов + ядровая таблица (KPTI).
    fn enter(&self, cpu: CpuId, gate_stack_top: usize) -> Result<(), SyscallError>;

    /// Выход к пользователю: позиция возврата + пользовательская таблица.
    fn exit(&self, cpu: CpuId, ep: EnterPosition, user: UserSpace) -> Result<(), SyscallError>;
}

// ───────────────────────────── Реестр хендлеров ─────────────────────────────

/// Хендлер одного сискола: семантика вызова (ЛОГИКА — вне крейта).
///
/// Object-safe: реестр хранит `&'static dyn SyscallHandler` — хендлеры
/// сисколов в ядре статические объекты (как векторы прерываний), время
/// жизни — программы. Реентери в менеджеры через `ctx` — паника
/// заимствования (однопоточный контракт крейта); собственное состояние
/// хендлер держит у себя и сериализует сам.
pub trait SyscallHandler {
    /// Исполнить сискол. Аргументы — сырые слова; результат — `usize`
    /// или errno-подобный отказ ([`SyscallError`]).
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet;
}

/// Число слотов таблицы сисколов: номера 0x00..0xFF.
///
/// Размер фиксирован сборкой (как вектор прерываний IDT): таблица —
/// один массив fat-указателей, занулённый линкером (.bss); регистрация —
/// запись указателя в слот. Группы номеров — см. `syscall::nums`;
/// 0x80..0xFE — платформенные, 0xFF — зарезервировано.
pub const SYSCALL_TABLE_SIZE: usize = 256;

/// Реестр сисколов: ПЛОСКАЯ таблица «номер -> хендлер».
///
/// Переработка v0.4 (было: интрузивное RB-дерево поверх slab-кэша —
/// O(log n) поиск, аллокации при регистрации, Drop-протокол слотов).
/// Микроядру с фиксированным набором ~60 сисколов дерево не нужно:
/// диспетчеризация — один bounds-check и одно чтение слота, O(1),
/// ноль аллокаций на любом пути.
///
/// Регистрация — платформенный код на старте (и осторожно на живую:
/// однопоточный контракт, реентери из хендлера — паника). Отсутствие
/// хендлера — `ENOSYS`-отказ, а не паника: пользовательский код вправе
/// звать любое число, ядро обязано отвечать детерминированно.
pub struct SyscallRegistry {
    slots: KRwLock<[Option<&'static dyn SyscallHandler>; SYSCALL_TABLE_SIZE]>,
}

impl SyscallRegistry {
    /// Пустой реестр: таблица занулена, аллокаций нет (прежний
    /// `new() -> Result` исчез вместе со slab-кэшем: отказ невозможен).
    pub fn new() -> Self {
        Self {
            slots: KRwLock::new([const { None }; SYSCALL_TABLE_SIZE]),
        }
    }

    /// Индекс слота по номеру (номера вне таблицы — ошибка регистрации).
    fn slot_index(number: SyscallNumber) -> Result<usize, SyscallError> {
        match usize::try_from(number.0) {
            Ok(idx) if idx < SYSCALL_TABLE_SIZE => Ok(idx),
            _ => Err(SyscallError::InvalidArgument),
        }
    }

    /// Зарегистрировать хендлер номера. Занятый слот —
    /// [`SyscallError::AlreadyExists`]; номер вне таблицы —
    /// [`SyscallError::InvalidArgument`].
    pub fn register(
        &self,
        number: SyscallNumber,
        handler: &'static dyn SyscallHandler,
    ) -> Result<(), SyscallError> {
        let idx = Self::slot_index(number)?;
        let mut slots = self.slots.write();
        if slots[idx].is_some() {
            return Err(SyscallError::AlreadyExists);
        }
        slots[idx] = Some(handler);
        Ok(())
    }

    /// Перезаписать слот (подмена платформой дефолтного хендлера своим —
    /// например, SYS_TIME поверх контракта TimeSource). Прежний хендлер
    /// теряется: ссылки статические, памяти не утекает. Номер вне
    /// таблицы — InvalidArgument.
    pub fn reregister(
        &self,
        number: SyscallNumber,
        handler: &'static dyn SyscallHandler,
    ) -> Result<(), SyscallError> {
        let idx = Self::slot_index(number)?;
        self.slots.write()[idx] = Some(handler);
        Ok(())
    }

    /// Снять хендлер номера (динамические подсистемы/отладка).
    pub fn unregister(&self, number: SyscallNumber) -> Result<(), SyscallError> {
        let idx = Self::slot_index(number)?;
        let mut slots = self.slots.write();
        if slots[idx].take().is_some() {
            Ok(())
        } else {
            Err(SyscallError::NotFound)
        }
    }

    /// Хендлер номера (горячий путь: bounds-check + чтение слота,
    /// `&'static` переживает заимствование).
    pub fn handler(&self, number: SyscallNumber) -> Option<&'static dyn SyscallHandler> {
        let idx = Self::slot_index(number).ok()?;
        self.slots.read()[idx]
    }

    /// Число занятых слотов (аудит).
    pub fn len(&self) -> usize {
        self.slots.read().iter().filter(|s| s.is_some()).count()
    }

    /// Пуст ли реестр.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Диспетчеризация: найти хендлер и позвать. Отсутствие номера —
    /// [`SyscallError::NotSupported`] (ENOSYS-аналог).
    ///
    /// НЕ содержит логики по номеру — только маршрутизация: семантика
    /// целиком в хендлере. Включённая трассировка (DEBUG_TRACE) пишет
    /// номер и аргументы в отладочную консоль до вызова хендлера.
    pub fn dispatch(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let number = number_from_args(args);
        debug::trace_dispatch(number, args);
        let handler = self.handler(number);
        match handler {
            Some(h) => h.invoke(ctx, args),
            None => Err(SyscallError::NotSupported),
        }
    }

    /// Диспетчеризация по явному номеру (arch-глюй передаёт номер отдельно
    /// от аргументов — как в регистре сискола).
    pub fn dispatch_number(
        &self,
        number: SyscallNumber,
        ctx: &mut SyscallCtx<'_>,
        args: &SyscallArgs,
    ) -> SyscallRet {
        debug::trace_dispatch(number, args);
        match self.handler(number) {
            Some(h) => h.invoke(ctx, args),
            None => Err(SyscallError::NotSupported),
        }
    }

    /// Установить ДЕФОЛТНУЮ таблицу крейта: все встроенные хендлеры по
    /// своим номерам (`syscall::nums`). Идемпотентна (перезапись слотов),
    /// повторный вызов восстанавливает именно крейтовые хендлеры.
    ///
    /// GCTL зовёт её при создании; для реестра вне GCTL платформа вызывает
    /// сама. Легаси-пример TASK_SPAWN (без capability-проверки) в таблицу
    /// НЕ входит — безопасный путь TASK_CREATE.
    pub fn install_default_table(&self) {
        use crate::syscall::debug::{
            DebugDumpTasksHandler, DebugDumpThreadsHandler, DebugTraceHandler, DebugWriteHandler,
        };
        use crate::syscall::io::{
            IopInHandler, IopOutHandler, IrqAckHandler, IrqAttachHandler, IrqDetachHandler,
            MmioMapHandler,
        };
        use crate::syscall::iommu::{
            IommuAttachHandler, IommuDetachHandler, IommuEnumHandler, IommuIrqMapHandler,
            IommuIrqUnmapHandler, IommuMapHandler, IommuUnmapHandler,
        };
        use crate::syscall::ipc::{
            EpCreateHandler, IpcCallHandler, IpcMsgClearHandler, IpcMsgLenHandler,
            IpcMsgWordHandler, IpcRecvAnyHandler, IpcRecvHandler, IpcSendHandler,
            IpcSendThreadHandler, NotifySignalHandler,
        };
        use crate::syscall::futex::{FutexWaitHandler, FutexWakeHandler};
        use crate::syscall::mem::{
            MemAllocHandler, MemFreeHandler, MemInfoHandler, MemMapAtHandler, MemProtectHandler,
            MemTransferHandler, RingDoorbellHandler, ShmBindDoorbellHandler, ShmCreateHandler,
            ShmDestroyHandler, ShmInfoHandler, ShmMapHandler, ShmSetupRingHandler,
        };
        use crate::syscall::system::{SelfInfoHandler, SysTimeHandler};
        use crate::syscall::task::{
            CapDeleteHandler, CapInfoHandler, CapListHandler, CapMintHandler, CapMintRangeHandler,
            CapRevokeHandler, CapSendHandler, TaskCreateHandler, TaskExitExceptionHandler,
            TaskExitHandler, TaskKillHandler, TaskLimitsInfoHandler, TaskSetExitEpHandler,
            TaskSetLimitsHandler, TaskSpawnImageHandler, ThreadCreateHandler, ThreadDestroyHandler,
            ThreadExRegsHandler, ThreadResumeHandler, ThreadSetPrioHandler, ThreadSetSliceNotifyHandler,
            ThreadSetTlsHandler, ThreadSuspendHandler, ThreadTerminateHandler, ThreadYieldHandler,
        };

        macro_rules! slot {
            ($num:expr, $h:path) => {
                let _ = self.reregister($num, &$h);
            };
        }

        // 0x00: системные.
        slot!(nums::SELF_INFO, SelfInfoHandler);
        slot!(nums::SYS_TIME, SysTimeHandler);

        // 0x10: задачи и потоки.
        slot!(nums::TASK_CREATE, TaskCreateHandler);
        slot!(nums::TASK_SET_EXIT_EP, TaskSetExitEpHandler);
        slot!(nums::TASK_EXIT, TaskExitHandler);
        slot!(nums::TASK_KILL, TaskKillHandler);
        slot!(nums::TASK_EXIT_EXCEPTION, TaskExitExceptionHandler);
        slot!(nums::THREAD_CREATE, ThreadCreateHandler);
        slot!(nums::THREAD_DESTROY, ThreadDestroyHandler);
        slot!(nums::THREAD_TERMINATE, ThreadTerminateHandler);
        slot!(nums::THREAD_SET_PRIO, ThreadSetPrioHandler);
        slot!(nums::THREAD_SUSPEND, ThreadSuspendHandler);
        slot!(nums::THREAD_RESUME, ThreadResumeHandler);
        slot!(nums::THREAD_YIELD, ThreadYieldHandler);
        slot!(nums::THREAD_EX_REGS, ThreadExRegsHandler);
        slot!(nums::TASK_SET_LIMITS, TaskSetLimitsHandler);
        slot!(nums::TASK_LIMITS_INFO, TaskLimitsInfoHandler);
        slot!(nums::TASK_SPAWN_IMAGE, TaskSpawnImageHandler);

        // 0x90: расширения планировщика (advisory, опционально).
        slot!(nums::THREAD_SET_SLICE_NOTIFY, ThreadSetSliceNotifyHandler);
        // v0.17: TLS-слово потока (opaque; грузит бекенд платформы).
        slot!(nums::THREAD_SET_TLS, ThreadSetTlsHandler);

        // 0x30: IPC (+ футеки — тот же класс блокировок, v0.17).
        slot!(nums::FUTEX_WAIT, FutexWaitHandler);
        slot!(nums::FUTEX_WAKE, FutexWakeHandler);

        // 0x20: capability.
        slot!(nums::CAP_MINT, CapMintHandler);
        slot!(nums::CAP_MINT_RANGE, CapMintRangeHandler);
        slot!(nums::CAP_SEND, CapSendHandler);
        slot!(nums::CAP_REVOKE, CapRevokeHandler);
        slot!(nums::CAP_DELETE, CapDeleteHandler);
        slot!(nums::CAP_LIST, CapListHandler);
        slot!(nums::CAP_INFO, CapInfoHandler);

        // 0x30: IPC.
        slot!(nums::EP_CREATE, EpCreateHandler);
        slot!(nums::IPC_SEND, IpcSendHandler);
        slot!(nums::IPC_RECV, IpcRecvHandler);
        slot!(nums::IPC_CALL, IpcCallHandler);
        slot!(nums::IPC_SEND_THREAD, IpcSendThreadHandler);
        slot!(nums::IPC_RECV_ANY, IpcRecvAnyHandler);
        slot!(nums::IPC_MSG_WORD, IpcMsgWordHandler);
        slot!(nums::IPC_MSG_LEN, IpcMsgLenHandler);
        slot!(nums::IPC_MSG_CLEAR, IpcMsgClearHandler);
        slot!(nums::NOTIFY_SIGNAL, NotifySignalHandler);

        // 0x40: сырые ресурсы (IoResource) и IRQ.
        slot!(nums::MMIO_MAP, MmioMapHandler);
        slot!(nums::IOP_IN, IopInHandler);
        slot!(nums::IOP_OUT, IopOutHandler);
        slot!(nums::IRQ_ATTACH, IrqAttachHandler);
        slot!(nums::IRQ_DETACH, IrqDetachHandler);
        slot!(nums::IRQ_ACK, IrqAckHandler);

        // 0x50: память.
        slot!(nums::MEM_ALLOC, MemAllocHandler);
        slot!(nums::MEM_FREE, MemFreeHandler);
        slot!(nums::MEM_TRANSFER, MemTransferHandler);
        slot!(nums::MEM_INFO, MemInfoHandler);
        slot!(nums::MEM_MAP_AT, MemMapAtHandler);
        // v0.17: смена прав отображённых страниц (mprotect-аналог).
        slot!(nums::MEM_PROTECT, MemProtectHandler);

        // 0x60: SHM io_uring.
        slot!(nums::SHM_CREATE, ShmCreateHandler);
        slot!(nums::SHM_SETUP_RING, ShmSetupRingHandler);
        slot!(nums::SHM_BIND_DOORBELL, ShmBindDoorbellHandler);
        slot!(nums::SHM_MAP, ShmMapHandler);
        slot!(nums::SHM_DESTROY, ShmDestroyHandler);
        slot!(nums::RING_DOORBELL, RingDoorbellHandler);
        slot!(nums::SHM_INFO, ShmInfoHandler);

        // 0x70: отладка.
        slot!(nums::DEBUG_WRITE, DebugWriteHandler);
        slot!(nums::DEBUG_DUMP_TASKS, DebugDumpTasksHandler);
        slot!(nums::DEBUG_TRACE, DebugTraceHandler);
        slot!(nums::DEBUG_DUMP_THREADS, DebugDumpThreadsHandler);

        // 0x80: IOMMU/DMA-ремаппинг (без сервиса — ENOSYS).
        slot!(nums::IOMMU_ENUM, IommuEnumHandler);
        slot!(nums::IOMMU_ATTACH, IommuAttachHandler);
        slot!(nums::IOMMU_MAP, IommuMapHandler);
        slot!(nums::IOMMU_UNMAP, IommuUnmapHandler);
        slot!(nums::IOMMU_DETACH, IommuDetachHandler);
        slot!(nums::IOMMU_IRQ_MAP, IommuIrqMapHandler);
        slot!(nums::IOMMU_IRQ_UNMAP, IommuIrqUnmapHandler);
    }
}

impl Default for SyscallRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// «Текущий номер» для dispatch без явного номера: конвенция — нулевой
/// аргумент. Платформа со своим ABI использует dispatch_number.
fn number_from_args(args: &SyscallArgs) -> SyscallNumber {
    SyscallNumber(args.arg(0) as u64)
}

// ───────────────────────────── Фасад ─────────────────────────────

/// Фасад сисколов: реестр + менеджеры, готовые к маршрутизации вызовов.
///
/// Ссылочный ВИД над владельцем (GCTL или платформенный код): фасад
/// конструируется на каждый вход дёшево (три ссылки) и не владеет ничем —
/// self-referential-проблем у владельца не возникает.
///
/// Методы делятся на два рода:
///   * инфраструктура: `dispatch*`, `resolve_handle`, `mint_transient`
///     (реестр, RAII-гарды — здесь);
///   * маршрутизация к менеджерам: тонкие методы `task_*`/`cap_*`
///     (см. `syscall::task`): проверка аргументов -> вызов менеджера ->
///     перевод ошибки в errno. Логики НЕ добавляется: семантика — в менеджерах.
pub struct SyscallFacade<'a> {
    tasks: &'a TcbManager,
    caps: &'a CapabilityManager,
    registry: &'a SyscallRegistry,
    // ==== Расширенные подсистемы (L4-слой; None — не подключены) ====
    ipc: Option<&'a IpcManager>,
    shm: Option<&'a ShmManager>,
    memory: Option<&'a dyn MemRouter>,
    space: Option<&'a dyn crate::mem::SpaceFactory>,
    copy: Option<&'a dyn crate::mem::UserCopy>,
    irq: Option<&'a IrqRouter>,
}

impl<'a> SyscallFacade<'a> {
    /// Фасад над тройкой «реестр + задачи + capability» (базовое ядро,
    /// обратная совместимость v0.2: расширенные подсистемы — None).
    pub fn new(
        tasks: &'a TcbManager,
        caps: &'a CapabilityManager,
        registry: &'a SyscallRegistry,
    ) -> Self {
        Self {
            tasks,
            caps,
            registry,
            ipc: None,
            shm: None,
            memory: None,
            space: None,
            copy: None,
            irq: None,
        }
    }

    /// Подключить IPC-подсистему (builder).
    pub fn with_ipc(mut self, ipc: &'a IpcManager) -> Self {
        self.ipc = Some(ipc);
        self
    }

    /// Подключить SHM-подсистему (builder).
    pub fn with_shm(mut self, shm: &'a ShmManager) -> Self {
        self.shm = Some(shm);
        self
    }

    /// Подключить роутер памяти (builder; живёт пока жив фасад).
    pub fn with_memory(mut self, memory: &'a dyn MemRouter) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Подключить фабрику адресных пространств (v0.9: TASK_CREATE
    /// порождает домен со своим пространством).
    pub fn with_space(mut self, space: &'a dyn crate::mem::SpaceFactory) -> Self {
        self.space = Some(space);
        self
    }

    /// Подключить канал чтения памяти задач (v0.9: спавн-дескриптор).
    pub fn with_copy(mut self, copy: &'a dyn crate::mem::UserCopy) -> Self {
        self.copy = Some(copy);
        self
    }

    /// Подключить IRQ-роутер (builder; привязки внешних линий).
    pub fn with_irq(mut self, irq: &'a IrqRouter) -> Self {
        self.irq = Some(irq);
        self
    }

    /// Реестр хендлеров (регистрация — платформенный код).
    pub fn registry(&self) -> &SyscallRegistry {
        self.registry
    }

    /// Диспетчеризация вызова: номер из нулевого аргумента (конвенция
    /// `current_number`), контекст — из идентификации вызова.
    ///
    /// `thread` — исполняющийся поток (L4): блокирующие операции (IPC,
    /// claim) паркуют его, arch-глюй после хендлера проверяет состояние
    /// и вместо возврата в пользователя переключает контекст; возврат
    /// материализуется из `ThreadObj::syscall_ret` при пробуждении.
    pub fn dispatch(
        &self,
        cpu: CpuId,
        task: TaskId,
        thread: ThreadId,
        args: &SyscallArgs,
    ) -> SyscallRet {
        let mut ctx = SyscallCtx {
            cpu,
            task,
            thread,
            tasks: self.tasks,
            caps: self.caps,
            ipc: self.ipc,
            shm: self.shm,
            memory: self.memory,
            space: self.space,
            copy: self.copy,
            irq: self.irq,
        };
        self.registry.dispatch(&mut ctx, args)
    }

    /// Диспетчеризация с явным номером (arch-глюй передаёт номер отдельно).
    pub fn dispatch_number(
        &self,
        cpu: CpuId,
        task: TaskId,
        thread: ThreadId,
        number: SyscallNumber,
        args: &SyscallArgs,
    ) -> SyscallRet {
        let mut ctx = SyscallCtx {
            cpu,
            task,
            thread,
            tasks: self.tasks,
            caps: self.caps,
            ipc: self.ipc,
            shm: self.shm,
            memory: self.memory,
            space: self.space,
            copy: self.copy,
            irq: self.irq,
        };
        self.registry.dispatch_number(number, &mut ctx, args)
    }

    /// Разрешить хендл задачи (RAII-снимок прав; см. [`HandleGuard`]).
    ///
    /// Чистое чтение cspace вызывающего: хендлы чужих задач неотличимы от
    /// битых (анти-side-channel политика `capability`).
    pub fn resolve_handle(
        &self,
        task: TaskId,
        handle: CapHandle,
    ) -> Result<HandleGuard<'a>, SyscallError> {
        HandleGuard::resolve(self.caps, self.tasks, task, handle)
    }

    /// Породить ТРАНЗИТНУЮ capability (mint) под срок жизни гарда:
    /// дроп гарда отзывает её поддерево автоматически.
    ///
    /// Типовой сценарий: сисколу нужен временный доступ к подресурсу
    /// (сужение badge) — выдаём производную, работаем, отзываем. Утечка
    /// транзитных прав при раннем return исключена RAII.
    pub fn mint_transient(
        &self,
        task: TaskId,
        source: CapHandle,
        spec: &MintSpec,
    ) -> Result<HandleGuard<'a>, SyscallError> {
        HandleGuard::mint_transient(self.caps, self.tasks, task, source, spec)
    }
}

impl fmt::Debug for SyscallFacade<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyscallFacade")
            .field("handlers", &self.registry.len())
            .finish()
    }
}

// ───────────────────────────── Гейт-менеджер (глобальная установка) ─────────────────────────────

/// Якорь установленной платформы сисколов: `&'static dyn SyscallPlatform`
/// в одноразовой статике.
///
/// Платформа регистрируется ОДИН раз на старте (как физический аллокатор —
/// `install_p_allocator`): asm-трамплин и ядро должны сходиться в одном
/// исполнителе входа/выхода. `Send`/`Sync` — как у статического сервиса
/// (сам бекенд обязан быть потокобезопасным на SMP, контракт трейта).
pub struct GateManager(&'static dyn SyscallPlatform);

unsafe impl Send for GateManager {}
unsafe impl Sync for GateManager {}

static SYSCALL_ACC_HOOK: Once<GateManager> = Once::new();

impl GateManager {
    /// Установить платформу (одноразово). Повторные вызовы игнорируют
    /// аргумент и возвращают установленную.
    pub fn install(
        platform: &'static dyn SyscallPlatform,
    ) -> Result<&'static dyn SyscallPlatform, GateError> {
        Ok(SYSCALL_ACC_HOOK.call_once(|| GateManager(platform)).0)
    }

    /// Установленная платформа (`None` — вход в сисколы невозможен:
    /// глюй обязан отказаться до переключения режимов).
    pub fn platform() -> Option<&'static dyn SyscallPlatform> {
        SYSCALL_ACC_HOOK.get().map(|g| g.0)
    }
}

/// FFI-хендл гейта для arch-глюя (asm-трамплин сисколов).
///
/// Возвращает сырой указатель на данные установленной платформы
/// (`null` — платформа не установлена): идентичность для сравнения
/// в глюе, НЕ для разыменования из asm. Контракт: указатель стабилен
/// (платформа — `&'static`), валидность проверяет сам глюй.
#[unsafe(no_mangle)]
pub extern "C" fn obtain_gate_handle() -> *const u8 {
    match GateManager::platform() {
        Some(p) => p as *const dyn SyscallPlatform as *const u8,
        None => core::ptr::null(),
    }
}

// ───────────────────────────── Тесты (host) ─────────────────────────────
//
// Хендлеры — статические с атомарными счётчиками (static требует Sync);
// менеджеры — настоящие (TcbManager/CapabilityManager), моков не нужно:
// фасад и так тонкий.

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use alloc::boxed::Box;

    use crate::task::TaskPriority;

    use super::*;
    /// Детерминированно-уникальный TaskId для тестов: uuid без фичи v4 —
    /// генератора нет, счётчик процесса даёт достаточную уникальность.
    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    /// Подсчёт вызовов + арифметика на аргументах/контексте.
    struct AddHandler {
        calls: AtomicUsize,
        base: usize,
    }

    impl SyscallHandler for AddHandler {
        fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.base + args.arg(0) + ctx.cpu + args.arg(1))
        }
    }

    /// Хендлер, работающий с менеджером задач через ctx (проверка
    /// проброса ссылок).
    struct TaskInfoHandler;

    impl SyscallHandler for TaskInfoHandler {
        fn invoke(&self, ctx: &mut SyscallCtx<'_>, _args: &SyscallArgs) -> SyscallRet {
            // Возвращает приоритет задачи-источника: 0 при её отсутствии.
            Ok(ctx
                .tasks
                .get(&ctx.task)
                .map(|v| v.priority.as_u8() as usize)
                .unwrap_or(0))
        }
    }

    static H_ADD: AddHandler = AddHandler {
        calls: AtomicUsize::new(0),
        base: 100,
    };
    static H_TASKINFO: TaskInfoHandler = TaskInfoHandler;

    fn registry_with_handlers() -> SyscallRegistry {
        let reg = SyscallRegistry::new();
        reg.register(SyscallNumber(0x81), &H_ADD).unwrap();
        reg.register(SyscallNumber(0x82), &H_TASKINFO).unwrap();
        reg
    }

    fn managers() -> (TcbManager, CapabilityManager) {
        (
            TcbManager::new().unwrap(),
            CapabilityManager::new().unwrap(),
        )
    }

    fn arg0(n: u64) -> SyscallArgs {
        // Конвенция current_number: номер — нулевой аргумент.
        SyscallArgs::new([n as usize, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn registry_register_dispatch_unregister() {
        let reg = registry_with_handlers();
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());

        let (tasks, caps) = managers();
        let task = uuid_next();

        let mut ctx = SyscallCtx::core(3, task, &tasks, &caps);

        // Номер 0x81: base=100 + a0(=номер) + cpu + a1. Счётчик хендлера —
        // статический (общий для тестов процесса): проверяем дельту, а не
        // абсолют (порядок тестов не гарантирован).
        let before = H_ADD.calls.load(Ordering::Relaxed);
        let ret = reg.dispatch(&mut ctx, &arg0(0x81)).unwrap();
        assert_eq!(ret, 100 + 0x81 + 3);
        assert_eq!(H_ADD.calls.load(Ordering::Relaxed), before + 1);

        // Номер 0x82: задача не создана — приоритет 0.
        assert_eq!(reg.dispatch(&mut ctx, &arg0(0x82)).unwrap(), 0);

        // Неизвестный номер — ENOSYS, не паника.
        let err = reg.dispatch(&mut ctx, &arg0(999)).unwrap_err();
        assert_eq!(err, SyscallError::NotSupported);
        assert_eq!(err.code(), 38);

        // Явный dispatch_number: тот же хендлер.
        let ret = reg
            .dispatch_number(
                SyscallNumber(0x81),
                &mut ctx,
                &SyscallArgs::new([0x81, 5, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(ret, 100 + 0x81 + 3 + 5);

        // Снятие: номер умирает, повторное снятие — NotFound.
        reg.unregister(SyscallNumber(0x81)).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(
            reg.dispatch_number(SyscallNumber(0x81), &mut ctx, &arg0(0x81)),
            Err(SyscallError::NotSupported)
        );
        assert_eq!(
            reg.unregister(SyscallNumber(0x81)),
            Err(SyscallError::NotFound)
        );

        // Повторная регистрация снятого номера — ок.
        reg.register(SyscallNumber(0x81), &H_ADD).unwrap();
        // Дубликат живого номера — отказ.
        assert_eq!(
            reg.register(SyscallNumber(0x81), &H_ADD),
            Err(SyscallError::AlreadyExists)
        );
    }

    #[test]
    fn flat_table_bounds_and_reregister() {
        let reg = SyscallRegistry::new();
        assert!(reg.is_empty());

        // Границы таблицы: 0 и 255 — валидные слоты, 256 и u64::MAX — нет.
        reg.register(SyscallNumber(0), &H_ADD).unwrap();
        reg.register(SyscallNumber(SYSCALL_TABLE_SIZE as u64 - 1), &H_TASKINFO)
            .unwrap();
        assert_eq!(reg.len(), 2);
        assert_eq!(
            reg.register(SyscallNumber(SYSCALL_TABLE_SIZE as u64), &H_ADD),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            reg.register(SyscallNumber(u64::MAX), &H_ADD),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            reg.unregister(SyscallNumber(u64::MAX)),
            Err(SyscallError::InvalidArgument)
        );

        // reregister: подмена занятого слота платформой — молча ок.
        reg.reregister(SyscallNumber(0), &H_TASKINFO).unwrap();
        let (tasks, caps) = managers();
        let mut ctx = SyscallCtx::core(0, uuid_next(), &tasks, &caps);
        assert_eq!(
            reg.dispatch_number(SyscallNumber(0), &mut ctx, &SyscallArgs::none())
                .unwrap(),
            0
        );
        // ...и запись в пустой слот эквивалентна register.
        reg.reregister(SyscallNumber(0x90), &H_ADD).unwrap();
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn default_table_installs_all_groups() {
        let reg = SyscallRegistry::new();
        reg.install_default_table();
        assert!(!reg.is_empty());

        // Все группы плотной нумерации заняты (последний номер каждой).
        for n in [
            nums::SELF_INFO,
            nums::SYS_TIME,
            nums::TASK_CREATE,
            nums::THREAD_EX_REGS,
            nums::CAP_INFO,
            nums::NOTIFY_SIGNAL,
            nums::IRQ_ACK,
            nums::MEM_INFO,
            nums::SHM_INFO,
            nums::DEBUG_DUMP_THREADS,
        ] {
            assert!(reg.handler(n).is_some(), "слот {n:?} пуст");
        }

        // Легаси-пример TASK_SPAWN (без права) в дефолтную таблицу не входит.
        assert!(reg.handler(nums::TASK_SPAWN).is_none());

        // IOMMU-группа 0x80 занята дефолтной таблицей (v0.6);
        // v0.16: зона планировщика начинается с 0x90 —
        // THREAD_SET_SLICE_NOTIFY ставит слот дефолтной таблицей.
        assert!(reg.handler(SyscallNumber(0x80)).is_some());
        assert!(reg.handler(SyscallNumber(0x84)).is_some());
        assert!(reg.handler(nums::THREAD_SET_SLICE_NOTIFY).is_some());
        assert!(reg.handler(SyscallNumber(0xFE)).is_none());

        // Идемпотентность: повторная установка не меняет счётчик.
        let before = reg.len();
        reg.install_default_table();
        assert_eq!(reg.len(), before);

        // Подмена платформой дефолтного слота + восстановление.
        reg.reregister(nums::SYS_TIME, &H_ADD).unwrap();
        assert_eq!(
            reg.handler(nums::SYS_TIME)
                .map(|h| h as *const dyn SyscallHandler),
            Some(&H_ADD as &dyn SyscallHandler as *const dyn SyscallHandler)
        );
        reg.install_default_table();
        assert_eq!(reg.len(), before);
    }

    #[test]
    fn facade_dispatch_and_ctx_plumbing() {
        let reg = registry_with_handlers();
        let (tasks, caps) = managers();
        let facade = SyscallFacade::new(&tasks, &caps, &reg);

        let task = uuid_next();
        tasks.create(task, TaskPriority(77)).unwrap();

        // Хендлер читает менеджер задач через ctx фасада.
        let ret = facade.dispatch(0, task, task, &arg0(0x82)).unwrap();
        assert_eq!(ret, 77, "приоритет задачи доехал через ctx");

        // dispatch_number фасада.
        let ret = facade
            .dispatch_number(
                0,
                task,
                task,
                SyscallNumber(0x81),
                &SyscallArgs::new([0x81, 4, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(ret, 100 + 0x81 + 4);

        // Неизвестный номер.
        assert_eq!(
            facade.dispatch_number(0, task, task, SyscallNumber(42), &SyscallArgs::none()),
            Err(SyscallError::NotSupported)
        );
    }

    #[test]
    fn gate_state_per_cpu() {
        let mut gate: SyscallGate<256, 2> = SyscallGate::new();
        assert_eq!(gate.cpu_count(), 2);
        assert_eq!(gate.stack_size(), 256);

        // Позиции возврата: запись/чтение по CPU, изоляция слотов.
        let pos = EnterPosition::new(0xDEAD_BEEF, 0x1000);
        gate.set_enter_position(1, pos).unwrap();
        assert_eq!(gate.enter_position(1), Ok(Some(pos)));
        assert_eq!(gate.enter_position(0), Ok(None));
        assert_eq!(pos.ip(), 0xDEAD_BEEF);
        assert_eq!(pos.sp(), 0x1000);

        // Пользовательское пространство CPU: корень + пара тегов.
        let user = UserSpace::tagged(
            PhysADDR(0x1_0000),
            AsidPair::new(
                crate::hal::traits::asid::AddressSpaceId(1),
                crate::hal::traits::asid::AddressSpaceId(2),
            ),
        );
        gate.set_user_space(1, user).unwrap();
        assert_eq!(gate.user_space(1), Ok(user));
        assert_eq!(gate.user_space(0), Ok(UserSpace::default()));
        assert_eq!(user.root, Some(PhysADDR(0x1_0000)));
        assert_eq!(user.asid.map(|p| p.user().as_u16()), Some(1));

        // Вершина стека: конец массива, выровнен на размер (массив inline).
        let top = gate.stack_top(0).unwrap();
        let base = gate.cpus[0].stack().as_ptr() as usize;
        assert_eq!(top - base, 256);

        // Вне границ — детерминированный отказ.
        assert_eq!(
            gate.set_enter_position(2, pos),
            Err(GateError::InvalidCpu(2))
        );
        assert_eq!(gate.enter_position(2), Err(GateError::InvalidCpu(2)));
        assert_eq!(gate.stack_top(9), Err(GateError::InvalidCpu(9)));
    }

    #[test]
    fn platform_install_is_one_shot() {
        struct EchoPlatform {
            cpu: usize,
        }

        impl SyscallPlatform for EchoPlatform {
            fn cpu_count(&self) -> usize {
                self.cpu
            }

            fn enter(&self, cpu: CpuId, _stack: usize) -> Result<(), SyscallError> {
                if cpu < self.cpu {
                    Ok(())
                } else {
                    Err(SyscallError::InvalidArgument)
                }
            }

            fn exit(
                &self,
                cpu: CpuId,
                _ep: EnterPosition,
                _user: UserSpace,
            ) -> Result<(), SyscallError> {
                if cpu < self.cpu {
                    Ok(())
                } else {
                    Err(SyscallError::InvalidArgument)
                }
            }
        }

        // Установка один раз на процесс тестов: если другой тест уже
        // установил платформу — принимаем её (call_once идемпотентен).
        let p: &'static EchoPlatform = Box::leak(Box::new(EchoPlatform { cpu: 4 }));
        let installed = GateManager::install(p).unwrap();
        assert_eq!(installed.cpu_count(), 4);

        // Повторная установка игнорируется: возвращается та же.
        let again = GateManager::install(p).unwrap();
        assert_eq!(
            again as *const dyn SyscallPlatform,
            installed as *const dyn SyscallPlatform
        );
        assert!(GateManager::platform().is_some());

        // FFI-хендл: ненулевой указатель на данные платформы.
        let handle = obtain_gate_handle();
        assert!(!handle.is_null());

        // Контракт бекенда: валидация cpu.
        assert!(installed.enter(3, 0x1000).is_ok());
        assert!(installed.enter(4, 0x1000).is_err());
        assert!(
            installed
                .exit(0, EnterPosition::new(0, 0), UserSpace::default())
                .is_ok()
        );
    }
}
