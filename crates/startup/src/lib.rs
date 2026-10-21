// ==== STARTUP: арх-НЕЗАВИСИМАЯ последовательность запуска ядра ====
//
// Этот крейт — ЧИСТАЯ ПОЛИТИКА порядка инициализации. В нём нет ни одного
// машинного адреса, регистра или ISA-примитива: всё железо скрыто за двумя
// контрактами, которые реализует платформенный крейт (x86_64: `backend`):
//
//   * [`Platform`] — арх-поверхность: консоль, источник времени,
//     планировщик, изоляция Meltdown, фабрика адресных пространств
//     (`MMAPInterface + KMAPInterface`), direct-map физики, ABI старта
//     пользователя (стек/argv) и диспетчеризация (`run`);
//   * [`KernelGlue`] — интеграционная плоскость «арх-гейт <-> ядро»:
//     диспетчеризация сисколов, активация пространств, смерть/фолты
//     потоков. Реализация `Glue<MMAP>` живёт здесь же (моно-морфизация
//     над GCTL), арх-гейт бекенда зовёт её через глобальную установку.
//
// Последовательность [`kinit`] (порядок — единственная собственность
// этого крейта):
//
//   BootInfo.validate -> физические пулы (2 x LLFree: ядро/пользователь,
//   AllocAll + избирательное освобождение Available) -> куча (talc) ->
//   slab-пул -> GCTL -> DebugSink/TimeSource/планировщик -> KMAP
//   (изоляция + регионы ядра) -> ELF загрузка init (xmas-elf, map_fixed)
//   -> стек + argv -> задача/поток init -> стартовый IPC (argc/argv +
//   boot_state транзитом) -> platform.run() (диспетчеризация, навсегда).
#![no_std]

extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};

use boot_info::BootInfo;
use pkg_generic_interface::GCTL;
use pkg_generic_interface::hal::traits::asid::{ASIDInterface, AddressSpaceMode, FlushMode};
use pkg_generic_interface::hal::traits::kmap::{IsolationPolicy, KMAPInterface, KernelRegion};
use pkg_generic_interface::hal::traits::mmap::{MMAPInterface, MemErrorCode, VirtualADDR};
use pkg_generic_interface::syscall::debug::DebugSink;
use pkg_generic_interface::syscall::system::TimeSource;
use pkg_generic_interface::syscall::types::{SyscallArgs, SyscallRet};
use pkg_generic_interface::syscall::{self};
use pkg_generic_interface::task::scheduler::SchedulerInterface;
use pkg_generic_interface::task::{CpuId, TaskId, TaskPriority, TaskState, TcbManager, ThreadId};

pub mod elfload;
pub mod pools;

pub use pools::Pools;

// ───────────────────────────── Лог ─────────────────────────────

/// Строка в раннюю консоль (до/после установки DebugSink — единый путь:
/// платформа всегда умеет писать; DebugSink сискола DEBUG_WRITE ставится
/// на тот же приёмник).
pub fn log(platform: &impl Platform, s: &str) {
    platform.console_write(s);
}

/// Лог с переводом строки.
pub fn logln(platform: &impl Platform, s: &str) {
    platform.console_write(s);
    platform.console_write("\r\n");
}

// ───────────────────────────── Platform ─────────────────────────────

/// Архитектурная поверхность ядра: ВСЁ железо startup видит только через
/// этот контракт. Перенос ядра на другую ISA = реализация Platform (+ head
/// + гейт), политика [`kinit`] не меняется.
///
/// Методы делятся на три группы:
///  * сервисы (консоль/время/планировщик/debug sink) — глобальные,
///    устанавливаются в kinit;
///  * память (фабрика MMAP, direct-map, изоляция, регионы ядра в KMAP);
///  * запуск пользователя (стек/argv/окно фасада, `run`).
pub trait Platform: Sync {
    /// Тип адресного пространства пользователя бекенда.
    type Mmap: MMAPInterface + KMAPInterface + ASIDInterface + 'static;

    /// Легаси-шина платформы (v0.11): фиксированные устройства, которые
    /// не обходит PCI/ACPI-перечислитель (x86_64: ISA — COM1/PIT).
    /// kinit регистриует её в реестре устройств и выдаёт init'у
    /// DeviceReference на всё найденное — root-сервер устройств.
    /// None — у платформы нет легаси-устройств.
    fn legacy_bus(
        &self,
    ) -> Option<&'static dyn pkg_generic_interface::hal::device::traits::BusEnumerator> {
        None
    }

    /// Ранняя консоль (побайтово; до установки DebugSink).
    fn console_write(&self, s: &str);

    /// Приёмник DEBUG_WRITE (устанавливается в kinit; None — без отладки).
    fn debug_sink(&self) -> Option<&'static dyn DebugSink>;

    /// Источник монотонного времени (SYS_TIME; None — ENOSYS).
    fn time_source(&self) -> Option<&'static dyn TimeSource>;

    /// Планировщик-бекенд (SchedulerInterface + block-очереди IPC/claims).
    fn scheduler(&self) -> &'static dyn SchedulerInterface;

    /// Политика изоляции Meltdown/Spectre для фасадов (см. KMap).
    fn isolation_policy(&self) -> IsolationPolicy;

    /// Регионы ядра для переноса в пользовательские таблицы (KMAP).
    fn kernel_regions(&self) -> Vec<KernelRegion>;

    /// Новое адресное пространство пользователя (PML4/TTBR + контракты).
    fn make_mmap(&self) -> Result<Self::Mmap, MemErrorCode>;

    /// Direct-map чтение физики (образы модулей, BootInfo).
    ///
    /// # Safety-контракт
    /// `phys..phys+len` — валидная физическая память на время жизни
    /// платформы (образы модулей живут до конца загрузки сессии).
    fn phys_slice(&self, phys: u64, len: usize) -> &[u8];

    /// Виртуальная база direct-map (physmap): указатели ядерной кучи =
    /// физика + эта база (см. gallocator::init_frames). Куча обязана
    /// жить в диапазоне, переносимом в пользовательские таблицы.
    fn physmap_base(&self) -> u64;

    /// Direct-map запись в физику (кадры пользователя при загрузке ELF).
    ///
    /// # Safety-контракт
    /// Кадры принадлежат вызывающему (выделены из пула пользователя).
    fn phys_slice_mut(&self, phys: u64, len: usize) -> &mut [u8];

    /// База фасадного окна аллокаций (x86_64: USER_ALLOC_BASE = 16 TiB).
    fn user_alloc_base(&self) -> VirtualADDR;

    /// Размер фасадного окна в страницах (MEM_ALLOC и sисколы памяти).
    fn user_window_pages(&self) -> usize;

    /// Вершина стека первого потока (ABI платформы пользователя).
    fn user_stack_top(&self) -> u64;

    /// Стек первого потока, страницы.
    fn user_stack_pages(&self) -> usize;

    /// Число CPU (v0.5: 1; SMP-расширение — будущие итерации).
    fn cpu_count(&self) -> usize {
        1
    }

    /// Диспетчеризация: войти в первый пользовательский контекст и больше
    /// никогда не вернуться (idle-цикл планировщика — внутри).
    fn run(&self) -> !;
}

// ───────────────────────────── KernelGlue ─────────────────────────────

/// Интеграционная плоскость «арх-гейт <-> ядро» (реализуется здесь,
/// моно-морфизацией над GCTL; см. [`Glue`]).
///
/// Арх-гейт бекенда (syscall entry / timer tick / fault) вызывает эти
/// методы на границе режимов. Всё, что можно выразить контрактами ядра,
/// выражается здесь — бекенду остаются только регистры и таблицы.
pub trait KernelGlue: Send + Sync {
    /// Диспетчеризация сискола (полный фасад GCTL + память).
    /// Возврат — машинное слово ABI (`syscall_ret_to_raw`).
    fn dispatch(
        &self,
        cpu: CpuId,
        task: TaskId,
        thread: ThreadId,
        number: u64,
        args: &SyscallArgs,
    ) -> isize;

    /// Поток заблокирован? (гейт после диспетчера решает: возврат или
    /// переключение контекста).
    fn thread_blocked(&self, thread: ThreadId) -> bool;

    /// Поток мёртв? (TASK_EXIT/каскад: гейт переключается, не возвращаясь).
    fn thread_dead(&self, thread: ThreadId) -> bool;

    /// (entry, stack_top) потока — первый контекст при диспетчеризации.
    fn thread_start_info(&self, thread: ThreadId) -> Option<(usize, usize)>;

    /// Домен-владелец потока (per-CPU зеркало текущей задачи).
    fn thread_owner(&self, thread: ThreadId) -> Option<TaskId>;

    /// Перевести поток в Running (диспетчеризация; без хука в ядре —
    /// состояние ставит гейт после переключения).
    fn mark_running(&self, thread: ThreadId);

    /// Забрать материализованный возврат заблокированного сискола
    /// (ядро пишет его при пробуждении; None — возврата нет).
    fn take_syscall_ret(&self, thread: ThreadId) -> Option<usize>;

    /// Активировать адресное пространство владельца потока (CR3/TTBR
    /// через контракт фасада; false — пространства нет, гейт гасит поток).
    fn activate_space_of(&self, thread: ThreadId) -> bool;

    /// Поток завершён (Dead): погасить TCB, разрушить домен, если он
    /// опустел (гейт вызывает ПЕРЕД переключением на следующего).
    fn reap_thread(&self, thread: ThreadId);

    /// Пользовательский фолт (страничка/GP/...): диагностика + смерть
    /// домена (v0.5: без pager-протокола; расширение — L4 fault-IPC).
    fn user_fault(&self, thread: ThreadId, vector: u8, code: u64, addr: u64, rip: u64);

    /// Всего живых потоков (idle-цикл: 0 — «все ушли», платформа может
    /// остановить машину или ждать прерываний).
    fn live_thread_count(&self) -> usize;

    /// v0.10, CPU-квоты: поток `thread` уступил CPU, потребив `ticks`
    /// тиков (вытеснение/уступка — гейт планировщика под BKL). Ядро
    /// заряжает их домену-владельцу; возврат `true` — домен за
    /// пределом `cpu_quota`: гейт обязан запарковать поток (троттлинг)
    /// до границы периода вместо возврата в очередь готовности.
    ///
    /// Дефолт — `false` (учёт не поддержан): бекенды без квот продолжают
    /// работать как раньше.
    fn on_timeslice_consumed(&self, _thread: ThreadId, _ticks: usize) -> bool {
        false
    }

    /// v0.10, CPU-квоты: граница периода — сбросить учёт потребления всех
    /// доменов (вызывает бекенд планировщика под BKL; потоки из
    /// троттл-листа в готовность возвращает сам бекенд).
    fn on_cpu_period(&self) {}

    /// v0.11, внешние линии: событие на линии GSI (IOAPIC; бекенд — из
    /// обработчика прерываний под BKL). Ядро доставляет его драйверу —
    /// signal-слово в endpoint привязки (IrqRouter). Возврат `true` —
    /// событие учтено (линия привязана), `false` — линии нет (spurious).
    ///
    /// Дефолт — `false` (платформа без внешних линий работает как
    /// раньше: IRQ_ATTACH не возводит линию).
    fn on_external_irq(&self, _gsi: u32) -> bool {
        false
    }
}

static GLUE: spin::Once<&'static dyn KernelGlue> = spin::Once::new();

// ───────────────────── v0.9: сервисы над GCTL+платформой ─────────────────────

/// Фабрика адресных пространств над платформой (SpaceFactory):
/// TASK_CREATE/TASK_SPAWN_IMAGE рождает домен со своим UMAP;
/// смерть домена — destroy_space (кадры owned-записей возвращаются
/// пулу, external-окна остаются источнику).
struct PlatformSpaces<P: Platform + 'static> {
    platform: &'static P,
    gctl: &'static GCTL<P::Mmap>,
}

impl<P: Platform + 'static> pkg_generic_interface::mem::SpaceFactory for PlatformSpaces<P> {
    fn create_space(&self, task: TaskId) -> Result<(), MemErrorCode> {
        // Геометрию рантайм-пространств kinit уже настроил
        // (configure_runtime_spaces) — фабрика только строит MMAP-бекенд
        // и отдаёт его менеджеру.
        let mmap = self
            .platform
            .make_mmap()
            .map_err(|_| MemErrorCode::InternalError)?;
        self.gctl.memory_manager().create_task_space(task, mmap)
    }

    fn destroy_space(&self, task: TaskId) -> Result<(), MemErrorCode> {
        self.gctl.memory_manager().destroy_task_space(&task)
    }
}

/// Чтение памяти задачи из ядра (UserCopy): физика региона через
/// MemRouter + direct-map платформы. Спавн-дескриптор и будущие
/// copyin-протоколы (серверы конфигурации) читаются так, без
/// промотирования страниц ядра.
impl<P: Platform + 'static> pkg_generic_interface::mem::UserCopy for PlatformSpaces<P> {
    fn read_task_bytes(
        &self,
        task: TaskId,
        vaddr: usize,
        out: &mut [u8],
    ) -> Result<(), MemErrorCode> {
        let router = self.gctl.leak_mem_router();
        let (v_base, p_base, pages) = router
            .region_at(task, VirtualADDR(vaddr))
            .ok_or(MemErrorCode::NotFound)?;
        let off = vaddr - v_base.0;
        let len = out.len();
        if off + len > pages * 4096 {
            return Err(MemErrorCode::InvalidArgument(
                "user window exceeds its region",
            ));
        }
        let src = self.platform.phys_slice(p_base.0 as u64 + off as u64, len);
        out.copy_from_slice(src);
        Ok(())
    }
}

/// Установить glue (одноразово; вызывается kinit перед platform.run()).
pub fn install_glue(glue: &'static dyn KernelGlue) {
    GLUE.call_once(|| glue);
}

/// Установленный glue (арх-гейт бекенда; None — до kinit: гейт обязан
/// отказаться от диспетчеризации).
pub fn glue() -> Option<&'static dyn KernelGlue> {
    GLUE.get().copied()
}

// ───────────────────────────── Glue<MMAP> ─────────────────────────────

/// Реализация [`KernelGlue`] над GCTL (моно-морфизация в kinit).
struct Glue<MMAP: MMAPInterface + 'static> {
    gctl: &'static GCTL<MMAP>,
    router: &'static dyn pkg_generic_interface::mem::MemRouter,
    /// Фабрика адресных пространств + чтение памяти задач (v0.9).
    space: &'static dyn pkg_generic_interface::mem::SpaceFactory,
    copy: &'static dyn pkg_generic_interface::mem::UserCopy,
}

// SAFETY (дисциплина v0.5, как APXCTL в ядре): однопроцессорная загрузка.
// Все входы в ядро сериализованы: syscall исполняется с IF=0 (FMASK
// гасит IF), таймер приходит только в user-режиме; значит все вызовы Glue
// — строго последовательны, RefCell-контракт ядра не нарушается. SMP
// потребует big-kernel-lock на входах (OFF_DEPTH) — задокументировано.
unsafe impl<MMAP: MMAPInterface + ASIDInterface + 'static> Send for Glue<MMAP> {}
unsafe impl<MMAP: MMAPInterface + ASIDInterface + 'static> Sync for Glue<MMAP> {}

impl<MMAP: MMAPInterface + ASIDInterface + 'static> Glue<MMAP> {
    /// Доступ к фасаду задачи init-загрузки (или любой другой) — обёртка
    /// над `with_facade` с единым переводом ошибок.
    #[allow(clippy::type_complexity)]
    fn facade_op<R>(
        &self,
        task: &TaskId,
        f: impl FnOnce(
            &mut pkg_generic_interface::mem::UFacade<MMAP, pkg_generic_interface::mem::ARCPool>,
        ) -> R,
    ) -> Option<R> {
        self.gctl.memory_manager().with_facade(task, f)
    }
}

impl<MMAP: MMAPInterface + KMAPInterface + ASIDInterface + 'static> KernelGlue for Glue<MMAP> {
    fn dispatch(
        &self,
        cpu: CpuId,
        task: TaskId,
        thread: ThreadId,
        number: u64,
        args: &SyscallArgs,
    ) -> isize {
        let facade = self
            .gctl
            .syscall_facade()
            .with_memory(self.router)
            .with_space(self.space)
            .with_copy(self.copy);
        let ret: SyscallRet =
            facade.dispatch_number(cpu, task, thread, syscall::SyscallNumber(number), args);
        pkg_generic_interface::syscall::types::syscall_ret_to_raw(ret)
    }

    fn thread_blocked(&self, thread: ThreadId) -> bool {
        self.gctl
            .task_manager()
            .thread_view(&thread)
            .is_some_and(|v| v.state == TaskState::Blocked)
    }

    fn thread_dead(&self, thread: ThreadId) -> bool {
        self.gctl
            .task_manager()
            .thread_view(&thread)
            .map(|v| v.state == TaskState::Dead)
            .unwrap_or(true) // нет потока — считать мёртвым (защита гейта)
    }

    fn thread_start_info(&self, thread: ThreadId) -> Option<(usize, usize)> {
        self.gctl.task_manager().thread_start_info(&thread)
    }

    fn thread_owner(&self, thread: ThreadId) -> Option<TaskId> {
        self.gctl.task_manager().thread_task(&thread)
    }

    fn mark_running(&self, thread: ThreadId) {
        // Ready→Running; ошибки (например, Dead-каскад в полёте) не
        // фатальны — гейт всё равно уходит в этот контекст.
        let _ = self
            .gctl
            .task_manager()
            .thread_set_state(&thread, TaskState::Running);
    }

    fn take_syscall_ret(&self, thread: ThreadId) -> Option<usize> {
        self.gctl.task_manager().take_thread_syscall_ret(&thread)
    }

    fn activate_space_of(&self, thread: ThreadId) -> bool {
        let tasks = self.gctl.task_manager();
        let Some(owner) = tasks.thread_task(&thread) else {
            return false;
        };
        self.gctl
            .memory_manager()
            .with_facade(&owner, |f| {
                f.activate(AddressSpaceMode::User, FlushMode::FlushAll)
            })
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    fn reap_thread(&self, thread: ThreadId) {
        let tasks = self.gctl.task_manager();
        let owner = tasks.thread_task(&thread);
        // TCB потока гасим первым (поток уже Dead).
        let _ = tasks.destroy_thread(thread);
        let Some(owner) = owner else { return };
        // Домен опустел и мёртв — снести TCB задачи (только Dead-потоки).
        let task_dead = tasks
            .get(&owner)
            .is_some_and(|v| v.state == TaskState::Dead);
        let live = tasks
            .threads_of(&owner)
            .into_iter()
            .filter(|t| t.state != TaskState::Dead)
            .count();
        if task_dead && live == 0 {
            // v0.9: полный контракт смерти домена —
            //   1. cspace домена: отозвать все его capability;
            //   2. SHM-регионы домена: кадры в пул (владелец мёртв);
            //   3. TCB (теперь пустой) — разрушить;
            //   4. адресное пространство — unbind + дроп фасада
            //      (owned-кадры в пул, external-окна остаются источникам).
            // Порядок — контракт «revoke_all → destroy» менеджеров;
            // отказы шагов не фатальны (idempotent-хвост).
            let _ = self.gctl.capability_manager().revoke_all(tasks, owner);
            for id in self.gctl.shm_manager().regions_of(&owner) {
                let _ = self.gctl.shm_manager().destroy(id);
            }
            let _ = tasks.destroy(owner);
            let _ = self.space.destroy_space(owner);
            if let Some(sink) = syscall::debug::debug_sink() {
                sink.write(b"\r\n[kernel] task reaped: cspace revoked, space dropped\r\n");
            }
        }
    }

    fn user_fault(&self, thread: ThreadId, vector: u8, code: u64, addr: u64, rip: u64) {
        let tasks = self.gctl.task_manager();
        let owner = tasks.thread_task(&thread);
        if let Some(s) = syscall::debug::debug_sink() {
            use alloc::fmt::Write;
            let mut line = String::new();
            let _ = write!(
                line,
                "\r\n[kernel] user fault: vec={:#x} code={:#x} addr={:#x} rip={:#x} thread={} — killing task\r\n",
                vector, code, addr, rip, thread
            );
            s.write(line.as_bytes());
        }
        // v0.5: смерть домена (каскад гасит потоки). Pager-протокол L4
        // (фолт как IPC потоку-владельцу страницы) — расширение.
        if let Some(owner) = owner {
            let _ = tasks.set_state(&owner, TaskState::Dead);
            for t in tasks.threads_of(&owner) {
                if t.state != TaskState::Dead {
                    let _ = tasks.thread_set_state(&t.thread_id, TaskState::Dead);
                }
                let _ = tasks.destroy_thread(t.thread_id);
            }
            let _ = tasks.destroy(owner);
        }
    }

    fn live_thread_count(&self) -> usize {
        self.gctl.task_manager().total_thread_count()
    }

    fn on_timeslice_consumed(&self, thread: ThreadId, ticks: usize) -> bool {
        let tasks = self.gctl.task_manager();
        let Some(owner) = tasks.thread_task(&thread) else {
            return false;
        };
        // Аудит «cpu quota: ... throttled» печатает сам менеджер при
        // первом входе домена за предел квоты.
        tasks.charge_cpu(&owner, ticks).unwrap_or(false)
    }

    fn on_cpu_period(&self) {
        self.gctl.task_manager().on_cpu_period();
    }

    /// v0.11: событие внешней линии (IOAPIC) — IrqRouter кладёт
    /// signal-слово (= gsi) в endpoint привязки. ok(true) — линия
    /// привязана; Ok(false) — spurious (событий больше не будет);
    /// Err — роутер в непригодном состоянии (аудит драйвера бекенда).
    fn on_external_irq(&self, gsi: u32) -> bool {
        let router = self.gctl.irq_router();
        matches!(
            router.irq_event(
                self.gctl.task_manager(),
                self.gctl.capability_manager(),
                self.gctl.ipc_manager(),
                gsi
            ),
            Ok(true)
        )
    }
}

// ───────────────────────────── Идентификаторы init ─────────────────────────────

/// Задача-домен init-сервера (детерминизм для отладки; генератор UUID
/// в no_std — лишняя сущность, а стартовые ID — часть ABI отладки).
pub const INIT_TASK_ID: u128 = 0x0000_0000_0000_1000;
/// Главный поток init.
pub const INIT_THREAD_ID: u128 = 0x0000_0000_0000_1001;

fn task_id(v: u128) -> TaskId {
    uuid::Uuid::from_u128(v)
}

// ───────────────────────────── kinit ─────────────────────────────

/// Стартовая последовательность ядра. Не возвращается: последний шаг —
/// `platform.run()` (диспетчеризация первого потока / idle).
///
/// Любой фатальный отказ печатается в консоль и останавливает машину
/// (v0.5: паника загрузки честнее, чем «продолжим как-нибудь»).
pub fn kinit<P: Platform + 'static>(bi: &BootInfo, platform: &'static P) -> ! {
    logln(platform, "kinit: startup sequence v0.5");

    // 1. Протокол загрузки.
    if let Err(e) = bi.validate() {
        // До всего: только консоль платформы.
        let msg = concat_paths("kinit: FATAL boot_info protocol: ", e, "\r\n");
        platform.console_write(&msg);
        platform.run() // консоль есть — уходим в idle с сообщением
    }

    // 2. Отладочная консоль ядра (DEBUG_WRITE сискола).
    if let Some(sink) = platform.debug_sink() {
        syscall::debug::install_debug_sink(sink);
    }

    // 4. Куча ядра + slab-пул подсистем (physmap-виртуальные указатели:
    //    валидны и под пользовательским CR3 — см. Platform::physmap_base).
    let mut pools = pools::build(bi, platform);
    pkg_generic_interface::mem::gallocator::init_frames(
        pools.take_kernel(),
        pools.kernel_base as usize,
        platform.physmap_base() as usize,
    );
    pkg_generic_interface::mem::gallocator::init_slab_pool(4096);
    let p_alloc = pkg_generic_interface::mem::install_p_allocator(pools.take_user());
    logln(platform, "kinit: pools up (kernel + user), heap ready");

    // 5. GCTL (корневой фасад, навсегда).
    let gctl: &'static mut GCTL<P::Mmap> = match GCTL::new(p_alloc.clone()) {
        Ok(g) => Box::leak(Box::new(g)),
        Err(e) => fatal(platform, &alloc::format!("kinit: FATAL GCTL: {e}\r\n")),
    };

    // 6. Сервисы платформы: время + планировщик.
    if let Some(ts) = platform.time_source() {
        syscall::system::install_time_source(ts);
    }
    gctl.task_manager().install_scheduler(platform.scheduler());

    // 7. KMAP: изоляция + регионы ядра в пользовательских таблицах.
    let mut kmap = pkg_generic_interface::mem::kmap::KMap::new(platform.isolation_policy());
    for region in platform.kernel_regions() {
        if let Err(e) = kmap.add(region) {
            fatal(
                platform,
                &alloc::format!("kinit: FATAL kmap region: {e:?}\r\n"),
            );
        }
    }
    gctl.memory_manager_mut().install_kmap(kmap);

    // 8. init-сервер: задача + адресное пространство.
    let init_task = task_id(INIT_TASK_ID);
    let init_thread = task_id(INIT_THREAD_ID);
    if let Err(e) = gctl.task_manager().create(init_task, TaskPriority(120)) {
        fatal(platform, &alloc::format!("kinit: FATAL init task: {e}\r\n"));
    }

    // 8.1 Право творца (v0.6): init получает TaskTCB на САМОГО себя —
    // THREAD_CREATE для SMP-стресса и TASK_CREATE для порождения служб.
    // L4-модель: право выдаётся явным грантом ядра, init находит хендл
    // через CAP_LIST (kind = 2).
    //
    // 8.2 Мастер-грант IOMMU (v0.9): группа сисколов 0x80 гейтована
    // capability IommuAdmin — init (менеджер устройств) получает его
    // здесь; порождённые песочницы его НЕ получают и не передают.
    {
        use pkg_generic_interface::capability::{
            ActionPermissions, CapabilityBadge, CapabilityGate, ContainerACCCapability,
        };
        let creator_gate = CapabilityGate::new(
            ContainerACCCapability::TaskTCB { task_id: init_task },
            ActionPermissions::all(),
            CapabilityBadge::FULL,
        );
        if let Err(e) =
            gctl.capability_manager()
                .grant(gctl.task_manager(), init_task, creator_gate)
        {
            fatal(
                platform,
                &alloc::format!("kinit: FATAL init TaskTCB grant: {e:?}\r\n"),
            );
        }
        let iommu_gate = CapabilityGate::new(
            ContainerACCCapability::IommuAdmin,
            ActionPermissions::all(),
            CapabilityBadge::FULL,
        );
        if let Err(e) = gctl
            .capability_manager()
            .grant(gctl.task_manager(), init_task, iommu_gate)
        {
            fatal(
                platform,
                &alloc::format!("kinit: FATAL init IommuAdmin grant: {e:?}\r\n"),
            );
        }

        // 8.3 Легаси-шина платформы (v0.11): фиксированные устройства
        // (x86_64: ISA COM1/PIT) — реестр + DeviceReference init'у на
        // каждое живое: init — root-сервер устройств (claim/IRQ/
        // IOMMU-гейты у него уже есть; порождённые песочницы грантов НЕ
        // получают — права не протекают вниз по дереву задач).
        if let Some(bus) = platform.legacy_bus() {
            if let Err(e) = gctl.device_manager_mut().register_bus(bus) {
                fatal(
                    platform,
                    &alloc::format!("kinit: FATAL legacy bus register: {e:?}\r\n"),
                );
            }
            match gctl.device_manager_mut().enumerate() {
                Ok(report) => {
                    let dm = gctl.device_manager();
                    let mut granted = 0usize;
                    for rec in dm.records().iter() {
                        if !rec.functional || dm.get_alive(&rec.path).is_none() {
                            continue;
                        }
                        let _ = dm.export_capability(
                            gctl.task_manager(),
                            gctl.capability_manager(),
                            init_task,
                            &rec.path,
                            ActionPermissions::all(),
                            CapabilityBadge::FULL,
                        );
                        granted += 1;
                    }
                    log(
                        platform,
                        &alloc::format!(
                            "kinit: legacy bus \"{}\": {} discovered, {} granted to init\r\n",
                            bus.bus_name(),
                            report.discovered,
                            granted
                        ),
                    );
                }
                Err(e) => {
                    // Шина опциональна: отказ перечисления — НЕ фатален
                    // (устройств не будет, демо честно пропустится).
                    log(
                        platform,
                        &alloc::format!("kinit: legacy bus enumerate failed: {e:?}\r\n"),
                    );
                }
            }
        }
    }

    let facade = match gctl.memory_manager_mut().create_ufacade(
        match platform.make_mmap() {
            Ok(m) => m,
            Err(e) => fatal(
                platform,
                &alloc::format!("kinit: FATAL address space: {e:?}\r\n"),
            ),
        },
        platform.user_window_pages(),
        platform.cpu_count(),
        platform.user_alloc_base(),
    ) {
        Ok(f) => f,
        Err(e) => fatal(platform, &alloc::format!("kinit: FATAL ufacade: {e:?}\r\n")),
    };
    // Фасад живёт вечно: leak владеющего бокса (привязка — по стабильному
    // адресу slab-слота).
    let facade: &'static pkg_generic_interface::mem::FacadeBox<
        P::Mmap,
        pkg_generic_interface::mem::ARCPool,
    > = Box::leak(Box::new(facade));
    gctl.memory_manager().bind_facade(init_task, facade);
    // Настройка с мутабельным доступом закончена: замораживаем GCTL в
    // разделяемую ссылку на остаток жизни системы.
    let gctl: &'static GCTL<P::Mmap> = gctl;

    // 9. ELF + стек + argv + стартовый IPC.
    let module = match bi.init_module() {
        Some(m) => m,
        None => fatal(platform, "kinit: FATAL no init module in boot_info\r\n"),
    };
    let blob = platform.phys_slice(module.base, module.len as usize);
    // boot_state — транзитом в argv (протокол старта: ядро НЕ интерпретирует).
    let state: Vec<(String, String)> = bi
        .state_vars()
        .iter()
        .map(|v| (String::from(v.name_str()), String::from(v.value_str())))
        .collect();
    let loaded = match elfload::load(
        platform,
        gctl,
        init_task,
        facade,
        blob,
        module.name_str(),
        &p_alloc,
        &state,
    ) {
        Ok(l) => l,
        Err(e) => fatal(platform, &alloc::format!("kinit: FATAL ELF load: {e}\r\n")),
    };

    if let Err(e) = gctl.task_manager().create_thread(
        init_thread,
        init_task,
        TaskPriority(120),
        loaded.entry,
        platform.user_stack_top() as usize,
    ) {
        fatal(
            platform,
            &alloc::format!("kinit: FATAL init thread: {e}\r\n"),
        );
    }

    // Стартовый IPC (L4): argc/argv + boot_state транзитом. Сообщение
    // паркуется в очередь потока (init ещё не в open-receive).
    let msg = Box::new(pkg_generic_interface::ipc::IpcMessage::start_args(
        pkg_generic_interface::ipc::IPC_KERNEL_FROM,
        loaded.argc as u64,
        loaded.argv_vaddr as u64,
        loaded.argv_bytes as u64,
    ));
    if let Err(e) = gctl.ipc_manager().send_thread(
        gctl.task_manager(),
        None,
        pkg_generic_interface::ipc::IPC_KERNEL_FROM,
        init_thread,
        msg,
    ) {
        fatal(platform, &alloc::format!("kinit: FATAL start-IPC: {e}\r\n"));
    }

    // 10. Glue (арх-гейт <-> ядро) и диспетчеризация.
    //
    // v0.9: фабрика адресных пространств — над GCTL + платформой
    // (геометрия окна/стек — политика Platform). Leaked на век системы:
    // Glue раздаёт её syscall-фасаду (TASK_CREATE рождает домен СО
    // пространством) и убирает пространства мёртвых доменов в reap.
    gctl.memory_manager().configure_runtime_spaces(
        platform.user_window_pages(),
        platform.cpu_count(),
        platform.user_alloc_base(),
    );
    let space_factory: &'static PlatformSpaces<P> =
        Box::leak(Box::new(PlatformSpaces { platform, gctl }));
    install_glue(Box::leak(Box::new(Glue {
        gctl,
        router: gctl.leak_mem_router(),
        space: space_factory,
        copy: space_factory,
    })));

    logln(platform, "kinit: handing off to dispatcher");
    platform.run()
}

// ───────────────────────────── Мелочи ─────────────────────────────

/// Фаталь: напечатать и уйти в платформенный idle (машина жива — serial
/// доступен для осмотра; v0.5 без panic-обработчика в no_std).
fn fatal(platform: &impl Platform, msg: &str) -> ! {
    platform.console_write(msg);
    platform.run()
}

/// Склейка трёх &str без fmt::Arguments-аллокаций в ранних фазах
/// (консоль платформы доступна до кучи).
fn concat_paths(a: &str, b: &str, c: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len());
    s.push_str(a);
    s.push_str(b);
    s.push_str(c);
    s
}
