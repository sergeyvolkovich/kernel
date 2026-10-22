// ==== X86Platform: реализация startup::Platform на x86_64 ====
//
// Вся арх-специфика загрузки в одном месте: консоль/время/планировщик —
// модули бекенда; регионы ядра для KMAP — из линк-символов образа
// (head.S/kernel.ld); изоляция — RDCL_NO-проверка (raw-cpuid); стек и
// окно пользователя — константы ABI из arch::boot.

use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use kernel_hal::traits::kmap::{IsolationPolicy, KernelRegion};
use kernel_hal::traits::mmap::{MMAPMemoryFlags, MemErrorCode, VirtualADDR};
use pkg_generic_interface::syscall::debug::DebugSink;
use pkg_generic_interface::syscall::system::TimeSource;

use arch::boot;

use crate::console;
use crate::lapic;
use crate::memory::UserTables;
use crate::sched;

/// Размер окна фасада: 1 GiB (MEM_ALLOC-сисколы пользователя).
const USER_WINDOW_PAGES: usize = (1 << 30) / 4096;
/// Стек init: 16 страниц (64 KiB).
const USER_STACK_PAGES: usize = 16;
/// Вершина стека: на 16 MiB ниже базы фасадного окна (не пересекается).
pub const USER_STACK_TOP: u64 = boot::USER_ALLOC_BASE - (16 << 20);

// Линк-символы образа ядра (kernel.ld): границы образа.
unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// Явное «meltdown=allow» из командной строки (boot_cfg.xml → cmdline
/// ядра): принял риск — получай единственную возможную в v0.5 политику
/// (MapFullKernel; KPTI не реализован — conservative ГАРАНТИРОВАННО
/// уронит ядро на первом переключении в пользователя: верхняя половина
/// пользовательских таблиц пуста).
static MELTDOWN_ALLOW: AtomicBool = AtomicBool::new(false);

/// Зафиксировать согласие на загрузку без RDCL_NO (вызывает kmain
/// при meltdown=allow — до kinit/изоляции).
pub fn set_meltdown_allow() {
    MELTDOWN_ALLOW.store(true, Ordering::Release);
}

/// Платформа x86_64 (BSP, v0.5).
pub struct X86Platform;

impl X86Platform {
    /// Размер образа ядра, байт.
    fn kernel_image_len() -> u64 {
        // SAFETY: линк-символы валидны всегда.
        unsafe { (&raw const __kernel_end) as u64 - (&raw const __kernel_start) as u64 }
    }

    /// Политика изоляции по CPUID: RDCL_NO (Meltdown закрыт) — полное
    /// supervisor-only ядро; иначе — консервативная изоляция (KPTI-класс
    /// не реализован в v0.5 → честный отказ загрузки, см. kmain).
    /// meltdown=allow (эмуляторы) — MapFullKernel: без RDCL_NO эмулятор
    /// не имеет и самой спекулятивной утечки, а альтернатив нет.
    fn probe_isolation() -> IsolationPolicy {
        let p = if crate::cpu::has_rdcl_no() || MELTDOWN_ALLOW.load(Ordering::Acquire) {
            IsolationPolicy::MapFullKernel
        } else {
            IsolationPolicy::conservative()
        };
        crate::kprintln!(
            "platform: isolation policy = {} (rdcl_no={}, allow={})",
            if matches!(p, IsolationPolicy::MapFullKernel) {
                "MapFullKernel"
            } else {
                "conservative"
            },
            crate::cpu::has_rdcl_no(),
            MELTDOWN_ALLOW.load(Ordering::Acquire)
        );
        p
    }
}

impl startup::Platform for X86Platform {
    type Mmap = UserTables;

    fn console_write(&self, s: &str) {
        console::kprint_str(s);
    }

    fn debug_sink(&self) -> Option<&'static dyn DebugSink> {
        Some(&console::CONSOLE_SINK)
    }

    fn time_source(&self) -> Option<&'static dyn TimeSource> {
        Some(&lapic::TIME_SOURCE)
    }

    fn scheduler(&self) -> &'static dyn pkg_generic_interface::task::SchedulerInterface {
        sched::scheduler()
    }

    fn isolation_policy(&self) -> IsolationPolicy {
        Self::probe_isolation()
    }

    fn kernel_regions(&self) -> Vec<KernelRegion> {
        // Ядро в пользовательских таблицах: high-half образ, supervisor RWX
        // (флаги уже в ядерных PML4-записях — копируем их как есть).
        let pages = (Self::kernel_image_len() as usize + 4095) / 4096;
        let mut regions = vec![
            KernelRegion::kernel(
                "kernel-image",
                VirtualADDR(boot::KERNEL_LINK_BASE as usize),
                pages,
                MMAPMemoryFlags::RW, // фактические права — в копируемых записях
            )
            .expect("kernel region geometry is valid by construction"),
        ];

        // Physmap (PML4[256], 4 GiB): ОБЯЗАТЕЛЕН в пользовательских
        // таблицах — ядро трогает phys_ptr (таблицы страниц, MMIO LAPIC,
        // кадры пользователя) и при АКТИВНОМ пользовательском CR3
        // (переключение контекста, сисколы фасада памяти). Supervisor-only
        // по построению ядерных записей. Без него — #PF в ядре.
        regions.push(
            KernelRegion::kernel(
                "physmap",
                VirtualADDR(boot::PHYSMAP_BASE as usize),
                (boot::PHYSMAP_COVERAGE as usize) / 4096,
                MMAPMemoryFlags::RW,
            )
            .expect("physmap region geometry is valid by construction"),
        );
        regions
    }

    fn make_mmap(&self) -> Result<UserTables, MemErrorCode> {
        UserTables::new()
    }

    fn phys_slice(&self, phys: u64, len: usize) -> &[u8] {
        // SAFETY: контракт вызова — валидная физика на время жизни образа.
        unsafe { core::slice::from_raw_parts(crate::memory::phys_ptr::<u8>(phys), len) }
    }

    fn physmap_base(&self) -> u64 {
        boot::PHYSMAP_BASE
    }

    fn phys_slice_mut(&self, phys: u64, len: usize) -> &mut [u8] {
        // SAFETY: контракт вызова — кадры принадлежат вызывающему.
        unsafe { core::slice::from_raw_parts_mut(crate::memory::phys_ptr::<u8>(phys), len) }
    }

    fn user_alloc_base(&self) -> VirtualADDR {
        VirtualADDR(boot::USER_ALLOC_BASE as usize)
    }

    fn user_window_pages(&self) -> usize {
        USER_WINDOW_PAGES
    }

    fn user_stack_top(&self) -> u64 {
        USER_STACK_TOP
    }

    fn user_stack_pages(&self) -> usize {
        USER_STACK_PAGES
    }

    fn cpu_count(&self) -> usize {
        crate::smp::cpu_count() // v0.6: топология MADT (BSP + поднятые AP)
    }

    fn run(&self) -> ! {
        // SMP v0.12: IF-хуки спин-локов ядра (sync.rs) — ДО любого
        // параллельного исполнения (release_aps/диспетчеризация).
        // GS:DEPTH — бывший BKL-счётчик, теперь глубина локов.
        pkg_generic_interface::sync::install_hooks(pkg_generic_interface::sync::SpinHooks {
            wait: spin_hooks_wait,
            wake: spin_hooks_wake,
            depth_inc: spin_hooks_depth_inc,
            depth_dec: spin_hooks_depth_dec,
            depth: spin_hooks_depth,
        });
        // kinit завершён (пулы/куча/GCTL/glue) — но fatal-пути тоже
        // попадают сюда ДО готовности: VT-d ставится только при живом
        // пуле кадров, APы отпускаются только при живом glue.
        if pkg_generic_interface::mem::gallocator::frames().is_some() {
            // Число CPU — в SELF_INFO (слово 5).
            pkg_generic_interface::syscall::system::install_cpu_count(crate::smp::cpu_count());
            // IOMMU (Intel VT-d / AMD-Vi): DMAR/IVRS -> драйверы + сервис
            // сисколов (агрегатор). До release_aps — конкуренции нет.
            crate::iommu::init_and_install();
            // IOAPIC (v0.11): MADT-топология -> контроллер + сервис
            // внешних линий (IRQ_ATTACH возводит линии). После IOMMU —
            // IRTE-ремаппинг линий видит включённый IR.
            crate::ioapic::init();
            // I/O-порты (v0.14): медитированный сервис IOP_IN/IOP_OUT
            // (исполнение in/out в ядре за IoResource(IoPort)-cap;
            // прямой доступ из юзерспейса не существует: IOPL=0).
            pkg_generic_interface::syscall::io::install_io_port_service(&crate::ioport::X86_PORTS);
        }
        if let Some(glue) = startup::glue() {
            // v0.13: единица CPU-времени — циклов TSC на тик (квоты
            // субтик-точны; TSC откалиброван в start_timer до kinit).
            // ДО release_aps: дальше значение неизменно, читается без
            // локов на горячем пути заряда.
            glue.set_cpu_time_unit(crate::lapic::tsc_per_tick());
            // v0.16: базовый слайс EEVDF (тот же источник калибровки,
            // до release_aps и до первого enqueue — сущности рождаются
            // с правильной виртуальной шкалой).
            crate::sched::set_base_slice(
                crate::lapic::tsc_per_tick().saturating_mul(arch::boot::SCHED_HZ / 10),
            );
            // APы из парковки в планировщик (resched-IPI будит hlt).
            crate::smp::release_aps();
        }
        // Первый вход BSP в диспетчеризацию — без BKL (v0.12):
        // schedule_next синхронизирован своими структурами (MPMC +
        // KSpin + валидация состояний), APы стартуют симметрично
        // (см. smp::ap_entry64).
        sched::schedule_next()
    }
}

// ───────────────────── IF-хуки спин-локов (SMP v0.12) ─────────────────────

/// Спин на «глубине 0» — с прерываниями: доставляются IPI (в частности
/// shootdown-ACK держателю KMEM — единственного лока с cross-CPU
/// ожиданием; см. sync.rs). Глубина читается ДО захвата (инкремент —
/// после), так что здесь она ещё «прежняя».
fn spin_hooks_wait() {
    if arch::percpu::depth() == 0 {
        unsafe { x86_64::instructions::interrupts::enable() };
    }
}

/// Захватили после спина: вернуть IF=0, если ждали на глубине 0
/// (дисциплина «держатель лока всегда IF=0»).
fn spin_hooks_wake() {
    if arch::percpu::depth() == 0 {
        x86_64::instructions::interrupts::disable();
    }
}

fn spin_hooks_depth_inc() {
    arch::percpu::set_depth(arch::percpu::depth() + 1);
}

fn spin_hooks_depth_dec() {
    let d = arch::percpu::depth();
    debug_assert!(d > 0, "sync: depth_dec без захвата (протокол)");
    arch::percpu::set_depth(d - 1);
}

fn spin_hooks_depth() -> u32 {
    arch::percpu::depth() as u32
}
