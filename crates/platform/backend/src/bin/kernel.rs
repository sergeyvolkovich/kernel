// ==== kernel: бинарный образ ядра x86_64 ====
//
// head.S (таблицы: high-half + physmap + identity-транзит) -> kmain:
// платформенная инициализация -> арх-НЕЗАВИСИМАЯ startup::kinit.
// Вся политика запуска — в крейте startup; здесь только железо.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use backend::X86Platform;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Форматированные паники (assert!/expect!) не дают as_str() — пишем
    // Display целиком (message + location) в консоль.
    use core::fmt::Write;
    backend::console::init_console();
    let mut c = backend::console::ComConsole::COM1;
    let _ = write!(c, "\r\n[kernel] PANIC: {}\r\n", info);
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}

/// Платформа (статика: startup::kinit требует 'static).
static PLATFORM: X86Platform = X86Platform;

/// Вход из head.S: RDI = физический адрес BootInfo.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(bootinfo_phys: u64) -> ! {
    // 1. Консоль (первое, что делает ядро: вся отладка через serial).
    backend::console::init_console();
    backend::console::kprint_str("\r\n=== rust-l4 kernel v0.6 (x86_64, SMP + VT-d) ===\r\n");

    // 2. FPU/SSE (fxsave/fxrstor контекста + таблиц): CR0.EM=0, TS=0,
    //    CR4.OSFXSR|OSXMMEXCPT.
    backend::cpu::fpu_enable();

    // 3. Снапшот ядерного корня (CR3 = таблицы head.S) ДО любого
    //    activate пользовательского пространства.
    let root = backend::memory::init_kernel_root();
    backend::console::kprint_str("kmain: kernel root CR3 ok\r\n");
    let _ = root;

    // 4. BootInfo (physmap head.S покрывает 4 GiB): cmdline читаем ДО
    //    политики Meltdown — явное «meltdown=allow» из boot_cfg.xml
    //    (единственный законный источник) снимает отказ для эмуляторов:
    //    QEMU/TCG не эмулирует ни RDCL_NO, ни саму спекулятивную
    //    утечку (данных физически нет), а без KPTI в v0.5 загрузка на
    //    уязвимом РЕАЛЬНОМ железе обязана останавливаться.
    let bi: &boot_info::BootInfo =
        unsafe { &*backend::memory::phys_ptr::<boot_info::BootInfo>(bootinfo_phys) };
    let meltdown_allow = bi.cmdline_str().split(' ').any(|t| t == "meltdown=allow");

    // Meltdown-класс: без RDCL_NO полная загрузка (MapFullKernel на
    // уязвимом CPU, без KPTI-implementation) — отказ (кроме явного
    // meltdown=allow: эмуляторы).
    let rdcl_no = backend::cpu::has_rdcl_no();
    if !rdcl_no && !meltdown_allow {
        backend::gate::kpanic(
            "kmain: CPU lacks RDCL_NO (Meltdown-class); KPTI is not implemented in v0.5 (boot_state/cmdline meltdown=allow — только для эмуляторов)",
        );
    }
    if !rdcl_no {
        // Согласие принято: политика изоляции обязана стать MapFullKernel
        // (conservative без KPTI = пустая верхняя половина пользовательских
        // таблиц = гарантированный triple fault на первом входе в user).
        backend::platform::set_meltdown_allow();
        backend::console::kprint_str(
            "kmain: WARNING: RDCL_NO not reported; meltdown=allow assumed (emulator?)\r\n",
        );
    }

    // 5. GDT/TSS/per-CPU/syscall-MSR + IDT + LAPIC-таймер.
    backend::cpu::bsp_init();
    backend::cpu::install_idt();
    if let Err(e) = backend::lapic::init() {
        backend::gate::kpanic(e);
    }
    if let Err(e) = backend::lapic::start_timer() {
        backend::gate::kpanic(e);
    }
    // v0.13: режим таймера — диагностика точности квот (TSC-deadline
    // взводится при CPUID-фиче; QEMU/TCG её вырезает — периодический
    // фолбэк, заряд циклами и TSC-граница периода работают в обоих).
    if backend::lapic::using_tsc_deadline() {
        backend::console::kprint_str("kmain: timer mode: tsc-deadline (sub-tick quotas)\r\n");
    } else {
        backend::console::kprint_str(
            "kmain: timer mode: periodic fallback (tsc-deadline not exposed)\r\n",
        );
    }
    backend::console::kprint_str("kmain: cpu+lapic+timer up\r\n");

    // 5.5 SMP: топология MADT + SIPI-запуск AP (ДО kinit — без кучи;
    // APы доходят до парковки и ждут release в platform::run).
    backend::smp::bring_up(bi);

    // 6. Арх-независимая последовательность запуска (BootInfo уже
    //    прочитан в шаге 4).
    x86_64::instructions::interrupts::enable();
    startup::kinit(bi, &PLATFORM)
}
