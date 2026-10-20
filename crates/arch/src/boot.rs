// ==== Константы загрузочного ABI (заглушка <-> ядро <-> AP) ====
//
// Фиксированные физические адреса протокола запуска. Числа — часть
// ABI нашей связки: заглушка грузит ядро на KERNEL_PHYS_BASE, ядро
// кладёт SIPI-трамплин на AP_TRAMPOLINE_PHYS и общается с AP через
// почтовый ящик в хвосте страницы трамплина. Менять можно только
// согласовав все стороны (stub/kernel/trampoline-asm) — это НЕ
// свободные константы.

/// Минимальный физический адрес размещения образа ядра.
///
/// v0.5.2 (boot-фикс): размещение ядра ДИНАМИЧЕСКОЕ — заглушка ищет
/// 2 MiB-выровненное свободное окно в [KERNEL_PHYS_BASE .. 4 GiB)
/// (физика 16 MiB занята декомпрессированным DXE-том OVMF), head.S
/// вычисляет поправку link-phys на входе. Фактическая база —
/// BootInfo.kernel.phys_base; число здесь — только НИЖНЯЯ граница
/// (выше VGA/legacy-дыр и низких BIOS-областей).
///
/// Ядро исполняется по ВИРТУАЛЬНЫМ адресам верхней половины
/// (KERNEL_LINK_BASE); вход head.S исполняется identity по физике
/// (прошивочные таблицы заглушки), строит свои таблицы и прыгает.
pub const KERNEL_PHYS_BASE: u64 = 0x0100_0000;

/// Линк-адрес ядра (high-half, -2 GiB зона): .text/.rodata/.data
/// линкуются сюда; head.S строит отображение KERNEL_LINK_BASE ->
/// фактическая физика образа (динамическое размещение) и прыгает
/// из identity в high-half.
///
/// v0.5.1 (boot-фикс): 0xFFFF_FFFF_8100_0000 = -2GiB + 16MiB — так
/// KERNEL_LINK_OFFSET остаётся ровно -2 GiB, а ОБЕ стороны пары
/// (линк-адрес и минимальная физика 16MiB) выровнены на 2 MiB: head.S
/// мапит образ ядра большими страницами. Прежнее значение
/// 0xFFFF_FFFF_8010_0000 ломало 2MiB-выравнивание (смещение 1MiB).
pub const KERNEL_LINK_BASE: u64 = 0xFFFF_FFFF_8100_0000;

/// Смещение линка: virt = KERNEL_LINK_BASE + (phys - KERNEL_PHYS_BASE).
pub const KERNEL_LINK_OFFSET: u64 = KERNEL_LINK_BASE - KERNEL_PHYS_BASE;

/// Direct map (physmap): вся физическая память верхней половиной,
/// supervisor RW NX; 2 MiB-страницами. Строится статикой head.S на
/// первые 4 GiB (4 PD-таблицы в bss) — RAM больше 4 GiB в v0.5 не
/// поддерживается (ограничение задокументировано, расширение — v0.6).
pub const PHYSMAP_BASE: u64 = 0xFFFF_8000_0000_0000;
/// Покрытие physmap из head.S.
pub const PHYSMAP_COVERAGE: u64 = 4 * 1024 * 1024 * 1024;

/// База виртуального диапазона пользовательских фасадов (allocation_base
/// при create_ufacade): 16 TiB — вне legacy-дыр нижних 4 GiB, внутри
/// нижней (пользовательской) половины каноничного пространства.
pub const USER_ALLOC_BASE: u64 = 0x0000_1000_0000_0000;

// ───────────────────── SIPI-трамплин AP ─────────────────────

/// Физический адрес 16-битного кода трамплина AP (SIPI стартует сюда).
///
/// 0x8000 (32 KiB): ниже 1 MiB (real mode SIPI), выше EBDA (~0x9FC00)
/// и ядра; страница не конфликтует с boot_info (заглушка размещает
/// его в свободной памяти выше).
pub const AP_TRAMPOLINE_PHYS: u64 = 0x8000;

/// Вектор SIPI = PHYS >> 12 (байт в сообщении INIT-SIPI-SIPI).
pub const AP_SIPI_VECTOR: u32 = (AP_TRAMPOLINE_PHYS >> 12) as u32;

/// Почтовый ящик трамплина: страница 0x8000, хвост 0x8F00+ (код
/// трамплина укладывается в первые сотни байт; хвост — протокол).
/// Поля: BSP пишет до SIPI, AP читает после включения long mode;
/// AP_MAGIC пишет AP, BSP поллит её как «CPU на связи».
pub mod ap_mailbox {
    /// Дескриптор lgdt (u16 limit + u64 base) для входа AP в long mode.
    pub const GDT_DESC: u64 = 0x8F00;
    /// Точка входа long mode (u64): AP прыгает сюда с включённым
    /// пейджингом и настроенным GS.
    pub const LONG_ENTRY: u64 = 0x8F10;
    /// Физический адрес per-CPU блока ЭТОГО AP (u64): AP кладёт в GS.
    pub const PERCPU: u64 = 0x8F18;
    /// Вершина стека AP (u64).
    pub const STACK: u64 = 0x8F20;
    /// AP пишет сюда AP_MAGIC_OK попав в long mode (u32); BSP поллит.
    pub const MAGIC: u64 = 0x8F28;
    /// Значение готовности AP.
    pub const MAGIC_OK: u32 = 0xC0FF_EE01;
    /// Физический адрес корня таблиц страниц (PML4 head.S) для включения
    /// пейджинга AP (u64; v0.6 — дописано в конец протокола).
    pub const CR3: u64 = 0x8F30;
}

/// Геометрия трамплина внутри страницы 0x8000 (VMA-независимые смещения;
/// фиксируются линкер-скриптом: смещение стадии = её физический адрес
/// минус 0x8000).
pub mod trampoline {
    /// 16-битная стадия (real mode, вход SIPI).
    pub const OFF_STAGE16: u64 = 0x000;
    /// 32-битная стадия (protected, PAE, включение long mode).
    pub const OFF_STAGE32: u64 = 0x100;
    /// 64-битная стадия (long mode: селекторы, стек, GS, MAGIC, прыжок).
    pub const OFF_STAGE64: u64 = 0x200;
    /// Мини-GDT трамплина: null / code32 / data32 / code64 (4 x 8 байт).
    pub const OFF_GDT: u64 = 0x800;
    /// Псевдодескриптор lgdt (u16 limit + u32 base + pad) — читается
    /// 16-битным lgdt до включения PE.
    pub const OFF_GDT_DESC: u64 = 0xF00;
    /// Конец протокольного хвоста (почтовый ящик 0x8F00+).
    pub const OFF_MAILBOX: u64 = 0xF00;
}

/// Стек AP: 16 KiB (4 страницы) — вход в ядро + запуск до переключения
/// на ядровый стек потока.
pub const AP_STACK_PAGES: usize = 4;

// ───────────────────── MSR ─────────────────────

/// IA32_GS_BASE: база сегмента GS (per-CPU блоки).
pub const MSR_IA32_GS_BASE: u32 = 0xC000_0101;
/// IA32_APIC_BASE: база локального APIC (backend включает xAPIC).
pub const MSR_IA32_APIC_BASE: u32 = 0x0000_001B;
/// IA32_EFER: расширенные флаги (LME/LMA/NXE/SCE).
pub const MSR_IA32_EFER: u32 = 0xC000_0080;
/// IA32_STAR: селекторы входа syscall/sysret.
pub const MSR_IA32_STAR: u32 = 0xC000_0081;
/// IA32_LSTAR: RIP входа syscall.
pub const MSR_IA32_LSTAR: u32 = 0xC000_0082;
/// IA32_FMASK: маска RFLAGS для syscall.
pub const MSR_IA32_FMASK: u32 = 0xC000_0084;

// ───────────────────── Разное ─────────────────────

/// Локальный APIC (xAPIC, MMIO): дефолтная физическая база QEMU/PC.
/// Точная база читается из MSR_IA32_APIC_BASE (биты 12+) и MADT —
/// константа здесь только как ожидаемое значение для sanity-чека.
pub const LAPIC_DEFAULT_PHYS: u64 = 0xFEE0_0000;

/// IOAPIC (QEMU q35): дефолтная база (MADT даёт точную).
pub const IOAPIC_DEFAULT_PHYS: u64 = 0xFEC0_0000;

/// PIT (8254): канал 0 data — для калибровки TSC (backend).
pub const PIT_CH0_DATA: u16 = 0x40;
/// PIT: командный порт (BCD/binary, режим 2).
pub const PIT_MODE_CMD: u16 = 0x43;
/// Частота PIT: 1193182 Гц (кварц PC).
pub const PIT_FREQUENCY_HZ: u64 = 1_193_182;

// ───────────────────── Векторы прерываний (IDT/LAPIC) ─────────────────────

/// LAPIC-таймер (периодический тик планировщика).
pub const VEC_TIMER: u8 = 0x20;
/// IPI: запрос перепланировки (resched; целевой CPU ставит флаг
/// NEED_RESCHED в своём per-CPU блоке — обработчик чистый asm).
pub const VEC_IPI_RESCHED: u8 = 0x21;
/// IPI: TLB shootdown (целевой CPU инвалидирует локальный TLB и ACK'ает
/// бит в глобальном pending-битмапе; обработчик без BKL).
pub const VEC_IPI_SHOOTDOWN: u8 = 0x22;
/// IPI: останов CPU (паника ядра: все CPU замораживаются cli+hlt).
pub const VEC_IPI_HALT: u8 = 0x23;
/// Spurious-прерывание LAPIC (без EOI; вектор из SVR).
pub const VEC_SPURIOUS: u8 = 0xFF;
/// Частота тика планировщика, Гц (10 мс квант).
pub const SCHED_HZ: u64 = 100;

/// RFLAGS по умолчанию для первого входа в пользователя: IF=1, бит 1.
pub const USER_RFLAGS: u64 = 0x202;
