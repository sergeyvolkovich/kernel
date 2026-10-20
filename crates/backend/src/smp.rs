// ==== SMP: топология (MADT) + SIPI-запуск AP + IPI-механика ====
//
// Полноценный SMP v0.6. Модель синхронизации — big kernel lock (klock.rs):
// пользователь исполняется на всех CPU параллельно, входы в ядро
// сериализованы; планировщик — глобальная очередь готовности + per-CPU
// текущий поток/квант/флаг перепланировки (GS-блок).
//
// Последовательность запуска AP:
//
//   BSP (kmain, до kinit — без кучи!):
//     1. smp::bring_up(bi): MADT -> топология; копия трамплина на
//        0x8000; почтовый ящик (LONG_ENTRY/PERCPU/STACK/CR3);
//        INIT-SIPI-SIPI каждому AP; поллинг MAGIC_OK (TSC-таймаут).
//     2. AP исполняет трамплин: real -> protected -> long mode
//        (таблицы BSP: identity 0..4GiB + physmap + high-half),
//        ставит GS/стек, пишет MAGIC_OK, прыгает в ap_entry64.
//     3. ap_entry64 (Rust, IF=0): per-CPU GDT/TSS/IDT/MSR/FPU,
//        LAPIC (SIVR+ID), mark_online, ap_park (sti+hlt до RELEASED).
//     4. BSP продолжает kinit (пулы/куча/GCTL/glue/init).
//     5. X86Platform::run(): release_aps (RELEASED=true + resched-IPI)
//        — APы просыпаются, включают LAPIC-таймер (частота BSP),
//        уходят в диспетчеризацию (idle на пустой очереди).
//
// Трамплин — position-fixed блоб: смещения стадий внутри страницы 0x8000
// зафиксированы (kernel.ld: .trampoline), дальние прыжки — абсолютные
// константы (0x8100/0x8200), данные — только почтовый ящик по фикс.
// физике. Блоб собирается с high-half VMA и КОПИРУЕТСЯ на 0x8000: все
// внутренние переходы обязаны быть относительными либо вычисленными
// через фиксированные адреса — абсолютных линк-зависимых ссылок нет.
//
// MADT-парсер — slice-based (физика читается через physmap на цели и
// напрямую в host-тестах): RSDP -> XSDT|RSDT -> таблицы по сигнатуре.

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use arch::boot;
use arch::percpu;

use crate::memory::phys_ptr;

/// Отладочный маркер: один байт прямо в COM1 (мимо блокировок/кучи —
/// работает на любой стадии и в панике). Убирается после стабилизации.
#[inline]
pub(crate) fn mark(b: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") b,
            options(nomem, nostack, preserves_flags)
        );
    }
}

// ───────────────────── Топология ─────────────────────

/// Максимум CPU (статические массивы per-CPU данных: 32 x (блок 4K +
/// GDT/TSS ~2K) + 31 стек по 16K ≈ 900 KiB .bss — сознательная цена
/// простоты; QEMU -smp до 32).
pub const MAX_CPUS: usize = 32;

/// Запись о CPU из MADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuEntry {
    /// ACPI processor id (соответствует uid в namespace; не лапик).
    pub processor_id: u8,
    /// LAPIC id (аппаратная идентичность для IPI).
    pub lapic_id: u8,
    /// Флаг Enabled (MADT Local APIC flags bit 0).
    pub enabled: bool,
    /// Флаг Online Capable (MADT rev 5+ bit 1: выключен, но включаем).
    pub online_capable: bool,
}

/// Топология системы (статика — bring_up до кучи).
///
/// Слоты НЕ уплотняются: cpu_id = индекс слота = индекс всех per-CPU
/// массивов (блоки/стеки/GDT/TSS) и битов ONLINE. Дыра (таймаут AP)
/// остаётся дырой навсегда — обмен местами сломал бы соответствие
/// «cpu_id ↔ физические массивы» у уже запущенных CPU.
pub struct Topology {
    /// CPU[0] = BSP (lapic_id сверяется с MSR/LAPIC на bring-up).
    pub cpus: [Option<CpuEntry>; MAX_CPUS],
    /// Число занятых слотов (без дыр между ними — дыры не считаются).
    pub present: usize,
    /// Слоты (1 + максимум запущенных AP; для обхода по индексам).
    pub slots: usize,
    /// Физический адрес контроллера LAPIC из MADT (sanity к MSR).
    pub lapic_phys: u64,
    /// Физический адрес RSDP (сохраняем для VT-d: поиск DMAR в run()).
    pub rsdp_phys: u64,
}

impl Topology {
    const fn new() -> Self {
        Self {
            cpus: [None; MAX_CPUS],
            present: 1,
            slots: 1,
            lapic_phys: 0,
            rsdp_phys: 0,
        }
    }
}

/// Топология (заполняется bring_up; до bring_up — BSP, single).
pub static mut TOPOLOGY: Topology = Topology::new();

/// Ссылка на топологию (single-writer: bring_up на BSP до AP).
pub fn topology() -> &'static Topology {
    // SAFETY: топология пишется один раз на BSP до старта AP; дальше
    // только чтения всеми CPU.
    unsafe { &*(&raw const TOPOLOGY) }
}

/// Число присутствующих CPU (минимум 1).
#[inline]
pub fn cpu_count() -> usize {
    topology().present.max(1)
}

/// LAPIC id логического CPU (или 0).
pub fn lapic_id_of(cpu: usize) -> u8 {
    topology()
        .cpus
        .get(cpu)
        .and_then(|c| c.map(|c| c.lapic_id))
        .unwrap_or(0)
}

/// Битмап CPU, дошедших до планировщика (mark_online).
static ONLINE: AtomicU64 = AtomicU64::new(1); // BSP онлайн по построению

/// Число онлайн CPU.
pub fn online_count() -> u32 {
    ONLINE.load(Ordering::Relaxed).count_ones()
}

/// Битмап онлайн CPU.
pub fn online_mask() -> u64 {
    ONLINE.load(Ordering::Relaxed)
}

/// Флаг: APы отпущены в планировщик (release_aps; до этого — park).
static RELEASED: AtomicBool = AtomicBool::new(false);

// ───────────────────── ACPI: RSDP -> XSDT/RSDT -> таблица ─────────────────────

/// Ошибка ACPI-обхода.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// Не RSDP (сигнатура/чексумма).
    BadRsdp,
    /// Таблица не найдена.
    NotFound,
    /// Таблица меньше собственного заголовка / кривые длины.
    Truncated,
    /// Неподдерживаемая ревизия структуры.
    UnsupportedRevision,
}

/// Заголовок ACPI-таблицы: сигнатура + длина (первые 8 байт формата).
fn table_len(hdr: &[u8]) -> Result<usize, AcpiError> {
    if hdr.len() < 8 {
        return Err(AcpiError::Truncated);
    }
    let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if len < 36 {
        return Err(AcpiError::Truncated);
    }
    Ok(len)
}

/// Найти в RSDP таблицу по сигнатуре. Возврат: (физический адрес, длина).
///
/// Читатель-независимый: `read` замыкает доступ к физике (цель —
/// physmap-читалка по 8 байт; тесты — срез в памяти).
pub fn find_table<F>(rsdp_phys: u64, sig: &[u8; 4], read: F) -> Result<(u64, usize), AcpiError>
where
    F: Fn(u64, usize) -> [u8; 8],
{
    // RSDP: сигнатура 8 байт "RSD PTR ", ревизия @9, RSDT @16, XSDT @24.
    let magic = read(rsdp_phys + 0, 8);
    if &magic != b"RSD PTR " {
        return Err(AcpiError::BadRsdp);
    }
    let rev = read(rsdp_phys + 9, 1)[0];
    let xsdt = u64::from_le_bytes(read(rsdp_phys + 24, 8));
    let r4 = read(rsdp_phys + 16, 4);
    let rsdt = u32::from_le_bytes([r4[0], r4[1], r4[2], r4[3]]) as u64;

    let (root, wide) = if rev >= 2 && xsdt != 0 {
        (xsdt, true)
    } else if rsdt != 0 {
        (rsdt, false)
    } else {
        return Err(AcpiError::UnsupportedRevision);
    };

    let hdr = read(root, 8);
    let len = table_len(&hdr)?;
    let entries = (len - 36) / if wide { 8 } else { 4 };
    for i in 0..entries {
        let off = 36 + i * if wide { 8 } else { 4 };
        let p = if wide {
            u64::from_le_bytes(read(root + off as u64, 8))
        } else {
            let r4 = read(root + off as u64, 4);
            u32::from_le_bytes([r4[0], r4[1], r4[2], r4[3]]) as u64
        };
        let h = read(p, 8);
        if &h[0..4] == &sig[..] {
            let l = table_len(&h)?;
            return Ok((p, l));
        }
    }
    Err(AcpiError::NotFound)
}

/// Список CPU из MADT (без кучи: фиксированный массив).
pub struct CpuList {
    pub cpus: [Option<CpuEntry>; MAX_CPUS],
    pub count: usize,
    pub lapic_phys: u64,
}

impl CpuList {
    fn new() -> Self {
        Self {
            cpus: [None; MAX_CPUS],
            count: 0,
            lapic_phys: 0,
        }
    }
}

/// Разобрать MADT в `CpuList` (slice-based, host-тестируемый).
pub fn madt_cpus(madt: &[u8]) -> Result<CpuList, AcpiError> {
    if madt.len() < 44 {
        return Err(AcpiError::Truncated);
    }
    if &madt[0..4] != b"APIC" {
        return Err(AcpiError::NotFound);
    }
    let len = table_len(&madt[0..8])?;
    if madt.len() < len {
        return Err(AcpiError::Truncated);
    }
    let mut out = CpuList::new();
    out.lapic_phys = u32::from_le_bytes([madt[36], madt[37], madt[38], madt[39]]) as u64;
    let mut off = 44;
    while off + 2 <= len {
        let etype = madt[off];
        let elen = madt[off + 1] as usize;
        if elen < 2 || off + elen > len {
            return Err(AcpiError::Truncated);
        }
        // Тип 0 = Processor Local APIC: [type][len][proc_id][apic_id][flags u32].
        if etype == 0 && elen >= 8 && out.count < MAX_CPUS {
            let flags =
                u32::from_le_bytes([madt[off + 4], madt[off + 5], madt[off + 6], madt[off + 7]]);
            let e = CpuEntry {
                processor_id: madt[off + 2],
                lapic_id: madt[off + 3],
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
            };
            // Дубликаты (перечисление с разными флагами) — берём первый.
            if !out.cpus[..out.count]
                .iter()
                .any(|c| c.is_some_and(|c| c.lapic_id == e.lapic_id))
            {
                out.cpus[out.count] = Some(e);
                out.count += 1;
            }
        }
        off += elen;
    }
    Ok(out)
}

// ───────────────────── Трамплин (position-fixed блоб) ─────────────────────

// Секции .tramp16/.tramp32/.tramp64/.trampgdt собираются линкером в
// страницу с фикс. смещениями (kernel.ld: OFF_STAGE16/32/64, GDT@0x800,
// псевдодескриптор@0xF00). Абсолютные дальние прыжки — константы физики.
global_asm!(
    ".intel_syntax noprefix",
    // ==== Стадия 1: real mode, вход SIPI (физика 0x8000) ====
    ".section .tramp16, \"a\"",
    ".code16",
    "tramp16_start:",
    "    cli",
    "    cld",
    "    mov al, 0x61",
    "    mov dx, 0x3f8",
    "    out dx, al",
    "    xor ax, ax",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    mov sp, 0x7000", // скретч-стек ниже трамплина
    // GDT трамплина: псевдодескриптор @0x8F00 (limit u16 + base u32);
    // 16-битный lgdt читает 6 байт — база 0x8800 влезает в 24 бита.
    "    lgdt [0x8F00]",
    "    mov al, 0x62",
    "    mov dx, 0x3f8",
    "    out dx, al",
    // PE (пейджинг выключен, identity = линейный = физический).
    "    mov eax, cr0",
    "    or eax, 1",
    "    mov cr0, eax",
    "    mov al, 0x63",
    "    mov dx, 0x3f8",
    "    out dx, al",
    // Дальний прыжок: CS=0x08 (code32), EIP=0x8100 — фиксированная
    // физика стадии 2 (смещение 0x100 от 0x8000). GAS-intel не
    // принимает ptr16:imm — короткий выход в AT&T-синтаксис.
    "    .att_syntax",
    "    ljmp $0x08, $0x8100",
    "    .intel_syntax noprefix",
    "tramp16_end:",
    // ==== Стадия 2: protected 32, PAE, включение long mode ====
    ".section .tramp32, \"a\"",
    ".code32",
    "tramp32_start:",
    "    mov al, 0x64",
    "    mov dx, 0x3f8",
    "    out dx, al",
    "    mov ax, 0x10", // data32 трамплина
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov esp, 0x7000",
    // PAE + CR3 из почтового ящика (таблицы BSP: identity + physmap +
    // high-half; ядро в образе доступно по линк-адресам уже сейчас).
    "    mov eax, cr4",
    "    or eax, 0x20",
    "    mov cr4, eax",
    "    mov eax, [0x8F30]", // mailbox CR3
    "    mov cr3, eax",
    "    mov al, 0x65",
    "    mov dx, 0x3f8",
    "    out dx, al",
    // EFER.LME (IA32_EFER = 0xC0000080).
    "    mov ecx, 0xC0000080",
    "    rdmsr",
    "    or eax, 0x100",
    "    wrmsr",
    // PG (PE уже включён) — CPU входит в compatibility mode.
    "    mov eax, cr0",
    "    or eax, 0x80000000",
    "    mov cr0, eax",
    "    mov al, 0x66",
    "    mov dx, 0x3f8",
    "    out dx, al",
    // Дальний прыжок в 64-битный сегмент (0x18): вход в long mode
    // (AT&T-форма, см. выше).
    "    .att_syntax",
    "    ljmp $0x18, $0x8200",
    "    .intel_syntax noprefix",
    "tramp32_end:",
    // ==== Стадия 3: long mode, подготовка и прыжок в ядро ====
    ".section .tramp64, \"a\"",
    ".code64",
    "tramp64_start:",
    "    mov al, 0x67",
    "    mov dx, 0x3f8",
    "    out dx, al",
    "    mov ax, 0x10",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    xor eax, eax",
    "    mov fs, ax",
    "    mov gs, ax", // GS-базу ставим wrmsr ниже
    // Стек AP (static .bss ядра — high-half, валиден под CR3 BSP).
    "    mov rsp, [0x8F20]", // mailbox STACK
    "    sub rsp, 8",        // ABI: entry rsp ≡ 8 mod 16 (как после call)
    // GS-база = per-CPU блок AP (kernel .bss — high-half VMA).
    "    mov rcx, 0xC0000101", // IA32_GS_BASE
    "    mov rax, [0x8F18]",   // mailbox PERCPU
    "    mov rdx, rax",
    "    shr rdx, 32",
    "    wrmsr",
    "    mov al, 0x68",
    "    mov dx, 0x3f8",
    "    out dx, al",
    // Я на связи: MAGIC_OK (BSP поллит).
    "    mov dword ptr [0x8F28], 0xC0FFEE01",
    // Прыжок в ядро (high-half точка входа ap_entry64). IF=0 с самой
    // первой инструкции трамплина — прерываний не было и не будет.
    "    mov rax, [0x8F10]", // mailbox LONG_ENTRY
    "    jmp rax",
    "tramp64_end:",
    // ==== Мини-GDT трамплина (константы; копируется вместе с блобом) ====
    // 0x00 null | 0x08 code32 (G,D) | 0x10 data32 | 0x18 code64 (L).
    ".section .trampgdt, \"a\"",
    ".align 8",
    "tramp_gdt:",
    "    .quad 0",                  // 0x00 null
    "    .quad 0x00CF9A000000FFFF", // 0x08 code32: base0, G, D
    "    .quad 0x00CF92000000FFFF", // 0x10 data32: RW, G, B
    "    .quad 0x00A09A000000FFFF", // 0x18 code64: L=1, D=0
    "tramp_gdt_end:",
    // Псевдодескриптор lgdt @0xF00 (u16 limit + u32 base + pad):
    // GDT из 4 записей = 32 байта, лимит 31; база = 0x8800.
    ".section .trampdesc, \"a\"",
    ".short 0x1F",
    ".long 0x00008800",
    ".short 0",
    "tramp_desc_end:",
);

// Линк-символы границ блоба (физически — внутри образа; копия уезжает
// на 0x8000). Размер блоба — от первой стадии до конца GDT-хвоста.
unsafe extern "C" {
    static tramp16_start: u8;
    static tramp_desc_end: u8;
}

/// Вход AP в ядро (long mode, IF=0, GS/стек установлены трамплином).
#[unsafe(no_mangle)]
extern "C" fn ap_entry64() -> ! {
    mark(b'A');
    let cpu = percpu::cpu_id() as usize;
    if cpu == 0 || cpu >= MAX_CPUS {
        crate::gate::kpanic("smp: ap_entry64 with bad cpu id (mailbox/percpu bug)");
    }
    // per-CPU привилегированное состояние (аналог bsp_init).
    crate::cpu::ap_init(cpu);
    mark(b'B');
    // LAPIC этого CPU: SIVR + собственный ID (сверка с MADT ниже).
    if let Err(e) = crate::lapic::init() {
        crate::gate::kpanic(e);
    }
    mark(b'C');
    let madt_lapic = lapic_id_of(cpu);
    if madt_lapic != 0 && percpu::lapic_id() != madt_lapic as u32 {
        crate::gate::kpanic("smp: LAPIC id mismatch AP vs MADT (topology bug)");
    }
    // Я дошёл до парковки: отметить онлайн (учёт shootdown-битмапа).
    ONLINE.fetch_or(1u64 << cpu, Ordering::AcqRel);
    crate::kprintln!("smp: cpu{} online (lapic {})", cpu, percpu::lapic_id());
    mark(b'D');

    // Парковка до release_aps: sti+hlt; будит resched-IPI. Гонки
    // пробуждения исключены (проверка флага под cli; sti+hlt —
    // атомарная пара через interrupt shadow).
    loop {
        x86_64::instructions::interrupts::disable();
        if RELEASED.load(Ordering::Acquire) {
            break;
        }
        x86_64::instructions::interrupts::enable_and_hlt();
        mark(b'w'); // проснулись, но ещё не отпущены (диагностика)
    }

    // Отпущены: таймер (частота BSP) и диспетчеризация. IF пока 0 —
    // schedule_next включит прерывания входом в пользователя (iretq с
    // user rflags) либо idle (enable_and_hlt).
    mark(b'T');
    crate::lapic::start_timer_shared();
    mark(b'S');
    // Первый вход в диспетчеризацию — ПОД BKL (иначе гонка с BSP в
    // schedule_next/run на RefCell-структурах GCTL: KERNEL FAULT).
    // Дисциплина: schedule_next всегда вызывается держателем BKL;
    // idle_loop отпустит замок перед сном.
    crate::klock::acquire();
    crate::sched::schedule_next()
}

// ───────────────────── Bring-up (BSP, до кучи) ─────────────────────

/// Physmap-читалка 8-байтовых окон (цель; тесты подставляют срез).
fn phys_read8(phys: u64, len: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    // SAFETY: physmap покрывает 4 GiB; читаем только прошивочные таблицы.
    let src = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(phys), len) };
    out[..len].copy_from_slice(&src[..len]);
    out
}

/// Прочитать физический срез таблицы (после определения длины).
fn phys_slice(phys: u64, len: usize) -> &'static [u8] {
    // SAFETY: таблицы прошивки живут всю сессию.
    unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(phys), len) }
}

/// Запустить AP (вызывается kmain ДО startup::kinit — без аллокаций).
///
/// Отказы не фатальны (кроме полного отсутствия RSDP): неподнявшийся AP
/// исключается из топологии; система живёт на оставшихся.
pub fn bring_up(bi: &boot_info::BootInfo) {
    let topo: &mut Topology = unsafe { &mut *(&raw mut TOPOLOGY) };
    topo.rsdp_phys = bi.firmware.rsdp;

    // BSP всегда есть (запись 0; LAPIC id уточнён lapic::init ранее).
    topo.cpus[0] = Some(CpuEntry {
        processor_id: 0,
        lapic_id: percpu::lapic_id() as u8,
        enabled: true,
        online_capable: true,
    });
    topo.present = 1;
    topo.slots = 1;

    crate::kprintln!("smp: bring_up rsdp={:#x}", bi.firmware.rsdp);
    if bi.firmware.rsdp == 0 {
        crate::kprintln!("smp: no RSDP in boot_info — single CPU (BSP)");
        return;
    }
    // Топология из MADT.
    match find_table(bi.firmware.rsdp, b"APIC", phys_read8) {
        Ok((madt_phys, len)) => {
            crate::kprintln!("smp: MADT at {:#x} len {}", madt_phys, len);
            match madt_cpus(phys_slice(madt_phys, len)) {
                Ok(list) => {
                    let bsp_lapic = percpu::lapic_id() as u8;
                    let mut next = 1usize;
                    for c in list.cpus.into_iter().flatten() {
                        if !(c.enabled || c.online_capable) {
                            continue;
                        }
                        if c.lapic_id == bsp_lapic {
                            // Это мы: уточнить запись BSP.
                            topo.cpus[0] = Some(c);
                            continue;
                        }
                        if next < MAX_CPUS {
                            topo.cpus[next] = Some(c);
                            next += 1;
                        }
                    }
                    topo.slots = next;
                    topo.present = next;
                    if list.lapic_phys != 0 && list.lapic_phys != boot::LAPIC_DEFAULT_PHYS {
                        // Не дефолтная база: lapic::init сверит MSR и откажет
                        // сам; здесь только предупреждение.
                        crate::kprintln!(
                            "smp: MADT lapic base {:#x} (non-default)",
                            list.lapic_phys
                        );
                    }
                }
                Err(e) => crate::kprintln!("smp: MADT parse failed: {:?} — single CPU", e),
            }
        }
        Err(e) => crate::kprintln!("smp: MADT not found ({:?}) — single CPU", e),
    }

    crate::kprintln!(
        "smp: topology slots={} present={} bsp_lapic={}",
        topo.slots,
        topo.present,
        percpu::lapic_id()
    );
    if topo.present <= 1 {
        crate::kprintln!("smp: single CPU system (BSP only)");
        return;
    }

    // Копия трамплина на 0x8000 (physmap-запись; identity тоже жив).
    // SAFETY: границы блоба — линк-символы; страница 0x8000 свободна
    // (ниже EBDA, вне памяти ядра; заглушка её не занимает).
    let blob_start = unsafe { (&raw const tramp16_start) as *const u8 };
    let blob_end = unsafe { (&raw const tramp_desc_end) as *const u8 };
    let blob_len = blob_end as usize - blob_start as usize;
    debug_assert!(blob_len <= 0xF00, "trampoline blob overflows mailbox page");
    unsafe {
        core::ptr::copy_nonoverlapping(
            blob_start,
            phys_ptr::<u8>(boot::AP_TRAMPOLINE_PHYS),
            blob_len,
        );
    }

    // Почтовый ящик: общие поля. Константы ap_mailbox — АБСОЛЮТНЫЕ
    // физические адреса хвоста страницы трамплина (0x8F00+), НЕ смещения
    // от AP_TRAMPOLINE_PHYS (баг v0.6.0: писали в 0x10F10+ — AP читал
    // мусорный CR3=0 и трипл-фолтился на первом же fetch после PG=1).
    // SAFETY: запись в скопированный блоб (физика 0x8F00+).
    unsafe {
        *phys_ptr::<u64>(boot::ap_mailbox::LONG_ENTRY) = ap_entry64 as usize as u64;
        *phys_ptr::<u64>(boot::ap_mailbox::CR3) = crate::memory::kernel_root();
    }

    // INIT-SIPI-SIPI каждому AP + поллинг MAGIC_OK (TSC-таймаут 200 мс).
    let mut up = 1usize;
    for cpu in 1..topo.slots {
        let entry = topo.cpus[cpu].expect("topology slot");
        let percpu_block = crate::cpu::percpu_block(cpu) as u64;
        let stack_top = crate::cpu::kernel_stack_top(cpu);
        // Подготовка блока AP ДО SIPI (SELF/CPU_ID/KERNEL_RSP/DEPTH/
        // NEED_RESCHED/QUANTUM): трамплин ставит GS и прыгает в ядро —
        // rust-часть рассчитывает на заполненный блок.
        // SAFETY: чужой блок — до старта его владельца (SIPI ещё не был).
        unsafe {
            percpu::write_block(percpu_block, |w| {
                w.self_ptr(percpu_block);
                w.cpu_id(cpu as u32);
                w.kernel_rsp(stack_top);
                w.depth(0);
                w.need_resched(0);
                w.quantum(0);
            });
        }
        // SAFETY: mailbox-поля этого AP (абсолютная физика 0x8F00+).
        unsafe {
            *phys_ptr::<u64>(boot::ap_mailbox::PERCPU) = percpu_block;
            *phys_ptr::<u64>(boot::ap_mailbox::STACK) = stack_top;
            *phys_ptr::<u32>(boot::ap_mailbox::MAGIC) = 0;
        }
        let lapic = entry.lapic_id as u32;
        crate::kprintln!("smp: SIPI to cpu{} (lapic {})...", cpu, lapic);
        mark(b'1');
        if crate::lapic::start_ap(lapic) {
            mark(b'2');
            // Поллинг готовности (MAGIC_OK) — до 200 мс по TSC.
            let deadline = crate::lapic::uptime_ns() + 200_000_000;
            mark(b'3');
            let magic = loop {
                if unsafe { *phys_ptr::<u32>(boot::ap_mailbox::MAGIC) }
                    == boot::ap_mailbox::MAGIC_OK
                {
                    break boot::ap_mailbox::MAGIC_OK;
                }
                if crate::lapic::uptime_ns() > deadline {
                    break 0;
                }
                core::hint::spin_loop();
            };
            if magic == boot::ap_mailbox::MAGIC_OK {
                crate::kprintln!("smp: AP cpu{} (lapic {}) started", cpu, lapic);
                up += 1;
            } else {
                crate::kprintln!("smp: AP cpu{} (lapic {}) TIMEOUT — excluded", cpu, lapic);
                topo.cpus[cpu] = None;
                topo.present -= 1;
            }
        } else {
            crate::kprintln!("smp: AP cpu{} (lapic {}) IPI failed — excluded", cpu, lapic);
            topo.cpus[cpu] = None;
            topo.present -= 1;
        }
    }
    crate::kprintln!(
        "smp: {} of {} CPUs started (bring-up done)",
        up,
        topo.present
    );
}

// ───────────────────── Release (после kinit) ─────────────────────

/// Отпустить APы в планировщик (X86Platform::run: пулы/куча/GCTL/glue
/// готовы). Порядок: флаг (Release) -> IPI-будильник (AcqRel-парный
/// доступ) — парковка AP либо видит флаг под cli, либо ловит IPI.
pub fn release_aps() {
    let n = cpu_count();
    let old = RELEASED.swap(true, Ordering::AcqRel);
    crate::kprintln!(
        "smp: release_aps cpus={} released(was {}) icr={:#x}",
        n,
        old,
        crate::lapic::icr_raw()
    );
    if n <= 1 || old {
        return; // один CPU или уже отпущены
    }
    crate::lapic::broadcast_others(boot::VEC_IPI_RESCHED);
}

// ───────────────────── TLB shootdown ─────────────────────

/// Режим инвалидации для рассылки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShootMode {
    /// Одна страница (invlpg по адресу).
    Page,
    /// Всё нетегированное (перезагрузка CR3).
    All,
    /// Всё, включая глобальные записи (CR3 + CR4.PGE toggle).
    AllGlobal,
}

struct Shootdown {
    addr: AtomicU64,
    mode: AtomicU8,
    /// Битмап CPU, чей ACK ждём (каждый целевой CPU снимает свой бит).
    pending: AtomicU64,
}

static SHOOT: Shootdown = Shootdown {
    addr: AtomicU64::new(0),
    mode: AtomicU8::new(0),
    pending: AtomicU64::new(0),
};

/// Локальная инвалидация (текущий CPU).
fn flush_local(mode: ShootMode, addr: u64) {
    use x86_64::instructions::tlb;
    match mode {
        ShootMode::Page => tlb::flush(x86_64::VirtAddr::new(addr)),
        ShootMode::All => tlb::flush_all(),
        // SAFETY: привилегированный код ядра; полный сброс глобальных.
        ShootMode::AllGlobal => unsafe { crate::memory::flush_all_global() },
    }
}

/// TLB shootdown: инвалидировать на ВСЕХ CPU (вызывающий — под BKL;
/// см. memory.rs invalidate_tlb — единственный источник запросов).
///
/// Инициатор флэшится сам, прочие онлайн-CPU — через IPI+ACK. Цели,
/// не дошедшие до планировщика, не ждутся (битмап ONLINE). Тупики
/// исключены: цели либо в user (IPI сразу), либо в BKL-спине с IF=1
/// (IPI доставляется в спине), либо в ядре с IF=0 (ACK по sysret —
/// ограниченно, без взаимного ожидания).
pub fn tlb_shootdown(mode: ShootMode, addr: u64) {
    let me = percpu::cpu_id() as usize;
    let others = online_mask() & !(1u64 << me);
    flush_local(mode, addr);
    if others == 0 {
        return;
    }
    SHOOT.addr.store(addr, Ordering::Relaxed);
    SHOOT.mode.store(
        match mode {
            ShootMode::Page => 1,
            ShootMode::All => 2,
            ShootMode::AllGlobal => 3,
        },
        Ordering::Relaxed,
    );
    core::sync::atomic::fence(Ordering::SeqCst);
    SHOOT.pending.store(others, Ordering::Release);
    crate::lapic::broadcast_others(boot::VEC_IPI_SHOOTDOWN);
    while SHOOT.pending.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

/// Rust-часть обработчика shootdown-IPI (из ctxswitch::ipi_shoot_entry;
/// без BKL — трогает только локальный TLB и ACK-битмап).
#[unsafe(no_mangle)]
extern "C" fn shootdown_c() {
    let m = SHOOT.mode.load(Ordering::Relaxed);
    let mode = match m {
        1 => ShootMode::Page,
        2 => ShootMode::All,
        _ => ShootMode::AllGlobal,
    };
    flush_local(mode, SHOOT.addr.load(Ordering::Relaxed));
    let me = percpu::cpu_id() as usize;
    SHOOT.pending.fetch_and(!(1u64 << me), Ordering::AcqRel);
    crate::lapic::eoi();
}

// ───────────────────── Паника: останов всех CPU ─────────────────────

/// Заморозить прочие CPU (halt-IPI) — вызывается kpanic на BSP/AP.
pub fn halt_others() {
    let _ = crate::lapic::try_broadcast_all(boot::VEC_IPI_HALT);
}

// ───────────────────── Host-тесты парсера ─────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Сборка ACPI-заголовка (36 байт): сигнатура + длина + нули.
    fn hdr(sig: &[u8; 4], len: usize) -> Vec<u8> {
        let mut v = vec![0u8; 36];
        v[0..4].copy_from_slice(&sig[..]);
        v[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        v
    }

    fn rsdp(rev: u8, rsdt: u32, xsdt: u64) -> Vec<u8> {
        let mut v = vec![0u8; 36];
        v[0..8].copy_from_slice(b"RSD PTR ");
        v[8] = 0; // checksum (тесты не проверяют)
        v[9] = rev;
        v[16..20].copy_from_slice(&rsdt.to_le_bytes());
        v[20..24].copy_from_slice(&36u32.to_le_bytes());
        v[24..32].copy_from_slice(&xsdt.to_le_bytes());
        v
    }

    fn reader(mem: &[u8]) -> impl Fn(u64, usize) -> [u8; 8] + '_ {
        move |p, n| {
            let mut out = [0u8; 8];
            let s = p as usize;
            out[..n].copy_from_slice(&mem[s..s + n]);
            out
        }
    }

    #[test]
    fn find_table_via_rsdt() {
        // Память: RSDP@0x100 -> RSDT@0x200 -> MADT@0x300, DMAR@0x400.
        let mut mem = vec![0u8; 0x1000];
        mem[0x100..0x100 + 36].copy_from_slice(&rsdp(1, 0x200, 0));
        let mut rsdt = hdr(b"RSDT", 36 + 8);
        rsdt.extend_from_slice(&0x300u32.to_le_bytes());
        rsdt.extend_from_slice(&0x400u32.to_le_bytes());
        mem[0x200..0x200 + rsdt.len()].copy_from_slice(&rsdt);
        let madt = hdr(b"APIC", 44);
        mem[0x300..0x300 + madt.len()].copy_from_slice(&madt);
        let dmar = hdr(b"DMAR", 36);
        mem[0x400..0x400 + dmar.len()].copy_from_slice(&dmar);

        let r = reader(&mem);
        assert_eq!(find_table(0x100, b"APIC", r), Ok((0x300, 44)));
        assert_eq!(find_table(0x100, b"DMAR", r), Ok((0x400, 36)));
        assert_eq!(find_table(0x100, b"HPET", r), Err(AcpiError::NotFound));
        assert_eq!(find_table(0x500, b"APIC", r), Err(AcpiError::BadRsdp));
    }

    #[test]
    fn find_table_prefers_xsdt() {
        let mut mem = vec![0u8; 0x1000];
        // rev 2 + валидный XSDT — RSDT-поле обязано игнорироваться.
        mem[0x100..0x100 + 36].copy_from_slice(&rsdp(2, 0xDEAD, 0x200));
        let mut xsdt = hdr(b"XSDT", 36 + 8);
        xsdt.extend_from_slice(&0x400u64.to_le_bytes());
        mem[0x200..0x200 + xsdt.len()].copy_from_slice(&xsdt);
        let madt = hdr(b"APIC", 44);
        mem[0x400..0x400 + madt.len()].copy_from_slice(&madt);
        assert_eq!(find_table(0x100, b"APIC", reader(&mem)), Ok((0x400, 44)));
    }

    #[test]
    fn madt_cpus_parse() {
        let mut madt = hdr(b"APIC", 44);
        madt.extend_from_slice(&0xFEE00000u32.to_le_bytes()); // lapic addr
        madt.extend_from_slice(&0u32.to_le_bytes()); // flags
        // CPU 0 (BSP): enabled. CPU 2: enabled. CPU 3: disabled.
        madt.extend_from_slice(&[0x00, 8, 0x00, 0x00]); // proc 0, lapic 0
        madt.extend_from_slice(&1u32.to_le_bytes());
        madt.extend_from_slice(&[0x00, 8, 0x02, 0x02]); // proc 2, lapic 2
        madt.extend_from_slice(&1u32.to_le_bytes());
        madt.extend_from_slice(&[0x00, 8, 0x03, 0x03]);
        madt.extend_from_slice(&0u32.to_le_bytes());
        // IOAPIC-запись (тип 1) — не CPU, парсер обязан пропустить.
        madt.extend_from_slice(&[0x01, 12, 0x00, 0x00, 0x10, 0x00, 0x00, 0xF0]);
        madt.extend_from_slice(&0xFEC00000u32.to_le_bytes());
        let len = madt.len();
        madt[4..8].copy_from_slice(&(len as u32).to_le_bytes());

        let list = madt_cpus(&madt).expect("madt");
        assert_eq!(list.count, 3);
        assert_eq!(list.lapic_phys, 0xFEE00000);
        assert_eq!(
            list.cpus[0],
            Some(CpuEntry {
                processor_id: 0,
                lapic_id: 0,
                enabled: true,
                online_capable: false
            })
        );
        assert!(list.cpus[1].is_none()); // lapic 0 dup? нет: lapic 0 и 2 и 3 — уникальны
        assert_eq!(list.cpus[1].unwrap().lapic_id, 2);
        assert_eq!(list.cpus[2].unwrap().lapic_id, 3);
        assert!(!list.cpus[2].unwrap().enabled);
    }

    #[test]
    fn madt_dedup_by_lapic_id() {
        let mut madt = hdr(b"APIC", 44);
        madt.extend_from_slice(&0xFEE00000u32.to_le_bytes());
        madt.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..2 {
            madt.extend_from_slice(&[0x00, 8, 0x05, 0x05]);
            madt.extend_from_slice(&1u32.to_le_bytes());
        }
        let len = madt.len();
        madt[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let list = madt_cpus(&madt).expect("madt");
        assert_eq!(list.count, 1);
    }

    #[test]
    fn madt_truncated_entry() {
        let mut madt = hdr(b"APIC", 44);
        madt.extend_from_slice(&0xFEE00000u32.to_le_bytes());
        madt.extend_from_slice(&0u32.to_le_bytes());
        madt.extend_from_slice(&[0x00, 16, 0, 0]); // len=16, но данных нет
        let len = madt.len();
        madt[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        assert_eq!(madt_cpus(&madt), Err(AcpiError::Truncated));
    }
}
