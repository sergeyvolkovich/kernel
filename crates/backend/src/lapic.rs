// ==== Локальный APIC: включение + таймер + IPI (SMP) + часы ====
//
// xAPIC (MMIO через physmap). Частоты калибруются на BSP по PIT ch2
// (one-shot 50 мс): TSC (часы SYS_TIME) и LAPIC-таймер. AP берут
// калибровку BSP (LAPIC-таймеры одного кристалла поблизости
// идентичны; пересинкализрация по общему PIT из SMP — гонка на
// разделяемом канале, сознательно не делаем).
//
// IPI (v0.6): INIT-SIPI-SIPI запуск AP, resched/shootdown/halt
// рассылки. EOI-адрес — константа (PHYSMAP + дефолтная база LAPIC —
// инвариант, проверяемый init()); на этом стоит asm-обработчик
// resched (см. ctxswitch.rs).

use core::sync::atomic::{AtomicU64, Ordering};

use arch::boot;
use pkg_generic_interface::syscall::system::TimeSource;

use crate::memory::phys_ptr;

// Регистры xAPIC (смещения от базы).
const REG_ID: u32 = 0x020;
const REG_EOI: u32 = 0x0B0;
const REG_ICR_LOW: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_MASKED: u32 = 1 << 16;
const REG_TIMER_PERIODIC: u32 = 1 << 17;
const REG_TIMER_ICR: u32 = 0x380;
const REG_TIMER_CCR: u32 = 0x390;
const REG_TIMER_DCR: u32 = 0x3E0;
const REG_SIVR: u32 = 0x0F0;
const SIVR_ENABLE: u32 = 1 << 8;

// ICR: поля команды IPI.
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const ICR_INIT: u32 = 0b101 << 8;
const ICR_SIPI: u32 = 0b110 << 8;
// Intel SDM Vol.3 10.6 (Destination Shorthand, биты 18-19):
//   00 = dest-field | 01 = self | 10 = ALL INCLUDING self | 11 = ALL EXCLUDING self.
// Баг v0.6.1: константы были перепутаны (0b10 использовался для
// «кроме себя» — рассылка доставляла IPI и отправителю: сам-IPI
// становился pending на IF=0-участках и детонировал позже).
const ICR_SHORT_ALL_NOSELF: u32 = 0b11 << 18;
const ICR_SHORT_ALL_SELF: u32 = 0b10 << 18;
const ICR_DELIVERY_BUSY: u32 = 1 << 12;

/// Константный физический адрес EOI (для asm-обработчиков: см.
/// ctxswitch::ipi_resched_entry). Валиден, пока init() держит инвариант
/// «база = LAPIC_DEFAULT_PHYS».
pub const EOI_MMIO: u64 = arch::boot::PHYSMAP_BASE + arch::boot::LAPIC_DEFAULT_PHYS + 0x0B0;

/// База xAPIC (физика; = 0xFEE00000 на QEMU/PC).
static APIC_BASE: AtomicU64 = AtomicU64::new(0);
/// Калиброванная частота TSC, Гц.
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// Калиброванная частота LAPIC-таймера (после делителя), Гц.
static LAPIC_HZ: AtomicU64 = AtomicU64::new(0);

#[inline]
fn reg(off: u32) -> *mut u32 {
    let base = APIC_BASE.load(Ordering::Relaxed);
    // SAFETY: physmap покрывает MMIO-область; доступ выровнен на 4.
    unsafe { phys_ptr::<u32>(base + off as u64) }
}

#[inline]
fn read(off: u32) -> u32 {
    unsafe { reg(off).read_volatile() }
}

#[inline]
fn write(off: u32, v: u32) {
    unsafe { reg(off).write_volatile(v) }
}

/// Включить xAPIC (MSR IA32_APIC_BASE: bit11), проверить базу,
/// Spurious-вектор + снять software-disable. Идемпотентен — вызывается
/// КАЖДЫМ CPU (BSP из kmain, AP из ap_entry64): SIVR/LVT — per-CPU.
pub fn init() -> Result<(), &'static str> {
    use x86_64::registers::model_specific::Msr;
    let mut msr = Msr::new(boot::MSR_IA32_APIC_BASE);
    // SAFETY: привилегированный код ядра.
    let v = unsafe { msr.read() };
    let base = v & 0xFFFF_F000;
    if base != boot::LAPIC_DEFAULT_PHYS {
        return Err("lapic: unexpected APIC base (non-default layout unsupported)");
    }
    // SAFETY: включаем APIC (bit 11), xAPIC (не x2APIC: bit 10 чист).
    unsafe { msr.write(v | (1 << 11)) };

    APIC_BASE.store(base, Ordering::Relaxed);

    // Spurious-вектор: enable + вектор (без EOI).
    write(REG_SIVR, boot::VEC_SPURIOUS as u32 | SIVR_ENABLE);

    // LAPIC ID (для per-CPU; xAPIC: старшие 8 бит регистра).
    let id = read(REG_ID) >> 24;
    // SAFETY: своё per-CPU поле.
    unsafe { arch::percpu::write_u64(arch::percpu::OFF_LAPIC_ID, id as u64) };
    Ok(())
}

/// Отправить EOI (конец обработки прерывания).
#[inline]
pub fn eoi() {
    write(REG_EOI, 0);
}

// ───────────────────── Калибровка по PIT ─────────────────────

/// Прочитать порт u8.
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe {
        core::arch::asm!(".intel_syntax noprefix", "in al, dx", in("dx") port, out("al") v);
    }
    v
}

/// Записать в порт u8.
unsafe fn outb(port: u16, v: u8) {
    unsafe {
        core::arch::asm!(".intel_syntax noprefix", "out dx, al", in("dx") port, in("al") v);
    }
}

/// Подождать ~`usec` микросекунд по PIT ch2 (one-shot, gate ON).
/// Возвращает (tsc_before, tsc_after, lapic_ccr_before, lapic_ccr_after).
fn pit_window(usec: u64) -> (u64, u64, u32, u32) {
    let ticks = (boot::PIT_FREQUENCY_HZ * usec) / 1_000_000; // ~59.6K @ 50ms
    let ticks = ticks.min(0xFFFF);
    unsafe {
        // Gate2 ON (bit0), speaker OFF (bit1).
        let p61 = inb(0x61);
        outb(0x61, (p61 & !0x02) | 0x01);
        // PIT ch2: lo/hi, mode 0 (interrupt on terminal count).
        outb(0x43, 0xB0);
        outb(0x42, (ticks & 0xFF) as u8);
        outb(0x42, (ticks >> 8) as u8);

        let ccr0 = read(REG_TIMER_CCR);
        let tsc0 = rdtsc();
        // OUT2 (bit 5 порта 0x61) взводится по завершению счёта.
        while inb(0x61) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        let tsc1 = rdtsc();
        let ccr1 = read(REG_TIMER_CCR);
        (tsc0, tsc1, ccr0, ccr1)
    }
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    ((hi as u64) << 32) | lo as u64
}

/// Калибровать TSC + LAPIC и запустить периодический таймер (VEC_TIMER)
/// на BSP.
///
/// До вызова: lapic::init() + маскированный one-shot LVT (делитель 16).
pub fn start_timer() -> Result<(), &'static str> {
    if APIC_BASE.load(Ordering::Relaxed) == 0 {
        return Err("lapic: start_timer before init");
    }
    // One-shot, замаскированный (калибровка CCR), делитель 16.
    write(REG_TIMER_DCR, 0x3); // divide by 16
    write(REG_LVT_TIMER, REG_LVT_MASKED | boot::VEC_TIMER as u32);
    write(REG_TIMER_ICR, 0xFFFF_FFFF); // полный счёт

    // Окно 50 мс.
    let usec = 50_000;
    let (tsc0, tsc1, ccr0, ccr1) = pit_window(usec);
    let secs = usec as f64 / 1e6;

    let tsc_hz = ((tsc1 - tsc0) as f64 / secs) as u64;
    let lapic_hz = ((ccr0.wrapping_sub(ccr1)) as f64 / secs) as u64;
    if tsc_hz < 1_000_000 || lapic_hz < 1_000 {
        return Err("lapic: calibration failed (degenerate frequencies)");
    }
    TSC_HZ.store(tsc_hz, Ordering::Relaxed);
    LAPIC_HZ.store(lapic_hz, Ordering::Release);

    // Периодический тик: ICR = lapic_hz / SCHED_HZ.
    let icr = (lapic_hz / boot::SCHED_HZ).max(1);
    write(REG_LVT_TIMER, REG_TIMER_PERIODIC | boot::VEC_TIMER as u32);
    write(REG_TIMER_ICR, icr as u32);
    Ok(())
}

/// Запустить периодический таймер на AP (частота — калибровка BSP из
/// LAPIC_HZ; см. шапку модуля — перекалибровка по общему PIT из SMP
//  была бы гонкой на разделяемом канале).
pub fn start_timer_shared() {
    let hz = LAPIC_HZ.load(Ordering::Acquire);
    if hz == 0 {
        // Дегенерация (BSP не калибровал?): остаться без тика — AP будет
        // работать от resched-IPI; печатать из AP-контекста нельзя (до
        // BKL) — тихо.
        write(REG_LVT_TIMER, REG_LVT_MASKED);
        return;
    }
    write(REG_TIMER_DCR, 0x3); // divide by 16
    let icr = (hz / boot::SCHED_HZ).max(1);
    write(REG_LVT_TIMER, REG_TIMER_PERIODIC | boot::VEC_TIMER as u32);
    write(REG_TIMER_ICR, icr as u32);
}

// ───────────────────── IPI ─────────────────────

/// Дождаться свободного ICR (delivery status clear) с таймаутом TSC.
fn icr_wait() -> bool {
    let deadline = uptime_ns() + 10_000_000; // 10 мс
    while read(REG_ICR_LOW) & ICR_DELIVERY_BUSY != 0 {
        if uptime_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Послать IPI конкретному LAPIC (физический destination).
fn ipi_to(lapic: u32, cmd: u32) -> bool {
    if !icr_wait() {
        return false;
    }
    write(REG_ICR_HIGH, (lapic & 0xFF) << 24);
    write(REG_ICR_LOW, cmd);
    true
}

/// INIT-SIPI-SIPI (запуск AP; классика Intel SDM 8.4.3): INIT-assert,
/// 10 мс, SIPI вектор, 200 мкс, повторный SIPI (для надёжности на
/// старом железе; QEMU хватает одного, второй безвреден).
pub fn start_ap(lapic: u32) -> bool {
    let vec = boot::AP_SIPI_VECTOR;
    let sipi = ICR_SIPI | ICR_LEVEL_ASSERT | vec;
    if !ipi_to(lapic, ICR_INIT | ICR_LEVEL_ASSERT) {
        return false;
    }
    crate::smp::mark(b'i'); // INIT доставлен
    wait_ns(10_000_000);
    if !ipi_to(lapic, sipi) {
        return false;
    }
    crate::smp::mark(b's'); // SIPI #1
    wait_ns(200_000);
    ipi_to(lapic, sipi)
}

/// Рассылка всем, КРОМЕ себя (resched/shootdown: инициатор своё уже
/// сделал/сделает локально).
pub fn broadcast_others(vec: u8) {
    if !icr_wait() {
        crate::smp::mark(b'x'); // ICR busy — IPI молча потерян (редкий отказ)
        return;
    }
    write(REG_ICR_HIGH, 0);
    write(REG_ICR_LOW, (vec as u32) | ICR_SHORT_ALL_NOSELF);
}

/// Сырой ICR_LOW (диагностика release_aps: delivery-status и shorthand).
pub fn icr_raw() -> u32 {
    read(REG_ICR_LOW)
}

/// Рассылка всем, включая себя (halt-IPI паники; свой CPU уже cli).
pub fn try_broadcast_all(vec: u8) {
    if !icr_wait() {
        return;
    }
    write(REG_ICR_HIGH, 0);
    write(REG_ICR_LOW, (vec as u32) | ICR_SHORT_ALL_SELF);
}

/// Занятая задержка по TSC (запуск AP: окно между INIT и SIPI).
fn wait_ns(ns: u64) {
    let deadline = uptime_ns() + ns;
    while uptime_ns() < deadline {
        core::hint::spin_loop();
    }
}

/// Наносекунды с boot (TSC).
pub fn uptime_ns() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return 0;
    }
    (rdtsc() as u128 * 1_000_000_000u128 / hz as u128) as u64
}

// ───────────────────── TimeSource (SYS_TIME) ─────────────────────

/// Источник времени ядра (TSC, монотонный на одном CPU).
pub struct LapicTimeSource;

impl TimeSource for LapicTimeSource {
    fn now_ns(&self) -> u64 {
        uptime_ns()
    }
}

/// Статический экземпляр для установки в kinit.
pub static TIME_SOURCE: LapicTimeSource = LapicTimeSource;
