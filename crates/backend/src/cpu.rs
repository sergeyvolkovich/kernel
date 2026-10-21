// ==== CPU x86_64: GDT / TSS / IDT / per-CPU / syscall-гейт ====
//
// Единая точка настройки привилегированного состояния CPU. Селекторы —
// ABI syscall-гейта (см. ctxswitch.rs: STAR), менять только в паре.
//
//   0x00 null | 0x08 kcode | 0x10 kdata | 0x18 (база STAR)
//   0x20 udata | 0x28 ucode64 | 0x30 TSS
//
// v0.6 SMP: per-CPU данные — статические массивы (MAX_CPUS): блок
// GS (1 стр), GDT, TSS, ядровый стек (BSP 64 KiB, AP 16 KiB). BSP
// настраивает индекс 0 (bsp_init), каждый AP — свой (ap_init) из
// ap_entry64. IDT глобальный (одна таблица, lidt на каждом CPU).
//
// Дисциплина ядрового стека (неизменна с v0.5): фрейм на стеке всегда
// один — syscall с IF=0 (FMASK), тик только из user/hlt; НОВОЕ v0.6:
// вложение «таймер в BKL-спине» (IF=1 в спине захвата) — обработчик
// видит cs&3==0 и возвращается сразу, кадр корректен.

use x86_64::VirtAddr;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::structures::tss::TaskStateSegment;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use arch::boot;
use arch::percpu;

/// Селекторы (ABI: смещения в GDT — протокол syscall/sysret).
pub const SEL_KCODE: u16 = 0x08;
pub const SEL_KDATA: u16 = 0x10;
/// База STAR: sysret SS = +8, CS = +16 (т.е. udata=0x20, ucode=0x28).
pub const STAR_USER_BASE: u16 = 0x18;
pub const SEL_UDATA: u16 = 0x20;
pub const SEL_UCODE: u16 = 0x28;
/// Селекторы с RPL=3 (iretq-фреймы из user).
pub const SEL_UDATA_R3: u16 = 0x23;
pub const SEL_UCODE_R3: u16 = 0x2B;
pub const SEL_TSS: u16 = 0x30;

// ───────────────────── Per-CPU статические массивы ─────────────────────

/// Выровненный статический массив (repr(align) на статиках запрещён).
#[repr(align(16))]
struct Align16<T>(pub T);
#[repr(align(4096))]
struct Align4096<T>(pub T);

/// Ядровый стек BSP: 64 KiB в .bss (kinit: GCTL/ELF/fmt — глубже, чем
/// рабочий цикл AP).
static KERNEL_STACK_BSP: Align16<[u8; 64 * 1024]> = Align16([0; 64 * 1024]);

/// Ядровые стеки AP: 16 KiB каждый (boот::AP_STACK_PAGES = 4).
static AP_STACKS: [Align16<[u8; 16 * 1024]>; crate::smp::MAX_CPUS] =
    [const { Align16([0; 16 * 1024]) }; crate::smp::MAX_CPUS];

/// Per-CPU блоки (одна страница на CPU, .bss; [0] = BSP).
static PERCPU_BLOCKS: [Align4096<[u8; percpu::PERCPU_SIZE]>; crate::smp::MAX_CPUS] =
    [const { Align4096([0; percpu::PERCPU_SIZE]) }; crate::smp::MAX_CPUS];

/// Обёртка Sync для статических MaybeUninit (заполняются один раз на
/// «своём» CPU до появления чужих читателей; см. bsp_init/ap_init).
struct OnceCell<T>(UnsafeCell<MaybeUninit<T>>);
unsafe impl<T> Sync for OnceCell<T> {}
impl<T> OnceCell<T> {
    fn mut_ptr(&self) -> *mut T {
        // SAFETY-контракт ячейки: одноразовая инициализация на своём CPU.
        unsafe { core::mem::MaybeUninit::as_mut_ptr(&mut *self.0.get()) }
    }
}

/// GDT каждого CPU (индексы-ABI обязаны совпадать у всех: см. SEL_*).
static GDT_CELLS: [OnceCell<GlobalDescriptorTable>; crate::smp::MAX_CPUS] = [const {
    OnceCell(UnsafeCell::new(MaybeUninit::new(
        GlobalDescriptorTable::new(),
    )))
};
    crate::smp::MAX_CPUS];
/// TSS каждого CPU (rsp0 — свой стек).
static TSS_CELLS: [OnceCell<TaskStateSegment>; crate::smp::MAX_CPUS] =
    [const { OnceCell(UnsafeCell::new(MaybeUninit::new(TaskStateSegment::new()))) };
        crate::smp::MAX_CPUS];

/// Вершина ядрового стека CPU (BSP: 64K; AP: 16K из AP_STACKS).
pub fn kernel_stack_top(cpu: usize) -> u64 {
    if cpu == 0 {
        KERNEL_STACK_BSP.0.as_ptr() as u64 + KERNEL_STACK_BSP.0.len() as u64
    } else {
        let s = &AP_STACKS[cpu];
        s.0.as_ptr() as u64 + s.0.len() as u64
    }
}

/// Per-CPU блок CPU (вирт. адрес; high-half .bss — валиден под ядерным
/// CR3 с самого входа AP).
pub fn percpu_block(cpu: usize) -> u64 {
    PERCPU_BLOCKS[cpu].0.as_ptr() as u64
}

/// Per-CPU блок BSP (вирт. адрес).
pub fn bsp_percpu_block() -> u64 {
    percpu_block(0)
}

// ───────────────────── GDT + TSS (общая сборка) ─────────────────────

/// Собрать GDT/TSS CPU и загрузить их. Возвращает селектор TSS.
///
/// SAFETY (контракт вызова): `cpu` — индекс СВОЕГО массива, вызывается
/// один раз на CPU (bsp_init на BSP, ap_init на AP) до входа в user.
unsafe fn load_gdt_tss(cpu: usize) {
    // SAFETY: см. контракт выше; значения живы статически.
    let tss: &'static mut TaskStateSegment = unsafe { &mut *TSS_CELLS[cpu].mut_ptr() };
    let gdt: &'static mut GlobalDescriptorTable = unsafe { &mut *GDT_CELLS[cpu].mut_ptr() };
    // TSS: rsp0 — ядровый стек ЭТОГО CPU (входы из user на нём).
    tss.privilege_stack_table[0] = VirtAddr::new(kernel_stack_top(cpu));

    // Порядок индексов — ABI (см. константы выше).
    let _kcode = gdt.append(Descriptor::kernel_code_segment()); // 0x08
    let _kdata = gdt.append(Descriptor::kernel_data_segment()); // 0x10
    let _star_base = gdt.append(Descriptor::kernel_data_segment()); // 0x18 (база STAR)
    let udata = gdt.append(Descriptor::user_data_segment()); // 0x20
    let ucode = gdt.append(Descriptor::user_code_segment()); // 0x28
    let tss_sel = gdt.append(Descriptor::tss_segment(tss)); // 0x30

    gdt.load();
    // SAFETY: GDT загружен, селекторы корректны; одноразовый вход CPU.
    unsafe {
        load_segments();
        x86_64::instructions::tables::load_tss(tss_sel);
    }
    let _ = ucode;
    let _ = udata;
}

/// Инициализация per-CPU блока CPU (SELF/CPU_ID/KERNEL_RSP + обнуление
/// SMP-полей). LAPIC_ID проставит lapic::init.
///
/// SAFETY (контракт): вызывается «своим» CPU один раз; для BSP — до
/// любых прерываний, для AP — до выхода из ap_entry64.
unsafe fn fill_percpu(cpu: usize, block: u64) {
    // SAFETY: блок свой, GS-база будет установлена ниже.
    unsafe {
        percpu::set_gs_base(block);
        percpu::write_u64(percpu::OFF_SELF, block);
        percpu::write_u64(percpu::OFF_CPU_ID, cpu as u64);
        percpu::write_u64(percpu::OFF_LAPIC_ID, 0); // уточнит lapic::init
        percpu::write_u64(percpu::OFF_KERNEL_RSP, kernel_stack_top(cpu));
        percpu::write_u64(percpu::OFF_DEPTH, 0);
        percpu::write_u64(percpu::OFF_NEED_RESCHED, 0);
        percpu::write_u64(percpu::OFF_QUANTUM, 0);
    }
}

/// Собрать GDT/TSS, загрузить, поставить GS-базу и syscall-MSR.
///
/// Вызывается ОДИН раз из kmain (BSP), до включения прерываний.
pub fn bsp_init() {
    // SAFETY: одноразовая инициализация BSP до любых прерываний.
    unsafe { load_gdt_tss(0) };
    // SAFETY: см. fill_percpu.
    unsafe { fill_percpu(0, bsp_percpu_block()) };
    // SAFETY: селекторы ABI согласованы (index 0 массивов = BSP).
    unsafe { install_syscall_msrs() };
}

/// Настройка привилегированного состояния AP (из ap_entry64; IF=0).
pub fn ap_init(cpu: usize) {
    // SAFETY: свой CPU, одноразово, до первого входа в user.
    unsafe { load_gdt_tss(cpu) };
    // Трамплин уже поставил GS-базу на наш блок — перезаполняем поля
    // (BSP заполнил их до SIPI; перезапись идентична).
    // SAFETY: см. fill_percpu.
    unsafe { fill_percpu(cpu, percpu_block(cpu)) };
    // SAFETY: MSR — per-CPU регистры: каждый AP ставит те же значения.
    unsafe { install_syscall_msrs() };
    // IDT глобальный, но lidt — per-CPU регистр.
    install_idt();
    fpu_enable();
}

/// Перезагрузка сегментных регистров после lgdt (kcode/kdata).
unsafe fn load_segments() {
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "push {kcode}",
            "lea {tmp}, [rip + 3f]",
            "push {tmp}",
            "retfq",
            "3:",
            "mov ecx, {kdata}",
            "mov ds, cx",
            "mov es, cx",
            "mov ss, cx",
            "xor ecx, ecx",
            "mov fs, cx",
            "mov gs, cx", // GS перезапишет set_gs_base (ниже) — порядок важен
            kcode = const SEL_KCODE,
            kdata = const SEL_KDATA,
            tmp = out(reg) _,
            out("ecx") _,
        );
    }
}

/// MSR syscall-гейта: STAR (селекторы), LSTAR (вход), FMASK (гасим IF),
/// EFER.SCE. FMASK = !USER_RFLAGS: в ядре IF=0 — дисциплина сериализации
/// (см. gate.rs; таймер не прерывает сискол, IPI — только в BKL-спине).
///
/// SAFETY (контракт): привилегированный контекст до первого входа в
/// пользователя НА ЭТОМ CPU.
unsafe fn install_syscall_msrs() {
    use x86_64::PrivilegeLevel;
    use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
    use x86_64::structures::gdt::SegmentSelector;

    let ucode = SegmentSelector(SEL_UCODE | 3);
    let udata = SegmentSelector(SEL_UDATA | 3);
    let kcode = SegmentSelector(SEL_KCODE);
    let kdata = SegmentSelector(SEL_KDATA);
    debug_assert_eq!(ucode.rpl(), PrivilegeLevel::Ring3);
    debug_assert_eq!(ucode.0, SEL_UCODE_R3);
    debug_assert_eq!(udata.0, SEL_UDATA_R3);

    // SAFETY: привилегированный код до первого входа в пользователя.
    unsafe {
        Star::write(ucode, udata, kcode, kdata)
            .expect("GDT layout violates STAR constraints (ABI bug)");
        LStar::write(VirtAddr::new(
            crate::ctxswitch::sys_entry as *const () as u64,
        ));
        // Гасим всё, кроме обязательного бита 1: IF=0 в ядре.
        SFMask::write({
            let mut f =
                x86_64::registers::rflags::RFlags::from_bits_retain(!arch::boot::USER_RFLAGS);
            // Бит 1 всегда 1 — маска безразлична к нему; оставляем как есть.
            f
        });
        let mut efer = Efer::read();
        efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
        efer.insert(EferFlags::NO_EXECUTE_ENABLE);
        Efer::write(efer);
    }
}

// ───────────────────── IDT ─────────────────────

/// Собрать и загрузить IDT (таймер + IPI + spurious + фолты).
///
/// IDT — СТАТИЧЕСКАЯ ячейка (не куча): это первая структура после
/// входа в rust, куча (gallocator) поднимается только в startup::kinit.
/// Таблица одна на все CPU (обработчики адресуют per-CPU через GS);
/// каждый CPU делает свой lidt (bsp_init/ap_init).
pub fn install_idt() {
    static IDT_CELL: OnceCell<InterruptDescriptorTable> = OnceCell(UnsafeCell::new(
        MaybeUninit::new(InterruptDescriptorTable::new()),
    ));
    // Идемпотентность: BSP собирает таблицу один раз; AP только lidt
    // (заполнение к этому моменту завершено — памятьный барьер не нужен:
    // AP стартует после MAGIC_OK, что позже завершения bsp_init).
    static FILLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    // SAFETY: одноразовая сборка на BSP до включения прерываний; AP
    // повторно только грузят ту же таблицу.
    unsafe {
        let idt: &'static mut InterruptDescriptorTable = &mut *IDT_CELL.mut_ptr();
        if !FILLED.swap(true, Ordering::Relaxed) {
            let addr = |f: unsafe extern "C" fn()| x86_64::VirtAddr::new(f as usize as u64);
            // SAFETY: обработчики корректны для своего вектора (asm-
            // обёртки восстанавливают состояние; rust-часть либо
            // возвращается, либо переключает контекст без возврата).
            idt[boot::VEC_TIMER].set_handler_addr(addr(crate::ctxswitch::timer_entry));
            idt[boot::VEC_IPI_RESCHED].set_handler_addr(addr(crate::ctxswitch::ipi_resched_entry));
            idt[boot::VEC_IPI_SHOOTDOWN].set_handler_addr(addr(crate::ctxswitch::ipi_shoot_entry));
            idt[boot::VEC_IPI_HALT].set_handler_addr(addr(crate::ctxswitch::ipi_halt_entry));
            idt[boot::VEC_SPURIOUS].set_handler_addr(addr(crate::ctxswitch::spurious_entry));
            // v0.11: внешние линии IOAPIC — по точке входа на GSI
            // (вектора VEC_EXTERNAL_BASE..+24; линии замаскированы в
            // IOAPIC до первого IRQ_ATTACH).
            for (gsi, entry) in crate::ctxswitch::IRQ_ENTRIES.iter().enumerate() {
                idt[boot::VEC_EXTERNAL_BASE + gsi as u8].set_handler_addr(addr(*entry));
            }
            idt.page_fault
                .set_handler_addr(addr(crate::ctxswitch::pf_entry));
            idt.general_protection_fault
                .set_handler_addr(addr(crate::ctxswitch::gp_entry));
            idt.double_fault
                .set_handler_addr(addr(crate::ctxswitch::df_entry));
        }
        // SAFETY: таблица жива статически и заполнена (контракт выше).
        unsafe { load_idt(idt) };
    }
}

/// Загрузить заполненную таблицу в lidt текущего CPU.
///
/// SAFETY: таблица жива статически и заполнена.
unsafe fn load_idt(idt: &'static InterruptDescriptorTable) {
    // x86_64 0.15: загрузка — метод таблицы (lidt — per-CPU регистр).
    // SAFETY: контракт вызова.
    unsafe { idt.load() };
}

// ───────────────────── Вспомогательное ─────────────────────

/// Включить FPU/SSE для ядра (eager-переключение контекстов):
/// CR0: EM=0, TS=0, MP=1; CR4: OSFXSR|OSXMMEXCPT.
pub fn fpu_enable() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    let mut cr0 = Cr0::read_raw();
    cr0 &= !(1 << 2); // EM
    cr0 &= !(1 << 3); // TS
    cr0 |= 1 << 1; // MP
    // SAFETY: привилегированный код ядра на старте (FPU ещё не используется).
    unsafe { Cr0::write_raw(cr0) };
    let mut cr4 = Cr4::read_raw();
    cr4 |= 1 << 9; // OSFXSR
    cr4 |= 1 << 10; // OSXMMEXCPT
    // SAFETY: как выше.
    unsafe { Cr4::write_raw(cr4) };
    let _ = Cr0::read();
    let _ = Cr4::read();
    let _: Cr0Flags = Cr0Flags::empty();
    let _: Cr4Flags = Cr4Flags::empty();
}

/// RDCL_NO (Meltdown закрыт): CPUID leaf7.0 EDX bit29 -> MSR 0x10A bit0.
pub fn has_rdcl_no() -> bool {
    let (_, _, _, edx) = cpuid_raw(7, 0);
    if edx & (1 << 29) == 0 {
        return false; // ARCH_CAPABILITIES MSR отсутствует
    }
    // SAFETY: чтение MSR в привилегированном коде ядра.
    let v = unsafe { x86_64::registers::model_specific::Msr::new(0x10A).read() };
    v & 1 == 1
}

/// Сырой CPUID (leaf, subleaf) -> (eax, ebx, ecx, edx).
///
/// EBX занят LLVM — обходим сохранением rbx на стек.
fn cpuid_raw(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let a: u32;
    let b: u32;
    let c: u32;
    let d: u32;
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "push rbx",
            "cpuid",
            "mov {rbx:e}, ebx",
            "pop rbx",
            in("eax") leaf,
            in("ecx") subleaf,
            lateout("eax") a,
            lateout("ecx") c,
            lateout("edx") d,
            rbx = out(reg) b,
        );
    }
    (a, b, c, d)
}

/// Прочитать CR2 (адрес фолта).
pub fn cr2() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(".intel_syntax noprefix", "mov {v}, cr2", v = out(reg) v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// Текущий поток из per-CPU (u128 ThreadId).
pub fn current_thread() -> uuid::Uuid {
    uuid::Uuid::from_u128(arch::percpu::current_thread())
}

/// Текущая задача из per-CPU.
pub fn current_task() -> uuid::Uuid {
    uuid::Uuid::from_u128(arch::percpu::current_task())
}
