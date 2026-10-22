// ==== Ассемблерная граница режимов (syscall / timer / faults / enter) ====
//
// Единый язык фреймов: UserCtx (sched.rs) — сохранённое состояние потока.
// Пути:
//   * sys_entry: syscall (rcx=rip, r11=rflags, rsp=user); фрейм на
//     единый ядровый стек (gs:KSP), указатель — в gs:FRAME для rust;
//   * timer_entry: тик LAPIC; полный фрейм (user) или возврат (kernel);
//   * pf/gp/df_entry: фолты; user — смерть домена, kernel — паника;
//   * enter_user: вход по iretq-фрейму (универсально: и первый вход, и
//     возобновление) — без танцев с порядком rsp/rax sysret.
//
// Дисциплина ядрового стека (один на CPU, вершина фиксирована):
// фрейм на нём всегда один — вложений нет (syscall с IF=0, тик только из
// user/hlt, фолты из user; фолт в ядре — паника, стек не важен).

use core::arch::global_asm;

global_asm!(
    ".intel_syntax noprefix",
    ".section .text",
    ".globl sys_entry",
    "sys_entry:",
    // rcx = rip, r11 = rflags, rsp = user rsp, rax = номер сискола.
    "mov gs:[0x38], rsp", // OFF_USER_RSP: сохранить пользовательский
    "mov rsp, gs:[0x30]", // OFF_KERNEL_RSP: единый ядровый стек
    // GPR (кроме rax/rcx/r11 — их значения в фрейме словом ниже).
    "push rdi",
    "push rsi",
    "push rdx",
    "push r10",
    "push r8",
    "push r9",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rcx",           // rip
    "push r11",           // rflags
    "mov gs:[0x50], rsp", // OFF_FRAME: указатель фрейма для rust
    // SysV-вызов syscall_c(nr, a1..a6): rdi=nr, rsi..r9=a1..a5, a6=стек.
    // Вход syscall: rax=nr, rdi..r9/r10=a1..a6 — перестановка обязательна
    // (баг v0.5.2: rdi оставался a1 ->.nr=0 -> все сисколы ошибочны).
    // NOTE: r9/a6 (шестой регистр пользователя) передаётся, но ядро его
    // не читает: SYSCALL_ARGS = [nr, a1..a5] (см. syscall_c в gate.rs).
    "sub rsp, 8",   // ABI-выравнивание: 14 GPR + 8 = 15 слотов, с a6 = 16
    "push r9",      // a6 -> 7-й аргумент @ [rsp+8] в callee
    "mov r9, r8",   // a5
    "mov r8, r10",  // a4
    "mov rcx, rdx", // a3
    "mov rdx, rsi", // a2
    "mov rsi, rdi", // a1
    "mov rdi, rax", // nr
    "call syscall_c",
    // Сюда попадаем ТОЛЬКО при возврате в пользователя (блокировка/смерть/
    // переключение уходят без возврата): rax = возвращаемое значение.
    "add rsp, 16",
    "pop r11", // rflags
    "pop rcx", // rip
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "pop r9",
    "pop r8",
    "pop r10",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "mov rsp, gs:[0x38]", // пользовательский стек
    "sysretq",
    // ───────────────────────── тик LAPIC ─────────────────────────
    ".globl timer_entry",
    "timer_entry:",
    // CPU-фрейм (user): [SS][RSP][RFLAGS][CS][RIP]; kernel: [RFLAGS][CS][RIP].
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp", // кадр (аргумент)
    "mov rbx, rsp", // якорь: rbx callee-saved — переживёт вызов
    "and rsp, -16", // ABI: pre-call 16 (user rsp произволен)
    "call timer_c", // вернулась => продолжаем прерванного
    "mov rsp, rbx", // возврат: снять выравнивание (rbx сохранён callee)
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "iretq",
    // ───────────────────────── фолты (PF/GP/DF) ─────────────────────────
    ".globl pf_entry",
    "pf_entry:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    "mov rbx, rsp", // якорь выравнивания (callee-saved)
    "and rsp, -16",
    "mov rsi, 14",
    "call fault_c", // не возвращается (user) / hlt (kernel)
    "mov rsp, rbx",
    "cli",
    "1:",
    "hlt",
    "jmp 1b",
    ".globl gp_entry",
    "gp_entry:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    "mov rbx, rsp", // якорь выравнивания (callee-saved)
    "and rsp, -16",
    "mov rsi, 13",
    "call fault_c",
    "mov rsp, rbx",
    "cli",
    "1:",
    "hlt",
    "jmp 1b",
    ".globl df_entry",
    "df_entry:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    "mov rbx, rsp", // якорь выравнивания (callee-saved)
    "and rsp, -16",
    "mov rsi, 8",
    "call fault_c",
    "mov rsp, rbx",
    "cli",
    "1:",
    "hlt",
    "jmp 1b",
    // ───────────────────── spurious (без EOI) ─────────────────────
    ".globl spurious_entry",
    "spurious_entry:",
    "iretq",
    // ───────────────────── IPI: resched (без кадра; без BKL) ─────────────────────
    // Максимально дёшево: флаг в СВОЁМ per-CPU блоке (gs:0x58 =
    // OFF_NEED_RESCHED) + EOI по константному адресу (physmap +
    // дефолтная база LAPIC — инвариант lapic::init) + iretq. Адрес EOI
    // не влезает в disp32 — через регистр; rax сохраняем (обработчик
    // обязан сохранить всё, что трогает).
    ".globl ipi_resched_entry",
    "ipi_resched_entry:",
    "mov qword ptr gs:[0x58], 1", // NEED_RESCHED = 1
    "push rax",
    "mov rax, 0xFFFF8000FEE000B0", // EOI (xAPIC MMIO, const)
    "mov qword ptr [rax], 0",
    "pop rax",
    "iretq",
    // ───────────────────── IPI: TLB shootdown ─────────────────────
    // Полный GPR-кадр (Rust-часть читает SHOOT-состояние, чистит бит).
    ".globl ipi_shoot_entry",
    "ipi_shoot_entry:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rbx, rsp", // якорь выравнивания
    "and rsp, -16",
    "call shootdown_c", // EOI внутри
    "mov rsp, rbx",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "iretq",
    // ───────────────────── IPI: halt (паника ядра) ─────────────────────
    ".globl ipi_halt_entry",
    "ipi_halt_entry:",
    "cli",
    "1:",
    "hlt",
    "jmp 1b",
    // ───────────────────── внешние линии IOAPIC (v0.11) ─────────────────────
    // Процессор НЕ сообщает вектор прерывания: на каждую линию — своя
    // точка входа (стаб кладёт gsi и уходит в общий кадр). Кадр — как у
    // тика; обработчик никогда не переключает контекст (только доставка
    // signal — вытеснение доделает ближайший sysret/тик), поэтому
    // возврат всегда iretq в прерванного.
    ".globl irq_entry_0",
    "irq_entry_0:",
    "push 0",
    "jmp irq_common",
    ".globl irq_entry_1",
    "irq_entry_1:",
    "push 1",
    "jmp irq_common",
    ".globl irq_entry_2",
    "irq_entry_2:",
    "push 2",
    "jmp irq_common",
    ".globl irq_entry_3",
    "irq_entry_3:",
    "push 3",
    "jmp irq_common",
    ".globl irq_entry_4",
    "irq_entry_4:",
    "push 4",
    "jmp irq_common",
    ".globl irq_entry_5",
    "irq_entry_5:",
    "push 5",
    "jmp irq_common",
    ".globl irq_entry_6",
    "irq_entry_6:",
    "push 6",
    "jmp irq_common",
    ".globl irq_entry_7",
    "irq_entry_7:",
    "push 7",
    "jmp irq_common",
    ".globl irq_entry_8",
    "irq_entry_8:",
    "push 8",
    "jmp irq_common",
    ".globl irq_entry_9",
    "irq_entry_9:",
    "push 9",
    "jmp irq_common",
    ".globl irq_entry_10",
    "irq_entry_10:",
    "push 10",
    "jmp irq_common",
    ".globl irq_entry_11",
    "irq_entry_11:",
    "push 11",
    "jmp irq_common",
    ".globl irq_entry_12",
    "irq_entry_12:",
    "push 12",
    "jmp irq_common",
    ".globl irq_entry_13",
    "irq_entry_13:",
    "push 13",
    "jmp irq_common",
    ".globl irq_entry_14",
    "irq_entry_14:",
    "push 14",
    "jmp irq_common",
    ".globl irq_entry_15",
    "irq_entry_15:",
    "push 15",
    "jmp irq_common",
    ".globl irq_entry_16",
    "irq_entry_16:",
    "push 16",
    "jmp irq_common",
    ".globl irq_entry_17",
    "irq_entry_17:",
    "push 17",
    "jmp irq_common",
    ".globl irq_entry_18",
    "irq_entry_18:",
    "push 18",
    "jmp irq_common",
    ".globl irq_entry_19",
    "irq_entry_19:",
    "push 19",
    "jmp irq_common",
    ".globl irq_entry_20",
    "irq_entry_20:",
    "push 20",
    "jmp irq_common",
    ".globl irq_entry_21",
    "irq_entry_21:",
    "push 21",
    "jmp irq_common",
    ".globl irq_entry_22",
    "irq_entry_22:",
    "push 22",
    "jmp irq_common",
    ".globl irq_entry_23",
    "irq_entry_23:",
    "push 23",
    "jmp irq_common",
    "irq_common:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",         // кадр (не читается — семантика дока irq_c)
    "mov rsi, [rsp + 120]", // gsi: слово под 15 регистрами
    "mov rbx, rsp",         // якорь выравнивания (callee-saved)
    "and rsp, -16",
    "call irq_c", // EOI внутри; всегда возвращается
    "mov rsp, rbx",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "add rsp, 8", // слово gsi от стаба
    "iretq",
    // ───────────────────────── вход в пользователя ─────────────────────────
    // enter_user(ctx: *mut UserCtx) -> !  (iretq-фрейм; порядок загрузки
    // GPR свободен — rsp/rax восстанавливает iretq)
    ".globl enter_user",
    "enter_user:",
    "fxrstor64 [rdi + 144]", // off::FX
    "mov rax, [rdi + 24]",   // RAX
    "mov rbx, [rdi + 32]",
    "mov rcx, [rdi + 40]",
    "mov rdx, [rdi + 48]",
    "mov rsi, [rdi + 56]",
    "mov rbp, [rdi + 72]",
    "mov r8,  [rdi + 80]",
    "mov r9,  [rdi + 88]",
    "mov r10, [rdi + 96]",
    "mov r11, [rdi + 104]",
    "mov r12, [rdi + 112]",
    "mov r13, [rdi + 120]",
    "mov r14, [rdi + 128]",
    "mov r15, [rdi + 136]",
    // iretq-фрейм в kernel стеке: [SS][RSP][RFLAGS][CS][RIP]
    "push 0x23",                 // SS = SEL_UDATA|3
    "push qword ptr [rdi + 16]", // RSP
    "push qword ptr [rdi + 8]",  // RFLAGS
    "push 0x2B",                 // CS = SEL_UCODE|3
    "push qword ptr [rdi + 0]",  // RIP
    "mov rdi, [rdi + 64]",       // RDI (последним: ctx больше не нужен)
    "iretq",
    ".size sys_entry, .-sys_entry",
);

// Rust-объявления asm-символов.
unsafe extern "C" {
    /// Вход syscall (LSTAR).
    pub fn sys_entry();
    /// Вход тика (IDT VEC_TIMER).
    pub fn timer_entry();
    /// #PF (вектор 0x0E).
    pub fn pf_entry();
    /// #GP (вектор 0x0D).
    pub fn gp_entry();
    /// #DF (вектор 0x08).
    pub fn df_entry();
    /// Spurious LAPIC.
    pub fn spurious_entry();
    /// IPI resched (VEC_IPI_RESCHED).
    pub fn ipi_resched_entry();
    /// IPI TLB shootdown (VEC_IPI_SHOOTDOWN).
    pub fn ipi_shoot_entry();
    /// IPI halt (VEC_IPI_HALT; не возвращается).
    pub fn ipi_halt_entry();
    /// Внешние линии IOAPIC (v0.11): по одной точке на GSI 0..=23
    /// (VEC_EXTERNAL_BASE + N); стаб кладёт N и уходит в irq_common.
    pub fn irq_entry_0();
    pub fn irq_entry_1();
    pub fn irq_entry_2();
    pub fn irq_entry_3();
    pub fn irq_entry_4();
    pub fn irq_entry_5();
    pub fn irq_entry_6();
    pub fn irq_entry_7();
    pub fn irq_entry_8();
    pub fn irq_entry_9();
    pub fn irq_entry_10();
    pub fn irq_entry_11();
    pub fn irq_entry_12();
    pub fn irq_entry_13();
    pub fn irq_entry_14();
    pub fn irq_entry_15();
    pub fn irq_entry_16();
    pub fn irq_entry_17();
    pub fn irq_entry_18();
    pub fn irq_entry_19();
    pub fn irq_entry_20();
    pub fn irq_entry_21();
    pub fn irq_entry_22();
    pub fn irq_entry_23();
    /// Вход в пользователя по контексту (не возвращается).
    pub fn enter_user(ctx: *mut crate::sched::UserCtx) -> !;
}

/// Таблица входов внешних линий (индекс = GSI относительно базы
/// контроллера; cpu.rs заполняет IDT по VEC_EXTERNAL_BASE + индекс).
pub const IRQ_ENTRIES: [unsafe extern "C" fn(); arch_x86::boot::EXTERNAL_GSI_COUNT] = [
    irq_entry_0,
    irq_entry_1,
    irq_entry_2,
    irq_entry_3,
    irq_entry_4,
    irq_entry_5,
    irq_entry_6,
    irq_entry_7,
    irq_entry_8,
    irq_entry_9,
    irq_entry_10,
    irq_entry_11,
    irq_entry_12,
    irq_entry_13,
    irq_entry_14,
    irq_entry_15,
    irq_entry_16,
    irq_entry_17,
    irq_entry_18,
    irq_entry_19,
    irq_entry_20,
    irq_entry_21,
    irq_entry_22,
    irq_entry_23,
];
