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
    /// Вход в пользователя по контексту (не возвращается).
    pub fn enter_user(ctx: *mut crate::sched::UserCtx) -> !;
}
