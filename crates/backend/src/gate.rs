// ==== Rust-граница режимов: сисколы, тик, фолты, диспетчеризация ====
//
// Вызывается ТОЛЬКО из ctxswitch-asm. Дисциплина: функция либо
// возвращается (продолжение прерванного), либо уходит в
// [`crate::sched::schedule_next`] без возврата (блокировка/смерть/
// вытеснение: фрейм сохранён в контекст потока, ядровый стек свободен).

use alloc::boxed::Box;

use pkg_generic_interface::syscall::types::SyscallArgs;
use startup::KernelGlue;

use crate::cpu;
use crate::lapic;
use crate::sched::{self, UserCtx};

/// Установленный glue (kinit) — единственный путь к ядру отсюда.
pub fn kernel_glue() -> &'static dyn KernelGlue {
    startup::glue().expect("gate: kernel glue not installed (before kinit?)")
}

// ───────────────────── Syscall ─────────────────────

/// Фрейм sys_entry на ядровом стеке (порядок push в ctxswitch.rs).
#[repr(C)]
struct SysFrame {
    rflags: u64,
    rip: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    r9: u64,
    r8: u64,
    r10: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

/// Rust-часть syscall-гейта (asm: rax=nr, rdi..r9=a1..a6).
///
/// Возвращает значение сискола пользователю; при блокировке/смерти/
/// вытеснении — не возвращается (контекст сохранён, диспетчеризация
/// переключила CPU на другой поток).
///
/// SMP v0.6: вход — захват BKL (klock.rs); все не-возвратные пути
/// освобождают его внутри (finalize_and_enter); нормальный возврат —
/// release перед sysret. cpu — из GS (per-CPU), не константа 0.
#[unsafe(no_mangle)]
extern "C" fn syscall_c(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let glue = kernel_glue();
    let thread = cpu::current_thread();
    let task = cpu::current_task();
    if thread.as_u128() == 0 {
        kpanic("gate: syscall with no current thread (GS/percpu broken?)");
    }

    // BKL: ядро (RefCell-структуры GCTL) — только под замком. Вход с
    // IF=0 (FMASK); захват спином с IF=1 (доставка IPI — см. klock).
    crate::klock::acquire();
    let cpu_id = arch::percpu::cpu_id() as usize;

    // Раскладка SyscallArgs — конвенция ядра (`syscall::types`, см.
    // `number_from_args`): слот 0 = НОМЕР (для registry::dispatch),
    // слоты 1..5 = аргументы пользователя a1..a5. Баг v0.5.2: гейт
    // клал [a1..a6] -> хендлеры читали arg(1)=rsi (сдвиг на регистр:
    // rdi-аргумент терялся, DEBUG_WRITE ронял первое слово, IPC_MSG_WORD
    // получал чужой индекс). Шестой регистр пользователя (r9/a6) в ABI
    // не участвует: SYSCALL_ARG_COUNT=6 = номер + 5 аргументов.
    let args = SyscallArgs::new([
        nr as usize,
        a1 as usize,
        a2 as usize,
        a3 as usize,
        a4 as usize,
        a5 as usize,
    ]);
    let ret = glue.dispatch(cpu_id, task, thread, nr, &args);

    // Смерть потока (TASK_EXIT/каскад): reap + диспетчеризация.
    if glue.thread_dead(thread) {
        sched::scheduler().drop_context(thread);
        glue.reap_thread(thread);
        sched::schedule_next();
    }

    // Блокировка (IPC/claim): фрейм -> контекст, дальше без возврата.
    if glue.thread_blocked(thread) {
        let frame =
            unsafe { &*(arch::percpu::read_u64(arch::percpu::OFF_FRAME) as *const SysFrame) };
        let user_rsp = unsafe { arch::percpu::read_u64(arch::percpu::OFF_USER_RSP) };
        let ctx = frame_to_ctx(frame, user_rsp, ret as u64);
        sched::park_current(Box::new(ctx));
    }

    // Вытеснение (квант истёк/yield): текущий — в хвост, дальше без
    // возврата... но возврат значения уже записан в ctx.rax.
    if sched::scheduler().take_need_resched() {
        let frame =
            unsafe { &*(arch::percpu::read_u64(arch::percpu::OFF_FRAME) as *const SysFrame) };
        let user_rsp = unsafe { arch::percpu::read_u64(arch::percpu::OFF_USER_RSP) };
        let mut ctx = frame_to_ctx(frame, user_rsp, ret as u64);
        // ВНИМАНИЕ: frame.rip — это сохранённый syscall-гейтом rcx, т.е.
        // rip ПОСЛЕ инструкции syscall (+2 уже учтён железом). Баг v0.5:
        // здесь делали rip += 2 — двойное продвижение отправляло поток в
        // середину инструкции (SMP-вытеснение проявило: декод мусора,
        // #PF на запись в RX). rcx-семантика уже выставлена frame_to_ctx.
        sched::scheduler().rotate_current();
        let boxed: Box<UserCtx> = Box::new(ctx);
        sched::park_current(boxed); // BKL держится до enter_user
    }

    // Возврат в пользователя: отпустить BKL ДО sysret (IF восстановит
    // sysret из r11 = user-rflags).
    crate::klock::release();
    ret as i64
}

/// Фрейм sys_entry -> UserCtx (rax = будущее возвращаемое значение;
/// rcx/r11 пользователя = rip/rflags — семантика syscall).
fn frame_to_ctx(frame: &SysFrame, user_rsp: u64, rax: u64) -> UserCtx {
    let mut ctx = UserCtx {
        rip: frame.rip,
        rflags: frame.rflags,
        rsp: user_rsp,
        rax,
        rbx: frame.rbx,
        rcx: frame.rip,
        rdx: frame.rdx,
        rsi: frame.rsi,
        rdi: frame.rdi,
        rbp: frame.rbp,
        r8: frame.r8,
        r9: frame.r9,
        r10: frame.r10,
        r11: frame.rflags,
        r12: frame.r12,
        r13: frame.r13,
        r14: frame.r14,
        r15: frame.r15,
        fx: [0; 512],
    };
    // FPU текущего потока: fxsave в чистую область контекста.
    // SAFETY: fx область выровнена (repr align 16), 512 байт.
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "fxsave64 [{fx}]",
            fx = in(reg) ctx.fx.as_mut_ptr(),
            options(nostack)
        );
    }
    ctx
}

// ───────────────────── Тик ─────────────────────

/// Фрейм timer_entry: 15 GPR + CPU-фрейм.
#[repr(C)]
struct TickFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    // CPU (user): rip, cs, rflags, rsp, ss; (kernel): rip, cs, rflags.
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

#[unsafe(no_mangle)]
extern "C" fn timer_c(frame: *mut TickFrame) {
    let f = unsafe { &mut *frame };
    lapic::eoi();
    let from_user = (f.cs & 3) == 3;

    if !from_user {
        // Прервано ядро: idle/hlt (готовность могла прибавиться — idle
        // сам перепроверит) ИЛИ BKL-спин чужого захвата (SMP: вложение
        // одного таймера в ядровый стек — дисциплина см. gate.rs шапка;
        // здесь возврат без BKL). Быстрый путь без замка.
        return;
    }

    // Тик планировщика: квант СВОЕГО CPU (GS, без BKL — атомики
    // per-CPU; ядро-структуры не трогаем).
    use pkg_generic_interface::task::SchedulerInterface;
    use pkg_generic_interface::task::SchedulerInterface as _;
    sched::scheduler().perform_tick(1);

    // Вытеснение — только если просят (квант/IPI-resched): остальное
    // требует ядра -> BKL. Быстрые тики (квант жив) идут без замка.
    if !sched::scheduler().take_need_resched() {
        return;
    }

    // Потенциальное вытеснение: glue-обращения — под BKL. Захват с
    // IF=1-спином: конкурент может держать ядро, наш IPI/EOI уже
    // отработали (EOI в начале обработчика).
    crate::klock::acquire();
    let glue = kernel_glue();
    let thread = cpu::current_thread();
    if thread.as_u128() == 0 {
        // Тик до первого входа в пользователя (kinit) — невозможно
        // (from_user), но безопасно выйти.
        crate::klock::release();
        return;
    }
    if glue.live_thread_count() > 1 {
        // Вытеснение: фрейм -> контекст, rotate, дальше без возврата
        // (BKL отпустит finalize_and_enter).
        let ctx = UserCtx {
            rip: f.rip,
            rflags: f.rflags,
            rsp: f.rsp,
            rax: f.rax,
            rbx: f.rbx,
            rcx: f.rcx,
            rdx: f.rdx,
            rsi: f.rsi,
            rdi: f.rdi,
            rbp: f.rbp,
            r8: f.r8,
            r9: f.r9,
            r10: f.r10,
            r11: f.r11,
            r12: f.r12,
            r13: f.r13,
            r14: f.r14,
            r15: f.r15,
            fx: [0; 512],
        };
        let mut boxed: Box<UserCtx> = Box::new(ctx);
        unsafe {
            core::arch::asm!(
                "fxsave64 [{fx}]",
                fx = in(reg) boxed.fx.as_mut_ptr(),
                options(nostack)
            );
        }
        sched::scheduler().rotate_current();
        sched::park_current(boxed);
    }
    // Единственный поток: вытеснение бессмысленно — вернуть управление
    // (need_resched уже снят take_need_resched выше).
    crate::klock::release();
}

// ───────────────────── Фолты ─────────────────────

/// Фрейм фолта: 15 GPR + [err] + CPU-фрейм.
#[repr(C)]
struct FaultFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    err: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

#[unsafe(no_mangle)]
extern "C" fn fault_c(frame: *mut FaultFrame, vec: u8) -> ! {
    let f = unsafe { &mut *frame };
    let glue = kernel_glue();
    let thread = cpu::current_thread();

    if (f.cs & 3) != 3 {
        // Фолт в ядре — баг ядра: паника (стек/таблицы могли умереть).
        kpanic("gate: KERNEL FAULT (bug) — see serial log");
    }

    // User-фолт: смерть домена — путь через ядро, под BKL.
    crate::klock::acquire();

    // vec — номер вектора от asm-точки (14=#PF, 13=#GP, 8=#DF): все
    // юзер-фолты v0.5 фатальны для домена, но диагностика обязана
    // показывать настоящий вектор (баг v0.5.2: печатали 0).
    let addr = cpu::cr2();
    glue.user_fault(thread, vec, f.err, addr, f.rip);
    // user_fault гасит домен: добить диспетчеризацией (BKL отпустит
    // finalize_and_enter следующего потока).
    sched::scheduler().drop_context(thread);
    glue.reap_thread(thread);
    sched::schedule_next()
}

// ───────────────────── Диспетчеризация/вспомогательное ─────────────────────

/// Активировать пространство владельца потока + зеркала GS.
pub fn activate_thread_space(thread: uuid::Uuid) -> bool {
    let glue = kernel_glue();
    let ok = glue.activate_space_of(thread);
    if ok {
        let owner = glue.thread_owner(thread);
        arch::percpu::set_current_thread(thread.as_u128());
        arch::percpu::set_current_task(owner.map(|o| o.as_u128()).unwrap_or(0));
    }
    ok
}

/// Пометить Running (после переключения).
pub fn mark_running(thread: uuid::Uuid) {
    kernel_glue().mark_running(thread);
}

/// Reap мёртвого (контекст + TCB).
pub fn reap_thread(thread: uuid::Uuid) {
    let glue = kernel_glue();
    sched::scheduler().drop_context(thread);
    glue.reap_thread(thread);
    arch::percpu::set_current_thread(0);
}

/// Финализировать вход: материализованный возврат блокировки -> rax.
///
/// SMP: ПОСЛЕДНЯЯ точка ядра перед iretq — освобождение BKL (инвариант:
/// каждый не-возвратный путь диспетчеризации приводит сюда).
pub fn finalize_and_enter(thread: uuid::Uuid, mut ctx: Box<UserCtx>) -> ! {
    if let Some(r) = kernel_glue().take_syscall_ret(thread) {
        ctx.rax = r as u64;
    }
    let leaked: &'static mut UserCtx = alloc::boxed::Box::leak(ctx);
    crate::klock::release();
    // SAFETY: контекст валиден (построен/сохранён гейтом), вход не
    // возвращается.
    unsafe { crate::ctxswitch::enter_user(leaked) }
}

/// Вход в пользователя (простой: из sched::schedule_next).
pub fn enter_user(ctx: &'static mut UserCtx) -> ! {
    unsafe { crate::ctxswitch::enter_user(ctx) }
}

/// Idle: нет готовых потоков. Ждём прерываний; если живых потоков нет —
/// сообщение и сон навсегда (нормальный конец демонстрации: init вышел).
///
/// SMP-инвариант: вызывается ТОЛЬКО из schedule_next (BKL держится);
/// перед сном BKL отпускается, при будке (появилась готовность) —
/// перевзват и снова schedule_next (без возврата).
pub fn idle_loop() -> ! {
    // Fatal-пути startup могут дойти сюда ДО установки glue (boot_info
    // протокол/ELF/пулы): без ядра нет и диспетчеризации — честное
    // сообщение и сон навсегда (машина жива для осмотра по serial).
    let Some(glue) = startup::glue() else {
        crate::console::kprint_str(
            "\r\n[kernel] idle before kinit (fatal boot path) — halting\r\n",
        );
        loop {
            x86_64::instructions::interrupts::enable_and_hlt();
        }
    };
    // Сообщение печатается под BKL (путь сюда — из schedule_next).
    let live = glue.live_thread_count();
    let msg = if live == 0 {
        "\r\n[kernel] all user threads gone — halting (boot chain OK)\r\n"
    } else {
        "\r\n[kernel] idle: no runnable threads (all blocked) — waiting\r\n"
    };
    crate::console::kprint_str(msg);
    // Сон без BKL: прерывания будят (таймер/IPI), has_ready — атомики
    // готовности (без ядра), перезапуск диспетчеризации — под замком.
    crate::klock::release();
    loop {
        x86_64::instructions::interrupts::enable_and_hlt();
        // Проснулись (тик/IPI): если появились готовые — вернуться в
        // диспетчеризацию (повторная проверка под BKL: между hlt и
        // захватом поток могли разобрать).
        if sched::scheduler().has_ready() {
            crate::klock::acquire();
            if sched::scheduler().has_ready() {
                sched::schedule_next(); // не возвращается
            }
            // Разобрали без нас — снова спать.
            crate::klock::release();
        }
        // Нет готовых: продолжить сон (двойная проверка не нужна —
        // следующий таймер/IPI разбудит снова).
    }
}

/// Паника ядра: сообщение, останов прочих CPU (halt-IPI) и свой CPU —
/// навсегда (без разворачивания).
pub fn kpanic(msg: &str) -> ! {
    x86_64::instructions::interrupts::disable();
    // СНАЧАЛА печать (halt-IPI мгновенно заморозит остальных — их
    // полупечатанные строки не должны терять нашу).
    crate::console::kprint_str("\r\n[kernel] PANIC: ");
    crate::console::kprint_str(msg);
    crate::console::kprint_str("\r\n");
    crate::smp::halt_others();
    loop {
        x86_64::instructions::hlt();
    }
}
