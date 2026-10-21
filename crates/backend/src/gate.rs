// ==== Rust-граница режимов: сисколы, тик, фолты, диспетчеризация ====
//
// Вызывается ТОЛЬКО из ctxswitch-asm. Дисциплина: функция либо
// возвращается (продолжение прерванного), либо уходит в
// [`crate::sched::schedule_next`] без возврата (блокировка/смерть/
// вытеснение: фрейм сохранён в контекст потока, ядровый стек свободен).
//
// SMP v0.12 — БЕЗ Big Kernel Lock (klock.rs демонтирован): входы в ядро
// НЕ сериализуются глобальным замком. Синхронизация — fine-grained
// локами менеджеров ядра (KRwLock/KSpin, ранги — см. `kernel::sync`)
// + lock-free структуры планировщика (sched.rs). IF-дисциплина: вход —
// IF=0 (гейты); лок берётся/ждётся по правилам sync (спин на глубине
// 0 — с IF=1: IPI доставляются, shootdown-ACK приходит). Переключение
// контекста (schedule_next/enter_user) локов НЕ держит: все гарды
// отпущены до входа в пользователя (контекст — единоличное владение
// CPU после эксклюзивного pop из готовности).

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
/// SMP v0.12: без BKL — диспетчер берёт локи менеджеров по мере нужды
/// (RAII-гарды, дисциплина рангов `kernel::sync`). cpu — из GS.
#[unsafe(no_mangle)]
extern "C" fn syscall_c(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let glue = kernel_glue();
    let thread = cpu::current_thread();
    let task = cpu::current_task();
    if thread.as_u128() == 0 {
        kpanic("gate: syscall with no current thread (GS/percpu broken?)");
    }

    let cpu_id = arch::percpu::cpu_id() as usize;

    // Раскладка SyscallArgs — конвенция ядра (`syscall::types`, см.
    // `number_from_args`): слот 0 = НОМЕР (для registry::dispatch),
    // слоты 1..6 = аргументы пользователя a1..a6. Баг v0.5.2: гейт
    // клал [a1..a6] -> хендлеры читали arg(1)=rsi (сдвиг на регистр:
    // rdi-аргумент терялся, DEBUG_WRITE ронял первое слово, IPC_MSG_WORD
    // получал чужой индекс). v0.15: шестой регистр пользователя (r9/a6)
    // ПОДКЛЮЧЁН к ABI (SYSCALL_ARG_COUNT=7): первый потребитель —
    // CAP_MINT_RANGE(0x27), arg6 = new_len. Прежние сисколлы получают
    // arg(6)=0 — их ABI не меняется.
    let args = SyscallArgs::new([
        nr as usize,
        a1 as usize,
        a2 as usize,
        a3 as usize,
        a4 as usize,
        a5 as usize,
        a6 as usize,
    ]);

    // SMP v0.12: КОНТЕКСТ-ВХОД — до диспетчера, безусловно.
    //
    // Любая публикация блокировки внутри диспетча (IPC send/recv/call,
    // recv_any, DEVICE_CLAIM: перевод в Blocked + парковка в очередь)
    // оказывается ПОСЛЕ сохранения контекста — cross-CPU пробуждение
    // (claim → mailbox → Ready → enqueue) не может войти в поток со
    // старым контекстом (первый вход падал бы в start_info — рестарт
    // с точки входа). rax здесь = номер сискола: возврат блокировки
    // материализуется пробуждением (`syscall_ret` в
    // `finalize_and_enter`), вытеснение сохранит rax=ret поверх.
    //
    // Повторного сохранения на блок-пути НЕТ: оно затёрло бы контекст
    // СЛЕДУЮЩЕГО блокирования потока после повторного входа и быстрого
    // повторного парка на другом CPU.
    //
    // v0.13: бокс — из per-CPU пула (без аллокатора), запись — в
    // per-CPU слот планировщика (без локов; обычный сискол без
    // блока/вытеснения дальше слота не идёт).
    {
        let frame =
            unsafe { &*(arch::percpu::read_u64(arch::percpu::OFF_FRAME) as *const SysFrame) };
        let user_rsp = unsafe { arch::percpu::read_u64(arch::percpu::OFF_USER_RSP) };
        let mut ctx = sched::alloc_ctx();
        fill_ctx_from_frame(&mut ctx, frame, user_rsp, nr);
        sched::scheduler().save_context(thread, ctx);
    }

    let ret = glue.dispatch(cpu_id, task, thread, nr, &args);

    // Смерть потока (TASK_EXIT/каскад): reap + диспетчеризация.
    // Проверка монотонна (Dead терминален) — гонки нет: сработает и
    // позже; повторный reap идемпотентен.
    if glue.thread_dead(thread) {
        sched::scheduler().drop_context(thread);
        glue.reap_thread(thread);
        sched::schedule_next();
    }

    // Блокировка (IPC/claim): решение — по per-CPU защёлке диспетчера
    // (`record_block_latch` в хендлерах), НЕ по повторному чтению TCB:
    // между диспетчем и чтением cross-CPU пробуждение могло уже вывести
    // поток в Running — sysret дал бы ДВОЙНОЙ запуск (класс гонок,
    // который раньше закрывал BKL).
    if pkg_generic_interface::syscall::take_block_latch(cpu_id) {
        if glue.thread_blocked(thread) {
            // v0.13: блокировка — тоже конец отрезка исполнения: заряд
            // домену циклы отрезка (rdtsc-разность с метки
            // диспетчеризации; анти-спин-пол — 1 тик за проход, как v0.10:
            // «вычислить-и-заблокироваться» не дешевле честного кванта).
            // Решением троттлить пренебрегаем: поток уже паркуется сам.
            if let Some(cur) = sched::scheduler().current_thread() {
                let cycles = sched::scheduler()
                    .cycles_since_dispatch()
                    .max(sched::min_charge_cycles());
                let _ = glue.on_cpu_cycles_consumed(cur, cycles);
            }
        }
        // Поток ещё Blocked — обычный парк (контекст уже сохранён
        // входом). Уже разбужен/исполняется на другом CPU — свой фрейм
        // просто бросаем: идентичный контекст той же точки входа
        // сохранён на входе и принят другим CPU. Без sysret в обоих
        // случаях — только диспетчеризация.
        sched::schedule_next();
    }

    // Вытеснение (квант истёк/yield/дедлайн/wrap-периода): единый
    // preempt-шаг v0.10 — refill CPU-периода, заряд квоты домену
    // (циклами v0.13), rotate или троттл-парк; не возвращается
    // (вход следующего — свои локи).
    if sched::scheduler().take_need_resched() {
        let frame =
            unsafe { &*(arch::percpu::read_u64(arch::percpu::OFF_FRAME) as *const SysFrame) };
        let user_rsp = unsafe { arch::percpu::read_u64(arch::percpu::OFF_USER_RSP) };
        // ВНИМАНИЕ: frame.rip — это сохранённый syscall-гейтом rcx, т.е.
        // rip ПОСЛЕ инструкции syscall (+2 уже учтён железом). Баг v0.5:
        // здесь делали rip += 2 — двойное продвижение отправляло поток в
        // середину инструкции (SMP-вытеснение проявило: декод мусора,
        // #PF на запись в RX). rcx-семантика уже выставлена fill_ctx.
        let mut boxed = sched::alloc_ctx();
        fill_ctx_from_frame(&mut boxed, frame, user_rsp, ret as u64);
        sched::preempt_step(boxed); // не возвращается
    }

    // Возврат в пользователя: локов не держим (RAII-гарды менеджеров
    // отработали внутри dispatch-цепочки); IF восстановит sysret из
    // r11 = user-rflags.
    ret as i64
}

/// Заполнить контекст из фрейма sys_entry (rax = будущее возвращаемое
/// значение; rcx/r11 пользователя = rip/rflags — семантика syscall).
/// v0.13: пишем в бокс из per-CPU пула (без аллокации на входе).
fn fill_ctx_from_frame(ctx: &mut UserCtx, frame: &SysFrame, user_rsp: u64, rax: u64) {
    ctx.rip = frame.rip;
    ctx.rflags = frame.rflags;
    ctx.rsp = user_rsp;
    ctx.rax = rax;
    ctx.rbx = frame.rbx;
    ctx.rcx = frame.rip;
    ctx.rdx = frame.rdx;
    ctx.rsi = frame.rsi;
    ctx.rdi = frame.rdi;
    ctx.rbp = frame.rbp;
    ctx.r8 = frame.r8;
    ctx.r9 = frame.r9;
    ctx.r10 = frame.r10;
    ctx.r11 = frame.rflags;
    ctx.r12 = frame.r12;
    ctx.r13 = frame.r13;
    ctx.r14 = frame.r14;
    ctx.r15 = frame.r15;
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

    // v0.13: граница CPU-периода — TSC-часы (ТОЧНАЯ граница, а не
    // ближайший тик). ЗДЕСЬ — только флаг: закрытие (refill — локи
    // менеджеров) из прерывания ядра запрещено (см. ниже); снимут
    // preempt-путь (первым шагом) или idle-будка после hlt.
    if sched::period_due() {
        arch::percpu::set_need_resched();
    }

    let from_user = (f.cs & 3) == 3;

    if !from_user {
        // Прервано ядро: idle/hlt (готовность могла прибавиться — idle
        // сам перепроверит) ИЛИ спин на локах ядра другого CPU (SMP
        // v0.12: вложение таймера в ядровый стек; дисциплина — см.
        // шапку; все локи — короткие, вложенный тик возвращается
        // без единого захвата). Локов менеджеров НЕ БРАТЬ: прерванный
        // мог быть спиннером глубины 0 — его лок держит другой (IF=0),
        // вложенный захват того же лока — дедлок (IPI не доставить).
        // Флаг need_resched от границы останется — его снимет следующий
        // вход в пользователя/preempt-шаг.
        //
        // v0.13 TSC-deadline: one-shot ПОГАШЕН этим срабатыванием —
        // перевзвод (граница уже прошла — эпсилон: вытеснение первым
        // же возвратом в пользователя; границы ядра короткие).
        if crate::lapic::using_tsc_deadline() {
            sched::rearm_deadline_from_kernel();
        }
        return;
    }

    // Вытеснение по таймеру:
    //   * периодический фолбэк — квант СВОЕГО CPU (GS, атомики per-CPU;
    //     ядро-структуры не трогаем);
    //   * TSC-deadline — срабатывание ЕСТЬ граница (квант RR/бюджет
    //     домена/период — что ближе): немедленный флаг.
    if crate::lapic::using_tsc_deadline() {
        arch::percpu::set_need_resched();
    } else {
        // Тик планировщика: квант СВОЕГО CPU (GS, атомики per-CPU;
        // ядро-структуры не трогаем).
        use pkg_generic_interface::task::SchedulerInterface;
        sched::scheduler().perform_tick(1);
    }

    // Вытеснение — только если просят (квант/дедлайн/IPI-resched): остальное
    // требует ядра -> preempt-шаг. Быстрые тики (квант жив) — мимо.
    if !sched::scheduler().take_need_resched() {
        return;
    }

    // Потенциальное вытеснение: glue-обращения preempt-шага берут
    // локи менеджеров по дисциплине sync (спины — с IF при глубине 0:
    // pending IPI/EOI уже отработали, EOI — в начале обработчика).
    let thread = cpu::current_thread();
    if thread.as_u128() == 0 {
        // Тик до первого входа в пользователя (kinit) — невозможно
        // (from_user), но безопасно выйти.
        return;
    }
    // v0.10: единый preempt-шаг работает и для ЕДИНСТВЕННОГО потока —
    // квота обязана парковать и его (старый выход «вытеснение
    // бессмысленно» кормил бы одиночного спиннера-DoS бессрочно).
    // v0.13: бокс — из per-CPU пула, без аллокации.
    let mut boxed = sched::alloc_ctx();
    boxed.rip = f.rip;
    boxed.rflags = f.rflags;
    boxed.rsp = f.rsp;
    boxed.rax = f.rax;
    boxed.rbx = f.rbx;
    boxed.rcx = f.rcx;
    boxed.rdx = f.rdx;
    boxed.rsi = f.rsi;
    boxed.rdi = f.rdi;
    boxed.rbp = f.rbp;
    boxed.r8 = f.r8;
    boxed.r9 = f.r9;
    boxed.r10 = f.r10;
    boxed.r11 = f.r11;
    boxed.r12 = f.r12;
    boxed.r13 = f.r13;
    boxed.r14 = f.r14;
    boxed.r15 = f.r15;
    unsafe {
        core::arch::asm!(
            "fxsave64 [{fx}]",
            fx = in(reg) boxed.fx.as_mut_ptr(),
            options(nostack)
        );
    }
    sched::preempt_step(boxed);
}

// ───────────────────── Внешние линии (v0.11) ─────────────────────

/// Внешнее прерывание IOAPIC (asm: irq_entry_N -> irq_common -> сюда).
///
/// SMP v0.12: держатели локов ядра всегда IF=0 — сюда нельзя попасть,
/// пока кто-то держит лок (прерывание физически невозможно). Обработчик
/// помечает себя «в ядре» (depth+1) ДО обращений к менеджерам: тогда
/// его собственные спины на занятых локах идут с IF=0 и вложение
/// внешних прерываний ограничено одним уровнем (окно спина глубины 0).
/// EOI сразу (QEMU по TMR-вектору рассылает широковещательный EOI
/// IOAPIC — remote_irr level-линий гасится эмулятором).
///
/// Доставка: glue.on_external_irq(gsi) -> IrqRouter -> signal-слово
/// (= gsi) в endpoint драйвера; склейки/пробуждения — внутренности IPC
/// (per-gate локи). Переключения контекста НЕТ: разбуженный поток
/// подберёт ближайший sysret/тик (нужен resched-флаг — его ставят
/// пути пробуждения).
#[unsafe(no_mangle)]
extern "C" fn irq_c(_frame: *mut TickFrame, gsi: u32) {
    lapic::eoi();
    // Пояс безопасности (не должен срабатывать при IF-дисциплине):
    // глубина > 0 = мы прервали держателя лока — событие теряется
    // с счётчиком, не паникой.
    if pkg_generic_interface::sync::lock_depth() > 0 {
        crate::ioapic::note_dropped();
        return;
    }
    // Маркер «в ядре»: спины этого хендлера — с IF=0 (безграничное
    // вложение level-линий исключено); снятие — на выходе.
    pkg_generic_interface::sync::depth_enter();
    kernel_glue().on_external_irq(gsi);
    pkg_generic_interface::sync::depth_exit();
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
        // Диагностика (v0.11) — ДО паники: вектор/ошибка/CR2/RIP/RSP и ВСЕ
        // GPR фрейма — баг-репорт без этих слов бесполезен.
        let addr = cpu::cr2();
        let msg = alloc::format!(
            "\r\n[kernel] KERNEL FAULT vec={:#x} err={:#x} cr2={:#x} rip={:#x} rsp={:#x}\r\n\
             [kernel]   rax={:#x} rcx={:#x} rdx={:#x} rbx={:#x} rbp={:#x} rsi={:#x} rdi={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}\r\n",
            vec,
            f.err,
            addr,
            f.rip,
            f.rsp,
            f.rax,
            f.rcx,
            f.rdx,
            f.rbx,
            f.rbp,
            f.rsi,
            f.rdi,
            f.r8,
            f.r9,
            f.r10,
            f.r11,
            f.r12,
            f.r13,
            f.r14,
            f.r15,
        );
        crate::console::kprint_str(&msg);
        kpanic("gate: KERNEL FAULT (bug) — see serial log");
    }

    // User-фолт: смерть домена — пути ядра берут локи менеджеров
    // сами (дисциплина sync; спины — по правилам IF).
    // vec — номер вектора от asm-точки (14=#PF, 13=#GP, 8=#DF): все
    // юзер-фолты v0.5 фатальны для домена, но диагностика обязана
    // показывать настоящий вектор (баг v0.5.2: печатали 0).
    let addr = cpu::cr2();
    glue.user_fault(thread, vec, f.err, addr, f.rip);
    // user_fault гасит домен: добить диспетчеризацией (следующий
    // поток войдёт в пользователя без чужих локов).
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

/// Пометить Running (до входа в пользователя; Ready→Running под локом
/// менеджера). `false` — переход не состоялся (поток погашен): не входить.
pub fn mark_running(thread: uuid::Uuid) -> bool {
    kernel_glue().mark_running(thread)
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
/// SMP v0.12: локов НЕ держим (контекст — единоличное владение после
/// эксклюзивного pop из готовности; все гарды диспетчеризации отработали).
///
/// v0.13: метка диспетчеризации (rdtsc в GS: база заряда квот — отрезок
/// до вытеснения/блокировки) + взвод TSC-deadline точного вытеснения
/// (min(квант RR, бюджет домена, остаток периода); периодический
/// фолбэк — квант уже в GS от pick_next).
///
/// Бокс контекста уходит в Box::leak (enter_user не возвращается);
/// указатель помечен per-CPU «inflight» — рециклинг в пул на
/// СЛЕДУЮЩЕЙ диспетчеризации этого CPU (утечка v0.12 демонтирована).
pub fn finalize_and_enter(thread: uuid::Uuid, mut ctx: Box<UserCtx>) -> ! {
    if let Some(r) = kernel_glue().take_syscall_ret(thread) {
        ctx.rax = r as u64;
    }
    arch::percpu::set_dispatch_tsc(crate::lapic::read_tsc());
    sched::scheduler().arm_preempt_deadline(thread);
    let leaked: &'static mut UserCtx = alloc::boxed::Box::leak(ctx);
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
/// SMP v0.12: локов НЕ держим (schedule_next привёл сюда с пустыми
/// руками; has_ready — lock-free peek, refill/dispatch берут локи
/// на своих отрезках). Прерывания будят; гонки «разобрали без нас»
/// невозможны — schedule_next на пустом кольце просто вернётся сюда.
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
    let live = glue.live_thread_count();
    let msg = if live == 0 {
        "\r\n[kernel] all user threads gone — halting (boot chain OK)\r\n"
    } else {
        "\r\n[kernel] idle: no runnable threads (all blocked) — waiting\r\n"
    };
    crate::console::kprint_str(msg);
    loop {
        // v0.13: будка idle в TSC-deadline-режиме — one-shot на границу
        // CPU-периода: троттл-лист вернётся в готовность ТОЧНО в срок
        // (v0.10 будил ближайший тик; периодический фолбэк — тик сам
        // разбудит, взвод не нужен).
        if crate::lapic::using_tsc_deadline() {
            sched::arm_idle_deadline();
        }
        x86_64::instructions::interrupts::enable_and_hlt();
        // Границу CPU-периода закрывает и idle: его пробуждение —
        // легальный контекст для refill (локов не держим), а preempt-пути
        // в idle нет — троттл-лист разбудим сами, иначе замороженные
        // домены проспали бы до чужого пользовательского входа.
        if sched::cpu_period_refill_if_due() {
            if sched::scheduler().has_ready() {
                sched::schedule_next(); // не возвращается
            }
        }
        // Проснулись (дедлайн/тик/IPI): появились готовые — в диспетчеризацию.
        // Возврат из schedule_next сюда невозможен: он либо входит в
        // поток (не возвращается), либо сам возвращается в idle-цикл.
        if sched::scheduler().has_ready() {
            sched::schedule_next(); // не возвращается
        }
        // Нет готовых: продолжить сон (следующий таймер/IPI разбудит).
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
