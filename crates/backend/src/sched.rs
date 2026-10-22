// ==== Планировщик-бекенд x86_64 (v0.13: точность квот + per-CPU кэш; v0.12: SMP fine-grained) ====
//
// Реализация контракта `SchedulerInterface` ядра + собственные структуры
// диспетчеризации (контексты пользовательских потоков, очередь готовности,
// block-очереди IPC/claims).
//
// SMP v0.12 — БЕЗ Big Kernel Lock (демонтаж klock.rs):
//   * ГОТОВНОСТЬ — lock-free MPMC-кольцо Вьюкова ([`READY`]): нет
//     блокировок, нет ABA, нет аллокаций; enqueue из хуков TCB (под
//     write-гардом TcbManager — MPMC не берёт локов, инверсии рангов
//     нет), pick — из диспетчеризации без чужих локов;
//   * deschedule — ЛЕНИВЫЙ: запись остаётся в кольце, pick отсеивает
//     по фактическому состоянию потока (TCB read, свежий захват —
//     никаких локов не удерживается). Это закрывает и класс гонок
//     «kill в момент rotate»: Dead-поток, запушенный таймером другой
//     CPU, отсеется на pick вместо воскрешения;
//   * финальная защита от воскрешения — `mark_running` (Ready→Running
//     под write-гардом TCB): провал = мимо, диспетчеризация берёт
//     следующего (окно «валидация→запуск» между локами закрыто);
//   * block-очереди/троттл-лист — короткий KSpin (лист);
//   * политика изоляции — атомик (запись один раз до старта SMP):
//     `isolation_policy` читается из памяти-путей (под ops-локом KMEM),
//     вложенность KMEM→SCHED исключена (лист);
//   * текущий поток/квант/флаги — per-CPU (GS), как раньше;
//   * eager FPU: fxsave/fxrstor на каждом переключении (без CR0.TS).
//
// v0.13-1: ЛЕГАСИ TASK-LEVEL ENQUEUE ДЕМОНТИРОВАН. Единица планирования —
//   поток (L4): домены планировщику не адресуются (правка ядра —
//   `TcbManager::create/set_state` больше не зовут хуки бекенда).
//   Записи-призраки UUID задач в кольце (шум stale, отсев на pick,
//   пустые resched-IPI на каждый спавн домена) исчезли по построению;
//   временные bring-up счётчики v0.12 (DBG_*) и rotate_current
//   («метод для диагностики») удалены вместе с once-печатью в idle.
//
// v0.13-2: КОНТЕКСТЫ — per-CPU кэш + точная передача (демонтаж
//   «карта под локом на каждом шаге»):
//   * ГОРЯЧИЙ ПУТЬ — сискол-вход: контекст текущего потока пишется в
//     per-CPU СЛОТ ([`slot`]) без единого лока и без аллокации (боксы
//     рециклируются per-CPU пулом [`CTX_CPU`]). Обычный сискол без
//     блокировки/вытеснения вообще не касается глобального состояния;
//   * ПАРКИ (IPC-block, suspend, preempt-rotate, троттл) — контекст
//     экспортируется слот -> глобальная карта (`INNER.contexts`) ДО
//     публикации состояния потока (хуки enqueue/deschedule — они
//     стреляют на CPU-владельце до фиксации перехода под write-гардом
//     менеджера; вкладка локов менеджер->SCHED — односторонняя, без
//     инверсии). Инвариант: поток Ready/Blocked => его контекст — в
//     карте; Running => в слоте CPU-владельца (не более чем в одном
//     месте, дублей нет);
//   * ВЫБОР (pick) — контекст ИЗЫМАЕТСЯ из карты (remove, а не клон
//     680 Б как в v0.12): zero-copy передача между CPU. Вошедший бокс
//     помечается per-CPU «inflight» и рециклируется в пул на СЛЕДУЮЩЕЙ
//     диспетчеризации этого CPU (asm-чтения enter_user давно завершены)
//     — демонтаж Box::leak (утечка ~700 Б на каждое переключение v0.12);
//   * ОТКАЗ ПУБЛИКАЦИИ (поток убит в окне вытеснения) — слот гасится
//     release_slot_if: бокс в пул, утечки нет;
//   * МЁРТВЫЕ ПАРКИ — записи потоков, чей TCB разрушен ядровыми
//     kill-путями без гейт-reap, подметает sweep_dead_contexts на
//     границе периода (v0.12 оставлял их в карте навсегда).
//   SAFETY per-CPU кэша: свой элемент трогает ТОЛЬКО владелец CPU;
//   прерывания, которые ВОЗВРАЩАЮТСЯ (тип !from_user, irq_c, IPI-флаг),
//   кэш не трогают; пути вытеснения/фолта/смерти не возвращаются —
//   взаимоисключение по потоку управления. Указатели inflight — сырые
//   (Box::leak + from_raw-рециклинг, UserCtx без Drop).
//
// CPU-квоты v0.13 (троттлинг песочницы — точность TSC-deadline):
//   * учёт — в GTCB доменов В ЦИКЛАХ TSC (`on_cpu_cycles_consumed`):
//     отрезок = rdtsc(вытеснение) - rdtsc(диспетчеризация), субтик-
//     точность, включая ядровые участки; «минимум 1 тик» заменён полом
//     MIN_CHARGE_CYCLES (yield-цикл честно измерен и не дешевле кванта);
//   * период — ГЛОБАЛЬНАЯ TSC-граница [`PERIOD_END`]: wall-время
//     CPU_PERIOD_TICKS/(ncpu*SCHED_HZ) с — семантика v0.10 (суммарные
//     тики всех CPU) сохранена, но граница ТОЧНАЯ, а не «на ближайшем
//     тике»; закрытие — CAS (один победитель на границу): refill
//     доменов + дренаж троттл-листа + resched-IPI + sweep мёртвых;
//   * ВЫТЕСНЕНИЕ — LAPIC TSC-deadline (CPUID-детект, фолбэк — прежний
//     периодический тик): each-диспетчеризация взводит one-shot на
//     min(RR-квант, остаток бюджета домена, остаток периода) — домен
//     перебирает квоту В ТОЧНЫЙ МОМЕНТ исчерпания, а не «до тика»;
//   * idle-будка взводит deadline на границу периода — троттл-лист
//     возвращается в готовность точно в срок.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use kernel_hal::traits::kmap::IsolationPolicy;
use pkg_generic_interface::task::scheduler::{
    BlockQueueId, CpuId, SchedulerError, SchedulerInterface,
};
use pkg_generic_interface::task::{TaskId, TaskPriority, ThreadId};

use crate::gate;

// ───────────────────── Контекст пользовательского потока ─────────────────────

/// Полное состояние пользовательского потока: sysret-фрейм + GPR + FPU.
///
/// Первое вхождение потока строит контекст из (entry, stack_top) ядра
/// (thread_start_info через glue) с чистым FPU-состоянием.
#[repr(C, align(16))]
pub struct UserCtx {
    // Системные слова (индексы — asm, менять только в паре с ctxswitch.S).
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// FXSAVE-область (512 Б, выравнивание структуры гарантирует 16).
    pub fx: [u8; 512],
}

/// Смещения полей UserCtx (проверка согласованности с asm).
pub mod off {
    pub const RIP: usize = 0;
    pub const RFLAGS: usize = 8;
    pub const RSP: usize = 16;
    pub const RAX: usize = 24;
    pub const RBX: usize = 32;
    pub const RCX: usize = 40;
    pub const RDX: usize = 48;
    pub const RSI: usize = 56;
    pub const RDI: usize = 64;
    pub const RBP: usize = 72;
    pub const R8: usize = 80;
    pub const R9: usize = 88;
    pub const R10: usize = 96;
    pub const R11: usize = 104;
    pub const R12: usize = 112;
    pub const R13: usize = 120;
    pub const R14: usize = 128;
    pub const R15: usize = 136;
    pub const FX: usize = 144;
}

impl UserCtx {
    /// Свежий контекст первого входа: entry + вершина стека, чистое FPU.
    pub fn fresh(entry: usize, stack_top: usize) -> Self {
        let mut ctx = Self::zeroed();
        ctx.rip = entry as u64;
        ctx.rflags = arch::boot::USER_RFLAGS;
        ctx.rsp = stack_top as u64;
        // Валидное чистое состояние x87/SSE для fxrstor: FCW=0x037F,
        // MXCSR=0x1F80 (иначе #GP на fxrstor).
        ctx.fx[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        let mxcsr_off = 24; // FXSAVE: MXCSR @ 24
        ctx.fx[mxcsr_off..mxcsr_off + 4].copy_from_slice(&0x1F80u32.to_le_bytes());
        ctx
    }

    /// Нулевой скелет (пул/аллокатор: вызывающий заполняет поля фрейма).
    pub fn zeroed() -> Self {
        Self {
            rip: 0,
            rflags: 0,
            rsp: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            fx: [0; 512],
        }
    }
}

// ───────────────────── Готовность: per-CPU EEVDF + витрина (v0.18) ─────────────────────

/// Готовность — по ОДНОЙ очереди EEVDF на CPU (`crates/eevdf`: политика
/// + данные; сериализация — leaf-KSpin каждой очереди в `crate::lb::RQ`).
/// Замена единого глобального набора v0.16: поток живёт на своей
/// «домашней» очереди (cache affinity), размещение на пробуждении —
/// `lb::place_and_enqueue` (home → idle → push-assist), а
/// перегруженные ядра публикуют кандидатов-жертв в витрину
/// (`lb::SHELF`), откуда недогруженные забирают работу двухфазным
/// claim'ом (CAS по слоту → перенос с сохранением lag).
///
/// Синхронизация: RQ[cpu]/HOME/inbox'ы — leaf-ранг KSpin, НИКОГДА не
/// вкладываются друг в друга (последовательные захваты — ок); хуки из-под
/// TCB-write берут их вложенно по прежнему рангу TCB→SCHED.
///
/// Сигналы v0.18: per-task EWMA опозданий (tardiness) и per-core
/// pressure (доля опоздавших dispatch'ей) считаются в крейте eevdf
/// на каждом pick; гистерезис публикации/подкрутки — `lb`.

/// Битмап простаивающих CPU — делегирован балансировщику (lb::IDLE_MASK:
/// та же семантика, плюс штамп входа в idle для «дешёвого» пробуждения).
/// Пробуждение готовности будит точечным resched-IPI цель размещения
/// (idle-цель или urgent-случай по CUR_DL) — см. lb::notify_target.

/// Зафиксировать базовый слайс EEVDF (циклы TSC) — один раз после
/// калибровки TSC, ДО release_aps (рядом с set_cpu_time_unit).
pub fn set_base_slice(cycles: u64) {
    crate::lb::init_base_slice(cycles);
}

/// Отметить свой CPU простаивающим (перед hlt) / активным (после):
/// бит в lb::IDLE_MASK + штамп входа в idle (lb выбирает самое
/// «дешёвое» для пробуждения ядро — недавно уснувшее).
#[inline]
pub fn set_cpu_idle(cpu: usize, idle: bool) {
    let bit = 1u64 << (cpu & 63);
    if idle {
        crate::lb::IDLE_MASK.fetch_or(bit, Ordering::Release);
        crate::lb::IDLE_ENTER[cpu & (crate::smp::MAX_CPUS - 1)]
            .store(crate::lapic::read_tsc(), Ordering::Relaxed);
    } else {
        crate::lb::IDLE_MASK.fetch_and(!bit, Ordering::Release);
    }
}

// (v0.18) Разбудить нужные CPU при публикации готовности —
// точечно для ЦЕЛИ размещения: см. lb::place_and_enqueue →
// lb::notify_target (idle-цель обязана проснуться; urgent — только если
// новый дедлайн бьёт дедлайн работающего CUR_DL[target]). Замена
// глобального kick_cpus_after_ready v0.16 (обход running-набора всей
// очереди на каждом enqueue).

// ───────────────────── Состояние планировщика (KSpin — лист) ─────────────────────

struct Inner {
    /// Троттл-лист CPU-квот (v0.10): потоки доменов, перебравших
    /// `cpu_quota`, — до границы периода. Контексты — в `contexts`
    /// (парковка как у Blocked), из готовности исключены.
    throttled: VecDeque<ThreadId>,
    /// Контексты ПАРКОВАННЫХ потоков (Blocked/Ready/Suspended/троттл —
    /// v0.13: Running-контекст живёт в per-CPU слоте; карта — только
    /// для не-исполняющихся, изымается на pick, а не клонируется).
    contexts: BTreeMap<u128, Box<UserCtx>>,
    /// Block-очереди (IPC-endpoint'ы, claims): FIFO.
    block_queues: BTreeMap<u64, VecDeque<ThreadId>>,
    next_queue_id: u64,
}

/// Бекенд-состояние, НЕ попавшее в lock-free структуры: короткий
/// спин-лок (лист: под ним другие ядровые локи не берутся; вкладка из
/// хуков TcbManager менеджер->SCHED — единственная, односторонняя).
static INNER: pkg_generic_interface::sync::KSpin<Inner> =
    pkg_generic_interface::sync::KSpin::new(Inner {
        throttled: VecDeque::new(),
        contexts: BTreeMap::new(),
        block_queues: BTreeMap::new(),
        next_queue_id: 1,
    });

/// Политика изоляции: атомик (запись — ОДИН раз, до старта SMP;
/// чтение — из памяти-путей под ops-локом KMEM: без SCHED-вложения).
/// 0 = UserTableIsolation (conservative), 1 = MapFullKernel.
static POLICY: AtomicU8 = AtomicU8::new(0);

// ───────────────────── Per-CPU кэш контекстов (v0.13) ─────────────────────

/// Глубина per-CPU пула боксов: покрывает слот + inflight + пик
/// (save/save/load-паттерны) без аллокатора; излишки честно дропаются.
const CTX_FREELIST_CAP: usize = 4;

/// Per-CPU состояние контекстов. Элемент массива [`CTX_CPU`] трогает
/// ТОЛЬКО владелец CPU (см. SAFETY в шапке модуля).
#[repr(align(64))]
struct CtxCpu {
    /// Контекст текущего потока (ключ == GS current_thread): сискол-вход
    /// пишет сюда без локов; парки экспортируют в карту ДО публикации.
    slot_key: UnsafeCell<u128>,
    slot: UnsafeCell<Option<Box<UserCtx>>>,
    /// Бокс, отданный последнему enter_user этого CPU (Box::leak):
    /// рециклинг на следующей диспетчеризации (0 — нет).
    inflight: UnsafeCell<*mut UserCtx>,
    /// Пул свободных боксов (raw-указатели протухших Box).
    free: UnsafeCell<[*mut UserCtx; CTX_FREELIST_CAP]>,
    free_len: UnsafeCell<usize>,
}

impl CtxCpu {
    const fn new() -> Self {
        Self {
            slot_key: UnsafeCell::new(0),
            slot: UnsafeCell::new(None),
            inflight: UnsafeCell::new(null_mut()),
            free: UnsafeCell::new([null_mut(); CTX_FREELIST_CAP]),
            free_len: UnsafeCell::new(0),
        }
    }
}

// SAFETY: элемент CTX_CPU[i] доступен только CPU i (дисциплина шапки:
// возвращающиеся прерывания кэш не трогают, невозвращающиеся пути
// взаимоисключительны по потоку управления). Кросс-CPU доступ НЕТ —
// обмен контекстами идёт через INNER.contexts.
unsafe impl Sync for CtxCpu {}

static CTX_CPU: [CtxCpu; crate::smp::MAX_CPUS] = [const { CtxCpu::new() }; crate::smp::MAX_CPUS];

/// Свой per-CPU кэш контекстов (cpu = GS cpu_id; индекс в границах —
/// инвариант smp: cpu_id < MAX_CPUS).
#[inline]
fn ctx_cpu(cpu: usize) -> &'static CtxCpu {
    debug_assert!(cpu < crate::smp::MAX_CPUS);
    if cpu < crate::smp::MAX_CPUS {
        &CTX_CPU[cpu]
    } else {
        &CTX_CPU[0] // недостижимо (инвариант); безопасный деград
    }
}

/// Бокс контекста из per-CPU пула (или аллокатор при пустом пуле).
/// Горячий путь сискол-входа: без локов, без аллокации в стационаре.
pub fn alloc_ctx() -> Box<UserCtx> {
    let c = ctx_cpu(arch::percpu::cpu_id() as usize);
    // SAFETY: свой элемент; см. дисциплину шапки.
    unsafe {
        let len = *c.free_len.get();
        if len > 0 {
            let p = (*c.free.get())[len - 1];
            *c.free_len.get() = len - 1;
            Box::from_raw(p)
        } else {
            Box::new(UserCtx::zeroed())
        }
    }
}

/// Бокс в per-CPU пул (переполнение — честный drop в аллокатор).
fn recycle_ctx(cpu: usize, b: Box<UserCtx>) {
    let c = ctx_cpu(cpu);
    // SAFETY: свой элемент.
    unsafe {
        let len = *c.free_len.get();
        if len < CTX_FREELIST_CAP {
            (*c.free.get())[len] = Box::into_raw(b);
            *c.free_len.get() = len + 1;
        }
        // иначе: drop(b) — аллокатор
    }
}

// ───────────────────── Часы CPU-квот v0.13 (TSC) ─────────────────────

/// Длина CPU-периода в ЕДИНИЦАХ «суммарных тиков всех CPU» (семантика
/// v0.10 сохранена): wall-время периода = CPU_PERIOD_TICKS/(ncpu*SCHED_HZ)
/// секунд; 2 CPU ≈ 0.5 с стена. Квота домена — доля от общего бюджета.
pub const CPU_PERIOD_TICKS: u64 = 100;

/// RR-квант (как v0.10-v0.12: SCHED_HZ/10 тиков ≈ 100 мс на отрезок).
const QUANTUM_TICKS: u64 = arch::boot::SCHED_HZ / 10;

/// Санитайзер джиттера TSC (низ пол заряда — НЕ анти-спин; см.
/// [`min_charge_cycles`]).
const MIN_CHARGE_CYCLES: u64 = 1024;

/// Анти-спин-пол заряда за проход диспетчеризации (v0.10-семантика,
/// v0.13-единицы): минимум 1 ТИК (unit циклов) за каждый отрезок
/// «диспетчеризация -> парковка/вытеснение» — yield-цикл и
/// «вычислить-и-заблокироваться» не дешевле честного кванта
/// (болтливый IPC-DoS паркуется сотни раз за период — каждая
/// парковка жжёт ядровое время и честно заряжается тиком).
/// Длинные отрезки — ТОЧНЫЕ циклы: floor подхватывает только
/// субтик-отрезки (v0.10 грубил и в другую сторону: 2.4 тика
/// исполнения считались как 2).
pub fn min_charge_cycles() -> u64 {
    tsc_unit().max(MIN_CHARGE_CYCLES)
}

/// Перевзвод one-shot из ядра (!from_user): дедлайн прошёл — эпсилон
/// (~десятки мкс на ГГц-классе): перезапуск после iret, ядровые
/// секции короткие (инвариант IF-дисциплины).
const EPSILON_CYCLES: u64 = 50_000;

/// Глобальная TSC-граница текущего CPU-периода (v0.13). 0 — часы не
/// инициализированы (лениво: первый refill-чек на BSP задаёт now+период).
/// Продвижение — CAS: один победитель на границу (refill).
static PERIOD_END: AtomicU64 = AtomicU64::new(0);

/// Граница вытеснения СВОЕГО CPU (v0.16): TSC, когда текущий слайс
/// ОБЯЗАН закончиться (min(квант, бюджет домена, остаток периода) —
/// вычисляется при каждой диспетчеризации; idle-будка кладёт сюда
/// границу CPU-периода). 0 — взвода нет (до kinit).
static SLICE_PREEMPT_AT: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];

/// Граница advisory-уведомления «слайс заканчивается» СВОЕГО CPU
/// (v0.16, THREAD_SET_SLICE_NOTIFY): 0 — предупреждения нет (поток не
/// регистрировал / слайс слишком короткий / периодический фолбэк).
/// Срабатывание: timer_c доставляет kernel-сообщение в гейт потока
/// (best-effort) и перевзводит реальную границу SLICE_PREEMPT_AT.
static SLICE_WARN_AT: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];

/// Warn-маржа до границы вытеснения (v0.16): половина тика планировщика
/// (5 мс при SCHED_HZ=100) — поток успевает среагировать (yield/flush),
/// не слишком рано (не теряет слайс). Предупреждение взводится только
/// если до границы вытеснения осталось > 2 маржи (иначе — бессмысленно).
#[inline]
fn slice_warn_margin_cycles() -> u64 {
    (tsc_unit() / 2).max(1)
}

/// Прочитать границы своего CPU (timer_c: классификация срабатывания).
#[inline]
pub fn slice_boundaries(cpu: usize) -> (u64, u64) {
    (
        SLICE_WARN_AT[cpu].load(Ordering::Relaxed),
        SLICE_PREEMPT_AT[cpu].load(Ordering::Relaxed),
    )
}

/// Погасить предупредительную границу своего CPU (после доставки).
#[inline]
pub fn clear_slice_warn(cpu: usize) {
    SLICE_WARN_AT[cpu].store(0, Ordering::Relaxed);
}

/// Циклов TSC на один тик планировщика (единица квот; калибровка BSP).
#[inline]
fn tsc_unit() -> u64 {
    crate::lapic::tsc_per_tick()
}

/// RR-квант в циклах TSC.
#[inline]
fn quantum_cycles() -> u64 {
    tsc_unit().saturating_mul(QUANTUM_TICKS)
}

/// Длина периода в циклах TSC (wall-семантика v0.10: суммарные тики
/// всех CPU — делим на их число).
#[inline]
fn period_cycles() -> u64 {
    let ncpu = (crate::smp::cpu_count() as u64).max(1);
    (CPU_PERIOD_TICKS.saturating_mul(tsc_unit()) / ncpu).max(1)
}

/// Планировщик (единая статика; контракт-объект для TcbManager).
pub struct X86Sched;

static SCHED: X86Sched = X86Sched;

/// Ссылка на планировщик (установка в TcbManager::install_scheduler).
pub fn scheduler() -> &'static X86Sched {
    &SCHED
}

/// Зафиксировать политику изоляции (после RDCL_NO-проверки на старте;
/// ДО release_aps — дальше значение неизменно, читатели — без локов).
pub fn set_isolation_policy(policy: IsolationPolicy) {
    POLICY.store(
        match policy {
            IsolationPolicy::UserTableIsolation => 0,
            IsolationPolicy::MapFullKernel => 1,
        },
        Ordering::Release,
    );
}

impl X86Sched {
    // ==== API гейта (не контракт ядра) ====

    /// Текущий поток ЭТОГО CPU (GS — единственный источник истины;
    /// гейт ставит зеркало при входе в поток).
    pub fn current_thread(&self) -> Option<ThreadId> {
        let tid = arch::percpu::current_thread();
        if tid == 0 {
            None
        } else {
            Some(ThreadId::from_u128(tid))
        }
    }

    /// Сохранить контекст текущего потока (вытеснение/блокировка):
    /// гейт передаёт снятый с стека фрейм.
    ///
    /// v0.13: пишется в per-CPU СЛОТ (без локов/аллокаций; обычный
    /// сискол без блока/вытесления дальше слота не идёт). Глобальная
    /// карта получает контекст только на ПАРКЕ — [`Self::export_slot_if`]
    /// (хуки enqueue/deschedule, троттл) ДО публикации состояния.
    pub fn save_context(&self, thread: ThreadId, ctx: Box<UserCtx>) {
        debug_assert_eq!(
            arch::percpu::current_thread(),
            thread.as_u128(),
            "save_context: поток не текущий (слот — только владельцу)"
        );
        let c = ctx_cpu(arch::percpu::cpu_id() as usize);
        // SAFETY: свой элемент; см. дисциплину шапки.
        unsafe {
            *c.slot_key.get() = thread.as_u128();
            let old = (*c.slot.get()).replace(ctx);
            if let Some(old) = old {
                recycle_ctx(arch::percpu::cpu_id() as usize, old);
            }
        }
    }

    /// Экспортировать слот потока в глобальную карту (парк: поток покидает
    /// Running — его контекст обязан стать видимым pick'ерам ДО фиксации
    /// перехода; хуки стреляют под write-гардом менеджера ДО коммита).
    pub fn export_slot_if(&self, thread: ThreadId) {
        let c = ctx_cpu(arch::percpu::cpu_id() as usize);
        // SAFETY: свой элемент.
        unsafe {
            if *c.slot_key.get() != thread.as_u128() {
                return; // контекст потока — не у нас (уже экспортирован/
                // взят; кросс-CPU парки сюда не попадают — слот чужого
                // CPU не читаем)
            }
            *c.slot_key.get() = 0;
            if let Some(b) = (*c.slot.get()).take() {
                // Вставка заменяет протухший хвост, если он был
                // (инвариант «Running => в карте пусто» — защита от
                // деградации, не норма).
                INNER.lock().contexts.insert(thread.as_u128(), b);
            }
        }
    }

    /// Погасить слот потока без экспорта (публикация не состоялась:
    /// requeue/throttle вернули false — поток убит в окне вытеснения;
    /// контекст больше никому не нужен, бокс — в пул).
    pub fn release_slot_if(&self, thread: ThreadId) {
        let c = ctx_cpu(arch::percpu::cpu_id() as usize);
        // SAFETY: свой элемент.
        unsafe {
            if *c.slot_key.get() != thread.as_u128() {
                return;
            }
            *c.slot_key.get() = 0;
            if let Some(b) = (*c.slot.get()).take() {
                recycle_ctx(arch::percpu::cpu_id() as usize, b);
            }
        }
    }

    /// Перевыпуск нужен? (гейт проверяет на выходе из сискола; флаг
    /// ставится тиком/deadline/IPI — per-CPU, без блокировок).
    pub fn take_need_resched(&self) -> bool {
        arch::percpu::take_need_resched()
    }

    /// Выбрать следующий поток: лучший eligible-кандидат СВОЕЙ очереди
    /// EEVDF (минимальный виртуальный дедлайн; lb::pick публикует
    /// CUR_DL/pressure-зеркала). `None` — пусто (idle-петля гейта
    /// попробует украсть работу с витрины до hlt). Валидация живости —
    /// в [`schedule_next`] (нужен glue для чтения состояния TCB):
    /// с eager-deschedule протухшие записи — только гонки переходов
    /// (поток покинул Ready между нашим pick и mark_running),
    /// pick их честно потребляет.
    ///
    /// Квант: периодический фолбэк — тики в GS (как v0.10); TSC-deadline
    /// — квант взводится at finalize (точная граница, тики не нужны).
    pub fn pick_next(&self) -> Option<ThreadId> {
        let cpu = arch::percpu::cpu_id() as usize;
        let (next, _dl) = crate::lb::pick(cpu)?;
        if !crate::lapic::using_tsc_deadline() {
            arch::percpu::set_quantum(arch::boot::SCHED_HZ / 10);
        }
        Some(ThreadId::from_u128(next))
    }

    // ==== CPU-квоты v0.10/v0.13 (троттлинг песочницы) ====

    /// Циклы, потреблённые текущим потоком с диспетчеризации (v0.13:
    /// точный отрезок для заряда; метка — OFF_DISPATCH_TSC в GS,
    /// ставится finalize_and_enter).
    pub fn cycles_since_dispatch(&self) -> u64 {
        crate::lapic::read_tsc().saturating_sub(arch::percpu::dispatch_tsc())
    }

    /// Запарковать текущий поток в троттл-лист (домен за пределом
    /// cpu_quota): НЕ возвращается в готовность до границы периода.
    /// Слот экспортируется в карту (парк: pick после unthrottle возьмёт
    /// контекст оттуда).
    pub fn throttle_current(&self) {
        let cpu = arch::percpu::cpu_id() as usize;
        if let Some(t) = self.current_thread() {
            self.export_slot_if(t);
            // EEVDF (v0.16): сущность покидает running-набор своей
            // очереди и помечается throttled — возврат в готовность
            // только через unthrottle (граница периода).
            crate::lb::mark_throttled(cpu, t.as_u128());
            INNER.lock().throttled.push_back(t);
        }
    }

    /// Граница периода: дренаж троттл-листа в готовность (FIFO-порядок
    /// сохранён; маршрутизация — по домашним очередям в lb). Возврат —
    /// число возвращённых потоков; notify внутри lb будит цели.
    pub fn unthrottle_all(&self) -> usize {
        // v0.19: drain the throttle list without heap traffic — fixed
        // 64-id chunks go straight to the balancer (the v0.18 path built
        // two Vecs, one of them under the INNER lock).
        let mut total = 0usize;
        loop {
            let mut chunk = [0u128; 64];
            let mut n = 0usize;
            {
                let mut inner = INNER.lock();
                while n < chunk.len() {
                    match inner.throttled.pop_front() {
                        Some(t) => {
                            chunk[n] = t.as_u128();
                            n += 1;
                        }
                        None => break,
                    }
                }
            }
            if n == 0 {
                break;
            }
            crate::lb::unthrottle_batch(&chunk[..n]);
            total += n;
        }
        total
    }

    /// Число потоков в троттл-листе (диагностика/аудит).
    pub fn throttled_count(&self) -> usize {
        INNER.lock().throttled.len()
    }

    /// Контекст потока (zero-copy v0.13): свой слот (повторный выбор) ->
    /// глобальная карта парковки (ИЗЪЯТИЕМ; пока поток Running, в карте
    /// пусто — дублей нет) -> первый вход (start_info ядра). Прошлый
    /// inflight-бокс рециклируется в пул (asm-чтения завершены).
    pub fn context_of(&self, thread: ThreadId) -> Option<Box<UserCtx>> {
        let cpu = arch::percpu::cpu_id() as usize;
        let c = ctx_cpu(cpu);
        let mut got: Option<Box<UserCtx>> = None;
        // SAFETY: свой элемент.
        unsafe {
            // 1) собственный слот (поток пере-выбран тем же CPU до парка —
            // редкий, но легальный путь: запись отсеялась бы по состоянию).
            if *c.slot_key.get() == thread.as_u128() {
                *c.slot_key.get() = 0;
                got = (*c.slot.get()).take();
            }
        }
        // 2) карта парковки: изъять (владение боксом переходит сюда).
        if got.is_none() {
            got = INNER.lock().contexts.remove(&thread.as_u128());
        }
        // 3) первый вход: (entry, stack) из ядра.
        if got.is_none() {
            let (entry, stack) = gate::kernel_glue().thread_start_info(thread)?;
            let mut b = alloc_ctx();
            *b = UserCtx::fresh(entry, stack);
            got = Some(b);
        }
        let b = got?;
        // Рециклинг прошлого inflight + пометка нового: бокс уйдёт в
        // Box::leak (finalize), указатель помним сами.
        // SAFETY: свой элемент; prev принадлежит нашему пулу/аллокатору.
        unsafe {
            let prev = *c.inflight.get();
            if !prev.is_null() {
                recycle_ctx(cpu, Box::from_raw(prev));
            }
            *c.inflight.get() = Box::into_raw(b);
            Some(Box::from_raw(*c.inflight.get()))
        }
    }

    /// Забыть контекст мёртвого потока (гейт после reap; слот — свой,
    /// карта — кросс-CPU: kill-пути ядра гасят потоки с любого CPU).
    /// v0.16: заодно — EEVDF-сущность (кэш планировщика не течёт).
    /// v0.18: сущность живёт на домашней очереди — вычистка через
    /// lb::drop_thread (маршрутизация + unregister).
    pub fn drop_context(&self, thread: ThreadId) {
        let cpu = arch::percpu::cpu_id() as usize;
        let c = ctx_cpu(cpu);
        // SAFETY: свой элемент.
        unsafe {
            if *c.slot_key.get() == thread.as_u128() {
                *c.slot_key.get() = 0;
                if let Some(b) = (*c.slot.get()).take() {
                    recycle_ctx(cpu, b);
                }
                crate::lb::drop_thread(thread.as_u128());
                return;
            }
        }
        if let Some(b) = INNER.lock().contexts.remove(&thread.as_u128()) {
            recycle_ctx(cpu, b);
        }
        crate::lb::drop_thread(thread.as_u128());
    }

    /// Подмет записи карты, чей TCB разрушен (ядровые kill-пути без
    /// гейт-reap: user_fault-каскад, kill-сисколы — v0.12 оставлял их
    /// навсегда). Граница периода: карта мала, поток не горячий.
    ///
    /// v0.16: сюда же — EEVDF-сущности мёртвых потоков (кэш планировщика
    /// не течёт; drop_context чистит основные пути, этот — страховка).
    /// v0.18: сущности размазаны по per-CPU очередям + таблица маршрутизации
    /// lb::HOME — зачистка делегирована lb::sweep_dead (обходит ВСЕ
    /// очереди: вора могло убить в момент трансфера).
    ///
    /// Локи: ключи копируются под своим локом, БЕЗ glue-вызовов (вкладка
    /// SCHED->менеджер запрещена — экспорт-хуки вкладывают наоборот);
    /// state-запросы — без локов; удаление — повторный короткий захват.
    pub fn sweep_dead_contexts(&self) -> usize {
        let keys: alloc::vec::Vec<u128> = {
            let inner = INNER.lock();
            inner.contexts.keys().copied().collect()
        };
        let mut dead = 0usize;
        for k in keys {
            let gone = gate::kernel_glue()
                .thread_state(ThreadId::from_u128(k))
                .is_none();
            if gone {
                if let Some(b) = INNER.lock().contexts.remove(&k) {
                    drop(b); // редкий путь — аллокатор, не пул (чужой поток)
                }
                dead += 1;
            }
        }
        // EEVDF-сущности + маршрутизация: обход всех очередей.
        dead += crate::lb::sweep_dead(&|id| {
            gate::kernel_glue().thread_state(ThreadId::from_u128(id)).is_none()
        });
        // Троттл-лист: мёртвые ссылки вычистим по пути (редкий случай).
        {
            let mut inner = INNER.lock();
            let stale: Vec<ThreadId> = inner
                .throttled
                .iter()
                .filter(|t| {
                    gate::kernel_glue().thread_state(**t).is_none()
                })
                .copied()
                .collect();
            for t in stale {
                if let Some(pos) = inner.throttled.iter().position(|&x| x == t) {
                    inner.throttled.remove(pos);
                }
                dead += 1;
            }
        }
        dead
    }

    /// Есть ли готовые в СВОЕЙ очереди? (зеркало lb::RDY — без локов;
    /// idle-петля до hlt успеет ещё украсть с витрины — см. gate.rs).
    pub fn has_ready(&self) -> bool {
        let cpu = arch::percpu::cpu_id() as usize;
        crate::lb::ready(cpu) != 0
    }

    // ==== TSC-deadline v0.13/v0.16 (точное вытеснение + advisory-уведомления) ====

    /// Зарядить текущему потоку исполненные циклы в EEVDF-сущность
    /// (vruntime += delta * NICE0 / weight; слайс-остаток уменьшается)
    /// + записать конец отрезка (v0.18: util-EWMA/last_ran — lb::charge_and_park).
    ///
    /// Вызывается ДО любой публикации состояния (rotate/троттл/блок):
    /// пока сущность числится running, заряд идёт по «горячему» пути;
    /// заряд опосле dequeue тоже корректен (сущность персистентна —
    /// сервис обязан быть учтён, см. charge в крейте).
    pub fn charge_current(&self, thread: ThreadId, delta_exec: u64) {
        if delta_exec == 0 {
            return;
        }
        let cpu = arch::percpu::cpu_id() as usize;
        crate::lb::charge_and_park(cpu, thread.as_u128(), delta_exec);
    }

    /// Взвести one-shot вытеснения для входящего потока (finalize; только
    /// в TSC-deadline-режиме): deadline = now + min(RR-квант, остаток
    /// бюджета домена, остаток CPU-периода). Домен без квоты — квант RR;
    /// троттленный ре-разбуженный поток (бюджет ~0) погаснет немедленно —
    /// квота больше не «до ближайшего тика».
    ///
    /// v0.16: если поток зарегистрировал advisory-гейт конца слайса
    /// (THREAD_SET_SLICE_NOTIFY) и до границы хватает места — таймер
    /// взводится на ГРАНИЦУ ПРЕДУПРЕЖДЕНИЯ (preempt_at - margin): при
    /// срабатывании timer_c доставит уведомление и перевзведёт реальную
    /// границу; поток продолжает исполняться. Семантика best-effort и
    /// ничего не энфорсит (см. gate::timer_c).
    pub fn arm_preempt_deadline(&self, thread: ThreadId) {
        if !crate::lapic::using_tsc_deadline() {
            return;
        }
        let now = crate::lapic::read_tsc();
        let mut span = quantum_cycles();
        let mut warn_gate = false;
        if let Some(glue) = startup::glue() {
            if let Some(left) = glue.cpu_budget_cycles_left(thread) {
                span = span.min(left);
            }
            // Advisory-канал конца слайса зарегистрирован? (один
            // read-лок менеджера на диспетчеризацию — рядом с
            // budget-запросом выше.)
            warn_gate = glue.slice_warn_gate(thread).is_some();
        }
        let end = PERIOD_END.load(Ordering::Acquire);
        if end > now {
            span = span.min(end - now);
        }
        let preempt_at = now.saturating_add(span.max(1));
        let cpu = arch::percpu::cpu_id() as usize;
        SLICE_PREEMPT_AT[cpu].store(preempt_at, Ordering::Relaxed);

        // Предупреждение: только при запасе > 2 маржи (иначе — сразу
        // реальная граница: слишком поздно предупреждать).
        let margin = slice_warn_margin_cycles();
        let warn_at = if warn_gate && span > margin.saturating_mul(2) {
            let at = preempt_at - margin;
            if at > now {
                at
            } else {
                0
            }
        } else {
            0
        };
        SLICE_WARN_AT[cpu].store(warn_at, Ordering::Relaxed);
        crate::lapic::arm_tsc_deadline(if warn_at != 0 { warn_at } else { preempt_at });
    }
}

impl SchedulerInterface for X86Sched {
    fn current(&self, cpu: CpuId) -> Option<TaskId> {
        // Крестное чтение GS чужого CPU — через его per-CPU блок
        // (владелец блоков — backend::cpu).
        if cpu as u64 == arch::percpu::cpu_id() as u64 {
            let tid = arch::percpu::current_thread();
            return if tid == 0 {
                None
            } else {
                Some(TaskId::from_u128(tid))
            };
        }
        let block = crate::cpu::percpu_block(cpu as usize);
        // SAFETY: чтение чужого блока (заполняется до старта владельца;
        // меняется только владельцем) — неатомарная пара lo/hi допустима
        // для диагностики (гонка даёт лишь смесь старых/новых половинок).
        unsafe {
            let lo = core::ptr::read_volatile(arch::percpu::block_ptr::<u64>(
                block,
                arch::percpu::OFF_CURRENT_THREAD,
            ));
            let hi = core::ptr::read_volatile(arch::percpu::block_ptr::<u64>(
                block,
                arch::percpu::OFF_CURRENT_THREAD + 8,
            ));
            if lo == 0 && hi == 0 {
                None
            } else {
                Some(TaskId::from_u128(((hi as u128) << 64) | lo as u128))
            }
        }
    }

    fn enqueue(&self, task: TaskId) -> Result<(), SchedulerError> {
        // Поток публикуется в Ready: контекст — из слота в карту ДО
        // публикации (write-гард менеджера держится — pick'ер заблокирован на
        // чтении состояния до коммита; локи очередей и карта локов не вкладывают).
        self.export_slot_if(task);
        // v0.18: размещение на домашнюю очередь (cache affinity; idle-цель
        // или push-assist при перегрузе) + точечный notify — см. lb.
        crate::lb::place_and_enqueue(task.as_u128());
        Ok(())
    }

    fn deschedule(&self, task: TaskId) -> Result<(), SchedulerError> {
        // Поток покидает Running (Blocked/Suspended/Dead). Контекст —
        // из слота в карту (свой CPU: блокируется/приостанавливается
        // только исполняющийся; кросс-CPU kill слот не трогает — там
        // ключ не совпадёт, чистка на стороне владельца).
        self.export_slot_if(task);
        // Eager-deschedule (v0.16): сущность — ИЗ очереди готовности
        // (вместо «ленивого отсева на pick»: фантомные веса портили бы
        // avg_vruntime EEVDF). Идемпотентно (запись могла быть уже
        // потреблена pick'ером — тогда это no-op). v0.18: сущность — на
        // ДОМАШНЕЙ очереди потока (lb::dequeue_from_home).
        let was_throttled = crate::lb::dequeue_from_home(task.as_u128());
        // Троттл-лист — точное удаление, но ТОЛЬКО для троттленных
        // (флаг в EEVDF-сущности): раньше — O(n) scan на КАЖДОЙ
        // блокировке потока (горячий путь IPC), теперь — O(log n)
        // проверка, редкий O(n) — только у действительно троттленных.
        if was_throttled {
            let mut inner = INNER.lock();
            if let Some(pos) = inner.throttled.iter().position(|&t| t == task) {
                inner.throttled.remove(pos);
            }
        }
        Ok(())
    }

    /// v0.16: приоритет = вес EEVDF (таблица nice-весов). Поток в очереди
    /// — перепозиционирование (дедлайн пересчитан под новый вес);
    /// исполняющийся — вес учтётся последующими зарядами. Вызывается и
    /// при СОЗДАНИИ потока (ядро сеет начальный приоритет до enqueue).
    /// v0.18: сущности может ещё не быть нигде (до первого enqueue) — вес
    /// паркуется в lb::HOME.pending и потребится при размещении (это
    /// чинит потерю сеянного приоритета первого слайса в v0.16).
    fn on_priority_change(
        &self,
        task: TaskId,
        priority: TaskPriority,
    ) -> Result<(), SchedulerError> {
        crate::lb::set_thread_weight(task.as_u128(), eevdf::weight_for_priority(priority.as_u8()));
        Ok(())
    }

    /// Физическое переключение выполняется гейтом на границе режимов
    /// (см. gate.rs): ядро в нашем потоке управления этот хук не зовёт.
    fn switch_context(
        &self,
        _cpu: CpuId,
        _prev: Option<TaskId>,
        _next: TaskId,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn isolation_policy(&self, _cpu: CpuId) -> IsolationPolicy {
        // Атомик: путь читается из памяти-операций (под ops-локом KMEM) —
        // без вложения SCHED-лока в KMEM (ранги).
        match POLICY.load(Ordering::Acquire) {
            1 => IsolationPolicy::MapFullKernel,
            _ => IsolationPolicy::UserTableIsolation,
        }
    }

    // ==== Block-очереди (IPC rendezvous, claims) ====

    fn block_queue_create(&self) -> Result<BlockQueueId, SchedulerError> {
        let mut inner = INNER.lock();
        let id = inner.next_queue_id;
        inner.next_queue_id += 1;
        inner.block_queues.insert(id, VecDeque::new());
        Ok(BlockQueueId::new(id))
    }

    fn block_queue_destroy(&self, queue: BlockQueueId) -> Result<(), SchedulerError> {
        let mut inner = INNER.lock();
        match inner.block_queues.remove(&queue.as_u64()) {
            Some(q) if q.is_empty() => Ok(()),
            Some(_) => Err(SchedulerError::Backend("block queue not empty")),
            None => Err(SchedulerError::Backend("unknown block queue")),
        }
    }

    fn block_push(&self, queue: BlockQueueId, thread: ThreadId) -> Result<(), SchedulerError> {
        let mut inner = INNER.lock();
        inner
            .block_queues
            .get_mut(&queue.as_u64())
            .ok_or(SchedulerError::Backend("unknown block queue"))?
            .push_back(thread);
        Ok(())
    }

    fn block_remove(&self, queue: BlockQueueId, thread: ThreadId) -> Result<bool, SchedulerError> {
        let mut inner = INNER.lock();
        let q = inner
            .block_queues
            .get_mut(&queue.as_u64())
            .ok_or(SchedulerError::Backend("unknown block queue"))?;
        if let Some(pos) = q.iter().position(|&t| t == thread) {
            q.remove(pos);
            return Ok(true);
        }
        Ok(false)
    }

    fn block_pop_front(&self, queue: BlockQueueId) -> Result<Option<ThreadId>, SchedulerError> {
        let mut inner = INNER.lock();
        Ok(inner
            .block_queues
            .get_mut(&queue.as_u64())
            .ok_or(SchedulerError::Backend("unknown block queue"))?
            .pop_front())
    }

    fn block_len(&self, queue: BlockQueueId) -> Result<usize, SchedulerError> {
        let inner = INNER.lock();
        inner
            .block_queues
            .get(&queue.as_u64())
            .map(|q| q.len())
            .ok_or(SchedulerError::Backend("unknown block queue"))
    }

    fn yield_now(&self, _current: ThreadId) -> Result<(), SchedulerError> {
        arch::percpu::set_need_resched();
        Ok(())
    }

    /// Тик планировщика — ТОЛЬКО периодический фолбэк (v0.13: в
    /// TSC-deadline-режиме квант — граница one-shot, тиков нет):
    /// уменьшить квант СВОЕГО CPU (per-CPU, без локов); при нуле —
    /// флаг resched.
    fn perform_tick(&self, delta: u64) {
        let _ = delta; // квант считаем тиками (см. gs:QUANTUM)
        let q = arch::percpu::quantum();
        if q > 0 {
            let q = q - 1;
            arch::percpu::set_quantum(q);
            if q == 0 {
                arch::percpu::set_need_resched();
            }
        }
    }
}

// ───────────────────── Часы периода (v0.13: TSC-граница) ─────────────────────

/// Пора закрывать период? (lock-free peek: rdtsc против PERIOD_END;
/// таймер/gate ставит need_resched, закрытие — `cpu_period_refill_if_due`).
pub fn period_due() -> bool {
    let end = PERIOD_END.load(Ordering::Acquire);
    end != 0 && crate::lapic::read_tsc() >= end
}

/// Текущая TSC-граница периода (idle-будка: взводит one-shot; 0 —
/// часы ещё не инициализированы, будка берёт now+период).
pub fn period_end_tsc() -> u64 {
    let end = PERIOD_END.load(Ordering::Acquire);
    if end != 0 {
        end
    } else {
        crate::lapic::read_tsc().saturating_add(period_cycles())
    }
}

/// Взвод будки idle (TSC-deadline): граница периода (перевзвод из ядра
/// — rearm_deadline_from_kernel — продлит её, а не уйдёт в эпсилон).
/// v0.16: граница пишется в SLICE_PREEMPT_AT (предупреждений в idle
/// нет — SLICE_WARN_AT гасится).
pub fn arm_idle_deadline() {
    let deadline = period_end_tsc();
    let cpu = arch::percpu::cpu_id() as usize;
    SLICE_PREEMPT_AT[cpu].store(deadline, Ordering::Relaxed);
    SLICE_WARN_AT[cpu].store(0, Ordering::Relaxed);
    crate::lapic::arm_tsc_deadline(deadline);
}

/// Перевзвод one-shot из ядра (timer_c !from_user: дедлайн сработал,
/// а preempt нельзя — держатель лока/спин). Границы ядра короткие:
/// перевзвод на следующую живую границу (предупреждение, если ещё
/// впереди; иначе реальная граница вытеснения) либо эпсилон —
/// вытеснение с первым же возвратом в пользователя.
///
/// v0.16: предупредительная граница, сработавшая в ЯДРЕ, — теряется
/// (доставка из прерывания под локами запрещена дисциплиной sync):
/// поток получит следующее предупреждение в следующем слайсе. Это
/// осознанная плата best-effort семантики API (ничего не энфорсит).
pub fn rearm_deadline_from_kernel() {
    let cpu = arch::percpu::cpu_id() as usize;
    let now = crate::lapic::read_tsc();
    let warn = SLICE_WARN_AT[cpu].load(Ordering::Relaxed);
    let preempt = SLICE_PREEMPT_AT[cpu].load(Ordering::Relaxed);
    let next = if preempt > now {
        if warn > now {
            warn
        } else {
            // Предупреждение сработало в ядре (или его не было) —
            // гасим и переводим будку на реальную границу.
            SLICE_WARN_AT[cpu].store(0, Ordering::Relaxed);
            preempt
        }
    } else {
        now.saturating_add(EPSILON_CYCLES)
    };
    crate::lapic::arm_tsc_deadline(next);
}

/// Граница CPU-периода (v0.13): TSC-часы, закрытие — CAS (один
/// победитель). Победивший: сброс учёта квот в ядре (glue) + возврат
/// троттл-листа в готовность + подмет мёртвых контекстов + resched-IPI.
///
/// Вызывается: preempt-шагом (первым делом — до заряда: свежий период
/// начинает счёт с нуля), idle-будкой после hlt, timer_c — только
/// флагом (need_resched) — закрытие НЕ из прерывания ядра (держатели
/// локов: вложенный захват менеджера из таймера — дедлок на спинах).
///
/// Возврат — был ли выполнен refill (idle по нему проверяет готовность).
pub fn cpu_period_refill_if_due() -> bool {
    let now = crate::lapic::read_tsc();
    // Ленивая инициализация часов (первый вызов): граница — now+период.
    if PERIOD_END.load(Ordering::Acquire) == 0 {
        let _ = PERIOD_END.compare_exchange(
            0,
            now.saturating_add(period_cycles()),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        return false;
    }
    // Продвижение границы до будущего: каждый успешный CAS — один
    // шаг периода; победитель шага делает refill (долгий простой
    // закрывает несколько шагов — пропущенные границы безвредны:
    // счётчики доменов уже пусты).
    let mut refilled = false;
    loop {
        let end = PERIOD_END.load(Ordering::Acquire);
        if now < end {
            break;
        }
        match PERIOD_END.compare_exchange(
            end,
            end.saturating_add(period_cycles()),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                refilled = true;
            }
            Err(_) => continue, // другой CPU продвинул — переоценка
        }
    }
    if !refilled {
        return false;
    }
    if let Some(glue) = startup::glue() {
        glue.on_cpu_period();
        let n = SCHED.unthrottle_all();
        let _ = SCHED.sweep_dead_contexts();
        // Будим нужных: unthrottle_all уже разослал (idle/urgent).
        let _ = n;
    }
    true
}

// ───────────────────── Диспетчеризация (гейт вызывает) ─────────────────────

/// Вытеснение текущего потока с учётом CPU-квот (v0.10..v0.16).
///
/// Единый preempt-шаг гейта (вызывается и из timer_c, и из выхода из
/// сискола — то есть при квант-истечении, IPI-resched и THREAD_YIELD):
///   1. закрыть границу CPU-периода (refill квот — до заряда: свежий
///      период начинает счёт с нуля, заряд в старый невозможен);
///   2. зарядить домену владельца циклы отрезка (rdtsc-разность с
///      метки диспетчеризации; субтик-точно, включая ядровые участки;
///      анти-спин-пол — min_charge_cycles: 1 тик за проход, как v0.10)
///      через glue (ядро решает: троттлить домен или исполняться дальше);
///   2b. зарядить EEVDF-сущность потока (v0.16: vruntime += delta —
///      ДО любой публикации, чтобы rotate/троттл/блок работали с уже
///      учтённым сервисом);
///   3. СОХРАНИТЬ КОНТЕКСТ в per-CPU слот (без локов; публикация —
///      только после сохранения: другой CPU войдёт в поток со старым
///      контекстом в окне между enqueue и save — невозможно);
///   4. публикация: requeue (Running -> Ready + enqueue-хук: экспорт
///      слота в карту + EEVDF-rotate — дедлайн сохраняется, пока жив
///      слайс) или троттл-парк (Ready без очереди + троттл-лист;
///      экспорт — внутри throttle_current);
///      отказ публикации (поток убит в окне) — слот гасим в пул;
///   5. schedule_next (не возвращается).
///
/// Замечание о гранулярности: домен, чей квот перебран, может иметь
/// второй поток в готовности — он отработает до одного вытеснения
/// (ограниченный перерасход ≤ живые_потоки × квант на границу; в
/// TSC-deadline-режиме перерасход дополнительно срезается точным
/// дедлайном бюджета каждого входящего потока).
pub fn preempt_step(ctx: Box<UserCtx>) -> ! {
    cpu_period_refill_if_due();
    let cpu = arch::percpu::cpu_id() as usize;
    let mut throttled = false;
    let mut exec_cycles = 0;
    if let Some(cur) = SCHED.current_thread() {
        exec_cycles = SCHED.cycles_since_dispatch().max(min_charge_cycles());
        // 2b (v0.16): EEVDF-заряд ДО любой публикации — rotate сохранит
        // дедлайн только при уже учтённом vruntime. v0.18: заодно — конец
        // отрезка (util-EWMA/last_ran) + CUR_DL=0 (уходим с CPU).
        SCHED.charge_current(cur, exec_cycles);
    }
    if let Some(glue) = startup::glue() {
        if let Some(cur) = SCHED.current_thread() {
            throttled = glue.on_cpu_cycles_consumed(cur, exec_cycles);
        }
    }
    if let Some(cur) = SCHED.current_thread() {
        // Шаг 3: контекст — в слот, ДО любой публикации готовности.
        SCHED.save_context(cur, ctx);
        // Шаг 4: публикация через автомат состояний ядра.
        if let Some(glue) = startup::glue() {
            if throttled && glue.throttle_thread(cur) {
                // Running -> Ready без очереди: троттл-лист до границы
                // периода (контекст экспортирован внутри — возобновление
                // после unthrottle возьмёт его из карты).
                SCHED.throttle_current();
            } else {
                // Rotate (EEVDF): Ready + домашняя очередь (enqueue-хук
                // экспортирует слот ДО публикации; rotate-путь в крейте
                // сохранит дедлайн, пока слайс не исчерпан). Отказ (поток
                // убит в окне вытеснения) — без ре-очереди: слот в пул,
                // дальше — «поток уже не наш».
                let requeued = glue.requeue_thread(cur);
                if !requeued {
                    SCHED.release_slot_if(cur);
                    // Публикация не состоялась: сущность обязана покинуть
                    // running-набор (поток больше не диспетчеризован нами).
                    crate::lb::dequeue_from_home(cur.as_u128());
                }
            }
        } else {
            // До kinit (idle-холостой путь) — квот и glue нет: экспорт
            // слота в карту и прямой rotate (SMP ещё спит — конкуренции
            // нет; слот обязан покинуть CPU: дальше schedule_next).
            SCHED.export_slot_if(cur);
            crate::lb::place_and_enqueue(cur.as_u128());
        }
    }
    // v0.18: сервис границы preempt — публикация витрины (гистерезис
    // давления + hard-starvation подкрутка idle), обработка вариант-B
    // заявок воров, редкий периодический steal недогруженного ядра.
    // Своё состояние уже опубликовано выше — конфликта с enqueue нет.
    crate::lb::on_preempt(cpu);
    schedule_next()
}

/// Выбрать следующий поток и уйти в него (не возвращается).
///
/// Порядок: дренаж inbox'а мигрантов (вариант-B доставки — до pick'а:
/// воры уже в Ready) → валидация состояния (eager-deschedule v0.16
/// убрал протухшие записи из очередей по построению; остаточный
/// отсев — гонки переходов: поток покинул Ready МЕЖДУ нашим pick и
/// mark_running) → activate CR3 владельца → mark_running (финальная
/// защита Ready→Running) → switch_to(ctx). Нет готовых — idle-цикл
/// (см. gate::idle_loop: перед hlt — дренаж inbox + попытка кражи
/// с витрины): сюда не возвращаемся.
pub fn schedule_next() -> ! {
    let cpu = arch::percpu::cpu_id() as usize;
    loop {
        // v0.18: мигранты из inbox (вариант B) — полноправные Ready.
        crate::lb::drain_handoffs(cpu);
        let next = match SCHED.pick_next() {
            Some(t) => t,
            None => {
                gate::idle_loop();
            }
        };
        // Защита от гонок переходов (см. выше): запись могла быть
        // потреблена pick'ером одновременно с уходом потока из Ready
        // (kill/suspend кросс-CPU). Мёртвых НЕ reap-им (владелец
        // состояния — их собственные пути), просто мимо.
        match gate::kernel_glue().thread_state(next) {
            Some(pkg_generic_interface::task::TaskState::Ready) => {}
            _ => {
                continue;
            }
        }
        // Пространство владельца (до переключения: ядро живёт в своём
        // отображении; таблицы пользователя загрузятся перед sysret).
        if !gate::activate_thread_space(next) {
            // Нет пространства — поток неисполним: погасить и дальше.
            gate::reap_thread(next);
            continue;
        }
        let ctx = match SCHED.context_of(next) {
            Some(c) => c,
            None => {
                // Нет start_info — поток без точки входа (битый): погасить.
                gate::reap_thread(next);
                continue;
            }
        };
        // Финальная защита от воскрешения: Ready→Running под write-гардом
        // TCB; провал (Kill в окне между валидацией и запуском) = мимо.
        if !gate::mark_running(next) {
            // Контекст уже изъят (наш inflight): рециклинг произойдёт на
            // следующем context_of этого CPU — ок; поток мёртв — мимо.
            continue;
        }
        gate::finalize_and_enter(next, ctx);
    }
}

/// Число паркованных контекстов (для отчёта; v0.13: карта — только
/// не-Running, Running-контексты живут в per-CPU слотах).
pub fn context_count() -> usize {
    INNER.lock().contexts.len()
}
