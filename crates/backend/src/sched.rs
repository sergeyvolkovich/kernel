// ==== Планировщик-бекенд x86_64 (v0.12: SMP fine-grained; v0.10: CPU-квоты) ====
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
//   * контексты/block-очереди/троттл-лист — короткий KSpin (лист);
//   * политика изоляции — атомик (запись один раз до старта SMP):
//     `isolation_policy` читается из памяти-путей (под ops-локом KMEM),
//     вложенность KMEM→SCHED исключена (лист);
//   * текущий поток/квант/флаги — per-CPU (GS), как раньше;
//   * eager FPU: fxsave/fxrstor на каждом переключении (без CR0.TS).
//
// CPU-квоты v0.10 (троттлинг песочницы) — семантика сохранена:
//   * учёт — в GTCB доменов, решение — ядро через glue
//     (`on_timeslice_consumed`), бекенд паркует поток в троттл-лист;
//   * период — ГЛОБАЛЬНЫЙ счётчик тиков `CPU_TICKS` (атомик, все CPU);
//   * граница периода — флаг `CPU_PERIOD_WRAP` (снимает preempt-путь/
//     idle-будка), дренаж троттл-листа + resched-IPI;
//   * заряд — при каждом вытеснении: max(1, slice_used) тиков.
//
// Инвариант IF (см. `kernel::sync`): держатели локов — IF=0; спин на
// глубине 0 — IF=1 (доставка IPI: shootdown-ACK/resched).

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use pkg_generic_interface::hal::traits::kmap::IsolationPolicy;
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
        let mut ctx = Self {
            rip: entry as u64,
            rflags: arch::boot::USER_RFLAGS,
            rsp: stack_top as u64,
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
        };
        // Валидное чистое состояние x87/SSE для fxrstor: FCW=0x037F,
        // MXCSR=0x1F80 (иначе #GP на fxrstor).
        ctx.fx[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        let mxcsr_off = 24; // FXSAVE: MXCSR @ 24
        ctx.fx[mxcsr_off..mxcsr_off + 4].copy_from_slice(&0x1F80u32.to_le_bytes());
        ctx
    }
}

// ───────────────────── Готовность: lock-free MPMC (Vyukov) ─────────────────────

/// Ёмкость кольца готовности: квота потоков системы — 512 (таблица
/// ThreadInner), плюс переходные дубли ленивого deschedule (Suspended→
/// Ready повторный enqueue при живой записи) — 1024 даёт двукратный запас.
/// Переполнение — честный отказ enqueue (полный откат создания хуком).
const READY_CAPACITY: usize = 1024;

/// Глобальная очередь готовности: lock-free MPMC-кольцо (см. `sync`).
/// Инвариант «≤1 записи на поток»: enqueue — только из переходов *→Ready
/// (хуки TCB под write-гардом) и rotate собственного потока (per-CPU
/// эксклюзив); повторный enqueue при живой записи возможен только через
/// Suspended→Ready (запись отсеется на pick по состоянию) — дубли
/// безопасны и коротложивущи.
static READY: pkg_generic_interface::sync::MpmcQueue<ThreadId, READY_CAPACITY> =
    pkg_generic_interface::sync::MpmcQueue::new();

// ───────────────────── Состояние планировщика (KSpin — лист) ─────────────────────

struct Inner {
    /// Троттл-лист CPU-квот (v0.10): потоки доменов, перебравших
    /// `cpu_quota`, — до границы периода. Контексты — в `contexts`
    /// (парковка как у Blocked), из готовности исключены.
    throttled: VecDeque<ThreadId>,
    /// Контексты живых потоков (создаются при первом входе / сохраняются
    /// при переключении).
    contexts: BTreeMap<u128, Box<UserCtx>>,
    /// Block-очереди (IPC-endpoint'ы, claims): FIFO.
    block_queues: BTreeMap<u64, VecDeque<ThreadId>>,
    next_queue_id: u64,
}

/// Бекенд-состояние, НЕ попавшее в lock-free структуры: короткий
/// спин-лок (лист: под ним другие ядровые локи не берутся).
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

// ── ВРЕМЕННАЯ ДИАГНОСТИКА v0.12-bringup (убрать после отладки) ──
pub static DBG_ENQ: AtomicU64 = AtomicU64::new(0);
pub static DBG_POP: AtomicU64 = AtomicU64::new(0);
pub static DBG_STALE: AtomicU64 = AtomicU64::new(0);
pub static DBG_MARKFAIL: AtomicU64 = AtomicU64::new(0);
pub static DBG_ENTER: AtomicU64 = AtomicU64::new(0);

/// Снимок счётчиков (print в idle).
pub fn dbg_snapshot() -> [u64; 5] {
    [
        DBG_ENQ.load(Ordering::Relaxed),
        DBG_POP.load(Ordering::Relaxed),
        DBG_STALE.load(Ordering::Relaxed),
        DBG_MARKFAIL.load(Ordering::Relaxed),
        DBG_ENTER.load(Ordering::Relaxed),
    ]
}

// ───────────────────── CPU-квоты v0.10: период и троттлинг ─────────────────────

/// Длина CPU-периода — ГЛОБАЛЬНЫХ тиков всех CPU (тик = 1/SCHED_HZ с).
/// 2 CPU ≈ 100 тиков/с суммарно → период ≈ 1 с стена; квота домена —
/// доля от этого бюджета (12 из 100 ≈ 12% CPU).
pub const CPU_PERIOD_TICKS: u64 = 100;

/// Глобальный счётчик тиков периода (инкремент — `note_wall_tick`,
/// вызывается из timer_c на КАЖДОМ тике: пользовательском, ядровом,
/// idle — иначе троттл-лист зависнет без будящего источника).
static CPU_TICKS: AtomicU64 = AtomicU64::new(0);

/// Флаг «период завершился — нужен refill». Ставит `note_wall_tick`,
/// снимает (once) preempt-путь/idle-будка.
static CPU_PERIOD_WRAP: AtomicBool = AtomicBool::new(false);

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
    pub fn save_context(&self, thread: ThreadId, ctx: Box<UserCtx>) {
        INNER.lock().contexts.insert(thread.as_u128(), ctx);
    }

    /// Перевыпуск нужен? (гейт проверяет на выходе из сискола; флаг
    /// ставится тиком или resched-IPI — per-CPU, без блокировок).
    pub fn take_need_resched(&self) -> bool {
        arch::percpu::take_need_resched()
    }

    /// Квант текущего потока истёк? (тик уменьшает квант своего CPU;
    /// сюда гейт заходит уже с need_resched — атомарное снятие).
    pub fn quantum_expired(&self) -> bool {
        arch::percpu::quantum() == 0
    }

    /// Выбрать следующий поток: lock-free pop из кольца готовности.
    /// None — пусто. Валидация живости (ленивый deschedule) — в
    /// [`schedule_next`] (нужен glue для чтения состояния TCB).
    ///
    /// Квант СВОЕМУ CPU (GS); SCHED_HZ/10 тиков ~ 100 мс. v0.10:
    /// и счётчик потреблённых тиков в ноль — заряд домену с чистого
    /// листа (см. preempt_step: max(1, slice_used) за вытеснение).
    pub fn pick_next(&self) -> Option<ThreadId> {
        let next = READY.pop()?;
        DBG_POP.fetch_add(1, Ordering::Relaxed);
        arch::percpu::set_quantum(arch::boot::SCHED_HZ / 10);
        arch::percpu::set_slice_used(0);
        Some(next)
    }

    /// Вернуть текущий поток в хвост (rotate, RR) — гейт при вытеснении.
    ///
    /// SMP v0.12: публикация — ТОЛЬКО через автомат состояний
    /// (`glue.requeue_thread`: Running -> Ready + enqueue-хук). Прямой
    /// пуш в кольцо без перехода — баг bring-up: ленивая валидация pick
    /// отсеивала записи по состоянию (Running) — вытесненные потоки
    /// терялись навсегда. Метод сохранён для диагностики.
    #[allow(dead_code)]
    pub fn rotate_current(&self) {
        if let Some(t) = self.current_thread() {
            let _ = READY.push(t);
        }
    }

    // ==== CPU-квоты v0.10 (троттлинг песочницы) ====

    /// Отметить глобальный тик периода (timer_c — КАЖДЫЙ тик ЛЮБОГО CPU,
    /// ДО развилки user/kernel/idle: иначе троттл-лист зависнет без
    /// будящего источника). Возврат `true` — период завершился:
    /// вызывающий ставит need_resched/refill-обработку.
    pub fn note_wall_tick(&self) -> bool {
        let t = CPU_TICKS.fetch_add(1, Ordering::Relaxed) + 1;
        if t % CPU_PERIOD_TICKS == 0 {
            CPU_PERIOD_WRAP.store(true, Ordering::Release);
            return true;
        }
        false
    }

    /// Есть ли незакрытая граница периода? (idle-будка — дешёвый peek
    /// без локов; once-снятие — `take_period_wrap` в refill-пути.)
    pub fn period_wrap_pending(&self) -> bool {
        CPU_PERIOD_WRAP.load(Ordering::Acquire)
    }

    /// Снять флаг границы периода (кто снял — тот и делает refill).
    pub fn take_period_wrap(&self) -> bool {
        CPU_PERIOD_WRAP.swap(false, Ordering::AcqRel)
    }

    /// Тики, потреблённые текущим потоком с диспетчеризации, — снять
    /// (сам заряд домену — в preempt-шаге через glue; минимум 1 — там).
    pub fn take_slice_used(&self) -> u64 {
        let v = arch::percpu::slice_used();
        arch::percpu::set_slice_used(0);
        v
    }

    /// Запарковать текущий поток в троттл-лист (домен за пределом
    /// cpu_quota): НЕ возвращается в готовность до границы периода.
    /// Контекст уже сохранён в `contexts` парком preempt-шага.
    pub fn throttle_current(&self) {
        if let Some(t) = self.current_thread() {
            INNER.lock().throttled.push_back(t);
        }
    }

    /// Граница периода: дренаж троттл-листа в готовность (FIFO-порядок
    /// сохранён). Возврат — число возвращённых потоков; гейт по >0
    /// рассылает resched-IPI (будим idle-CPU).
    pub fn unthrottle_all(&self) -> usize {
        let mut inner = INNER.lock();
        let n = inner.throttled.len();
        while let Some(t) = inner.throttled.pop_front() {
            let _ = READY.push(t);
        }
        n
    }

    /// Число потоков в троттл-листе (диагностика/аудит).
    pub fn throttled_count(&self) -> usize {
        INNER.lock().throttled.len()
    }

    /// Контекст потока (первый вход — построить из start_info).
    pub fn context_of(&self, thread: ThreadId) -> Option<Box<UserCtx>> {
        {
            let inner = INNER.lock();
            if let Some(ctx) = inner.contexts.get(&thread.as_u128()) {
                // Клонирование fx (680 Б) — переключение не горячее.
                let mut copy: Box<UserCtx> = Box::new(UserCtx {
                    rip: ctx.rip,
                    rflags: ctx.rflags,
                    rsp: ctx.rsp,
                    rax: ctx.rax,
                    rbx: ctx.rbx,
                    rcx: ctx.rcx,
                    rdx: ctx.rdx,
                    rsi: ctx.rsi,
                    rdi: ctx.rdi,
                    rbp: ctx.rbp,
                    r8: ctx.r8,
                    r9: ctx.r9,
                    r10: ctx.r10,
                    r11: ctx.r11,
                    r12: ctx.r12,
                    r13: ctx.r13,
                    r14: ctx.r14,
                    r15: ctx.r15,
                    fx: [0; 512],
                });
                copy.fx.copy_from_slice(&ctx.fx);
                return Some(copy);
            }
        }
        // Первый вход: (entry, stack) из ядра.
        let (entry, stack) = gate::kernel_glue().thread_start_info(thread)?;
        Some(Box::new(UserCtx::fresh(entry, stack)))
    }

    /// Забыть контекст мёртвого потока (гейт после reap).
    pub fn drop_context(&self, thread: ThreadId) {
        INNER.lock().contexts.remove(&thread.as_u128());
    }

    /// Есть ли готовые? (lock-free peek: длина — атомик; лишние
    /// пробуждения idle отсеет schedule_next).
    pub fn has_ready(&self) -> bool {
        !READY.is_empty()
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
        // Lock-free push из хука TCB (write-гард менеджера держится —
        // MPMC локов не берёт, инверсии рангов нет).
        DBG_ENQ.fetch_add(1, Ordering::Relaxed);
        READY
            .push(task)
            .map_err(|_| SchedulerError::Backend("ready ring full"))?;
        // Разбудить прочие CPU (idle-hlt или пограничный квант): флаг им
        // поставит IPI-обработчик. Шторм IPI на всплесках готовности —
        // принятая цена простоты (QEMU-масштаб).
        if crate::smp::online_mask() & !1 != 0 {
            crate::lapic::broadcast_others(arch::boot::VEC_IPI_RESCHED);
        }
        Ok(())
    }

    fn deschedule(&self, task: TaskId) -> Result<(), SchedulerError> {
        // Готовность — ЛЕНИВО: запись (если есть) отсеет pick по
        // состоянию TCB; удаление из кольца невозможно без обхода.
        // Троттл-лист — точное удаление (поток мог быть припаркован
        // квотой, когда его погасили (Dead-каскад) или приостановили).
        let mut inner = INNER.lock();
        if let Some(pos) = inner.throttled.iter().position(|&t| t == task) {
            inner.throttled.remove(pos);
        }
        Ok(())
    }

    fn on_priority_change(
        &self,
        _task: TaskId,
        _priority: TaskPriority,
    ) -> Result<(), SchedulerError> {
        // v0.5: одна очередь; переоценка порядка — будущая итерация.
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

    /// Тик планировщика: уменьшить квант СВОЕГО CPU (per-CPU, без локов —
    //  вызывается timer_c на быстром пути); при нуле — флаг resched.
    /// v0.10: копит и `slice_used` — потреблённые тики текущего потока
    /// (заряд домену — при вытеснении в preempt-шаге).
    fn perform_tick(&self, delta: u64) {
        let _ = delta; // квант считаем тиками (см. gs:QUANTUM)
        arch::percpu::set_slice_used(arch::percpu::slice_used() + 1);
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

// ───────────────────── Диспетчеризация (гейт вызывает) ─────────────────────

/// Граница CPU-периода (v0.10): сбросить учёт квот в ядре + вернуть
/// троттл-лист в готовность. Кто снял флаг — тот и выполнил (один раз
/// на границу). Возврат — был ли refill.
///
/// Вызывается: preempt-шагом (timer_c/выход из сискола), idle-будкой —
/// до разбора очередей готовности. Локи: атомик-флаг → glue (TCB
/// write) → троттл-дренаж (SchedKSpin) — последовательно, без гнёзд.
pub fn cpu_period_refill_if_due() -> bool {
    if !SCHED.take_period_wrap() {
        return false;
    }
    if let Some(glue) = startup::glue() {
        glue.on_cpu_period();
        let n = SCHED.unthrottle_all();
        if n > 0 {
            // Разбудить прочие CPU: в готовности появились потоки
            // (как enqueue — шторм IPI на всплесках принят ценой простоты).
            if crate::smp::online_mask() & !1 != 0 {
                crate::lapic::broadcast_others(arch::boot::VEC_IPI_RESCHED);
            }
        }
    }
    true
}

/// Вытеснение текущего потока с учётом CPU-квот (v0.10/v0.12).
///
/// Единый preempt-шаг гейта (вызывается и из timer_c, и из выхода из
/// сискола — то есть при квант-истечении, IPI-resched и THREAD_YIELD):
///   1. закрыть границу CPU-периода (refill квот — до заряда: свежий
///      период начинает счёт с нуля, заряд в старый невозможен);
///   2. зарядить домену владельца max(1, slice_used) тиков через glue
///      (ядро решает: троттлить домен или ещё можно исполняться);
///   3. СОХРАНИТЬ КОНТЕКСТ (SMP v0.12: публикация готовности — только
///      после сохранения: иначе другой CPU войдёт в поток со старым
///      контекстом в окне между enqueue и save);
///   4. публикация: requeue (Running -> Ready + enqueue-хук) или
///      троттл-парк (Ready без очереди + троттл-лист);
///   5. schedule_next (не возвращается).
///
/// Замечание о гранулярности: домен, чей квот перебран, может иметь
/// второй поток в готовности — он отработает до одного вытеснения
/// (ограниченный перерасход ≤ живые_потоки × квант на границу).
pub fn preempt_step(ctx: Box<UserCtx>) -> ! {
    cpu_period_refill_if_due();
    let mut throttled = false;
    if let Some(glue) = startup::glue() {
        if let Some(cur) = SCHED.current_thread() {
            // Минимум 1 тик за проход диспетчеризации: yield-цикл не
            // дешевле честного кванта (анти-спин-лазейка для квот).
            let used = SCHED.take_slice_used().max(1) as usize;
            throttled = glue.on_timeslice_consumed(cur, used);
        }
    }
    if let Some(cur) = SCHED.current_thread() {
        // Шаг 3: контекст — ДО любой публикации готовности.
        SCHED.save_context(cur, ctx);
        // Шаг 4: публикация через автомат состояний ядра.
        if let Some(glue) = startup::glue() {
            if throttled && glue.throttle_thread(cur) {
                // Running -> Ready без очереди: в троттл-лист до
                // границы периода (контекст уже сохранён — возобновление
                // возьмёт его как есть).
                SCHED.throttle_current();
            } else {
                // Rotate (RR): Ready + кольцо (+ resched-IPI из хука).
                // Отказ (поток убит/приостановлен в окне вытеснения) —
                // без ре-очереди: дальше — «поток уже не наш».
                let _ = glue.requeue_thread(cur);
            }
        } else {
            // До kinit (idle-холостой путь) — квот и glue нет: rotate.
            let _ = READY.push(cur);
        }
    }
    schedule_next()
}

/// Выбрать следующий поток и уйти в него (не возвращается).
///
/// Порядок: валидация состояния (ленивый deschedule: записи мёртвых/
/// заблокированных отсеиваются) → activate CR3 владельца →
/// mark_running (финальная защита Ready→Running) → switch_to(ctx).
/// Нет готовых — idle-цикл (см. gate::idle_loop): сюда не возвращаемся.
pub fn schedule_next() -> ! {
    loop {
        let next = match SCHED.pick_next() {
            Some(t) => t,
            None => {
                gate::idle_loop();
            }
        };
        // Ленивый deschedule: запись могла протухнуть (поток перевели в
        // Blocked/Suspended/Dead после enqueue; либо это UUID задачи из
        // легаси task-level set_state — потоков с таким ID нет). Мёртвых
        // НЕ reap-им (владелец состояния — их собственные пути), просто мимо.
        match gate::kernel_glue().thread_state(next) {
            Some(pkg_generic_interface::task::TaskState::Ready) => {}
            _ => {
                DBG_STALE.fetch_add(1, Ordering::Relaxed);
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
            DBG_MARKFAIL.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        DBG_ENTER.fetch_add(1, Ordering::Relaxed);
        gate::finalize_and_enter(next, ctx);
    }
}

/// Число живых контекстов (для отчёта).
pub fn context_count() -> usize {
    INNER.lock().contexts.len()
}
