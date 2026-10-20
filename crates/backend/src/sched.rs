// ==== Планировщик-бекенд x86_64 (v0.6: SMP, глобальная очередь + per-CPU) ====
//
// Реализация контракта `SchedulerInterface` ядра + собственные структуры
// диспетчеризации (контексты пользовательских потоков, очередь готовности,
// block-очереди IPC/claims). Политики v0.6 (SMP):
//
//   * ОДНА глобальная очередь готовности (FIFO/RR) — все CPU тянут из
//     неё под BKL; пер-процессорных очередей/stealing нет (следующая
//     итерация); миграция потока между CPU — бесплатный побочный эффект;
//   * текущий поток/квант/флаг перепланировки — per-CPU (GS-блок):
//     тик уменьшает квант СВОЕГО CPU, IPI-resched ставит флаг чужому;
//   * enqueue под BKL рассылает resched-IPI остальным (будим idle);
//   * eager FPU: fxsave/fxrstor на каждом переключении (без CR0.TS);
//   * контексты/block-очереди — глобальные (BKL сериализует доступ).
//
// Инвариант BKL (klock.rs): все методы ядра выполняются держателем BKL;
// быстрые per-CPU пути (тик, флаги) в атомиках/GS — без BKL.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
};
use spin::Mutex;

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

// ───────────────────── Состояние планировщика ─────────────────────

struct Inner {
    /// Готовность (FIFO, RR) — глобальная, все CPU под BKL.
    ready: VecDeque<ThreadId>,
    /// Контексты живых потоков (создаются при первом входе / сохраняются
    /// при переключении).
    contexts: BTreeMap<u128, Box<UserCtx>>,
    /// Block-очереди (IPC-endpoint'ы, claims): FIFO.
    block_queues: BTreeMap<u64, VecDeque<ThreadId>>,
    next_queue_id: u64,
    /// Изоляция (MapFullKernel после проверки RDCL_NO на старте).
    policy: IsolationPolicy,
}

pub struct X86Sched {
    inner: Mutex<Inner>,
}

static SCHED: X86Sched = X86Sched {
    inner: Mutex::new(Inner {
        ready: VecDeque::new(),
        contexts: BTreeMap::new(),
        block_queues: BTreeMap::new(),
        next_queue_id: 1,
        policy: IsolationPolicy::conservative(),
    }),
};

/// Ссылка на планировщик (установка в TcbManager::install_scheduler).
pub fn scheduler() -> &'static X86Sched {
    &SCHED
}

/// Зафиксировать политику изоляции (после RDCL_NO-проверки на старте).
pub fn set_isolation_policy(policy: IsolationPolicy) {
    SCHED.inner.lock().policy = policy;
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
        self.inner.lock().contexts.insert(thread.as_u128(), ctx);
    }

    /// Перевыпуск нужен? (гейт проверяет на выходе из сискола; флаг
    /// ставится тиком или resched-IPI — per-CPU, без блокировок).
    pub fn take_need_resched(&self) -> bool {
        arch::percpu::take_need_resched()
    }

    /// Квант текущего потока истёк? (тик уменьшает квант своего CPU;
    /// сюда гейт заходит уже с need_resched — атомарное снятие).
    pub fn quantum_expired(&self) -> bool {
        // v0.6: квант живёт в GS; уменьшение — в perform_tick. Здесь
        // только вопрос «ноль ли» (снятие не требуется).
        arch::percpu::quantum() == 0
    }

    /// Выбрать следующий поток: глобальная очередь готовности. None — idle.
    ///
    /// Вызывается гейтом (под BKL); Ready→Running меняет ядро через glue
    /// (mark_running) — здесь только очередь + пер-процессорные поля.
    pub fn pick_next(&self) -> Option<ThreadId> {
        let next = self.inner.lock().ready.pop_front()?;
        // Квант СВОЕМУ CPU (GS); SCHED_HZ/10 тиков ~ 100 мс.
        arch::percpu::set_quantum(arch::boot::SCHED_HZ / 10);
        Some(next)
    }

    /// Вернуть текущий поток в хвост (rotate, RR) — гейт при вытеснении.
    pub fn rotate_current(&self) {
        if let Some(t) = self.current_thread() {
            let mut inner = self.inner.lock();
            inner.ready.push_back(t);
        }
    }

    /// Контекст потока (первый вход — построить из start_info).
    pub fn context_of(&self, thread: ThreadId) -> Option<Box<UserCtx>> {
        {
            let inner = self.inner.lock();
            if let Some(ctx) = inner.contexts.get(&thread.as_u128()) {
                // Клонирование fx (680 Б) — переключение не горячее в v0.6.
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
        // Первый вход: (entry, stack_top) из ядра.
        let (entry, stack) = gate::kernel_glue().thread_start_info(thread)?;
        Some(Box::new(UserCtx::fresh(entry, stack)))
    }

    /// Забыть контекст мёртвого потока (гейт после reap).
    pub fn drop_context(&self, thread: ThreadId) {
        self.inner.lock().contexts.remove(&thread.as_u128());
    }

    /// Есть ли готовые?
    pub fn has_ready(&self) -> bool {
        !self.inner.lock().ready.is_empty()
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
        self.inner.lock().ready.push_back(task);
        // Разбудить прочие CPU (idle-hlt или пограничный квант): флаг им
        // поставит IPI-обработчик. Шторм IPI на всплесках готовности —
        // принятая цена простоты v0.6 (QEMU-масштаб).
        if crate::smp::online_mask() & !1 != 0 {
            crate::lapic::broadcast_others(arch::boot::VEC_IPI_RESCHED);
        }
        Ok(())
    }

    fn deschedule(&self, task: TaskId) -> Result<(), SchedulerError> {
        let mut inner = self.inner.lock();
        if let Some(pos) = inner.ready.iter().position(|&t| t == task) {
            inner.ready.remove(pos);
        }
        Ok(())
    }

    fn on_priority_change(
        &self,
        _task: TaskId,
        _priority: TaskPriority,
    ) -> Result<(), SchedulerError> {
        // v0.5: одна очередь; переоценка порядка — v0.6 (multi-queue).
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
        self.inner.lock().policy
    }

    // ==== Block-очереди (IPC rendezvous, claims) ====

    fn block_queue_create(&self) -> Result<BlockQueueId, SchedulerError> {
        let mut inner = self.inner.lock();
        let id = inner.next_queue_id;
        inner.next_queue_id += 1;
        inner.block_queues.insert(id, VecDeque::new());
        Ok(BlockQueueId::new(id))
    }

    fn block_queue_destroy(&self, queue: BlockQueueId) -> Result<(), SchedulerError> {
        let mut inner = self.inner.lock();
        match inner.block_queues.remove(&queue.as_u64()) {
            Some(q) if q.is_empty() => Ok(()),
            Some(_) => Err(SchedulerError::Backend("block queue not empty")),
            None => Err(SchedulerError::Backend("unknown block queue")),
        }
    }

    fn block_push(&self, queue: BlockQueueId, thread: ThreadId) -> Result<(), SchedulerError> {
        let mut inner = self.inner.lock();
        inner
            .block_queues
            .get_mut(&queue.as_u64())
            .ok_or(SchedulerError::Backend("unknown block queue"))?
            .push_back(thread);
        Ok(())
    }

    fn block_remove(&self, queue: BlockQueueId, thread: ThreadId) -> Result<bool, SchedulerError> {
        let mut inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
        Ok(inner
            .block_queues
            .get_mut(&queue.as_u64())
            .ok_or(SchedulerError::Backend("unknown block queue"))?
            .pop_front())
    }

    fn block_len(&self, queue: BlockQueueId) -> Result<usize, SchedulerError> {
        let inner = self.inner.lock();
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

    /// Тик планировщика: уменьшить квант СВОЕГО CPU (per-CPU, без BKL —
    //  вызывается timer_c на быстром пути); при нуле — флаг resched.
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

// ───────────────────── Диспетчеризация (гейт вызывает) ─────────────────────

/// Выбрать следующий поток и уйти в него (не возвращается).
///
/// Порядок: activate CR3 владельца → mark_running → switch_to(ctx).
/// Нет готовых — idle-цикл (см. gate::idle_loop): сюда не возвращаемся.
pub fn schedule_next() -> ! {
    loop {
        let next = match SCHED.pick_next() {
            Some(t) => t,
            None => {
                gate::idle_loop();
            }
        };
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
        gate::mark_running(next);
        gate::finalize_and_enter(next, ctx);
    }
}

/// Текущий контекст сохранения: вызвать перед schedule_next при блокировке
/// (гейт собрал UserCtx из фрейма).
pub fn park_current(ctx: Box<UserCtx>) -> ! {
    if let Some(cur) = SCHED.current_thread() {
        SCHED.save_context(cur, ctx);
    }
    schedule_next()
}

/// Число живых потоков (для отчёта).
pub fn context_count() -> usize {
    SCHED.inner.lock().contexts.len()
}
