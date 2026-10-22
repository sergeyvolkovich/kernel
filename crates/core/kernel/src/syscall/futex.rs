// ==== Футеки (v0.17): FUTEX_WAIT 0x3B / FUTEX_WAKE 0x3C ====
//
// Строительный блок юзерспейс-синхронизации (мьютексы, condvars,
// барьеры) — то, чего домен не может достичь без потери CPU: yield-петля
// жжёт квант, IPC-rendezvous требует endpoint на каждую блокировку.
// Футеки Linux-класса: спим на 32-битном слове пользовательской памяти,
// пока его значение равно ожидаемому; будим по тому же слову.
//
// КЛЮЧ — ФИЗИЧЕСКИЙ АДРЕС слова (vaddr -> pbase через MemRouter):
//   * один физический кадр, отображённый в несколько задач (SHM,
//     MEM_TRANSFER, MEM_MAP_AT), даёт ОДИН футекс — кросс-доменные
//     мьютексы на разделяемой памяти работают по построению;
//   * приватная память изолирована: у каждого домена своя физика —
//     подобрать чужой футекс по угаданному vaddr невозможно, ключ
//     не совпадёт. Модель прав НЕ расширяется: разделить футек =
//     разделить кадры, а кадры проходят через capability-гейты
//     памяти. «угадывание» физики ничего не даёт: чужие кадры в
//     пространство вызывающего не отображены, ключ для них построить
//     нельзя (region_at вернёт NotFound).
//
// Таблица: физадрес -> BlockQueueId планировщика (контракт
// `SchedulerInterface`: очередь живёт В бекенде, ядро только паркует/
// будит). Очередь создаётся лениво (первый ждущий), разрушается при
// дренаже (последний разбужен) — под тем же локом таблицы, поэтому
// вставка нового ждущего атомарна с дренажом (нет окна «очередь пуста,
// но ещё жива» между проверкой и уничтожением).
//
// ДИСЦИПЛИНА ЛОКОВ (см. `kernel::sync`): лок таблицы футексов ранга
// GATE — внутри него разрешены TCB (транзакции пробуждения) и SCHED
// (block_push/block_pop), как у RawGate у IPC. ЗАПРЕЩЕНО брать его
// под TCB/GATE/SCHED/KMEM — таблица берётся только на верхнем уровне
// syscall-хендлера. Память пользователя (UserCopy: KMEM-ранг) читается
// СТРОГО ВНЕ локa таблицы — как map-элементы IPC («map — KMEM, свой
// ранг»): под KMEM возможны shootdown-IPI, ожидание чужих CPU под
// локом таблицы — тупик.
//
// Гонка «потерянное пробуждение» (значение изменилось между проверкой
// и парком) закрывается RECHECK'ом ПОСЛЕ парковки — вне локов:
//   * значение изменилось -> снимаем себя с очереди (block_remove под
//     локом таблицы); снятие состоялось -> материализуем -EAGAIN и
//     будим себя (транзакция TCB); снятие НЕ состоялось -> нас уже
//     разбудил встречный wake (его 0 в syscall_ret) — ничего не делаем;
//   * значение не изменилось -> спим; встречный wake обязан взять лок
//     таблицы, прежде чем POPнуть нас — окно «изменение значения без
//     wake» между recheck и парком не существует (recheck идёт ПОСЛЕ
//     парка, а wake не может пройти мимо запаркованного).
//
// Таймаутов в v1 нет — как у IPC-блокировок ядра: таймер-сервер
// юзерспейса держит очереди времени и будит клиентов FUTEX_WAKE
// (классический L4-путь «ядро не хранит таймеры процессов»).

use alloc::collections::BTreeMap;

use crate::sync::KSpin;

use crate::hal::traits::mmap::VirtualADDR;
use crate::mem::{MemRouter, UserCopy};
use crate::syscall::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallRet};
use crate::syscall::{SyscallHandler, nums, record_block_latch};
use crate::syscall::types::SyscallNumber;
use crate::task::scheduler::BlockQueueId;
use crate::task::{TaskState, ThreadWait};

/// Таблица футексов: физический адрес слова -> очередь ждущих.
///
/// `BTreeMap::new()` — const, инициализация линкером (как EEVDF-руку
/// бекенда): ни аллокаций, ни Once на первом вызове.
static FUTEX_TABLE: KSpin<BTreeMap<u64, BlockQueueId>> = KSpin::new(BTreeMap::new());

/// Материализованное значение -EAGAIN для syscall_ret (конвенция
/// «отрицательный errno» в rax, см. `syscall_ret_to_raw`).
#[inline]
fn eagain_raw() -> usize {
    (-(SyscallError::TryAgain.code() as isize)) as usize
}

/// Прочитать 32-битное слово задачи по vaddr (вне локов: UserCopy —
/// KMEM-ранг). `Err(InvalidArgument)` — регион исчез/окно за регионом
/// (гонка снятия — честный отказ вместо вечного сна на пустоте).
fn read_word(
    copy: &dyn UserCopy,
    task: crate::task::TaskId,
    vaddr: usize,
) -> Result<u32, SyscallError> {
    let mut buf = [0u8; 4];
    copy.read_task_bytes(task, vaddr, &mut buf)
        .map_err(|_| SyscallError::InvalidArgument)?;
    Ok(u32::from_le_bytes(buf))
}

// ───────────────────── Хендлеры ─────────────────────

/// FUTEX_WAIT: уснуть на слове, если значение совпадает.
pub struct FutexWaitHandler;

impl FutexWaitHandler {
    pub const SYSCALL: SyscallNumber = nums::FUTEX_WAIT;
}

impl SyscallHandler for FutexWaitHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let uaddr = args.arg(1);
        let expected = args.arg(2) as u32;
        if uaddr % 4 != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        // Подсистемы: роутер (ключ) + канал чтения (значение).
        // Оба подключает владелец фасада; без них — ENOSYS (платформа
        // без direct-map, как у TASK_SPAWN_IMAGE).
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let copy = ctx.copy.ok_or(SyscallError::NotSupported)?;

        // 1. Ключ: физадрес слова (ВНЕ локов — KMEM-ранг роутера).
        let key = futex_key(router, ctx.task, uaddr)?;
        // 2. Первая проверка значения (вне локов): не совпало — без сна.
        if read_word(copy, ctx.task, uaddr)? != expected {
            return Err(SyscallError::TryAgain);
        }

        // 3. Парк под локом таблицы: найти/создать очередь, пометить
        //    ожидание, встать в очередь. Порядок — контракт
        //    BlockQueueId: сначала Blocked (хук deschedule), потом push.
        let sched = ctx
            .tasks
            .scheduler()
            .ok_or(SyscallError::NotSupported)?;
        let queue = {
            let mut table = FUTEX_TABLE.lock();
            let queue = match table.get(&key) {
                Some(q) => *q,
                None => {
                    // Первая блокировка на слове: создать очередь.
                    let q = sched.block_queue_create()?;
                    table.insert(key, q);
                    q
                }
            };
            ctx.tasks.thread_set_state(&ctx.thread, TaskState::Blocked)?;
            ctx.tasks.with_thread(&ctx.thread, |t| {
                t.wait = Some(ThreadWait::Queue { queue, tag: key });
            });
            sched.block_push(queue, ctx.thread)?;
            queue
        };

        // 4. RECHECK (вне локов): значение могло измениться между
        //    шагом 2 и парком — встречный wake обязан был бы POPнуть
        //    нас из очереди (под локом таблицы, шаг за шагом 3),
        //    но если он случился ДО нашего push — мы его не видели.
        //    Ошибка чтения (регион снят) трактуется как «изменилось».
        let changed = match read_word(copy, ctx.task, uaddr) {
            Ok(v) => v != expected,
            // Регион исчез (MEM_FREE в другом потоке): честный EINVAL
            // вместо вечного сна на несуществующей памяти.
            Err(_) => true,
        };
        if changed {
            let removed = {
                let _table = FUTEX_TABLE.lock();
                sched.block_remove(queue, ctx.thread)?
            };
            if removed {
                // Снятие состоялось: встречный wake нас не трогал —
                // материализуем -EAGAIN и будим себя (единая секция
                // TCB: wait + syscall_ret + Ready, как deliver_mailbox_wake).
                // Транзакция та же, что у FUTEX_WAKE: проверка тега
                // защищает от двойного пробуждения (wake успел раньше).
                ctx.tasks
                    .futex_wake_waiter(&ctx.thread, queue, key, eagain_raw())?;
            }
            // removed == false: wake уже забрал нас (syscall_ret = 0,
            // Ready) — ничего не трогаем, диспетчеризация вернёт его.
        }

        // 5. Блокировка (или самопробуждение): защёлка гейта — БЕЗ
        //    sysret (поток в Ready/Blocked, его вход — через
        //    диспетчеризацию с материализованным rax).
        record_block_latch(ctx.cpu);
        Ok(0)
    }
}

/// FUTEX_WAKE: разбудить до count ждущих на слове.
pub struct FutexWakeHandler;

impl FutexWakeHandler {
    pub const SYSCALL: SyscallNumber = nums::FUTEX_WAKE;
}

impl SyscallHandler for FutexWakeHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let uaddr = args.arg(1);
        let count = args.arg(2);
        if uaddr % 4 != 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let key = futex_key(router, ctx.task, uaddr)?;
        let sched = ctx
            .tasks
            .scheduler()
            .ok_or(SyscallError::NotSupported)?;

        // Всё — под одним локом таблицы: дренаж очереди атомарен с
        // удалением записи (новый ждущий не может вставить себя между
        // «очередь пуста» и destroy).
        let mut table = FUTEX_TABLE.lock();
        let Some(queue) = table.get(&key).copied() else {
            // Ждущих никогда не было — быстрый выход без создания очереди.
            return Ok(0);
        };
        let mut woken = 0usize;
        for _ in 0..count {
            match sched.block_pop_front(queue)? {
                None => break,
                Some(thread) => {
                    // Тег-проверка — в транзакции: поток мог быть
                    // SUSPEND'нут/убит пока стоял в очереди (его wait
                    // очищен теми путями) — такой будить нельзя.
                    if ctx.tasks.futex_wake_waiter(&thread, queue, key, 0)? {
                        woken += 1;
                    }
                }
            }
        }
        // Дренаж (последний забран или очередь иссякла): разрушить
        // очередь и убрать запись — таблица не течёт на потоках
        // «миллион локал-футексов».
        if sched.block_len(queue)? == 0 {
            let _ = sched.block_queue_destroy(queue);
            table.remove(&key);
        }
        Ok(woken)
    }
}

// ───────────────────── Ключ ─────────────────────

/// Физический адрес 32-битного слова (ключ футекса) в пространстве
/// задачи. `Err(InvalidArgument)` — адрес вне регионов (незамапленная
/// память: футек на ней невозможен).
fn futex_key(
    router: &dyn MemRouter,
    task: crate::task::TaskId,
    uaddr: usize,
) -> Result<u64, SyscallError> {
    let (v_base, p_base, _pages) = router
        .region_at(task, VirtualADDR(uaddr))
        .ok_or(SyscallError::InvalidArgument)?;
    Ok((p_base.0 + (uaddr - v_base.0)) as u64)
}

// ───────────────────── Тесты (host) ─────────────────────

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use alloc::collections::VecDeque;

    use crate::capability::CapabilityManager;
    use crate::hal::traits::mmap::{MemErrorCode, PhysADDR};
    use crate::mem::{MemRouter, UserCopy};
    use crate::syscall::SyscallRegistry;
    use crate::task::scheduler::SchedulerError;
    use crate::task::types::TaskPriority;
    use crate::task::{SchedulerInterface, TcbManager, ThreadId};

    use super::*;

    // ==== Фейки: роутер (один регион), канал чтения, планировщик ====

    const V_BASE: usize = 0x1000_0000;
    const P_BASE: usize = 0x5000_0000;

    struct FakeRouter;

    impl MemRouter for FakeRouter {
        fn alloc_region(
            &self,
            _task: crate::task::TaskId,
            _pages: usize,
            _flags: crate::hal::traits::mmap::MMAPMemoryFlags,
        ) -> Result<VirtualADDR, MemErrorCode> {
            unimplemented!()
        }
        fn free_region(
            &self,
            _task: crate::task::TaskId,
            _vaddr: VirtualADDR,
        ) -> Result<(), MemErrorCode> {
            unimplemented!()
        }
        fn map_external(
            &self,
            _task: crate::task::TaskId,
            _paddr: PhysADDR,
            _pages: usize,
            _flags: crate::hal::traits::mmap::MMAPMemoryFlags,
        ) -> Result<VirtualADDR, MemErrorCode> {
            unimplemented!()
        }
        fn region_at(
            &self,
            _task: crate::task::TaskId,
            vaddr: VirtualADDR,
        ) -> Option<(VirtualADDR, PhysADDR, usize)> {
            // Один регион на 4 страницы: ключ вычисляется смещением.
            if vaddr.0 >= V_BASE && vaddr.0 < V_BASE + 4 * 4096 {
                Some((VirtualADDR(V_BASE), PhysADDR(P_BASE), 4))
            } else {
                None
            }
        }
        fn protect_region(
            &self,
            _task: crate::task::TaskId,
            _vaddr: VirtualADDR,
            _pages: usize,
            _flags: crate::hal::traits::mmap::MMAPMemoryFlags,
        ) -> Result<(), MemErrorCode> {
            unimplemented!("futex tests do not protect")
        }
        fn transfer(
            &self,
            _dst: crate::task::TaskId,
            _dst_hint: usize,
            _src: crate::task::TaskId,
            _src_vaddr: usize,
            _pages: usize,
            _grant: bool,
            _flags: crate::hal::traits::mmap::MMAPMemoryFlags,
        ) -> Result<usize, MemErrorCode> {
            unimplemented!()
        }
        fn map_external_at(
            &self,
            _dst: crate::task::TaskId,
            _src: crate::task::TaskId,
            _src_vaddr: usize,
            _dst_vaddr: usize,
            _pages: usize,
            _flags: crate::hal::traits::mmap::MMAPMemoryFlags,
        ) -> Result<usize, MemErrorCode> {
            unimplemented!()
        }
    }

    /// Читаемая «память» задачи: слово по индексу (мьютекс — тесты
    /// хоста многопоточны, стенды независимы).
    struct FakeCopy {
        words: spin::Mutex<[u32; 4]>,
    }

    impl UserCopy for FakeCopy {
        fn read_task_bytes(
            &self,
            _task: crate::task::TaskId,
            vaddr: usize,
            out: &mut [u8],
        ) -> Result<(), MemErrorCode> {
            let off = vaddr - V_BASE;
            if vaddr < V_BASE || off + out.len() > 4 * 4096 {
                return Err(MemErrorCode::NotFound);
            }
            let words = self.words.lock();
            // Слово 0 — по V_BASE, слово 1 — по V_BASE+4, ...
            let w = words[off / 4];
            out.copy_from_slice(&w.to_le_bytes());
            Ok(())
        }
    }

    /// Планировщик с реальными block-очередями (как SyncSched в ipc-тестах).
    struct FakeSched {
        queues: KSpin<BTreeMap<u64, VecDeque<ThreadId>>>,
        next: AtomicU64,
    }

    impl FakeSched {
        fn new() -> Self {
            Self {
                queues: KSpin::new(BTreeMap::new()),
                next: AtomicU64::new(1),
            }
        }
    }

    impl SchedulerInterface for FakeSched {
        fn current(&self, _: crate::task::CpuId) -> Option<ThreadId> {
            None
        }
        fn enqueue(&self, _: ThreadId) -> Result<(), SchedulerError> {
            Ok(())
        }
        fn deschedule(&self, _: ThreadId) -> Result<(), SchedulerError> {
            Ok(())
        }
        fn on_priority_change(
            &self,
            _: ThreadId,
            _: TaskPriority,
        ) -> Result<(), SchedulerError> {
            Ok(())
        }
        fn switch_context(
            &self,
            _: crate::task::CpuId,
            _: Option<ThreadId>,
            _: ThreadId,
        ) -> Result<(), SchedulerError> {
            Ok(())
        }
        fn block_queue_create(&self) -> Result<BlockQueueId, SchedulerError> {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            self.queues.lock().insert(id, VecDeque::new());
            Ok(BlockQueueId::new(id))
        }
        fn block_queue_destroy(&self, q: BlockQueueId) -> Result<(), SchedulerError> {
            self.queues.lock().remove(&q.as_u64());
            Ok(())
        }
        fn block_push(&self, q: BlockQueueId, t: ThreadId) -> Result<(), SchedulerError> {
            self.queues
                .lock()
                .get_mut(&q.as_u64())
                .map(|vq| vq.push_back(t))
                .ok_or(SchedulerError::Backend("unknown queue"))
        }
        fn block_remove(&self, q: BlockQueueId, t: ThreadId) -> Result<bool, SchedulerError> {
            Ok(self
                .queues
                .lock()
                .get_mut(&q.as_u64())
                .and_then(|vq| {
                    vq.iter().position(|&x| x == t).map(|p| {
                        vq.remove(p);
                    })
                })
                .is_some())
        }
        fn block_pop_front(&self, q: BlockQueueId) -> Result<Option<ThreadId>, SchedulerError> {
            Ok(self
                .queues
                .lock()
                .get_mut(&q.as_u64())
                .and_then(|vq| vq.pop_front()))
        }
        fn block_len(&self, q: BlockQueueId) -> Result<usize, SchedulerError> {
            Ok(self
                .queues
                .lock()
                .get(&q.as_u64())
                .map(|vq| vq.len())
                .unwrap_or(0))
        }
        fn yield_now(&self, _: ThreadId) -> Result<(), SchedulerError> {
            Ok(())
        }
        fn perform_tick(&self, _: u64) {}
    }

    // ==== Стенд ====

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(0x7000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    struct Rig {
        tasks: TcbManager,
        caps: CapabilityManager,
        copy: FakeCopy,
    }

    fn rig() -> Rig {
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let sched: &'static FakeSched = Box::leak(Box::new(FakeSched::new()));
        tasks.install_scheduler(sched);
        Rig {
            tasks,
            caps,
            copy: FakeCopy {
                words: spin::Mutex::new([7, 0, 0, 0]),
            },
        }
    }

    fn ctx_of<'a>(
        rig: &'a Rig,
        task: crate::task::TaskId,
        thread: ThreadId,
    ) -> SyscallCtx<'a> {
        SyscallCtx::core(0, task, &rig.tasks, &rig.caps)
            .with_thread(thread)
            .with_memory(&FakeRouter)
            .with_copy(&rig.copy)
    }

    const UADDR: usize = V_BASE; // слово 0 (начальное значение 7)

    #[test]
    fn wait_mismatch_returns_eagain_without_park() {
        let rig = rig();
        let task = uuid_next();
        let thread = uuid_next();
        rig.tasks.create(task, TaskPriority(100)).unwrap();
        rig.tasks
            .create_thread(thread, task, TaskPriority(100), 0x1000, 0x2000)
            .unwrap();
        let mut ctx = ctx_of(&rig, task, thread);

        // expected=5, в памяти 7 -> -EAGAIN, поток остался Ready.
        let r = FutexWaitHandler.invoke(
            &mut ctx,
            &SyscallArgs::new([0x3B, UADDR, 5, 0, 0, 0, 0]),
        );
        assert_eq!(r, Err(SyscallError::TryAgain));
        assert_eq!(
            rig.tasks.thread_view(&thread).unwrap().state,
            TaskState::Ready
        );
    }

    #[test]
    fn wait_parks_then_wake_wakes() {
        let rig = rig();
        let task = uuid_next();
        let waiter = uuid_next();
        let waker = uuid_next();
        rig.tasks.create(task, TaskPriority(100)).unwrap();
        for t in [waiter, waker] {
            rig.tasks
                .create_thread(t, task, TaskPriority(100), 0x1000, 0x2000)
                .unwrap();
            // Хендлер паркует ИСПОЛНЯЮЩЕГОСЯ потока (Running -> Blocked,
            // как в реальном сисколе); созданный поток рождается Ready —
            // переводим в Running, как делают IPC-тесты.
            rig.tasks.thread_set_state(&t, TaskState::Running).unwrap();
        }

        // Waiter: значение 7 == expected 7 -> парк (recheck тоже 7).
        let mut ctx = ctx_of(&rig, task, waiter);
        let r = FutexWaitHandler.invoke(
            &mut ctx,
            &SyscallArgs::new([0x3B, UADDR, 7, 0, 0, 0, 0]),
        );
        assert_eq!(r, Ok(0));
        assert_eq!(
            rig.tasks.thread_view(&waiter).unwrap().state,
            TaskState::Blocked
        );
        assert!(matches!(
            rig.tasks.thread_wait(&waiter).unwrap(),
            Some(ThreadWait::Queue { .. })
        ));

        // Waker (тот же домен): будит 1.
        let mut ctx2 = ctx_of(&rig, task, waker);
        let r = FutexWakeHandler.invoke(
            &mut ctx2,
            &SyscallArgs::new([0x3C, UADDR, 1, 0, 0, 0, 0]),
        );
        assert_eq!(r, Ok(1));
        // Waiter: Ready + материализованный возврат 0.
        assert_eq!(
            rig.tasks.thread_view(&waiter).unwrap().state,
            TaskState::Ready
        );
        assert_eq!(rig.tasks.take_thread_syscall_ret(&waiter), Some(0));
        // Очередь дренирована -> запись удалена: повторный wake = 0.
        let r = FutexWakeHandler.invoke(
            &mut ctx2,
            &SyscallArgs::new([0x3C, UADDR, 1, 0, 0, 0, 0]),
        );
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn wait_value_changed_after_park_self_wakes_with_eagain() {
        let rig = rig();
        let task = uuid_next();
        let waiter = uuid_next();
        rig.tasks.create(task, TaskPriority(100)).unwrap();
        rig.tasks
            .create_thread(waiter, task, TaskPriority(100), 0x1000, 0x2000)
            .unwrap();
        // Исполняющийся поток (Running) — как в реальном вызове.
        rig.tasks
            .thread_set_state(&waiter, TaskState::Running)
            .unwrap();

        // Значение меняется МЕЖДУ первой проверкой и recheck'ом:
        // первая проверка видит 7 (парк), recheck видит 8 (self-wake).
        // Эмуляция: копия-«лестница» — читает 7 при первом вызове
        // и 8 при втором (изменение без реального второго потока).
        struct TwoPhaseCopy {
            reads: AtomicU64,
        }
        impl UserCopy for TwoPhaseCopy {
            fn read_task_bytes(
                &self,
                _task: crate::task::TaskId,
                _vaddr: usize,
                out: &mut [u8],
            ) -> Result<(), MemErrorCode> {
                let n = self.reads.fetch_add(1, Ordering::Relaxed);
                let w: u32 = if n == 0 { 7 } else { 8 };
                out.copy_from_slice(&w.to_le_bytes());
                Ok(())
            }
        }

        let mut ctx = {
            let copy: &'static TwoPhaseCopy =
                Box::leak(Box::new(TwoPhaseCopy { reads: AtomicU64::new(0) }));
            SyscallCtx::core(0, task, &rig.tasks, &rig.caps)
                .with_thread(waiter)
                .with_memory(&FakeRouter)
                .with_copy(copy)
        };

        let r = FutexWaitHandler.invoke(
            &mut ctx,
            &SyscallArgs::new([0x3B, UADDR, 7, 0, 0, 0, 0]),
        );
        assert_eq!(r, Ok(0)); // хендлер вернул 0 (блок-путь), НО...
        // ...поток уже Ready с материализованным -EAGAIN: потерянного
        // пробуждения нет, пользователь увидит -11.
        assert_eq!(
            rig.tasks.thread_view(&waiter).unwrap().state,
            TaskState::Ready
        );
        let ret = rig.tasks.take_thread_syscall_ret(&waiter);
        assert_eq!(ret, Some(eagain_raw()));
        assert_eq!(ret.unwrap() as i64, -11);
        // Очередь пуста (self-wake снял себя) -> запись удалена.
        let mut ctx2 = ctx_of(&rig, task, waiter);
        let r = FutexWakeHandler.invoke(
            &mut ctx2,
            &SyscallArgs::new([0x3C, UADDR, 1, 0, 0, 0, 0]),
        );
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn misaligned_and_unmapped_addresses_rejected() {
        let rig = rig();
        let task = uuid_next();
        let thread = uuid_next();
        rig.tasks.create(task, TaskPriority(100)).unwrap();
        rig.tasks
            .create_thread(thread, task, TaskPriority(100), 0x1000, 0x2000)
            .unwrap();
        let mut ctx = ctx_of(&rig, task, thread);

        // Не выровнено на 4.
        assert_eq!(
            FutexWaitHandler.invoke(
                &mut ctx,
                &SyscallArgs::new([0x3B, UADDR + 2, 0, 0, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            FutexWakeHandler.invoke(
                &mut ctx,
                &SyscallArgs::new([0x3C, UADDR + 1, 1, 0, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
        // Вне регионов (нет отображения — нет футекса).
        assert_eq!(
            FutexWaitHandler.invoke(
                &mut ctx,
                &SyscallArgs::new([0x3B, 0x9000_0000, 0, 0, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
    }

    #[test]
    fn handlers_registered_by_default_table() {
        let reg = SyscallRegistry::new();
        reg.install_default_table();
        assert!(reg.handler(nums::FUTEX_WAIT).is_some());
        assert!(reg.handler(nums::FUTEX_WAKE).is_some());
        assert_eq!(FutexWaitHandler::SYSCALL, SyscallNumber(0x3B));
        assert_eq!(FutexWakeHandler::SYSCALL, SyscallNumber(0x3C));
    }
}
