// ==== IPC-хендлеры: endpoint'ы, send/recv/call, fast-path, mailbox ====
//
// Каждый хендлер — те же три шага, что у `TaskSpawnHandler` (образец v0.2):
// идентификация (ctx.task/thread + capability) -> подсистема (`IpcManager`)
// -> перевод ошибки в errno. Блокирующие операции возвращают `Ok(0)` с
// потоком в `Blocked`: arch-глюй не возвращается в пользователя, а
// переключает контекст; возврат материализуется из `syscall_ret` при
// пробуждении (контракт в `syscall::mod` / `ipc::mod`).

use alloc::boxed::Box;

use crate::capability::{CapHandle, ContainerACCCapability};
use crate::ipc::{BlockMode, IpcMessage, RecvOutcome, SendOutcome};
use crate::syscall::nums;
use crate::task::ThreadId;

use super::SyscallHandler;
use super::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};

/// Флаг try-режима в аргументе flags.
pub const IPC_FLAG_TRY: usize = 1;

/// Собрать ThreadId из пары слов (ABI платформы: lo — младшие 64 бита).
fn thread_id_from(lo: usize, hi: usize) -> ThreadId {
    uuid::Uuid::from_u128(((hi as u128) << 64) | lo as u128)
}

// ==== EP_CREATE ====

/// Создание endpoint'а (ёмкость задаёт режим: 0 = rendezvous,
/// > 0 = notification-канал с буфером).
pub struct EpCreateHandler;

impl EpCreateHandler {
    pub const SYSCALL: SyscallNumber = nums::EP_CREATE;
}

impl SyscallHandler for EpCreateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let capacity = args.arg(1);
        // v0.9: предел endpoint'ов + общий предел cspace домена.
        if let Some(sec) = ctx.tasks.sec_view(&ctx.task) {
            let live = super::task::gate_cap_count(ctx);
            if live >= sec.limits.max_endpoints {
                super::task::sandbox_audit("EP_CREATE blocked: endpoint quota");
                return Err(SyscallError::QuotaExceeded);
            }
            let caps = ctx.tasks.cap_count(&ctx.task).unwrap_or(0);
            if caps >= sec.limits.max_caps {
                super::task::sandbox_audit("EP_CREATE blocked: cspace quota");
                return Err(SyscallError::QuotaExceeded);
            }
        }
        let handle = ipc.create_endpoint(
            ctx.tasks,
            ctx.caps,
            ctx.task,
            capacity,
            crate::capability::ActionPermissions::all(),
            crate::capability::CapabilityBadge::FULL,
        )?;
        Ok(handle.bits() as usize)
    }
}

// ==== IPC_SEND ====

/// Отправка в endpoint (блокирующая L4; try — флагом).
pub struct IpcSendHandler;

impl IpcSendHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_SEND;
}

impl SyscallHandler for IpcSendHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let ep = CapHandle(args.arg(1) as u64);
        let mode = mode_of(args.arg(5));

        let mut msg = Box::new(IpcMessage::new(ctx.thread));
        // До 3 inline-слов за вызов (arg2..4): ABI регистрового входа.
        for i in 2..5 {
            msg.push_word(args.arg(i) as u64);
        }

        match ipc.send(ctx.tasks, ctx.caps, ctx.memory, ctx.thread, ep, msg, mode)? {
            // Блокировка: Ok(0) + поток в Blocked (возврат при встрече).
            SendOutcome::Blocked => Ok(0),
            _ => Ok(0),
        }
    }
}

// ==== IPC_RECV ====

/// Приём из endpoint: возврат — слово 0 сообщения; слова 1.. — IPC_MSG_WORD.
pub struct IpcRecvHandler;

impl IpcRecvHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_RECV;
}

impl SyscallHandler for IpcRecvHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let ep = CapHandle(args.arg(1) as u64);
        let mode = mode_of(args.arg(2));

        // Ящик чистим ПЕРЕД приёмом: новое сообщение — единственное в нём.
        ipc.mailbox_clear(ctx.tasks, ctx.thread);
        match ipc.recv(ctx.tasks, ctx.caps, ctx.thread, ep, mode)? {
            // Прямая встреча: слово 0 — возврат, весь ящик (слова 1..)
            // обязан быть доступен IPC_MSG_WORD — v0.9 фиксирует тот же
            // баг класса «v0.5.2», что был у recv_any: сообщение
            // выбрасывалось после чтения слова 0.
            RecvOutcome::Message(msg) => {
                let word0 = msg.word(0) as usize;
                ipc.mailbox_set(ctx.tasks, ctx.thread, msg);
                Ok(word0)
            }
            // Поток заблокирован: сообщение окажется в ящике при встрече.
            RecvOutcome::Blocked => Ok(0),
        }
    }
}

// ==== IPC_CALL (L4: send + reply-recv без возврата в пользователя) ====

pub struct IpcCallHandler;

impl IpcCallHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_CALL;
}

impl SyscallHandler for IpcCallHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let ep = CapHandle(args.arg(1) as u64);
        let reply_ep = CapHandle(args.arg(2) as u64);
        let mode = mode_of(args.arg(5));

        // Reply-гейт резолвим СРАЗУ: фаза call пойдёт без capability.
        let reply = resolve_gate(ctx, reply_ep)?;

        let mut msg = Box::new(IpcMessage::new(ctx.thread));
        for i in 3..5 {
            msg.push_word(args.arg(i) as u64);
        }

        // Отправка с фазой call: после доставки сообщения поток сразу
        // переходит к приёму на reply-гейте (then_recv).
        let src = resolve_gate(ctx, ep)?;
        ipc.send_to_gate(
            ctx.tasks,
            ctx.caps,
            ctx.memory,
            ctx.thread,
            src,
            msg,
            mode,
            Some(reply),
        )?;
        // Ответ (если уже пришёл) — в почтовом ящике.
        Ok(0)
    }
}

// ==== IPC_SEND_THREAD (fast-path L4 по глобальному ThreadID) ====

pub struct IpcSendThreadHandler;

impl IpcSendThreadHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_SEND_THREAD;
}

impl SyscallHandler for IpcSendThreadHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let to = thread_id_from(args.arg(1), args.arg(2));
        let n_words = args.arg(5).min(2);

        let mut msg = Box::new(IpcMessage::new(ctx.thread));
        for i in 0..n_words {
            msg.push_word(args.arg(3 + i) as u64);
        }
        match ipc.send_thread(ctx.tasks, ctx.memory, ctx.thread, to, msg)? {
            SendOutcome::Delivered => Ok(0),
            SendOutcome::Parked => Ok(1), // припарковано в очереди потока
            _ => Ok(0),
        }
    }
}

// ==== IPC_RECV_ANY (open receive) ====

pub struct IpcRecvAnyHandler;

impl IpcRecvAnyHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_RECV_ANY;
}

impl SyscallHandler for IpcRecvAnyHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let mode = mode_of(args.arg(1));
        ipc.mailbox_clear(ctx.tasks, ctx.thread);
        match ipc.recv_any(ctx.tasks, ctx.thread, mode)? {
            // Сообщение обязано попасть в ящик: слово 0 — возврат, слова 1..
            // читаются IPC_MSG_WORD (баг v0.5.2: сообщение выбрасывалось).
            RecvOutcome::Message(msg) => {
                let word0 = msg.word(0) as usize;
                ipc.mailbox_set(ctx.tasks, ctx.thread, msg);
                Ok(word0)
            }
            RecvOutcome::Blocked => Ok(0),
        }
    }
}

// ==== Mailbox: чтение/длина/очистка ====

pub struct IpcMsgWordHandler;

impl IpcMsgWordHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_MSG_WORD;
}

impl SyscallHandler for IpcMsgWordHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let index = args.arg(1);
        ipc.mailbox_word(ctx.tasks, ctx.thread, index)
            .map(|w| w as usize)
            .ok_or(SyscallError::NotFound)
    }
}

pub struct IpcMsgLenHandler;

impl IpcMsgLenHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_MSG_LEN;
}

impl SyscallHandler for IpcMsgLenHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let _ = args;
        // (статус << 32) | слов: ITEM_ERRORS/FAST_PATH видны пользователю.
        let len = ipc.mailbox_len(ctx.tasks, ctx.thread);
        let status = ipc.mailbox_status(ctx.tasks, ctx.thread);
        Ok(((status.bits() as usize) << 32) | len)
    }
}

pub struct IpcMsgClearHandler;

impl IpcMsgClearHandler {
    pub const SYSCALL: SyscallNumber = nums::IPC_MSG_CLEAR;
}

impl SyscallHandler for IpcMsgClearHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let _ = args;
        ipc.mailbox_clear(ctx.tasks, ctx.thread);
        Ok(0)
    }
}

// ==== NOTIFY_SIGNAL (doorbell / async-уведомления) ====

pub struct NotifySignalHandler;

impl NotifySignalHandler {
    pub const SYSCALL: SyscallNumber = nums::NOTIFY_SIGNAL;
}

impl SyscallHandler for NotifySignalHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let ep = CapHandle(args.arg(1) as u64);
        let word = args.arg(2) as u64;
        let gate = resolve_gate(ctx, ep)?;
        ipc.signal(ctx.tasks, ctx.caps, gate, word)?;
        Ok(0)
    }
}

// ==== Вспомогательное ====

fn mode_of(flags: usize) -> BlockMode {
    if flags & IPC_FLAG_TRY != 0 {
        BlockMode::Try
    } else {
        BlockMode::Blocking
    }
}

/// Резолв Gate-capability вызывающего в ObjId endpoint'а.
fn resolve_gate(
    ctx: &SyscallCtx<'_>,
    handle: CapHandle,
) -> Result<crate::capability::ObjId, SyscallError> {
    let view = ctx.resolve(handle)?;
    match &view.cap_ref {
        ContainerACCCapability::Gate { gate_id } => Ok(*gate_id),
        _ => Err(SyscallError::InvalidArgument),
    }
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ActionPermissions, CapabilityBadge, CapabilityManager};
    use crate::ipc::IpcManager;
    use crate::syscall::SyscallRegistry;
    use crate::task::TaskId;
    use crate::task::{TaskPriority, TaskState, TcbManager};

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0x3000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    /// Фикстура: менеджеры + планировщик с block-очередями (см. claim::tests).
    struct MockScheduler {
        queues: core::cell::RefCell<
            alloc::collections::BTreeMap<u64, alloc::collections::VecDeque<ThreadId>>,
        >,
        next: core::cell::Cell<u64>,
    }

    impl MockScheduler {
        fn new() -> Self {
            Self {
                queues: core::cell::RefCell::new(alloc::collections::BTreeMap::new()),
                next: core::cell::Cell::new(1),
            }
        }
    }

    impl crate::task::SchedulerInterface for MockScheduler {
        fn current(&self, _: crate::task::CpuId) -> Option<ThreadId> {
            None
        }
        fn enqueue(&self, _: ThreadId) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn deschedule(&self, _: ThreadId) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn on_priority_change(
            &self,
            _: ThreadId,
            _: crate::task::TaskPriority,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn switch_context(
            &self,
            _: crate::task::CpuId,
            _: Option<ThreadId>,
            _: ThreadId,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn isolation_policy(
            &self,
            _: crate::task::CpuId,
        ) -> crate::hal::traits::kmap::IsolationPolicy {
            crate::hal::traits::kmap::IsolationPolicy::conservative()
        }
        fn perform_tick(&self, _: u64) {}
        fn block_queue_create(
            &self,
        ) -> Result<crate::task::BlockQueueId, crate::task::SchedulerError> {
            let id = self.next.get();
            self.next.set(id + 1);
            Ok(crate::task::BlockQueueId::new(id))
        }
        fn block_queue_destroy(
            &self,
            _: crate::task::BlockQueueId,
        ) -> Result<(), crate::task::SchedulerError> {
            Ok(())
        }
        fn block_push(
            &self,
            q: crate::task::BlockQueueId,
            t: ThreadId,
        ) -> Result<(), crate::task::SchedulerError> {
            self.queues
                .borrow_mut()
                .entry(q.0)
                .or_default()
                .push_back(t);
            Ok(())
        }
        fn block_remove(
            &self,
            q: crate::task::BlockQueueId,
            t: ThreadId,
        ) -> Result<bool, crate::task::SchedulerError> {
            let mut qs = self.queues.borrow_mut();
            if let Some(q) = qs.get_mut(&q.0) {
                if let Some(i) = q.iter().position(|x| *x == t) {
                    q.remove(i);
                    return Ok(true);
                }
            }
            Ok(false)
        }
        fn block_pop_front(
            &self,
            q: crate::task::BlockQueueId,
        ) -> Result<Option<ThreadId>, crate::task::SchedulerError> {
            Ok(self
                .queues
                .borrow_mut()
                .get_mut(&q.0)
                .and_then(|q| q.pop_front()))
        }
        fn block_len(
            &self,
            q: crate::task::BlockQueueId,
        ) -> Result<usize, crate::task::SchedulerError> {
            Ok(self.queues.borrow().get(&q.0).map_or(0, |q| q.len()))
        }
    }

    struct Fixture {
        tasks: &'static TcbManager,
        caps: &'static CapabilityManager,
        ipc: &'static IpcManager,
        reg: &'static SyscallRegistry,
        task: TaskId,
        thread: ThreadId,
    }

    fn fixture() -> Fixture {
        let tasks: &'static TcbManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(IpcManager::new()));
        let reg: &'static SyscallRegistry =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(SyscallRegistry::new()));
        let sched: &'static MockScheduler =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(MockScheduler::new()));
        tasks.install_scheduler(sched);

        reg.register(EpCreateHandler::SYSCALL, &EpCreateHandler)
            .unwrap();
        reg.register(IpcSendHandler::SYSCALL, &IpcSendHandler)
            .unwrap();
        reg.register(IpcRecvHandler::SYSCALL, &IpcRecvHandler)
            .unwrap();
        reg.register(IpcSendThreadHandler::SYSCALL, &IpcSendThreadHandler)
            .unwrap();
        reg.register(IpcRecvAnyHandler::SYSCALL, &IpcRecvAnyHandler)
            .unwrap();
        reg.register(IpcMsgWordHandler::SYSCALL, &IpcMsgWordHandler)
            .unwrap();
        reg.register(IpcMsgClearHandler::SYSCALL, &IpcMsgClearHandler)
            .unwrap();
        reg.register(NotifySignalHandler::SYSCALL, &NotifySignalHandler)
            .unwrap();

        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();
        let thread = uuid_next();
        tasks
            .create_thread(thread, task, TaskPriority(50), 0x4000, 0x8000)
            .unwrap();

        Fixture {
            tasks,
            caps,
            ipc,
            reg,
            task,
            thread,
        }
    }

    fn ctx<'a>(f: &Fixture) -> SyscallCtx<'a> {
        SyscallCtx::core(0, f.task, f.tasks, f.caps)
            .with_thread(f.thread)
            .with_ipc(f.ipc)
    }

    fn args(words: [usize; 6]) -> SyscallArgs {
        SyscallArgs::new(words)
    }

    #[test]
    fn ep_create_returns_handle() {
        let f = fixture();
        let mut c = ctx(&f);
        // arg0 = номер, arg1 = ёмкость 4 (notification-режим).
        let ret = f
            .reg
            .dispatch(
                &mut c,
                &args([EpCreateHandler::SYSCALL.as_u64() as usize, 4, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_ne!(ret, 0);
    }

    #[test]
    fn signal_then_recv_through_buffer() {
        let f = fixture();
        let mut c = ctx(&f);

        // Создаём notification-endpoint (ёмкость 4).
        let ep = f
            .reg
            .dispatch(
                &mut c,
                &args([EpCreateHandler::SYSCALL.as_u64() as usize, 4, 0, 0, 0, 0]),
            )
            .unwrap() as u64;

        // Signal (ядро-стиль): слово 0xDEAD.
        f.reg
            .dispatch(
                &mut c,
                &args([
                    NotifySignalHandler::SYSCALL.as_u64() as usize,
                    ep as usize,
                    0xDEAD,
                    0,
                    0,
                    0,
                ]),
            )
            .unwrap();

        // Приём: слово из буфера.
        let got = f
            .reg
            .dispatch(
                &mut c,
                &args([
                    IpcRecvHandler::SYSCALL.as_u64() as usize,
                    ep as usize,
                    0,
                    0,
                    0,
                    0,
                ]),
            )
            .unwrap();
        assert_eq!(got, 0xDEAD);

        // Буфер пуст: try-приём — EAGAIN.
        assert_eq!(
            f.reg.dispatch(
                &mut c,
                &args([
                    IpcRecvHandler::SYSCALL.as_u64() as usize,
                    ep as usize,
                    1,
                    0,
                    0,
                    0
                ])
            ),
            Err(SyscallError::TryAgain)
        );
    }

    #[test]
    fn send_thread_fast_path_park_and_open_receive() {
        let f = fixture();

        // Вторая задача-получатель.
        let peer_task = uuid_next();
        f.tasks.create(peer_task, TaskPriority::DEFAULT).unwrap();
        let peer = uuid_next();
        f.tasks
            .create_thread(peer, peer_task, TaskPriority(50), 0, 0)
            .unwrap();
        let pv = peer.as_u128();

        // Peer блокируется в open-receive (сначала диспетчеризация).
        f.tasks.thread_set_state(&peer, TaskState::Running).unwrap();
        let mut peer_ctx = SyscallCtx::core(0, peer_task, f.tasks, f.caps)
            .with_thread(peer)
            .with_ipc(f.ipc);
        let out = f
            .reg
            .dispatch(
                &mut peer_ctx,
                &args([IpcRecvAnyHandler::SYSCALL.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(out, 0);
        assert_eq!(
            f.tasks.thread_view(&peer).unwrap().state,
            TaskState::Blocked
        );

        // Fast-path отправка: получатель в open-receive — мгновенная доставка.
        let mut c = ctx(&f);
        f.reg
            .dispatch(
                &mut c,
                &args([
                    IpcSendThreadHandler::SYSCALL.as_u64() as usize,
                    pv as usize,
                    (pv >> 64) as usize,
                    0x1234,
                    0xBEEF,
                    2,
                ]),
            )
            .unwrap();

        // Peer разбужен, сообщение в ящике: слово 0 + слово 1.
        assert_eq!(f.tasks.thread_view(&peer).unwrap().state, TaskState::Ready);
        let w0 = f
            .reg
            .dispatch(
                &mut peer_ctx,
                &args([IpcMsgWordHandler::SYSCALL.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        let w1 = f
            .reg
            .dispatch(
                &mut peer_ctx,
                &args([IpcMsgWordHandler::SYSCALL.as_u64() as usize, 1, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(w0, 0x1234);
        assert_eq!(w1, 0xBEEF);

        // Отправитель в peer НЕ в open-receive: сообщение паркуется.
        let sender = f.thread;
        let sv = sender.as_u128();
        f.reg
            .dispatch(
                &mut peer_ctx,
                &args([
                    IpcSendThreadHandler::SYSCALL.as_u64() as usize,
                    sv as usize,
                    (sv >> 64) as usize,
                    0x77,
                    0,
                    1,
                ]),
            )
            .unwrap();
        // Теперь наш поток принимает open-receive: сначала диспетчеризация.
        f.tasks
            .thread_set_state(&f.thread, TaskState::Running)
            .unwrap();
        let got = f
            .reg
            .dispatch(
                &mut c,
                &args([IpcRecvAnyHandler::SYSCALL.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(got, 0x77);
    }

    #[test]
    fn rendezvous_send_blocks_until_recv() {
        let f = fixture();

        // Rendezvous-endpoint (ёмкость 0) у получателя.
        let peer_task = uuid_next();
        f.tasks.create(peer_task, TaskPriority::DEFAULT).unwrap();
        let peer = uuid_next();
        f.tasks
            .create_thread(peer, peer_task, TaskPriority(50), 0, 0)
            .unwrap();
        let mut peer_ctx = SyscallCtx::core(0, peer_task, f.tasks, f.caps)
            .with_thread(peer)
            .with_ipc(f.ipc);
        let ep = f
            .reg
            .dispatch(
                &mut peer_ctx,
                &args([EpCreateHandler::SYSCALL.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap() as u64;

        // Хендл endpoint'а живёт в cspace получателя: mint производной
        // отправителю (право передачи — Send+Mint корневого гранта).
        let sender_ep = f
            .caps
            .mint(
                f.tasks,
                peer_task,
                crate::capability::CapHandle(ep),
                f.task,
                &crate::capability::MintSpec::UNCHANGED,
            )
            .unwrap()
            .bits();

        // Отправитель (наш поток) блокируется: получателя нет.
        f.tasks
            .thread_set_state(&f.thread, TaskState::Running)
            .unwrap();
        let mut c = ctx(&f);
        let out = f
            .reg
            .dispatch(
                &mut c,
                &args([
                    IpcSendHandler::SYSCALL.as_u64() as usize,
                    sender_ep as usize,
                    0xCAFE,
                    0,
                    0,
                    0,
                ]),
            )
            .unwrap();
        assert_eq!(out, 0);
        assert_eq!(
            f.tasks.thread_view(&f.thread).unwrap().state,
            TaskState::Blocked
        );

        // Получатель принимает rendezvous: отправитель разбужен, слово — его.
        f.tasks.thread_set_state(&peer, TaskState::Running).unwrap();
        let got = f
            .reg
            .dispatch(
                &mut peer_ctx,
                &args([
                    IpcRecvHandler::SYSCALL.as_u64() as usize,
                    ep as usize,
                    0,
                    0,
                    0,
                    0,
                ]),
            )
            .unwrap();
        assert_eq!(got, 0xCAFE);
        assert_eq!(
            f.tasks.thread_view(&f.thread).unwrap().state,
            TaskState::Ready
        );
        assert_eq!(f.tasks.thread_syscall_ret(&f.thread), Some(Some(0)));

        // Try-отправка в rendezvous без получателя — EAGAIN.
        let mut c2 = ctx(&f);
        assert_eq!(
            f.reg.dispatch(
                &mut c2,
                &args([
                    IpcSendHandler::SYSCALL.as_u64() as usize,
                    sender_ep as usize,
                    1,
                    0,
                    0,
                    IPC_FLAG_TRY
                ])
            ),
            Err(SyscallError::TryAgain)
        );
    }

    /// Регрессия v0.5.2 (баг загрузочной цепочки в QEMU): recv_any на
    /// parked-pop-пути возвращал слово 0 и ВЫБРАСЫВАЛ сообщение — ящик
    /// оставался пустым, IPC_MSG_WORD отвечал NotFound, первый init
    /// получал мусорный argv_ptr (в образе — #PF по адресу -2) и домен
    /// умирал. Тест повторяет точную последовательность kinit: стартовое
    /// сообщение паркуется в очередь потока ДО его входа в open-receive.
    #[test]
    fn recv_any_parked_pop_fills_mailbox() {
        use crate::ipc::{IPC_KERNEL_FROM, IpcMessage, SendOutcome};

        let f = fixture();

        // Поток-приёмник жив, но НЕ в open-receive: send_thread паркует
        // сообщение в t.parked (так kinit стартует init).
        let msg = Box::new(IpcMessage::start_args(
            IPC_KERNEL_FROM,
            3,           // argc
            0x4000_1234, // argv_ptr
            24,          // argv_bytes
        ));
        let out = f
            .ipc
            .send_thread(f.tasks, None, IPC_KERNEL_FROM, f.thread, msg)
            .unwrap();
        assert!(matches!(out, SendOutcome::Parked));

        // Открытый приём: возврат = слово 0 (argc), сообщение — в ящике.
        let mut c = ctx(&f);
        let argc = f
            .reg
            .dispatch(
                &mut c,
                &args([IpcRecvAnyHandler::SYSCALL.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(argc, 3);

        // Слова 1..2 — из почтового ящика (до фикса: NotFound/-2).
        let w1 = f
            .reg
            .dispatch(
                &mut c,
                &args([IpcMsgWordHandler::SYSCALL.as_u64() as usize, 1, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(w1, 0x4000_1234);
        let w2 = f
            .reg
            .dispatch(
                &mut c,
                &args([IpcMsgWordHandler::SYSCALL.as_u64() as usize, 2, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(w2, 24);

        // За пределами сообщения — NotFound (детерминизм, не мусор).
        assert_eq!(
            f.reg.dispatch(
                &mut c,
                &args([IpcMsgWordHandler::SYSCALL.as_u64() as usize, 99, 0, 0, 0, 0]),
            ),
            Err(SyscallError::NotFound)
        );
    }
}
