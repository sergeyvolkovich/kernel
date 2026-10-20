// ==== Фасад задачных сисколов: маршрутизация БЕЗ логики ====
//
// Каждый метод здесь — ровно три шага:
//   1. идентификация вызывающего (task) и проверка хендла (capability),
//      если операция адресуется хендлом, а не TaskId;
//   2. вызов менеджера (`TcbManager` / `CapabilityManager`) — ВСЯ семантика
//      там: автоматы состояний, дерево деривации, хуки планировщика;
//   3. перевод ошибки менеджера в errno-подобный код (`SyscallError::from`).
//
// Сознательно НЕТ: собственной валидации поверх менеджерной (двойная
// валидация — источник расхождений), кэшей состояния задач (менеджер —
// источник истины), решения «что делать с задачей» (это логика планировщика
// и менеджера, не фасада).
//
// Регистрация этих операций как хендлеров — платформенное решение: методы
// можно звать напрямую из arch-глюя, а можно завернуть в статические
// хендлеры (`SyscallHandler`) и зарегистрировать в `SyscallRegistry`.
// Пример-хендлер — в конце файла: [`TaskSpawnHandler`] показывает, как
// фасадный метод превращается в полноценный сискол одной строкой.
//
// ==== Протокол запуска L4 (argc/argv через IPC) ====
//
// Спавн домена и передача аргументов — РАЗДЕЛЬНЫЕ шаги (как в L4):
//   1. `TASK_CREATE` — домен (cspace + адресное пространство);
//   2. `THREAD_CREATE` — главный поток (entry/stack — контекст строит
//      arch-глюй);
//   3. `TASK_SET_EXIT_EP` — регистрация exit-endpoint (родитель получит
//      три вида данных: код выхода / исключение / кем убита);
//   4. родитель шлёт стартовое сообщение ПРЯМОМУ ПОТОКУ главного потока
//      (`IPC_SEND_THREAD`, fast-path L4): слова
//      `[argc, argv_ptr, argv_bytes, envp_ptr, envp_bytes]`
//      (`IpcMessage::start_args`) + map-элемент с окном буфера argv;
//      главный поток начинает исполнение с `IPC_RECV_ANY` и получает
//      аргументы первым сообщением.
//
// ==== Протокол выхода ====
//
// `TASK_EXIT` (само-выход) / fault-обработчик arch-глюя
// (`SyscallFacade::task_exit_exception`) / terminate-по-capability —
// все пути доставляют `ExitPayload` на exit-endpoint задачи (см.
// `crate::ipc::ExitPayload`) и каскадно гасят потоки домена.

use crate::capability::{
    CapHandle, CapabilityGate, ContainerACCCapability, MintSpec, RevokeReport,
};
use crate::ipc::{ExitPayload, FaultInfo, KillSource, RegisterSnapshot};
use crate::task::TaskView;
use crate::task::{TaskId, TaskPriority, TaskState, ThreadId};

use super::nums;
use super::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};
use super::{SyscallFacade, SyscallHandler};

impl SyscallFacade<'_> {
    // ==== Жизненный цикл задач ====

    /// Зарегистрировать задачу (`Ready`). Идентификатор назначает вызывающий
    /// (capability-модель: TaskId — внешний ключ, см. `ContainerACCCapability::TaskTCB`).
    ///
    /// Возвращает машинное слово результата: 0 (успех); код возврата —
    /// errno-отказ менеджера.
    pub fn task_spawn(&self, task_id: TaskId, priority: TaskPriority) -> SyscallRet {
        self.tasks.create(task_id, priority)?;
        Ok(0)
    }

    /// Перевести задачу в `Dead` (terminate): диспетчиризация прекращается,
    /// поколения TargetRef гаснут, ресурсы отзовёт владелец контрактом
    /// «revoke_all -> terminate -> destroy».
    ///
    /// Возвращает прежнее состояние как usize (аудит выхода).
    pub fn task_terminate(&self, task_id: TaskId) -> SyscallRet {
        let from = self.tasks.set_state(&task_id, TaskState::Dead)?;
        Ok(from as usize)
    }

    /// Разрушить TCB завершённой задачи: менеджер задач требует `Dead` и
    /// пустой cspace — оба условия проверяет он сам, фасад только маршрутизирует
    /// (двойная проверка здесь расползлась бы с менеджерной при эволюции).
    pub fn task_destroy(&self, task_id: TaskId) -> SyscallRet {
        self.tasks.destroy(task_id)?;
        Ok(0)
    }

    /// Приостановить задачу извне (`Suspended`): в очередь планировщика
    /// не попадает до resume.
    pub fn task_suspend(&self, task_id: TaskId) -> SyscallRet {
        self.tasks.set_state(&task_id, TaskState::Suspended)?;
        Ok(0)
    }

    /// Вернуть приостановленную в `Ready`.
    pub fn task_resume(&self, task_id: TaskId) -> SyscallRet {
        self.tasks.set_state(&task_id, TaskState::Ready)?;
        Ok(0)
    }

    /// Смена приоритета (переоценка очередей — хук планировщика менеджера).
    pub fn task_set_priority(&self, task_id: TaskId, priority: TaskPriority) -> SyscallRet {
        self.tasks.set_priority(&task_id, priority)?;
        Ok(0)
    }

    /// Снимок состояния задачи (контекст вызова не даёт ссылок наружу —
    /// копия `TaskView`).
    pub fn task_view(&self, task_id: TaskId) -> Result<TaskView, SyscallError> {
        self.tasks.get(&task_id).ok_or(SyscallError::NotFound)
    }

    // ==== Потоки (L4: единицы планирования) ====

    /// Создать поток в домене `owner` (маршрутизация к менеджеру;
    /// приоритет по умолчанию — сменa `thread_set_priority`).
    pub fn thread_create(
        &self,
        owner: TaskId,
        thread_id: ThreadId,
        entry: usize,
        stack_top: usize,
    ) -> SyscallRet {
        self.tasks
            .create_thread(thread_id, owner, TaskPriority::DEFAULT, entry, stack_top)?;
        Ok(0)
    }

    /// Принудительное гашение потока (без exit-доставки: это операция
    /// над потоком, не над доменом).
    pub fn thread_terminate(&self, thread_id: ThreadId) -> SyscallRet {
        self.tasks.thread_set_state(&thread_id, TaskState::Dead)?;
        Ok(0)
    }

    /// Разрушить TCB завершённого потока.
    pub fn thread_destroy(&self, thread_id: ThreadId) -> SyscallRet {
        self.tasks.destroy_thread(thread_id)?;
        Ok(0)
    }

    /// Смена приоритета задачи/потока (общее пространство имён L4).
    pub fn sched_set_priority(&self, id: TaskId, priority: TaskPriority) -> SyscallRet {
        // Поток или задача — различает менеджер: сначала потоковая таблица,
        // затем задачная (пространство имён общее).
        if self.tasks.thread_view(&id).is_some() {
            self.tasks.thread_set_priority(&id, priority)?;
        } else {
            self.tasks.set_priority(&id, priority)?;
        }
        Ok(0)
    }

    // ==== Протокол выхода: доставка exit-состояния + каскад ====

    /// Само-выход задачи `task` с кодом (полный маршрут):
    /// 1. доставить [`ExitPayload::Exit`] на exit-endpoint (если
    ///    зарегистрирован); буфер endpoint'а переживает смерть домена;
    /// 2. отпустить локи устройств задачи (claim-подсистема);
    /// 3. перевести задачу в `Dead` — каскад гасит все потоки.
    ///
    /// Возврата в пользователя НЕ БУДЕТ (домен мёртв): arch-глюй после
    /// этого вызова переключает контекст, не возвращаясь к вызывающему.
    pub fn task_exit(
        &self,
        ipc: Option<&crate::ipc::IpcManager>,
        task: TaskId,
        code: usize,
    ) -> SyscallRet {
        self.task_exit_of(ipc, task, ExitPayload::Exit { code })
    }

    /// Аварийное завершение по исключению (вызывает arch-глюй из
    /// fault-обработчика): снимок регистров + указатели фолта уходят
    /// родителю вторым видом exit-данных.
    pub fn task_exit_exception(
        &self,
        ipc: Option<&crate::ipc::IpcManager>,
        task: TaskId,
        snapshot: crate::ipc::RegisterSnapshot,
        fault: crate::ipc::FaultInfo,
    ) -> SyscallRet {
        self.task_exit_of(ipc, task, ExitPayload::Exception { snapshot, fault })
    }

    /// Принудительное гашение задачи источником `by` (третий вид
    /// exit-данных: кем убита).
    pub fn task_kill(
        &self,
        ipc: Option<&crate::ipc::IpcManager>,
        task: TaskId,
        by: KillSource,
    ) -> SyscallRet {
        self.task_exit_of(ipc, task, ExitPayload::Killed { by })
    }

    /// Полный маршрут выхода для задачи `task` (общий хвост всех видов):
    /// exit-доставка -> освобождение локов -> каскад Dead.
    pub fn task_exit_of(
        &self,
        ipc: Option<&crate::ipc::IpcManager>,
        task: TaskId,
        payload: ExitPayload,
    ) -> SyscallRet {
        // 1. Exit-доставка (до смерти: endpoint жив, пока жив реестр задач).
        if let Some(ipc) = ipc {
            ipc.deliver_exit(self.tasks, self.caps, task, payload)?;
        }
        // 2. Локи устройств: домен умирает — ресурсы не переживают его.
        if let Some(devices) = self.devices {
            devices.claims().release_all_of(self.tasks, &task);
        }
        // 3. Каскад: задача Dead, потоки погашены менеджером.
        self.tasks.set_state(&task, TaskState::Dead)?;
        Ok(0)
    }

    // ==== Cspace-операции (тонкая маршрутизация к менеджеру capability) ====

    /// Выдать задаче корневую capability (точка входа доверия: права/badge
    /// назначает ГРАНТОДАТЕЛЬ; пользовательский сискол обязан сузить
    /// источник до уже выданной capability — этот метод для kernel-side glue).
    ///
    /// Возвращает хендл выданного слота.
    pub fn cap_grant(&self, task: TaskId, gate: CapabilityGate) -> Result<CapHandle, SyscallError> {
        self.caps
            .grant(self.tasks, task, gate)
            .map_err(SyscallError::from)
    }

    /// Породить производную capability (требует права Mint у источника).
    /// Возвращает хендл производной у получателя.
    pub fn cap_mint(
        &self,
        src_task: TaskId,
        src: CapHandle,
        dst_task: TaskId,
        spec: &MintSpec,
    ) -> Result<CapHandle, SyscallError> {
        self.caps
            .mint(self.tasks, src_task, src, dst_task, spec)
            .map_err(SyscallError::from)
    }

    /// Передать capability (требует права Send): хендл у получателя новый,
    /// старый гасится (хендлы локальны cspace).
    pub fn cap_send(
        &self,
        src_task: TaskId,
        src: CapHandle,
        dst_task: TaskId,
    ) -> Result<CapHandle, SyscallError> {
        self.caps
            .send(self.tasks, src_task, src, dst_task)
            .map_err(SyscallError::from)
    }

    /// Удалить один хендл (дерево деривации перепривязывается менеджером).
    pub fn cap_delete(&self, task: TaskId, handle: CapHandle) -> SyscallRet {
        self.caps.delete(self.tasks, task, handle)?;
        Ok(0)
    }

    /// Отозвать хендл со всем поддеревом производных; отчёт — машинное
    /// число погашенных слотов.
    pub fn cap_revoke(&self, task: TaskId, handle: CapHandle) -> Result<usize, SyscallError> {
        let RevokeReport { revoked_slots } = self
            .caps
            .revoke(self.tasks, task, handle)
            .map_err(SyscallError::from)?;
        Ok(revoked_slots)
    }
}

// ───────────────────────────── Пример-хендлер ─────────────────────────────

/// Пример превращения фасадного маршрута в полноценный сискол (ПАТТЕРН, не
/// навязываемый API): статический хендлер, читающий аргументы по ABI
/// платформы и зовущий менеджер теми же тремя шагами, что и методы фасада
/// (идентификация -> менеджер -> перевод ошибки).
///
/// ABI хендлера (документируется платформой в таблице сисколов):
///   arg0 = номер (конвенция `SyscallRegistry::dispatch`),
///   arg1..2 = TaskId (две половины u128),
///   arg3 = приоритет.
pub struct TaskSpawnHandler;

impl TaskSpawnHandler {
    /// Номер сискола примера (легаси v0.2; в дефолтную таблицу НЕ входит
    /// — безопасный путь TASK_CREATE с capability-проверкой).
    pub const SYSCALL: SyscallNumber = nums::TASK_SPAWN;
}

impl SyscallHandler for TaskSpawnHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        // Идентификация вызова уже в ctx (task/cpu); аргументы — сырые слова.
        let task_id = task_id_from_args(args.arg(1), args.arg(2));
        let priority = TaskPriority(args.arg(3) as u8);
        // Тот же маршрут, что у `SyscallFacade::task_spawn`: менеджер решает,
        // фасад/хендлер — только доставляют.
        ctx.tasks
            .create(task_id, priority)
            .map_err(SyscallError::from)?;
        Ok(0)
    }
}

// ───────────────────────────── Хендлеры L4-слоя ─────────────────────────────

/// Создание потока в домене по TaskTCB-capability (L4 thread_control).
///
/// ABI: arg1 = хендл TaskTCB, arg2 = entry, arg3 = stack_top,
/// arg4..5 = ThreadId(lo, hi).
pub struct ThreadCreateHandler;

impl ThreadCreateHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_CREATE;
}

impl SyscallHandler for ThreadCreateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        // 1. Идентификация: capability TaskTCB домена-цели.
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };
        // 2. Менеджер: создание потока (валидация владельца/коллизий там).
        let thread_id = task_id_from_args(args.arg(4), args.arg(5));
        ctx.tasks.create_thread(
            thread_id,
            task_id,
            TaskPriority::DEFAULT,
            args.arg(2),
            args.arg(3),
        )?;
        Ok(0)
    }
}

/// Принудительное гашение потока. ABI: arg1..2 = ThreadId(lo, hi).
pub struct ThreadTerminateHandler;

impl ThreadTerminateHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_TERMINATE;
}

impl SyscallHandler for ThreadTerminateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        ctx.tasks.thread_set_state(&id, TaskState::Dead)?;
        Ok(0)
    }
}

/// Разрушение TCB завершённого потока. ABI: arg1..2 = ThreadId(lo, hi).
pub struct ThreadDestroyHandler;

impl ThreadDestroyHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_DESTROY;
}

impl SyscallHandler for ThreadDestroyHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        ctx.tasks.destroy_thread(id)?;
        Ok(0)
    }
}

/// Приоритет задачи/потока (общее пространство имён). ABI: arg1..2 = id,
/// arg3 = приоритет.
pub struct ThreadSetPrioHandler;

impl ThreadSetPrioHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_SET_PRIO;
}

impl SyscallHandler for ThreadSetPrioHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        let priority = TaskPriority(args.arg(3) as u8);
        if ctx.tasks.thread_view(&id).is_some() {
            ctx.tasks.thread_set_priority(&id, priority)?;
        } else {
            ctx.tasks.set_priority(&id, priority)?;
        }
        Ok(0)
    }
}

/// Регистрация exit-endpoint задачи. ABI: arg1 = хендл Gate-capability.
pub struct TaskSetExitEpHandler;

impl TaskSetExitEpHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_SET_EXIT_EP;
}

impl SyscallHandler for TaskSetExitEpHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };
        ctx.tasks.set_exit_endpoint(&ctx.task, gate_id)?;
        Ok(0)
    }
}

/// Само-выход вызывающей задачи с кодом (протокол выхода: доставка
/// ExitPayload на exit-endpoint + локи + каскад Dead). ABI: arg1 = код.
///
/// Возврата в пользователя не будет: домен мёртв (arch-глюй переключает
/// контекст после хендлера — состояние задачи Dead).
pub struct TaskExitHandler;

impl TaskExitHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_EXIT;
}

impl SyscallHandler for TaskExitHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let code = args.arg(1);
        // 1. Exit-доставка (требует IPC-подсистему; без неё — тихо без
        //    уведомлений, домен всё равно умирает).
        if let Some(ipc) = ctx.ipc {
            ipc.deliver_exit(ctx.tasks, ctx.caps, ctx.task, ExitPayload::Exit { code })?;
        }
        // 2. Локи устройств + привязки IRQ.
        if let Some(devices) = ctx.devices {
            devices.claims().release_all_of(ctx.tasks, &ctx.task);
        }
        if let Some(irq) = ctx.irq {
            irq.detach_all_of(&ctx.task);
        }
        // 3. Каскад: задача Dead, потоки погашены.
        ctx.tasks.set_state(&ctx.task, TaskState::Dead)?;
        Ok(0)
    }
}

/// Создание задачи-домена с правом творца (L4 task_new).
///
/// ПРАВО: capability TaskTCB на САМОГО ВЫЗЫВАЮЩЕГО — ядро выдаёт её
/// доверенным задачам (spawn-сервер, devmon) как сигнал «можно плодить
/// домены»; платформа управляет доверием выдачей этого гранта.
/// ABI: arg1 = хендл TaskTCB(себя), arg2..3 = TaskId(lo, hi) новой
/// задачи, arg4 = приоритет.
pub struct TaskCreateHandler;

impl TaskCreateHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_CREATE;
}

impl SyscallHandler for TaskCreateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::MissingRight);
        };
        // Право творца: TCB именно на себя.
        if task_id != ctx.task {
            return Err(SyscallError::MissingRight);
        }
        let new_task = task_id_from_args(args.arg(2), args.arg(3));
        let priority = TaskPriority(args.arg(4) as u8);
        ctx.tasks.create(new_task, priority)?;
        Ok(0)
    }
}

/// Убийство задачи по праву TaskTCB на ЦЕЛЬ (L4 task_new-terminate).
///
/// Полный маршрут: exit-доставка Killed{source} -> локи -> IRQ ->
/// каскад Dead. ABI: arg1 = хендл TaskTCB цели.
pub struct TaskKillHandler;

impl TaskKillHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_KILL;
}

impl SyscallHandler for TaskKillHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::MissingRight);
        };
        // 1. Доставка «кем убита» (источник — вызывающий).
        if let Some(ipc) = ctx.ipc {
            ipc.deliver_exit(
                ctx.tasks,
                ctx.caps,
                task_id,
                ExitPayload::Killed {
                    by: KillSource::Task(ctx.task),
                },
            )?;
        }
        // 2. Локи + IRQ цели.
        if let Some(devices) = ctx.devices {
            devices.claims().release_all_of(ctx.tasks, &task_id);
        }
        if let Some(irq) = ctx.irq {
            irq.detach_all_of(&task_id);
        }
        // 3. Каскад.
        ctx.tasks.set_state(&task_id, TaskState::Dead)?;
        Ok(0)
    }
}

/// Гашение ВЫЗЫВАЮЩЕЙ задачи по исключению (паника рантайма, fault).
///
/// ABI: arg1 = fault_addr, arg2 = ip, arg3 = FaultKind (слово),
/// arg4..5 = первые 2 слова снимка регистров (полный снапшот —
/// платформенный payload; слова ABI — минимум для старта).
pub struct TaskExitExceptionHandler;

impl TaskExitExceptionHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_EXIT_EXCEPTION;
}

impl SyscallHandler for TaskExitExceptionHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let fault = FaultInfo {
            fault_addr: args.arg(1),
            ip: args.arg(2),
            kind: crate::ipc::FaultKind::from_word(args.arg(3) as u64),
        };
        let snapshot = RegisterSnapshot::from_words(&[args.arg(4) as u64, args.arg(5) as u64]);
        // 1. Exception-доставка.
        if let Some(ipc) = ctx.ipc {
            ipc.deliver_exit(
                ctx.tasks,
                ctx.caps,
                ctx.task,
                ExitPayload::Exception { snapshot, fault },
            )?;
        }
        // 2. Локи + IRQ.
        if let Some(devices) = ctx.devices {
            devices.claims().release_all_of(ctx.tasks, &ctx.task);
        }
        if let Some(irq) = ctx.irq {
            irq.detach_all_of(&ctx.task);
        }
        // 3. Каскад.
        ctx.tasks.set_state(&ctx.task, TaskState::Dead)?;
        Ok(0)
    }
}

/// Приостановка потока (L4 suspend). ABI: arg1..2 = ThreadId(lo, hi).
/// Право: TaskTCB домена потока — suspend чужого потока без права нельзя.
pub struct ThreadSuspendHandler;

impl ThreadSuspendHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_SUSPEND;
}

impl SyscallHandler for ThreadSuspendHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        ctx.tasks.thread_set_state(&id, TaskState::Suspended)?;
        Ok(0)
    }
}

/// Возобновление потока (L4 resume). ABI: arg1..2 = ThreadId(lo, hi).
pub struct ThreadResumeHandler;

impl ThreadResumeHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_RESUME;
}

impl SyscallHandler for ThreadResumeHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        ctx.tasks.thread_set_state(&id, TaskState::Ready)?;
        Ok(0)
    }
}

/// Уступка CPU (L4 yield) для ТЕКУЩЕГО потока. Без аргументов.
pub struct ThreadYieldHandler;

impl ThreadYieldHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_YIELD;
}

impl SyscallHandler for ThreadYieldHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, _args: &SyscallArgs) -> SyscallRet {
        // Хук планировщика: бекенд без приоритетных очередей трактует
        // yield как no-op (дефолт — Ok). Себя в очередь не ставим — это
        // решение бекенда.
        if let Some(s) = ctx.tasks.scheduler() {
            s.yield_now(ctx.thread)?;
        }
        Ok(0)
    }
}

/// L4 thread_ex_regs: смена entry/stack потока. ABI: arg1..2 =
/// ThreadId(lo, hi), arg3 = new entry (-1 = не менять), arg4 = new
/// stack (-1 = не менять), arg5 = что вернуть: 0 = прежний entry,
/// 1 = прежний stack.
pub struct ThreadExRegsHandler;

impl ThreadExRegsHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_EX_REGS;
}

impl SyscallHandler for ThreadExRegsHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        let entry = match args.arg(3) {
            usize::MAX => None,
            v => Some(v),
        };
        let stack = match args.arg(4) {
            usize::MAX => None,
            v => Some(v),
        };
        let (old_entry, old_stack) = ctx.tasks.thread_ex_regs(&id, entry, stack)?;
        Ok(if args.arg(5) == 0 {
            old_entry
        } else {
            old_stack
        })
    }
}

/// Обход cspace вызывающего (CAP_LIST). Слова по индексу: 0 = число
/// живых хендлов; далее по 2 слова на слот: (handle_bits, kind).
/// ABI: arg1 = индекс слова.
pub struct CapListHandler;

impl CapListHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_LIST;
}

impl SyscallHandler for CapListHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        // ABI (nums.rs): слово 0 = число занятых слотов; далее ПО ДВА
        // слова на слот: [1+2i] = handle_bits (ПОЛНЫЙ u64 — generation
        // в старших 32 битах, упаковка в одно слово стирала его: хендл
        // протухал при resolve — баг v0.4, проявился первым реальным
        // пользователем в v0.6), [2+2i] = kind.
        let idx = args.arg(1);
        let mut count = 0usize;
        let mut target: Option<u64> = None;
        ctx.caps.for_each_task_cap(ctx.tasks, ctx.task, |v| {
            if idx == 1 + count * 2 {
                target = Some(v.id.bits());
            }
            if idx == 2 + count * 2 {
                target = Some(cap_kind_word(&v.cap_ref));
            }
            count += 1;
        });
        match idx {
            0 => Ok(count),
            _ => target
                .map(|w| Ok(w as usize))
                .unwrap_or(Err(SyscallError::InvalidArgument)),
        }
    }
}

/// Снимок capability по хендлу (CAP_INFO). Слова по индексу: 0 = kind,
/// 1 = perms, 2 = badge (64 бита), 3 = alive, 4..5 = идентификация
/// (TaskTCB: TaskId lo/hi; Gate: obj_id; Irq: (gsi, obj_id);
/// DeviceReference: (компактное слово пути, 0)).
/// ABI: arg1 = хендл, arg2 = индекс.
pub struct CapInfoHandler;

impl CapInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_INFO;
}

impl SyscallHandler for CapInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ident: [u64; 2] = match &view.cap_ref {
            ContainerACCCapability::TaskTCB { task_id } => {
                let v = task_id.as_u128();
                [v as u64, (v >> 64) as u64]
            }
            ContainerACCCapability::Gate { gate_id } => [gate_id.0, 0],
            ContainerACCCapability::Irq { irq, obj_id } => [irq.0 as u64, obj_id.0],
            ContainerACCCapability::DeviceReference { .. } => {
                // Полный путь — только в реестре устройств; компактная
                // кодировка пути — та же, что у DEVICE_ENUM.
                [cap_path_word0(&view.cap_ref), 0]
            }
        };
        let words = [
            cap_kind_word(&view.cap_ref),
            view.perms.bits() as u64,
            view.badge.bits(),
            1, // alive: resolve уже отфильтровал погашенные
            ident[0],
            ident[1],
        ];
        let idx = args.arg(2);
        words
            .get(idx)
            .map(|w| Ok(*w as usize))
            .unwrap_or(Err(SyscallError::InvalidArgument))
    }
}

/// Слово-код типа capability (стабильная кодировка CAP_LIST/CAP_INFO).
fn cap_kind_word(cap: &ContainerACCCapability) -> u64 {
    match cap {
        ContainerACCCapability::DeviceReference { .. } => 1,
        ContainerACCCapability::TaskTCB { .. } => 2,
        ContainerACCCapability::Gate { .. } => 3,
        ContainerACCCapability::Irq { .. } => 4,
    }
}

/// Компактное слово пути устройства (общая кодировка с DEVICE_ENUM).
fn cap_path_word0(cap: &ContainerACCCapability) -> u64 {
    if let ContainerACCCapability::DeviceReference { dev_path } = cap {
        crate::syscall::device::path_word0(dev_path)
    } else {
        0
    }
}

/// Проверка права на поток: вызывающий владеет TaskTCB домена потока
/// ИЛИ сам поток — его домен (L4: свой домен — своя кухня).
fn require_thread_domain(ctx: &SyscallCtx<'_>, thread: &ThreadId) -> Result<(), SyscallError> {
    let owner = ctx
        .tasks
        .thread_task(thread)
        .ok_or(SyscallError::NotFound)?;
    if owner == ctx.task {
        return Ok(());
    }
    // Чужой домен: ищем TaskTCB на него в cspace вызывающего.
    let mut permitted = false;
    ctx.caps.for_each_task_cap(ctx.tasks, ctx.task, |v| {
        if let ContainerACCCapability::TaskTCB { task_id } = &v.cap_ref {
            if *task_id == owner {
                permitted = true;
            }
        }
    });
    if permitted {
        Ok(())
    } else {
        Err(SyscallError::MissingRight)
    }
}

// ==== Передача прав capability (map/grant-наследники L4) ====

/// Mint: производная capability (сужение прав/badge).
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя, arg4 = perms,
/// arg5 = badge.
pub struct CapMintHandler;

impl CapMintHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_MINT;
}

impl SyscallHandler for CapMintHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        let dst = task_id_from_args(args.arg(2), args.arg(3));
        let spec = MintSpec {
            perms: crate::capability::ActionPermissions::from_bits_retain(args.arg(4) as u8),
            badge: crate::capability::CapabilityBadge::from_bits(args.arg(5) as u64),
        };
        let handle = ctx.caps.mint(ctx.tasks, ctx.task, src, dst, &spec)?;
        Ok(handle.bits() as usize)
    }
}

/// Send: передача хендла (право Send у источника).
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя.
pub struct CapSendHandler;

impl CapSendHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_SEND;
}

impl SyscallHandler for CapSendHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        let dst = task_id_from_args(args.arg(2), args.arg(3));
        let handle = ctx.caps.send(ctx.tasks, ctx.task, src, dst)?;
        Ok(handle.bits() as usize)
    }
}

/// Revoke: отзыв хендла со всем поддеревом. ABI: arg1 = хендл.
pub struct CapRevokeHandler;

impl CapRevokeHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_REVOKE;
}

impl SyscallHandler for CapRevokeHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        let RevokeReport { revoked_slots } = ctx.caps.revoke(ctx.tasks, ctx.task, src)?;
        Ok(revoked_slots)
    }
}

/// Delete: удаление одного хендла. ABI: arg1 = хендл.
pub struct CapDeleteHandler;

impl CapDeleteHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_DELETE;
}

impl SyscallHandler for CapDeleteHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        ctx.caps.delete(ctx.tasks, ctx.task, src)?;
        Ok(0)
    }
}

/// Сборка TaskId из пары машинных слов (u128 -> Uuid): платформенный ABI
/// передаёт большие идентификаторы регистрами (`lo` — младшие 64 бита).
fn task_id_from_args(lo: usize, hi: usize) -> TaskId {
    let v = ((hi as u128) << 64) | (lo as u128);
    uuid::Uuid::from_u128(v)
}

// ───────────────────────────── Тесты (host) ─────────────────────────────

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use crate::capability::{
        ActionPermissions, CapHandle, CapabilityBadge, CapabilityGate, CapabilityManager,
        ContainerACCCapability, MintSpec,
    };
    use crate::task::{TaskPriority, TaskState, TcbManager};

    use super::super::nums;
    use super::super::types::SyscallArgs;
    use super::super::types::SyscallError;
    use super::super::{SyscallFacade, SyscallRegistry};
    use super::TaskSpawnHandler;
    /// Детерминированно-уникальный TaskId для тестов: uuid без фичи v4 —
    /// генератора нет, счётчик процесса даёт достаточную уникальность.
    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    /// Статические менеджеры для фасада-view (живут дольше теста).
    fn facade() -> (
        SyscallFacade<'static>,
        &'static TcbManager,
        &'static CapabilityManager,
        &'static SyscallRegistry,
    ) {
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let reg: &'static SyscallRegistry = Box::leak(Box::new(SyscallRegistry::new()));
        (SyscallFacade::new(tasks, caps, reg), tasks, caps, reg)
    }

    #[test]
    fn task_lifecycle_routing() {
        let (facade, _tasks, _caps, _reg) = facade();
        let id = uuid_next();

        // spawn -> Ready.
        assert_eq!(facade.task_spawn(id, TaskPriority(42)), Ok(0));
        assert_eq!(facade.task_view(id).unwrap().state, TaskState::Ready);
        assert_eq!(facade.task_view(id).unwrap().priority, TaskPriority(42));

        // suspend/resume.
        assert_eq!(facade.task_suspend(id), Ok(0));
        assert_eq!(facade.task_view(id).unwrap().state, TaskState::Suspended);
        assert_eq!(facade.task_resume(id), Ok(0));
        assert_eq!(facade.task_view(id).unwrap().state, TaskState::Ready);

        // Приоритет.
        assert_eq!(facade.task_set_priority(id, TaskPriority(7)), Ok(0));
        assert_eq!(facade.task_view(id).unwrap().priority, TaskPriority(7));

        // Дубликат — EEXIST-перевод ошибки менеджера.
        assert_eq!(
            facade.task_spawn(id, TaskPriority(1)),
            Err(SyscallError::AlreadyExists)
        );

        // terminate (возвращает прежнее состояние) -> destroy.
        let from = facade.task_terminate(id).unwrap();
        assert_eq!(from, TaskState::Ready as usize);
        assert_eq!(facade.task_view(id).unwrap().state, TaskState::Dead);
        assert_eq!(facade.task_destroy(id), Ok(0));
        assert_eq!(facade.task_view(id), Err(SyscallError::NotFound));

        // destroy незавершённой — Busy-перевод (контракт менеджера).
        let id2 = uuid_next();
        facade.task_spawn(id2, TaskPriority(1)).unwrap();
        assert_eq!(facade.task_destroy(id2), Err(SyscallError::Busy));
    }

    #[test]
    fn capability_routing_and_errno() {
        let (facade, _tasks, _caps, _reg) = facade();
        let task = uuid_next();
        facade.task_spawn(task, TaskPriority::DEFAULT).unwrap();
        let stranger = uuid_next();
        facade.task_spawn(stranger, TaskPriority::DEFAULT).unwrap();

        // Грант TCB-цели (kernel-side точка доверия).
        let gate = CapabilityGate::new(
            ContainerACCCapability::TaskTCB { task_id: task },
            ActionPermissions::all(),
            CapabilityBadge::FULL,
        );
        let h = facade.cap_grant(task, gate).unwrap();

        // Mint с сужением: Send-only.
        let spec = MintSpec {
            perms: ActionPermissions::FOR_SEND,
            badge: CapabilityBadge::from_bits(0xF),
        };
        let child = facade.cap_mint(task, h, stranger, &spec).unwrap();

        // Отправить обратно: у stranger новый хендл.
        let returned = facade.cap_send(stranger, child, task).unwrap();
        assert_ne!(returned, child);

        // Отзыв поддерева: 1 слот (ребенок уже передан —дерево у отправителя).
        let revoked = facade.cap_revoke(task, returned).unwrap();
        assert_eq!(revoked, 1);

        // Мёртвый хендл — InvalidHandle (нет/протух неразличимы).
        assert_eq!(
            facade.cap_delete(task, returned),
            Err(SyscallError::InvalidHandle)
        );
    }

    #[test]
    fn task_spawn_handler_pattern() {
        let (_facade, _tasks, _caps, reg) = facade();
        reg.register(TaskSpawnHandler::SYSCALL, &TaskSpawnHandler)
            .unwrap();

        let id = uuid_next();
        let v = id.as_u128();
        let lo = (v as u64) as usize;
        let hi = ((v >> 64) as u64) as usize;
        // arg0 = номер, arg1..2 = TaskId, arg3 = приоритет.
        let args = SyscallArgs::new([
            TaskSpawnHandler::SYSCALL.as_u64() as usize,
            lo,
            hi,
            55,
            0,
            0,
        ]);

        let (tasks, caps) = (
            Box::leak(Box::new(TcbManager::new().unwrap())) as &'static TcbManager,
            Box::leak(Box::new(CapabilityManager::new().unwrap())) as &'static CapabilityManager,
        );
        let mut ctx = crate::syscall::types::SyscallCtx::core(0, uuid_next(), tasks, caps);
        assert_eq!(reg.dispatch(&mut ctx, &args), Ok(0));
        assert_eq!(tasks.get(&id).unwrap().priority, TaskPriority(55));

        // Повторный spawn того же TaskId — EEXIST через тот же маршрут.
        assert_eq!(
            reg.dispatch(&mut ctx, &args),
            Err(SyscallError::AlreadyExists)
        );
    }

    /// ПОЛНЫЙ L4-цикл: спавн домена -> главный поток -> exit-endpoint ->
    /// стартовое сообщение argc/argv через IPC (fast-path) -> само-выход ->
    /// родитель получает все три вида exit-данных.
    #[test]
    fn l4_full_cycle_spawn_argv_exit() {
        use crate::ipc::{BlockMode, ExitPayload, IpcManager, RecvOutcome};
        use crate::syscall::ipc::{
            EpCreateHandler, IpcMsgWordHandler, IpcRecvAnyHandler, IpcSendThreadHandler,
        };
        use crate::syscall::nums;
        use crate::task::{TaskState, ThreadId};

        // Менеджеры (без планировщика: fast-path не блокирует отправителя,
        // блокировка получателя — set_state напрямую).
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));
        let reg: &'static SyscallRegistry = Box::leak(Box::new(SyscallRegistry::new()));
        reg.register(EpCreateHandler::SYSCALL, &EpCreateHandler)
            .unwrap();
        reg.register(IpcSendThreadHandler::SYSCALL, &IpcSendThreadHandler)
            .unwrap();
        reg.register(IpcRecvAnyHandler::SYSCALL, &IpcRecvAnyHandler)
            .unwrap();
        reg.register(IpcMsgWordHandler::SYSCALL, &IpcMsgWordHandler)
            .unwrap();

        // Родитель.
        let parent = uuid_next();
        tasks.create(parent, TaskPriority::DEFAULT).unwrap();
        let parent_thread = uuid_next();
        tasks
            .create_thread(parent_thread, parent, TaskPriority(50), 0, 0)
            .unwrap();

        // 1. Спавн домена-ребёнка.
        let child = uuid_next();
        tasks.create(child, TaskPriority::DEFAULT).unwrap();

        // 2. Главный поток ребёнка (entry/stack — raw-слова, arch-глюй).
        let main_thread: ThreadId = uuid_next();
        tasks
            .create_thread(main_thread, child, TaskPriority(60), 0x4000, 0x8000)
            .unwrap();

        // 3. Exit-endpoint РОДИТЕЛЯ (ёмкость 4: ядерная доставка не
        //    блокируется) + регистрация для ребёнка.
        let mut pctx = crate::syscall::SyscallCtx::core(0, parent, tasks, caps)
            .with_thread(parent_thread)
            .with_ipc(ipc);
        let exit_ep = reg
            .dispatch(
                &mut pctx,
                &SyscallArgs::new([nums::EP_CREATE.as_u64() as usize, 4, 0, 0, 0, 0]),
            )
            .unwrap() as u64;
        let exit_gate = caps
            .endpoint_of(tasks, parent, crate::capability::CapHandle(exit_ep))
            .unwrap();
        tasks.set_exit_endpoint(&child, exit_gate).unwrap();

        // 4. Ребёнок стартует: главный поток блокируется в open-receive
        //    (первая операция его жизни — приём argc/argv, протокол L4).
        tasks
            .thread_set_state(&main_thread, TaskState::Running)
            .unwrap();
        let mut cctx = crate::syscall::SyscallCtx::core(0, child, tasks, caps)
            .with_thread(main_thread)
            .with_ipc(ipc);
        let out = reg
            .dispatch(
                &mut cctx,
                &SyscallArgs::new([nums::IPC_RECV_ANY.as_u64() as usize, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(out, 0);
        assert_eq!(
            tasks.thread_view(&main_thread).unwrap().state,
            TaskState::Blocked
        );

        // 5. Родитель шлёт стартовое сообщение argc/argv ПРЯМОМУ ПОТОКУ
        //    (fast-path L4): [argc=3, argv_ptr, argv_bytes].
        let mv = main_thread.as_u128();
        let argv_word = (u64::from_le_bytes(*b"/bin/inj")) as usize; // сами данные — map-элементом
        reg.dispatch(
            &mut pctx,
            &SyscallArgs::new([
                nums::IPC_SEND_THREAD.as_u64() as usize,
                mv as usize,
                (mv >> 64) as usize,
                3, // argc
                argv_word,
                2,
            ]),
        )
        .unwrap();

        // Fast-path разбудил главный поток: argc в слове 0.
        assert_eq!(
            tasks.thread_view(&main_thread).unwrap().state,
            TaskState::Ready
        );
        let argc = reg
            .dispatch(
                &mut cctx,
                &SyscallArgs::new([
                    crate::syscall::nums::IPC_MSG_WORD.as_u64() as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]),
            )
            .unwrap();
        assert_eq!(argc, 3);

        // 6. Ребёнок само-выходит с кодом 42: exit-endpoint получает
        //    первый вид данных (код выхода), потоки гаснут каскадом.
        ipc.deliver_exit(tasks, caps, child, ExitPayload::Exit { code: 42 })
            .unwrap();
        tasks.set_state(&child, TaskState::Dead).unwrap();
        assert_eq!(
            tasks.thread_view(&main_thread).unwrap().state,
            TaskState::Dead
        );

        // 7. Родитель читает exit-сообщение из буфера endpoint'а.
        let out = ipc
            .recv(
                tasks,
                caps,
                parent_thread,
                crate::capability::CapHandle(exit_ep),
                BlockMode::Try,
            )
            .unwrap();
        let RecvOutcome::Message(msg) = out else {
            panic!("exit-сообщение обязано быть в буфере");
        };
        assert_eq!(msg.word(0), 1); // тег Exit
        assert_eq!(msg.word(3), 42); // код
        let back = ExitPayload::from_message(&msg).unwrap();
        assert_eq!(back, ExitPayload::Exit { code: 42 });

        // 8. Второй и третий виды: исключение (regs+fault) и кем убита.
        let child2 = uuid_next();
        tasks.create(child2, TaskPriority::DEFAULT).unwrap();
        tasks.set_exit_endpoint(&child2, exit_gate).unwrap();
        ipc.deliver_exit(
            tasks,
            caps,
            child2,
            ExitPayload::Exception {
                snapshot: crate::ipc::RegisterSnapshot::from_words(&[0xAAAA, 0xBBBB]),
                fault: crate::ipc::FaultInfo {
                    fault_addr: 0xDEAD_BEEF,
                    ip: 0x4000,
                    kind: crate::ipc::FaultKind::PageWrite,
                },
            },
        )
        .unwrap();
        tasks.set_state(&child2, TaskState::Dead).unwrap();

        let child3 = uuid_next();
        tasks.create(child3, TaskPriority::DEFAULT).unwrap();
        tasks.set_exit_endpoint(&child3, exit_gate).unwrap();
        ipc.deliver_exit(
            tasks,
            caps,
            child3,
            ExitPayload::Killed {
                by: crate::ipc::KillSource::Task(parent),
            },
        )
        .unwrap();
        tasks.set_state(&child3, TaskState::Dead).unwrap();

        // Оба сообщения — в буфере (FIFO).
        let msg2 = match ipc
            .recv(
                tasks,
                caps,
                parent_thread,
                crate::capability::CapHandle(exit_ep),
                BlockMode::Try,
            )
            .unwrap()
        {
            RecvOutcome::Message(m) => m,
            _ => panic!(),
        };
        assert_eq!(msg2.word(0), 2); // тег Exception
        assert_eq!(
            ExitPayload::from_message(&msg2),
            Some(ExitPayload::Exception {
                snapshot: crate::ipc::RegisterSnapshot::from_words(&[0xAAAA, 0xBBBB]),
                fault: crate::ipc::FaultInfo {
                    fault_addr: 0xDEAD_BEEF,
                    ip: 0x4000,
                    kind: crate::ipc::FaultKind::PageWrite
                }
            })
        );

        let msg3 = match ipc
            .recv(
                tasks,
                caps,
                parent_thread,
                crate::capability::CapHandle(exit_ep),
                BlockMode::Try,
            )
            .unwrap()
        {
            RecvOutcome::Message(m) => m,
            _ => panic!(),
        };
        assert_eq!(msg3.word(0), 3); // тег Killed
        assert_eq!(
            ExitPayload::from_message(&msg3),
            Some(ExitPayload::Killed {
                by: crate::ipc::KillSource::Task(parent)
            })
        );

        // IPC-статистика: доставки пошли.
        let (delivered, fast, _blocked) = ipc.stats();
        assert!(delivered >= 4);
        assert!(fast >= 1);
    }

    /// Мир с дефолтной таблицей сисколов (как GCTL отдаёт платформе).
    fn default_table_world() -> (
        &'static SyscallRegistry,
        &'static TcbManager,
        &'static CapabilityManager,
    ) {
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let reg: &'static SyscallRegistry = Box::leak(Box::new(SyscallRegistry::new()));
        reg.install_default_table();
        (reg, tasks, caps)
    }

    fn grant_tcb(
        caps: &CapabilityManager,
        tasks: &TcbManager,
        owner: crate::task::TaskId,
        target: crate::task::TaskId,
    ) -> CapHandle {
        caps.grant(
            tasks,
            owner,
            CapabilityGate::new(
                ContainerACCCapability::TaskTCB { task_id: target },
                ActionPermissions::all(),
                crate::capability::CapabilityBadge::FULL,
            ),
        )
        .unwrap()
    }

    #[test]
    fn task_create_requires_creator_tcb_on_self() {
        let (reg, tasks, caps) = default_table_world();
        let creator = uuid_next();
        tasks.create(creator, TaskPriority::DEFAULT).unwrap();
        let mut ctx = crate::syscall::SyscallCtx::core(0, creator, tasks, caps);

        // Без права (хендл битый) — EBADF.
        let new_id = uuid_next();
        let v = new_id.as_u128();
        let args = SyscallArgs::new([0, 0xDEAD, v as usize, (v >> 64) as usize, 5, 0]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args),
            Err(SyscallError::InvalidHandle)
        );

        // Право на ДРУГОГО — не право творца.
        let stranger = uuid_next();
        tasks.create(stranger, TaskPriority::DEFAULT).unwrap();
        let h_stranger = grant_tcb(caps, tasks, creator, stranger);
        let args = SyscallArgs::new([
            0,
            h_stranger.bits() as usize,
            v as usize,
            (v >> 64) as usize,
            5,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );

        // Право на себя — домен создан (L4 task_new).
        let h_self = grant_tcb(caps, tasks, creator, creator);
        let args = SyscallArgs::new([
            0,
            h_self.bits() as usize,
            v as usize,
            (v >> 64) as usize,
            5,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args),
            Ok(0)
        );
        assert_eq!(tasks.get(&new_id).unwrap().priority, TaskPriority(5));
    }

    #[test]
    fn task_kill_routes_exit_and_cascade() {
        use crate::ipc::IpcManager;
        let (reg, tasks, caps) = default_table_world();
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));

        let killer = uuid_next();
        tasks.create(killer, TaskPriority::DEFAULT).unwrap();
        let killer_thread = uuid_next();
        tasks
            .create_thread(killer_thread, killer, TaskPriority(50), 0, 0)
            .unwrap();
        let victim = uuid_next();
        tasks.create(victim, TaskPriority::DEFAULT).unwrap();
        let vthread = uuid_next();
        tasks
            .create_thread(vthread, victim, TaskPriority(9), 0x1000, 0x2000)
            .unwrap();

        // Право на жертву + exit-endpoint жертвы (уведомление убийцы).
        let h_victim = grant_tcb(caps, tasks, killer, victim);
        let mut kctx = crate::syscall::SyscallCtx::core(0, killer, tasks, caps).with_ipc(ipc);
        let exit_ep = reg
            .dispatch_number(
                nums::EP_CREATE,
                &mut kctx,
                &SyscallArgs::new([0, 4, 0, 0, 0, 0]),
            )
            .unwrap() as u64;
        let gate = caps.endpoint_of(tasks, killer, CapHandle(exit_ep)).unwrap();
        tasks.set_exit_endpoint(&victim, gate).unwrap();

        // KILL: Killed{source=killer} + каскад (поток жертвы погашен).
        let args = SyscallArgs::new([0, h_victim.bits() as usize, 0, 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_KILL, &mut kctx, &args),
            Ok(0)
        );
        assert_eq!(tasks.get(&victim).unwrap().state, TaskState::Dead);
        assert_eq!(tasks.thread_view(&vthread).unwrap().state, TaskState::Dead);

        // Уведомление — в буфере endpoint'а убийцы (тег 3 = Killed).
        let out = ipc
            .recv(
                tasks,
                caps,
                killer_thread,
                CapHandle(exit_ep),
                crate::ipc::BlockMode::Try,
            )
            .unwrap();
        let crate::ipc::RecvOutcome::Message(msg) = out else {
            panic!("Killed-уведомление обязано быть в буфере");
        };
        assert_eq!(msg.word(0), 3);
        assert_eq!(
            crate::ipc::ExitPayload::from_message(&msg),
            Some(crate::ipc::ExitPayload::Killed {
                by: crate::ipc::KillSource::Task(killer)
            })
        );
    }

    #[test]
    fn thread_suspend_resume_ex_regs_yield() {
        let (reg, tasks, caps) = default_table_world();
        let owner = uuid_next();
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();
        let t = uuid_next();
        tasks
            .create_thread(t, owner, TaskPriority(7), 0x4000, 0x8000)
            .unwrap();
        let mut ctx = crate::syscall::SyscallCtx::core(0, owner, tasks, caps).with_thread(t);
        let id = |ctx_id: uuid::Uuid| {
            let v = ctx_id.as_u128();
            [v as usize, (v >> 64) as usize]
        };

        // YIELD: дефолтный планировщик (нет) — Ok(0) без хука.
        assert_eq!(
            reg.dispatch_number(nums::THREAD_YIELD, &mut ctx, &SyscallArgs::none()),
            Ok(0)
        );

        // SUSPEND своего потока: Ready -> Suspended.
        let tv = id(t);
        let args = SyscallArgs::new([0, tv[0], tv[1], 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_SUSPEND, &mut ctx, &args),
            Ok(0)
        );
        assert_eq!(tasks.thread_view(&t).unwrap().state, TaskState::Suspended);

        // RESUME: Suspended -> Ready.
        assert_eq!(
            reg.dispatch_number(nums::THREAD_RESUME, &mut ctx, &args),
            Ok(0)
        );
        assert_eq!(tasks.thread_view(&t).unwrap().state, TaskState::Ready);

        // EX_REGS: смена entry (стек не трогаем), возврат прежнего entry.
        let args = SyscallArgs::new([0, tv[0], tv[1], 0x9000, usize::MAX, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_EX_REGS, &mut ctx, &args),
            Ok(0x4000)
        );
        // Второе слово возврата — прежний стек (меняем стек, читаем его).
        let args = SyscallArgs::new([0, tv[0], tv[1], usize::MAX, 0xA000, 1]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_EX_REGS, &mut ctx, &args),
            Ok(0x8000)
        );
        assert_eq!(tasks.thread_start_info(&t), Some((0x9000, 0xA000)));

        // Чужой поток без TaskTCB домена — MissingRight.
        let stranger = uuid_next();
        tasks.create(stranger, TaskPriority::DEFAULT).unwrap();
        let st = uuid_next();
        tasks
            .create_thread(st, stranger, TaskPriority(1), 0, 0)
            .unwrap();
        let sv = id(st);
        let args = SyscallArgs::new([0, sv[0], sv[1], 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_SUSPEND, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );
    }

    #[test]
    fn cap_list_and_info_words() {
        let (reg, tasks, caps) = default_table_world();
        let owner = uuid_next();
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();

        // Пустой cspace: 0 слотов.
        let mut ctx = crate::syscall::SyscallCtx::core(0, owner, tasks, caps);
        assert_eq!(
            reg.dispatch_number(
                nums::CAP_LIST,
                &mut ctx,
                &SyscallArgs::new([0, 0, 0, 0, 0, 0])
            ),
            Ok(0)
        );

        // Гранты: TaskTCB на себя + DeviceReference-подобный (Gate).
        let h_tcb = grant_tcb(caps, tasks, owner, owner);
        let v = owner.as_u128();

        // CAP_LIST: 1 слот, слово 1 = handle_bits (полный u64),
        // слово 2 = kind (2 = TaskTCB). Полный хендл обязан проходить
        // без потерь (generation в старших битах).
        let w = reg
            .dispatch_number(
                nums::CAP_LIST,
                &mut ctx,
                &SyscallArgs::new([0, 1, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(w as u64, h_tcb.bits(), "полный хендл без обрезания");
        let k = reg
            .dispatch_number(
                nums::CAP_LIST,
                &mut ctx,
                &SyscallArgs::new([0, 2, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(k, 2, "kind = TaskTCB");

        // CAP_INFO слова: kind / perms / badge / alive / TaskId.lo / hi.
        let mut info = |i: usize| {
            reg.dispatch_number(
                nums::CAP_INFO,
                &mut ctx,
                &SyscallArgs::new([0, h_tcb.bits() as usize, i, 0, 0, 0]),
            )
            .unwrap()
        };
        assert_eq!(info(0), 2); // TaskTCB
        assert_eq!(info(1) as u8, ActionPermissions::all().bits());
        assert_eq!(info(2), u64::MAX as usize); // badge FULL
        assert_eq!(info(3), 1); // alive
        assert_eq!(info(4), v as usize);
        assert_eq!(info(5), (v >> 64) as usize);
        // Вне диапазона — EINVAL.
        assert_eq!(
            reg.dispatch_number(
                nums::CAP_INFO,
                &mut ctx,
                &SyscallArgs::new([0, h_tcb.bits() as usize, 6, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
    }

    #[test]
    fn task_exit_exception_kills_caller_with_snapshot() {
        use crate::ipc::IpcManager;
        let (reg, tasks, caps) = default_table_world();
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));

        let watcher = uuid_next();
        tasks.create(watcher, TaskPriority::DEFAULT).unwrap();
        let watcher_thread = uuid_next();
        tasks
            .create_thread(watcher_thread, watcher, TaskPriority(50), 0, 0)
            .unwrap();
        let victim = uuid_next();
        tasks.create(victim, TaskPriority::DEFAULT).unwrap();

        // Exit-endpoint наблюдателя для жертвы.
        let mut wctx = crate::syscall::SyscallCtx::core(0, watcher, tasks, caps).with_ipc(ipc);
        let exit_ep = reg
            .dispatch_number(
                nums::EP_CREATE,
                &mut wctx,
                &SyscallArgs::new([0, 4, 0, 0, 0, 0]),
            )
            .unwrap() as u64;
        let gate = caps
            .endpoint_of(tasks, watcher, CapHandle(exit_ep))
            .unwrap();
        tasks.set_exit_endpoint(&victim, gate).unwrap();

        // Жертва гаснет по исключению (паника рантайма).
        let mut vctx = crate::syscall::SyscallCtx::core(0, victim, tasks, caps).with_ipc(ipc);
        let args = SyscallArgs::new([0, 0xDEAD_BEEF, 0x4000, 2, 0xAAAA, 0xBBBB]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_EXIT_EXCEPTION, &mut vctx, &args),
            Ok(0)
        );
        assert_eq!(tasks.get(&victim).unwrap().state, TaskState::Dead);

        // Слова Exception-доставки: тег 2, fault_addr, ip, kind=PageWrite.
        let out = ipc
            .recv(
                tasks,
                caps,
                watcher_thread,
                CapHandle(exit_ep),
                crate::ipc::BlockMode::Try,
            )
            .unwrap();
        let crate::ipc::RecvOutcome::Message(msg) = out else {
            panic!("Exception-уведомление обязано быть в буфере");
        };
        assert_eq!(msg.word(0), 2);
        assert_eq!(msg.word(3), 0xDEAD_BEEF);
        assert_eq!(msg.word(4), 0x4000);
        assert_eq!(msg.word(5), 2);
        assert_eq!(msg.payload(), Some(&[0xAAAA, 0xBBBB][..]));
    }
}
