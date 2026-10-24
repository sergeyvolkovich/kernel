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
use crate::hal::traits::mmap::{MMAPMemoryFlags, PAGE_SIZE};
use crate::ipc::{
    ExitPayload, FaultInfo, IPC_KERNEL_FROM, IpcMessage, KillSource, RegisterSnapshot,
};
use crate::task::TaskLimits;
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
    ///    зарегистрирован; в слова — код + CPU-статистика домена — v0.10,
    ///    вердикт песочницы без гонок с reaper'ом);
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
        // CPU-снимок ДО смерти домена (deliver раньше каскада — статистика
        // ещё живого GTCB; после — TCB уже разрушен).
        let (cpu_used, cpu_throttle_events) = self
            .tasks
            .sec_view(&task)
            .map(|sec| (sec.usage.cpu_used, sec.usage.cpu_throttle_events))
            .unwrap_or((0, 0));
        self.task_exit_of(
            ipc,
            task,
            ExitPayload::Exit {
                code,
                cpu_used,
                cpu_throttle_events,
            },
        )
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
        // 2. v0.14: локов устройств нет (реестр удалён); привязки IRQ
        //    гасятся каскадом смерти через Glue (detach_all_of).
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
        // v0.17: arg6 — начальное TLS-слово (0 = без TLS, до-v0.17
        // поведение; старые вызывающие не передают шестой аргумент —
        // SyscallArgs::arg(6) детерминированно 0, ABI не меняется).
        // Выставка НА создании закрывает гонку «создал -> выставил»:
        // свежий поток может быть диспетчеризован другим CPU раньше,
        // чем создатель дойдёт до THREAD_SET_TLS.
        let tls = args.arg(6);
        ctx.tasks.create_thread_with_tls(
            thread_id,
            task_id,
            TaskPriority::DEFAULT,
            args.arg(2),
            args.arg(3),
            tls,
        )?;
        Ok(0)
    }
}

/// Принудительное гашение потока. ПРАВО (v0.9): TaskTCB домена потока
/// ИЛИ собственный домен (как suspend/resume — «своя кухня»);
/// без права гасить чужой поток нельзя.
/// ABI: arg1..2 = ThreadId(lo, hi).
pub struct ThreadTerminateHandler;

impl ThreadTerminateHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_TERMINATE;
}

impl SyscallHandler for ThreadTerminateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        ctx.tasks.thread_set_state(&id, TaskState::Dead)?;
        Ok(0)
    }
}

/// Разрушение TCB завершённого потока. ПРАВО (v0.9): TaskTCB домена
/// ИЛИ собственный домен.
/// ABI: arg1..2 = ThreadId(lo, hi).
pub struct ThreadDestroyHandler;

impl ThreadDestroyHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_DESTROY;
}

impl SyscallHandler for ThreadDestroyHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        ctx.tasks.destroy_thread(id)?;
        Ok(0)
    }
}

/// Приоритет задачи/потока (общее пространство имён). ПРАВО (v0.9):
/// TaskTCB домена ИЛИ собственный домен; плюс ПОТОЛОК max_prio из
/// атрибутов песочницы ЦЕЛИ (песочница не даёт выйти за приоритет,
/// даже своему домену — иначе DoS-захват CPU).
/// ABI: arg1..2 = id, arg3 = приоритет.
pub struct ThreadSetPrioHandler;

impl ThreadSetPrioHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_SET_PRIO;
}

impl SyscallHandler for ThreadSetPrioHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        let priority = TaskPriority(args.arg(3) as u8);
        let target_domain = if let Some(owner) = ctx.tasks.thread_task(&id) {
            owner
        } else {
            id // не поток — считаем задачей (общее пространство имён)
        };
        require_thread_domain(ctx, &id)?;
        // v0.9: потолок приоритета цели (атрибут GTCB).
        if let Some(sec) = ctx.tasks.sec_view(&target_domain) {
            if priority.as_u8() > sec.limits.max_prio {
                sandbox_audit("priority escalation blocked: above sandbox ceiling");
                return Err(SyscallError::QuotaExceeded);
            }
        }
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
        //    уведомлений, домен всё равно умирает). CPU-статистика домена
        //    (v0.10) уходит в словах w4/w5 — вердикт песочницы у родителя.
        if let Some(ipc) = ctx.ipc {
            let (cpu_used, cpu_throttle_events) = ctx
                .tasks
                .sec_view(&ctx.task)
                .map(|sec| (sec.usage.cpu_used, sec.usage.cpu_throttle_events))
                .unwrap_or((0, 0));
            ipc.deliver_exit(
                ctx.tasks,
                ctx.caps,
                ctx.task,
                ExitPayload::Exit {
                    code,
                    cpu_used,
                    cpu_throttle_events,
                },
            )?;
        }
        // 2. Привязки внешних линий (v0.14: локов устройств больше нет).
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
/// Плюс v0.9: атрибут GTCB `may_spawn` (песочница гасит право творца
/// даже при наличии capability — наследование песочницы).
///
/// Возвращаемое слово — хендл TaskTCB(новой задачи) в cspace вызывающего
/// (право родителя: лимиты/потоки/kill). Если к фасаду подключена
/// фабрика пространств (`with_space`), домен рождается СО своим
/// адресным пространством (rollback: отказ фабрики гасит домен до
/// выдачи каких-либо прав).
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
        // v0.9: атрибут песочницы may_spawn (без него домен — «тупиковая
        // ветвь»: свои потомки не плодит).
        if !ctx.tasks.may_spawn(&ctx.task).unwrap_or(false) {
            sandbox_audit("spawn denied: task is sandboxed (may_spawn=0)");
            return Err(SyscallError::MissingRight);
        }
        let new_task = task_id_from_args(args.arg(2), args.arg(3));
        let priority = TaskPriority(args.arg(4) as u8);
        ctx.tasks.create(new_task, priority)?;
        // v0.9: адресное пространство домена (фабрика — сервис платформы).
        // Отказ — полный откат: домен без права и памяти не существует.
        if let Some(factory) = ctx.space {
            if let Err(e) = factory.create_space(new_task) {
                let _ = ctx.tasks.set_state(&new_task, TaskState::Dead);
                let _ = ctx.tasks.destroy(new_task);
                return Err(e.into());
            }
        }
        // v0.9: родителю — TaskTCB(нового домена): право назначать
        // лимиты (песочница), создавать потоки, убивать.
        let gate = crate::capability::CapabilityGate::new(
            ContainerACCCapability::TaskTCB { task_id: new_task },
            crate::capability::ActionPermissions::all(),
            crate::capability::CapabilityBadge::FULL,
        );
        match ctx.caps.grant(ctx.tasks, ctx.task, gate) {
            Ok(h) => Ok(h.bits() as usize),
            Err(e) => {
                // Откат: гасим домен (пространство умерло вместе с ним).
                if let Some(factory) = ctx.space {
                    let _ = factory.destroy_space(new_task);
                }
                let _ = ctx.tasks.set_state(&new_task, TaskState::Dead);
                let _ = ctx.tasks.destroy(new_task);
                Err(e.into())
            }
        }
    }
}

/// Назначение пределов песочницы задаче (v0.9, атрибуты GTCB).
///
/// ПРАВО: TaskTCB на ЦЕЛЬ. Семантика — ТРЕЩОТКА: переданные значения
/// только УЖЕСТОЧАЮТ текущие (меньше предел — строже; may_spawn —
/// только гасится). Задача, владеющая TCB на себя, расширить свою
/// песочницу не может — трещотка не даёт.
///
/// ABI: arg1 = хендл TaskTCB цели, arg2 = max_pages,
/// arg3 = max_threads | (max_endpoints << 32),
/// arg4 = max_shm | (max_caps << 32),
/// arg5 = max_prio (u8) | (may_spawn ? 0x100 : 0)
///       | (cpu_quota << 16) — квота CPU в тиках за период (v0.10);
///       биты 63:16 = 0 — квоту НЕ ТРОГАТЬ (наследие v0.9: нулевое
///       поле старых вызовов не замораживает домен), все единицы —
///       кандидат «без лимита» (трещотка не ослабит), 1 — замороз.
pub struct TaskSetLimitsHandler;

impl TaskSetLimitsHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_SET_LIMITS;
}

impl SyscallHandler for TaskSetLimitsHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::MissingRight);
        };
        let w32 = |w: usize| (w & 0xFFFF_FFFF) as usize;
        // CPU-квота (v0.10): старшие 48 бит arg5. 0 — «не трогать»
        // (наследие v0.9: нулевое поле старых вызовов не душит домен),
        // «все единицы» — кандидат usize::MAX (трещотка не ослабит).
        let cpu_quota_raw = args.arg(5) >> 16;
        let cpu_quota = if cpu_quota_raw == 0 || cpu_quota_raw == 0xFFFF_FFFF_FFFF {
            usize::MAX
        } else {
            cpu_quota_raw
        };
        let limits = crate::task::TaskLimits {
            max_pages: args.arg(2),
            max_threads: w32(args.arg(3)),
            max_endpoints: args.arg(3) >> 32,
            max_shm: w32(args.arg(4)),
            max_caps: args.arg(4) >> 32,
            max_prio: (args.arg(5) & 0xFF) as u8,
            may_spawn: args.arg(5) & 0x100 != 0,
            cpu_quota,
        };
        ctx.tasks.set_limits(&task_id, limits)?;
        sandbox_audit("limits tightened for child domain");
        Ok(0)
    }
}

/// Снимок атрибутов безопасности задачи (v0.9; v0.10 — слова 6..8 — CPU).
/// ПРАВО: TaskTCB на цель (аудит песочницы — привилегия родителя/самого
/// домена).
///
/// Слова по индексу: 0 = max_pages, 1 = usage pages, 2 = usage shm,
/// 3 = max_threads | (max_endpoints << 32), 4 = max_shm |
/// (max_caps << 32), 5 = max_prio | (may_spawn ? 0x100 : 0),
/// 6 = cpu_quota (usize::MAX = без лимита; v0.10),
/// 7 = cpu_used — тики текущего периода (v0.10),
/// 8 = cpu_throttle_events | (cpu_throttled ? 0x1_0000_0000 : 0) —
///     счётчик входов за предел квоты + текущий флаг троттлинга (v0.10).
/// ABI: arg1 = хендл TaskTCB цели, arg2 = индекс слова.
pub struct TaskLimitsInfoHandler;

impl TaskLimitsInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_LIMITS_INFO;
}

impl SyscallHandler for TaskLimitsInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::MissingRight);
        };
        let sec = ctx.tasks.sec_view(&task_id).ok_or(SyscallError::NotFound)?;
        let words = [
            sec.limits.max_pages,
            sec.usage.pages,
            sec.usage.shm,
            (sec.limits.max_threads & 0xFFFF_FFFF) | (sec.limits.max_endpoints << 32),
            (sec.limits.max_shm & 0xFFFF_FFFF) | (sec.limits.max_caps << 32),
            (sec.limits.max_prio as usize) | if sec.limits.may_spawn { 0x100 } else { 0 },
            sec.limits.cpu_quota,
            sec.usage.cpu_used,
            sec.usage.cpu_throttle_events
                | if sec.usage.cpu_throttled {
                    0x1_0000_0000
                } else {
                    0
                },
        ];
        let idx = args.arg(2);
        words.get(idx).copied().ok_or(SyscallError::InvalidArgument)
    }
}

// ==== Спавн по готовому образу (v0.9) ====

/// Размер заголовка спавн-дескриптора (байт; см. ABI в `nums::TASK_SPAWN_IMAGE`).
pub const SPAWN_DESC_HEADER_BYTES: usize = 0x70;
/// Размер одного сегментного дескриптора.
pub const SPAWN_DESC_SEGMENT_BYTES: usize = 32;
/// Максимум сегментов (полный размер дескриптора = 0x70 + 32*n).
pub const SPAWN_MAX_SEGMENTS: usize = 16;
/// Полный размер дескриптора (лимит copyin за один вызов).
pub const SPAWN_DESC_MAX_BYTES: usize =
    SPAWN_DESC_HEADER_BYTES + SPAWN_MAX_SEGMENTS * SPAWN_DESC_SEGMENT_BYTES;

/// Спавн домена из ЗАЛИНКОВАННОГО образа, подготовленного юзерспейсом.
///
/// Родитель (spawn-сервер, init) УЖЕ: разобрал ELF, выделил регионы
/// (MEM_ALLOC), скопировал байты сегментов/стека/argv и собрал
/// дескриптор. Ядро принимает ТОЛЬКО указатели на память родителя:
/// читает дескриптор (copyin-канал) и мапит готовые кадры в новое
/// пространство (map_external_at) — без единой пересылки данных.
///
/// Атомарность песочницы: лимиты применяются ДО первого потока —
/// ребёнок рождается в песочнице, «окно без лимитов» невозможно.
pub struct TaskSpawnImageHandler;

impl TaskSpawnImageHandler {
    pub const SYSCALL: SyscallNumber = nums::TASK_SPAWN_IMAGE;
}

/// Откат спавна: домен гасится целиком (Dead-каскад → пространство →
/// TCB). Кадры сегментов остаются у родителя (external-отображения);
/// cspace ребёнка пуст по построению (грант шёл в cspace родителя).
fn rollback_spawned_domain(
    ctx: &SyscallCtx<'_>,
    factory: &dyn crate::mem::SpaceFactory,
    task: TaskId,
) {
    let _ = ctx.tasks.set_state(&task, TaskState::Dead);
    let _ = factory.destroy_space(task);
    let _ = ctx.tasks.destroy(task);
}

impl SyscallHandler for TaskSpawnImageHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        // 0. Сервисы: фабрика пространств + чтение памяти + роутер.
        let factory = ctx.space.ok_or(SyscallError::NotSupported)?;
        let copy = ctx.copy.ok_or(SyscallError::NotSupported)?;
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;

        // 1. Право творца: TaskTCB на себя + may_spawn-атрибут.
        let handle = CapHandle(args.arg(1) as u64);
        let view = ctx.resolve(handle)?;
        let ContainerACCCapability::TaskTCB { task_id } = view.cap_ref else {
            return Err(SyscallError::MissingRight);
        };
        if task_id != ctx.task {
            return Err(SyscallError::MissingRight);
        }
        if !ctx.tasks.may_spawn(&ctx.task).unwrap_or(false) {
            sandbox_audit("spawn-image denied: sandboxed creator (may_spawn=0)");
            return Err(SyscallError::MissingRight);
        }
        let new_task = task_id_from_args(args.arg(2), args.arg(3));

        // 2. Дескриптор: чтение из памяти родителя по указателю.
        let desc_ptr = args.arg(4);
        let desc_len = args.arg(5);
        if desc_len < SPAWN_DESC_HEADER_BYTES
            || desc_len > SPAWN_DESC_MAX_BYTES
            || (desc_len - SPAWN_DESC_HEADER_BYTES) % SPAWN_DESC_SEGMENT_BYTES != 0
        {
            return Err(SyscallError::InvalidArgument);
        }
        let mut desc = [0u8; SPAWN_DESC_MAX_BYTES];
        if let Err(e) = copy.read_task_bytes(ctx.task, desc_ptr, &mut desc[..desc_len]) {
            sandbox_audit(&alloc::format!(
                "spawn-image: desc read failed @ {:#x}+{:#x}: {e:?}",
                desc_ptr,
                desc_len
            ));
            return Err(SyscallError::from(e));
        }
        let word = |i: usize| u64::from_le_bytes(desc[i * 8..i * 8 + 8].try_into().unwrap());
        let u32_at = |i: usize| u32::from_le_bytes(desc[i..i + 4].try_into().unwrap());
        let entry = word(0) as usize;
        let stack_top = word(1) as usize;
        let thread_id = task_id_from_args(word(2) as usize, word(3) as usize);
        let n_segments = u32_at(0x20) as usize;
        let argv_pages = u32_at(0x24) as usize;
        let argv_src = word(5) as usize;
        let argv_dst = word(6) as usize;
        let argv_bytes = word(7) as usize;
        let argc = word(8) as usize;
        let priority = desc[0x68];
        // Валидация геометрии ДО создания домена (отказ ничего не создаёт).
        if entry == 0 || stack_top == 0 || priority == 0 {
            return Err(SyscallError::InvalidArgument);
        }
        if n_segments == 0
            || n_segments > SPAWN_MAX_SEGMENTS
            || n_segments != (desc_len - SPAWN_DESC_HEADER_BYTES) / SPAWN_DESC_SEGMENT_BYTES
        {
            return Err(SyscallError::InvalidArgument);
        }
        if argv_pages > 0
            && (argv_src == 0
                || argv_dst == 0
                || argv_dst % PAGE_SIZE != 0
                || argv_bytes == 0
                || argv_bytes > argv_pages * PAGE_SIZE)
        {
            return Err(SyscallError::InvalidArgument);
        }
        let w32 = |w: u64| (w & 0xFFFF_FFFF) as usize;
        // CPU-квота ребёнка (v0.10): u32 @ 0x6C хвоста заголовка.
        // 0 — БЕЗ лимита (исторический нулевой паддинг дескрипторов v0.9:
        // старые сборщики спавна не знали поля — ребёнок не должен
        // замереть), 0xFFFF_FFFF — без лимита явно, 1..=0xFFFF_FFFE —
        // квота в тиках за период. Заморозить ребёнка намертво — квота 1
        // (или TASK_SET_LIMITS с нулём после спавна).
        let cpu_quota_raw = u32_at(0x6C);
        let cpu_quota = if cpu_quota_raw == 0 || cpu_quota_raw == 0xFFFF_FFFF {
            usize::MAX
        } else {
            cpu_quota_raw as usize
        };
        let limits = TaskLimits {
            max_pages: word(9) as usize,
            max_threads: w32(word(10)),
            max_endpoints: (word(10) >> 32) as usize,
            max_shm: w32(word(11)),
            max_caps: (word(11) >> 32) as usize,
            max_prio: (word(12) & 0xFF) as u8,
            may_spawn: word(12) & 0x100 != 0,
            cpu_quota,
        };

        // 3. Домен + пространство + ПЕСОЧНИЦА (лимиты до первого потока).
        if let Err(e) = ctx.tasks.create(new_task, TaskPriority(priority)) {
            sandbox_audit(&alloc::format!("spawn-image: task create failed: {e:?}"));
            return Err(e.into());
        }
        if let Err(e) = factory.create_space(new_task) {
            sandbox_audit(&alloc::format!("spawn-image: space create failed: {e:?}"));
            let _ = ctx.tasks.set_state(&new_task, TaskState::Dead);
            let _ = ctx.tasks.destroy(new_task);
            return Err(e.into());
        }
        if let Err(e) = ctx.tasks.set_limits(&new_task, limits) {
            sandbox_audit(&alloc::format!("spawn-image: set_limits failed: {e:?}"));
            rollback_spawned_domain(ctx, factory, new_task);
            return Err(e.into());
        }
        // 4. Право родителя: TaskTCB(ребёнка) — до любых отображений
        //    (отказ гранта откатывает пустой домен безхитростно; хендл
        //    возвращается последним словом вызова).
        let gate = CapabilityGate::new(
            ContainerACCCapability::TaskTCB { task_id: new_task },
            crate::capability::ActionPermissions::all(),
            crate::capability::CapabilityBadge::FULL,
        );
        let parent_handle = match ctx.caps.grant(ctx.tasks, ctx.task, gate) {
            Ok(h) => h,
            Err(e) => {
                sandbox_audit(&alloc::format!("spawn-image: grant failed: {e:?}"));
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(e.into());
            }
        };
        // 5. Сегменты: готовые кадры родителя → линк-адреса ребёнка.
        for i in 0..n_segments {
            let base = SPAWN_DESC_HEADER_BYTES + i * SPAWN_DESC_SEGMENT_BYTES;
            let seg = |k: usize| {
                u64::from_le_bytes(desc[base + k * 8..base + k * 8 + 8].try_into().unwrap())
            };
            let src = seg(0) as usize;
            let dst = seg(1) as usize;
            let pages = seg(2) as usize;
            let flags = MMAPMemoryFlags::from_bits_retain(seg(3) as u8);
            if pages == 0 || dst % PAGE_SIZE != 0 {
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(SyscallError::InvalidArgument);
            }
            if let Err(e) = ctx.tasks.charge_pages(&new_task, pages) {
                sandbox_audit("spawn-image: segment exceeds child page quota");
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(e.into());
            }
            if let Err(e) = router.map_external_at(new_task, ctx.task, src, dst, pages, flags) {
                sandbox_audit("spawn-image: segment mapping failed");
                ctx.tasks.refund_pages(&new_task, pages);
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(e.into());
            }
        }
        // 6. argv-блок (тот же механизм: кадры родителя → адрес ребёнка).
        if argv_pages > 0 {
            if let Err(e) = ctx.tasks.charge_pages(&new_task, argv_pages) {
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(e.into());
            }
            let flags = MMAPMemoryFlags::RW;
            if let Err(e) =
                router.map_external_at(new_task, ctx.task, argv_src, argv_dst, argv_pages, flags)
            {
                ctx.tasks.refund_pages(&new_task, argv_pages);
                rollback_spawned_domain(ctx, factory, new_task);
                return Err(e.into());
            }
        }
        // 7. Главный поток (лимиты уже на месте: create_thread проверит
        //    max_threads, приоритет — потолок max_prio через set_limits).
        if let Err(e) = ctx.tasks.create_thread(
            thread_id,
            new_task,
            TaskPriority(priority),
            entry,
            stack_top,
        ) {
            rollback_spawned_domain(ctx, factory, new_task);
            return Err(e.into());
        }
        // 8. Стартовое IPC ([argc, argv_dst, argv_bytes]) — паркуется в
        //    очередь потока (как kinit для init): протокол запуска L4.
        if let Some(ipc) = ctx.ipc {
            let msg = alloc::boxed::Box::new(IpcMessage::start_args(
                IPC_KERNEL_FROM,
                argc as u64,
                argv_dst as u64,
                argv_bytes as u64,
            ));
            let _ = ipc.send_thread(ctx.tasks, ctx.memory, IPC_KERNEL_FROM, thread_id, msg);
        }
        sandbox_audit("spawn-image: domain ready (linked image mapped)");
        Ok(parent_handle.bits() as usize)
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
        // 2. Привязки IRQ цели (v0.14: локов устройств больше нет).
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
        // 2. Привязки IRQ (v0.14: локов устройств больше нет).
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

/// TLS-слово потока (v0.17, THREAD_SET_TLS): НЕПРОЗРАЧНОЕ значение,
/// которое бекенд платформы грузит в регистр указателя потока при
/// каждой диспетчеризации. Ядро значение не интерпретирует (детали —
/// в доке `nums::THREAD_SET_TLS`).
/// ПРАВО: свой домен ИЛИ TaskTCB домена потока (как SUSPEND/RESUME).
/// ABI: arg1..2 = ThreadId(lo, hi), arg3 = слово.
/// Возврат: прежнее слово.
pub struct ThreadSetTlsHandler;

impl ThreadSetTlsHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_SET_TLS;
}

impl SyscallHandler for ThreadSetTlsHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let id = task_id_from_args(args.arg(1), args.arg(2));
        require_thread_domain(ctx, &id)?;
        let old = ctx.tasks.thread_set_tls(&id, args.arg(3))?;
        Ok(old)
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

/// Регистрация ОПЦИОНАЛЬНОГО advisory-канала «конец временного
/// промежутка близко» для ВЫЗЫВАЮЩЕГО потока (v0.16, EEVDF-бекенд).
/// ABI: arg1 = хендл Gate (0 = снять регистрацию).
///
/// Семантика — строго уведомительная, НЕ принуждающая (см. nums.rs):
/// реакция задачи опциональна, вытеснение от неё не зависит.
pub struct ThreadSetSliceNotifyHandler;

impl ThreadSetSliceNotifyHandler {
    pub const SYSCALL: SyscallNumber = nums::THREAD_SET_SLICE_NOTIFY;
}

impl SyscallHandler for ThreadSetSliceNotifyHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let raw = args.arg(1);
        if raw == 0 {
            // Снятие регистрации: уведомления больше не доставляются.
            ctx.tasks.set_thread_slice_warn(&ctx.thread, None)?;
            return Ok(0);
        }
        // Хендл обязан разрешаться в ЖИВОЙ гейт в cspace вызывающего
        // (валидность — как у TASK_SET_EXIT_EP: разовая проверка при
        // регистрации; отзыв гейта позже просто гасит доставку).
        let handle = CapHandle(raw as u64);
        let gate = match ctx.caps.get(ctx.tasks, ctx.task, handle) {
            Some(view) => match view.cap_ref {
                ContainerACCCapability::Gate { gate_id } => Some(gate_id),
                _ => return Err(SyscallError::InvalidArgument),
            },
            None => return Err(SyscallError::InvalidHandle),
        };
        ctx.tasks.set_thread_slice_warn(&ctx.thread, gate)?;
        Ok(0)
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
/// IoResource: (base, len|count) — v0.14).
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
            ContainerACCCapability::IommuAdmin => [0xFFFF_FFFF_FFFF_0001, 0],
            // v0.14: идентификация сырого ресурса — [base, len|count]
            // (разновидность — в слове 0: kind 6/7/8).
            ContainerACCCapability::IoResource { kind } => kind.ident_words(),
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
    // Стабильная кодировка CAP_LIST/CAP_INFO (см. `ContainerACCCapability::
    // kind_word`; 1 — DeviceReference — удалён в v0.14).
    cap.kind_word()
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

// ==== Хелперы безопасности v0.9 (скан cspace вызывающего) ====

/// Есть ли у вызывающего TaskTCB-право на задачу `target`? Тот же паттерн
/// идентификации, что у `require_thread_domain`: право — факт владения
/// capability, а не знание TaskId.
pub(crate) fn has_tcb_cap_on(ctx: &SyscallCtx<'_>, target: &TaskId) -> bool {
    let mut permitted = false;
    ctx.caps.for_each_task_cap(ctx.tasks, ctx.task, |v| {
        if let ContainerACCCapability::TaskTCB { task_id } = &v.cap_ref {
            if *task_id == *target {
                permitted = true;
            }
        }
    });
    permitted
}

/// Есть ли у вызывающего мастер-право IommuAdmin (гейт группы 0x80).
pub(crate) fn has_iommu_admin(ctx: &SyscallCtx<'_>) -> bool {
    let mut permitted = false;
    ctx.caps.for_each_task_cap(ctx.tasks, ctx.task, |v| {
        if matches!(v.cap_ref, ContainerACCCapability::IommuAdmin) {
            permitted = true;
        }
    });
    permitted
}

/// Число живых Gate-capability вызывающего (учёт предела endpoint'ов).
pub(crate) fn gate_cap_count(ctx: &SyscallCtx<'_>) -> usize {
    let mut n = 0usize;
    ctx.caps.for_each_task_cap(ctx.tasks, ctx.task, |v| {
        if matches!(v.cap_ref, ContainerACCCapability::Gate { .. }) {
            n += 1;
        }
    });
    n
}

/// Аудит песочницы: строка в консоль отладки ядра (каждая блокировка
/// операции домена-песочницы видна оператору — v0.9). Реализация
/// переехала в подсистему задач (`crate::task::sandbox_audit`: её
/// использует и CPU-троттлинг v0.10) — здесь остаётся реэкспорт,
/// чтобы существующие вызовы сискол-фасада не менялись.
pub(crate) use crate::task::sandbox_audit;

// ==== Передача прав capability (map/grant-наследники L4) ====

/// Mint: производная capability (сужение прав/badge).
/// ПРАВО v0.9: на ПОЛУЧАТЕЛЯ — свой домен ИЛИ TaskTCB получателя в
/// cspace вызывающего (знание TaskId чужого cspace правом не является);
/// плюс предел max_caps получателя (флуд чужого cspace — DoS).
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
        require_dst_capable(ctx, &dst)?;
        let spec = MintSpec {
            perms: crate::capability::ActionPermissions::from_bits_retain(args.arg(4) as u8),
            badge: crate::capability::CapabilityBadge::from_bits(args.arg(5) as u64),
            // Диапазон не запрошен: IoResource клонируется целиком
            // (прежняя семантика, ABI-совместимость).
            range: None,
        };
        let handle = ctx.caps.mint(ctx.tasks, ctx.task, src, dst, &spec)?;
        Ok(handle.bits() as usize)
    }
}

/// Mint с сужением ПОДДИАПАЗОНА IoResource (v0.15): CAP_MINT, где вместо
/// badge запрошен диапазон `new_base..new_base+new_len`, строго вложенный
/// в родительский той же разновидности. Проверки: право Mint у источника,
/// получатель — свой домен ИЛИ TaskTCB (плюс max_caps — как у CAP_MINT),
/// затем инварианты сужения в менеджере (RangeNotSubset — чистый отказ).
///
/// badge не сужается: гейты 0x40 (MMIO_MAP/IOP/IRQ_ATTACH) его не читают,
/// производная наследует badge родителя.
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя, arg4 = perms,
/// arg5 = new_base, arg6 = new_len (шестой регистр, v0.15).
pub struct CapMintRangeHandler;

impl CapMintRangeHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_MINT_RANGE;
}

impl SyscallHandler for CapMintRangeHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        let dst = task_id_from_args(args.arg(2), args.arg(3));
        require_dst_capable(ctx, &dst)?;
        let spec = MintSpec {
            perms: crate::capability::ActionPermissions::from_bits_retain(args.arg(4) as u8),
            badge: crate::capability::CapabilityBadge::FULL,
            range: Some((args.arg(5) as u64, args.arg(6) as u64)),
        };
        let handle = ctx.caps.mint(ctx.tasks, ctx.task, src, dst, &spec)?;
        Ok(handle.bits() as usize)
    }
}

/// Send: передача хендла (право Send у источника).
/// ПРАВО v0.9: на ПОЛУЧАТЕЛЯ — как у mint (свой домен ИЛИ TaskTCB
/// получателя) + предел max_caps получателя.
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя.
pub struct CapSendHandler;

impl CapSendHandler {
    pub const SYSCALL: SyscallNumber = nums::CAP_SEND;
}

impl SyscallHandler for CapSendHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let src = CapHandle(args.arg(1) as u64);
        let dst = task_id_from_args(args.arg(2), args.arg(3));
        require_dst_capable(ctx, &dst)?;
        let handle = ctx.caps.send(ctx.tasks, ctx.task, src, dst)?;
        Ok(handle.bits() as usize)
    }
}

/// Право на передачу capability в чужой cspace (v0.9): получатель —
/// САМ вызывающий ИЛИ у вызывающего есть TaskTCB на получателя.
/// Плюс ресурсный предел: живых хендлов получателя < max_caps.
fn require_dst_capable(ctx: &SyscallCtx<'_>, dst: &TaskId) -> Result<(), SyscallError> {
    if *dst == ctx.task {
        return Ok(());
    }
    if !has_tcb_cap_on(ctx, dst) {
        sandbox_audit("cap transfer blocked: no TaskTCB on destination");
        return Err(SyscallError::MissingRight);
    }
    if let Some(sec) = ctx.tasks.sec_view(dst) {
        let live = ctx.tasks.cap_count(dst).unwrap_or(0);
        if live >= sec.limits.max_caps {
            sandbox_audit("cap transfer blocked: destination cspace is full (max_caps)");
            return Err(SyscallError::QuotaExceeded);
        }
    }
    Ok(())
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
    use crate::task::{TaskId, TaskPriority, TaskState, TcbManager};

    use super::super::nums;
    use super::super::types::SyscallArgs;
    use super::super::types::SyscallError;
    use super::super::{SyscallFacade, SyscallRegistry};
    use super::{
        SPAWN_DESC_HEADER_BYTES, SPAWN_DESC_SEGMENT_BYTES, TaskSpawnHandler, TaskSpawnImageHandler,
    };
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
            range: None,
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
                &SyscallArgs::new([nums::EP_CREATE.as_u64() as usize, 4, 0, 0, 0, 0, 0]),
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
                &SyscallArgs::new([nums::IPC_RECV_ANY.as_u64() as usize, 0, 0, 0, 0, 0, 0]),
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
                0,
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
                    0,
                ]),
            )
            .unwrap();
        assert_eq!(argc, 3);

        // 6. Ребёнок само-выходит с кодом 42: exit-endpoint получает
        //    первый вид данных (код выхода), потоки гаснут каскадом.
        ipc.deliver_exit(
            tasks,
            caps,
            child,
            ExitPayload::Exit {
                code: 42,
                cpu_used: 0,
                cpu_throttle_events: 0,
            },
        )
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
        assert!(
            back == ExitPayload::Exit {
                code: 42,
                cpu_used: 0,
                cpu_throttle_events: 0,
            }
        );

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
        let args = SyscallArgs::new([0, 0xDEAD, v as usize, (v >> 64) as usize, 5, 0, 0]);
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
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );

        // Право на себя — домен создан (L4 task_new); возврат — хендл
        // TaskTCB(нового домена) в cspace творца (v0.9: право родителя
        // назначать лимиты/потоки/kill).
        let h_self = grant_tcb(caps, tasks, creator, creator);
        let args = SyscallArgs::new([
            0,
            h_self.bits() as usize,
            v as usize,
            (v >> 64) as usize,
            5,
            0,
            0,
        ]);
        let ret = reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args);
        assert!(ret.is_ok(), "TASK_CREATE с правом творца: {ret:?}");
        let child_handle = CapHandle(ret.unwrap() as u64);
        assert!(child_handle.bits() > 0, "возврат — хендл, не ноль");
        assert_eq!(tasks.get(&new_id).unwrap().priority, TaskPriority(5));
        // Хендл из возврата резолвится как TaskTCB именно на нового.
        let view = ctx.caps.get(tasks, creator, child_handle).unwrap();
        assert!(matches!(
            view.cap_ref,
            ContainerACCCapability::TaskTCB { task_id } if task_id == new_id
        ));
    }

    #[test]
    fn task_create_denied_in_sandbox() {
        let (reg, tasks, caps) = default_table_world();
        let creator = uuid_next();
        tasks.create(creator, TaskPriority::DEFAULT).unwrap();
        // Песочница: право творца погашено атрибутом may_spawn = false
        // (трещотка: даже при живой TaskTCB-капабилити).
        tasks
            .set_limits(&creator, crate::task::TaskLimits::UNLIMITED)
            .unwrap();
        tasks
            .set_limits(
                &creator,
                crate::task::TaskLimits {
                    may_spawn: false,
                    ..crate::task::TaskLimits::UNLIMITED
                },
            )
            .unwrap();
        let h_self = grant_tcb(caps, tasks, creator, creator);
        let new_id = uuid_next();
        let v = new_id.as_u128();
        let mut ctx = crate::syscall::SyscallCtx::core(0, creator, tasks, caps);
        let args = SyscallArgs::new([
            0,
            h_self.bits() as usize,
            v as usize,
            (v >> 64) as usize,
            5,
            0,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_CREATE, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );
        assert!(!tasks.contains(&new_id), "домен не создан");
    }

    #[test]
    fn sandbox_limits_ratchet_and_quotas() {
        let (reg, tasks, caps) = default_table_world();
        let parent = uuid_next();
        tasks.create(parent, TaskPriority::DEFAULT).unwrap();
        // «Создаём» ребёнка напрямую менеджером (spawn-путь покрыт тестом
        // выше) и назначаем песочницу через сискол по праву TaskTCB.
        let child = uuid_next();
        tasks.create(child, TaskPriority(80)).unwrap();
        let h_child = grant_tcb(caps, tasks, parent, child);
        let mut ctx = crate::syscall::SyscallCtx::core(0, parent, tasks, caps);

        // TASK_SET_LIMITS: страницы 8, потоки 2, endpoints 1, prio 100.
        let pack = |lo: usize, hi: usize| (lo & 0xFFFF_FFFF) | (hi << 32);
        let args = SyscallArgs::new([
            0,
            h_child.bits() as usize,
            8,
            pack(2, 1),
            pack(usize::MAX, usize::MAX),
            100,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_SET_LIMITS, &mut ctx, &args),
            Ok(0)
        );

        // Трещотка: попытка РАСШИРИТЬ (страницы 100) — принимается как
        // ужесточение не бывает: предел остался 8.
        let args = SyscallArgs::new([
            0,
            h_child.bits() as usize,
            100,
            pack(usize::MAX, usize::MAX),
            pack(usize::MAX, usize::MAX),
            255 | 0x100,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_SET_LIMITS, &mut ctx, &args),
            Ok(0)
        );
        let sec = tasks.sec_view(&child).unwrap();
        assert_eq!(sec.limits.max_pages, 8, "трещотка: расширение не прошло");
        assert_eq!(sec.limits.max_threads, 2);
        assert_eq!(sec.limits.max_endpoints, 1);
        assert_eq!(sec.limits.max_prio, 100, "трещотка: приоритет не расширен");
        assert!(!sec.limits.may_spawn, "may_spawn погашен");

        // Квоты менеджера: страницы сверх — PageQuota; потоки — ThreadQuota.
        tasks.charge_pages(&child, 8).unwrap();
        assert!(matches!(
            tasks.charge_pages(&child, 1),
            Err(crate::task::TaskError::PageQuota { .. })
        ));
        tasks.refund_pages(&child, 8);
        let t1 = uuid_next();
        tasks
            .create_thread(t1, child, TaskPriority(1), 0x1000, 0x9000)
            .unwrap();
        let t2 = uuid_next();
        tasks
            .create_thread(t2, child, TaskPriority(1), 0x1000, 0x9000)
            .unwrap();
        let t3 = uuid_next();
        assert!(matches!(
            tasks.create_thread(t3, child, TaskPriority(1), 0x1000, 0x9000),
            Err(crate::task::TaskError::ThreadQuota { .. })
        ));

        // TASK_LIMITS_INFO: слова читаются по праву TaskTCB.
        let mut word = |i: usize| {
            let args = SyscallArgs::new([0, h_child.bits() as usize, i, 0, 0, 0, 0]);
            reg.dispatch_number(nums::TASK_LIMITS_INFO, &mut ctx, &args)
                .unwrap()
        };
        assert_eq!(word(0), 8);
        assert_eq!(word(3) & 0xFFFF_FFFF, 2);
        assert_eq!(word(3) >> 32, 1);
        assert_eq!(word(5) & 0xFF, 100);
    }

    #[test]
    fn cpu_quota_abi_packing_and_info_words() {
        let (reg, tasks, caps) = default_table_world();
        let parent = uuid_next();
        tasks.create(parent, TaskPriority::DEFAULT).unwrap();
        let child = uuid_next();
        tasks.create(child, TaskPriority(80)).unwrap();
        let h_child = grant_tcb(caps, tasks, parent, child);
        let mut ctx = crate::syscall::SyscallCtx::core(0, parent, tasks, caps);

        // v0.9-вызов с нулевым полем квоты (arg5=100) — домен НЕ
        // заморожен: квота остаётся безлимитной (наследие ABI).
        let args = SyscallArgs::new([0, h_child.bits() as usize, 100, 0, 0, 100, 0]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_SET_LIMITS, &mut ctx, &args),
            Ok(0)
        );
        assert_eq!(
            tasks.sec_view(&child).unwrap().limits.cpu_quota,
            usize::MAX,
            "нулевое поле = квоту не трогать"
        );

        // Слово за пределами таблицы — InvalidArgument.
        let args = SyscallArgs::new([0, h_child.bits() as usize, 9, 0, 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_LIMITS_INFO, &mut ctx, &args),
            Err(SyscallError::InvalidArgument)
        );

        // Явная квота: arg5 = prio | (cpu_quota << 16).
        let args = SyscallArgs::new([0, h_child.bits() as usize, 0, 0, 0, 100 | (12 << 16), 0]);
        assert_eq!(
            reg.dispatch_number(nums::TASK_SET_LIMITS, &mut ctx, &args),
            Ok(0)
        );

        // Слова 6..8 — зеркало GTCB (чтение через сискол).
        let mut word = |i: usize| {
            let args = SyscallArgs::new([0, h_child.bits() as usize, i, 0, 0, 0, 0]);
            reg.dispatch_number(nums::TASK_LIMITS_INFO, &mut ctx, &args)
                .unwrap()
        };
        assert_eq!(word(6), 12, "квота назначена через arg5");
        assert_eq!(word(7), 0, "до зарядки — пусто");
        assert_eq!(word(8), 0);

        // Заряд/троттл — через менеджер (путь гейта); слова 7/8 — зеркало.
        assert!(!tasks.charge_cpu(&child, 8).unwrap());
        assert!(tasks.charge_cpu(&child, 8).unwrap());
        assert_eq!(word(7), 12, "кламп в квоту");
        assert_eq!(word(8), 1 | (1 << 32), "ивент + флаг троттлинга");
        assert_eq!(word(8) >> 32, 1, "флаг «троттлится сейчас»");

        // Граница периода: заряды сброшены, история — нет.
        assert_eq!(tasks.on_cpu_period(), 1);
        assert_eq!(word(7), 0);
        assert_eq!(word(8), 1, "история ивентов переживает refill");
        assert_eq!(word(8) >> 32, 0);
    }

    #[test]
    fn thread_terminate_requires_domain_right() {
        let (reg, tasks, caps) = default_table_world();
        let attacker = uuid_next();
        tasks.create(attacker, TaskPriority::DEFAULT).unwrap();
        let victim = uuid_next();
        tasks.create(victim, TaskPriority::DEFAULT).unwrap();
        let victim_thread = uuid_next();
        tasks
            .create_thread(victim_thread, victim, TaskPriority(5), 0x1000, 0x9000)
            .unwrap();

        // Чужой поток без TaskTCB на его домен — EPERM (v0.9: до —
        // гашение по голому ThreadId).
        let mut ctx = crate::syscall::SyscallCtx::core(0, attacker, tasks, caps);
        let v = victim_thread.as_u128();
        let args = SyscallArgs::new([0, v as usize, (v >> 64) as usize, 0, 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_TERMINATE, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );
        assert!(
            tasks
                .thread_view(&victim_thread)
                .is_some_and(|t| t.state != TaskState::Dead),
            "поток жив: прав не было"
        );

        // С правом — гасится.
        let _h = grant_tcb(caps, tasks, attacker, victim);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_TERMINATE, &mut ctx, &args),
            Ok(0)
        );
        assert!(
            tasks
                .thread_view(&victim_thread)
                .is_some_and(|t| t.state == TaskState::Dead)
        );
    }

    #[test]
    fn priority_ceiling_of_sandbox_blocks_escalation() {
        let (reg, tasks, caps) = default_table_world();
        let rogue = uuid_next();
        tasks.create(rogue, TaskPriority(60)).unwrap();
        let rogue_thread = uuid_next();
        tasks
            .create_thread(rogue_thread, rogue, TaskPriority(60), 0x1000, 0x9000)
            .unwrap();
        // Песочница: потолок 80; rogue владеет TaskTCB на себя («своя
        // кухня» — гейт пройдёт), но квота — нет.
        tasks
            .set_limits(
                &rogue,
                crate::task::TaskLimits {
                    max_prio: 80,
                    ..crate::task::TaskLimits::UNLIMITED
                },
            )
            .unwrap();
        let _h_self = grant_tcb(caps, tasks, rogue, rogue);
        let mut ctx = crate::syscall::SyscallCtx::core(0, rogue, tasks, caps);
        let v = rogue_thread.as_u128();
        let args = SyscallArgs::new([0, v as usize, (v >> 64) as usize, 255, 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_SET_PRIO, &mut ctx, &args),
            Err(SyscallError::QuotaExceeded)
        );
        // Внутри потолка — разрешено.
        let args = SyscallArgs::new([0, v as usize, (v >> 64) as usize, 80, 0, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_SET_PRIO, &mut ctx, &args),
            Ok(0)
        );
    }

    #[test]
    fn spawn_image_from_userspace_pointer() {
        use crate::hal::traits::kmap::{KMAPInterface, KernelRegion};
        use crate::hal::traits::mmap::{
            MMAPInterface, MMAPMemoryFlags, MemErrorCode, PageInfo, PhysADDR, VirtualADDR,
        };
        use crate::mem::{
            ARCPool, MemRouterImpl, MemoryManager, SpaceFactory, UserCopy, install_p_allocator,
        };

        // Мок MMAP+KMAP: записи фасада без реальных таблиц.
        #[derive(Clone)]
        struct SpawnMmap;
        impl MMAPInterface for SpawnMmap {
            fn extend_region(
                &mut self,
                _a: &llfree::LLFree<'static>,
                _v: VirtualADDR,
                p: PhysADDR,
                n: usize,
                _f: MMAPMemoryFlags,
            ) -> Result<PageInfo, MemErrorCode> {
                Ok(PageInfo::new(p, n))
            }
            fn shrink_region(
                &mut self,
                _a: &llfree::LLFree<'static>,
                _v: VirtualADDR,
                _n: usize,
            ) -> Result<(), MemErrorCode> {
                Ok(())
            }
        }
        impl KMAPInterface for SpawnMmap {
            fn map_kernel_region(&mut self, _r: &KernelRegion) -> Result<(), MemErrorCode> {
                Ok(())
            }
            fn unmap_kernel_region(&mut self, _r: &KernelRegion) -> Result<(), MemErrorCode> {
                Ok(())
            }
        }

        struct TestSpaceFactory(&'static MemoryManager<SpawnMmap, ARCPool>);
        impl SpaceFactory for TestSpaceFactory {
            fn create_space(&self, task: TaskId) -> Result<(), MemErrorCode> {
                self.0
                    .configure_runtime_spaces(64, 1, VirtualADDR(0x1000_0000));
                self.0.create_task_space(task, SpawnMmap)
            }
            fn destroy_space(&self, task: TaskId) -> Result<(), MemErrorCode> {
                self.0.destroy_task_space(&task)
            }
        }

        /// «Память пользователя»: дескриптор уже собран родителем —
        /// copyin-канал просто отдаёт байты.
        struct TestCopy(Vec<u8>);
        impl UserCopy for TestCopy {
            fn read_task_bytes(
                &self,
                _task: TaskId,
                _vaddr: usize,
                out: &mut [u8],
            ) -> Result<(), MemErrorCode> {
                out.copy_from_slice(&self.0[..out.len()]);
                Ok(())
            }
        }

        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let p_alloc = install_p_allocator(make_llfree_local(2048));
        let mut mm_box = Box::new(MemoryManager::<SpawnMmap, ARCPool>::new(p_alloc).unwrap());
        let parent = uuid_next();
        tasks.create(parent, TaskPriority(80)).unwrap();
        let facade = mm_box
            .create_facade(SpawnMmap, 64, 1, VirtualADDR(0x1000_0000))
            .unwrap();
        mm_box.bind_facade(parent, &facade);
        core::mem::forget(facade);
        let mm: &'static MemoryManager<SpawnMmap, ARCPool> = Box::leak(mm_box);
        mm.configure_runtime_spaces(64, 1, VirtualADDR(0x1000_0000));
        let factory: &'static TestSpaceFactory = Box::leak(Box::new(TestSpaceFactory(mm)));
        let ipc: &'static crate::ipc::IpcManager =
            Box::leak(Box::new(crate::ipc::IpcManager::new()));

        // Родитель УЖЕ подготовил регион образа (MEM_ALLOC + копия байтов
        // — в моке байтов нет, есть записи фасада; ядро их только мапит).
        let router = MemRouterImpl::new(mm);
        let mut ctx = crate::syscall::SyscallCtx::core(0, parent, tasks, caps)
            .with_ipc(ipc)
            .with_memory(&router)
            .with_space(factory);
        let seg_src = crate::syscall::SyscallHandler::invoke(
            &crate::syscall::mem::MemAllocHandler,
            &mut ctx,
            &SyscallArgs::new([0, 2, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0, 0]),
        )
        .unwrap();

        // argv-блок — СВОЙ регион родителя (инвариант фасада: одна
        // физическая страница — одно виртуальное окно в пространстве).
        let argv_src = crate::syscall::SyscallHandler::invoke(
            &crate::syscall::mem::MemAllocHandler,
            &mut ctx,
            &SyscallArgs::new([0, 1, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0, 0]),
        )
        .unwrap();

        // Дескриптор спавна: 1 сегмент RX + argv-блок.
        let child = uuid_next();
        let thread_id = uuid_next();
        let cv = child.as_u128();
        let tv = thread_id.as_u128();
        let push64 = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        let mut d = Vec::new();
        push64(&mut d, 0x4000_1000); // entry (линк-адрес)
        push64(&mut d, 0x4002_0000); // stack_top
        push64(&mut d, tv as u64); // thread_id lo
        push64(&mut d, (tv >> 64) as u64); // thread_id hi
        d.extend_from_slice(&1u32.to_le_bytes()); // n_segments
        d.extend_from_slice(&1u32.to_le_bytes()); // argv_pages
        push64(&mut d, argv_src as u64); // argv_src (свой регион родителя)
        push64(&mut d, 0x4003_0000u64); // argv_dst
        push64(&mut d, 24u64); // argv_bytes
        push64(&mut d, 1u64); // argc
        push64(&mut d, 8u64); // limits[0]: max_pages = 8
        push64(&mut d, 2u64); // limits[1]: max_threads = 2
        push64(&mut d, 4u64); // limits[2]: max_shm = 4
        push64(&mut d, 100u64); // limits[3]: max_prio = 100, may_spawn = 0
        d.push(90); // priority @ 0x68
        d.extend_from_slice(&[0u8; 3]); // паддинг 0x69..0x6B
        // v0.10: CPU-квота — u32 @ 0x6C (хвост заголовка).
        d.extend_from_slice(&12u32.to_le_bytes());
        while d.len() < SPAWN_DESC_HEADER_BYTES {
            d.push(0);
        }
        // Сегмент: src у родителя, dst — линк-адрес, 2 стр RX.
        push64(&mut d, seg_src as u64);
        push64(&mut d, 0x4000_0000u64);
        push64(&mut d, 2u64);
        push64(&mut d, MMAPMemoryFlags::RX.bits() as u64);
        assert_eq!(d.len(), SPAWN_DESC_HEADER_BYTES + SPAWN_DESC_SEGMENT_BYTES);

        let copy: &'static TestCopy = Box::leak(Box::new(TestCopy(d.clone())));
        let h_self = grant_tcb(caps, tasks, parent, parent);
        let mut ctx = crate::syscall::SyscallCtx::core(0, parent, tasks, caps)
            .with_ipc(ipc)
            .with_memory(&router)
            .with_space(factory)
            .with_copy(copy);
        let args = SyscallArgs::new([
            0,
            h_self.bits() as usize,
            cv as usize,
            (cv >> 64) as usize,
            0x1000_0000, // указатель на дескриптор (TestCopy отдаёт байты)
            d.len(),
            0,
        ]);
        let ret = crate::syscall::SyscallHandler::invoke(&TaskSpawnImageHandler, &mut ctx, &args)
            .expect("spawn по готовому образу");
        assert!(ret > 0, "возврат — хендл TaskTCB(ребёнка)");
        let h_child = CapHandle(ret as u64);
        let view = ctx.caps.get(tasks, parent, h_child).unwrap();
        assert!(matches!(
            view.cap_ref,
            ContainerACCCapability::TaskTCB { task_id } if task_id == child
        ));

        // Домен: приоритет из дескриптора, песочница применена ДО потока.
        assert_eq!(tasks.get(&child).unwrap().priority, TaskPriority(90));
        let sec = tasks.sec_view(&child).unwrap();
        assert_eq!(sec.limits.max_pages, 8);
        assert_eq!(sec.limits.max_threads, 2);
        assert!(!sec.limits.may_spawn);
        // v0.10: квота из дескриптора применена ДО первого потока —
        // ребёнок рождается сразу в CPU-песочнице.
        assert_eq!(sec.limits.cpu_quota, 12, "cpu_quota из u32 @ 0x6C");
        assert_eq!(sec.usage.pages, 3, "сегмент (2) + argv (1)");

        // Главный поток: Ready с линк-точкой входа; стартовое IPC —
        // припарковано (протокол запуска L4, как у init).
        let tv2 = tasks.thread_view(&thread_id).unwrap();
        assert_eq!(tv2.state, TaskState::Ready);
        assert_eq!(tv2.entry, 0x4000_1000);
        assert_eq!(tv2.stack_top, 0x4002_0000);
        let parked = tasks
            .with_thread(&thread_id, |t| t.parked.len())
            .unwrap_or(0);
        assert_eq!(parked, 1, "start-args припаркованы в очередь потока");
        let mm_has_child = mm.has_facade(&child);
        assert!(mm_has_child, "пространство ребёнка живо у менеджера");

        // Битый размер дескриптора — EINVAL, домен НЕ создан.
        let ghost = uuid_next();
        let gv = ghost.as_u128();
        let args = SyscallArgs::new([
            0,
            h_self.bits() as usize,
            gv as usize,
            (gv >> 64) as usize,
            0x1000_0000,
            SPAWN_DESC_HEADER_BYTES - 8,
            0,
        ]);
        assert_eq!(
            crate::syscall::SyscallHandler::invoke(&TaskSpawnImageHandler, &mut ctx, &args),
            Err(SyscallError::InvalidArgument)
        );
        assert!(!tasks.contains(&ghost));
    }

    /// Локальная мини-LLFree для спавн-теста (та же схема, что mem-тестов).
    fn make_llfree_local(frames: usize) -> llfree::LLFree<'static> {
        use llfree::{Alloc, Classing, MetaData};
        let (cl, _) = Classing::simple(1);
        let sizes = llfree::LLFree::metadata_size(&cl, frames);
        let mut local = aligned_box::AlignedBox::slice_from_value(64, sizes.local, 0u8).unwrap();
        let mut trees = aligned_box::AlignedBox::slice_from_value(64, sizes.trees, 0u8).unwrap();
        let mut lower = aligned_box::AlignedBox::slice_from_value(64, sizes.lower, 0u8).unwrap();
        let meta = unsafe {
            MetaData {
                local: core::slice::from_raw_parts_mut(local.as_mut_ptr(), local.len()),
                trees: core::slice::from_raw_parts_mut(trees.as_mut_ptr(), trees.len()),
                lower: core::slice::from_raw_parts_mut(lower.as_mut_ptr(), lower.len()),
            }
        };
        core::mem::forget((local, trees, lower));
        llfree::LLFree::new(frames, llfree::Init::FreeAll, &cl, meta).unwrap()
    }

    #[test]
    fn cap_send_to_foreign_cspace_requires_tcb_right() {
        let (reg, tasks, caps) = default_table_world();
        let attacker = uuid_next();
        tasks.create(attacker, TaskPriority::DEFAULT).unwrap();
        let victim = uuid_next();
        tasks.create(victim, TaskPriority::DEFAULT).unwrap();
        let h_any = grant_tcb(caps, tasks, attacker, attacker);

        // Отправить capability жертве «по адресу» — нельзя (нет права
        // на ЕЁ cspace: знание TaskId правом не является).
        let mut ctx = crate::syscall::SyscallCtx::core(0, attacker, tasks, caps);
        let vv = victim.as_u128();
        let args = SyscallArgs::new([
            0,
            h_any.bits() as usize,
            vv as usize,
            (vv >> 64) as usize,
            0,
            0,
            0,
        ]);
        assert_eq!(
            reg.dispatch_number(nums::CAP_SEND, &mut ctx, &args),
            Err(SyscallError::MissingRight)
        );
        assert_eq!(tasks.cap_count(&victim).unwrap(), 0, "cspace жертвы пуст");
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
                &SyscallArgs::new([0, 4, 0, 0, 0, 0, 0]),
            )
            .unwrap() as u64;
        let gate = caps.endpoint_of(tasks, killer, CapHandle(exit_ep)).unwrap();
        tasks.set_exit_endpoint(&victim, gate).unwrap();

        // KILL: Killed{source=killer} + каскад (поток жертвы погашен).
        let args = SyscallArgs::new([0, h_victim.bits() as usize, 0, 0, 0, 0, 0]);
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
        let args = SyscallArgs::new([0, tv[0], tv[1], 0, 0, 0, 0]);
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
        let args = SyscallArgs::new([0, tv[0], tv[1], 0x9000, usize::MAX, 0, 0]);
        assert_eq!(
            reg.dispatch_number(nums::THREAD_EX_REGS, &mut ctx, &args),
            Ok(0x4000)
        );
        // Второе слово возврата — прежний стек (меняем стек, читаем его).
        let args = SyscallArgs::new([0, tv[0], tv[1], usize::MAX, 0xA000, 1, 0]);
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
        let args = SyscallArgs::new([0, sv[0], sv[1], 0, 0, 0, 0]);
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
                &SyscallArgs::new([0, 0, 0, 0, 0, 0, 0])
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
                &SyscallArgs::new([0, 1, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(w as u64, h_tcb.bits(), "полный хендл без обрезания");
        let k = reg
            .dispatch_number(
                nums::CAP_LIST,
                &mut ctx,
                &SyscallArgs::new([0, 2, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(k, 2, "kind = TaskTCB");

        // CAP_INFO слова: kind / perms / badge / alive / TaskId.lo / hi.
        let mut info = |i: usize| {
            reg.dispatch_number(
                nums::CAP_INFO,
                &mut ctx,
                &SyscallArgs::new([0, h_tcb.bits() as usize, i, 0, 0, 0, 0]),
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
                &SyscallArgs::new([0, h_tcb.bits() as usize, 6, 0, 0, 0, 0])
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
                &SyscallArgs::new([0, 4, 0, 0, 0, 0, 0]),
            )
            .unwrap() as u64;
        let gate = caps
            .endpoint_of(tasks, watcher, CapHandle(exit_ep))
            .unwrap();
        tasks.set_exit_endpoint(&victim, gate).unwrap();

        // Жертва гаснет по исключению (паника рантайма).
        let mut vctx = crate::syscall::SyscallCtx::core(0, victim, tasks, caps).with_ipc(ipc);
        let args = SyscallArgs::new([0, 0xDEAD_BEEF, 0x4000, 2, 0xAAAA, 0xBBBB, 0]);
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

    /// Репродукция v0.11-сценария «два инстанса → два reap → выход init»:
    /// kinit-гранты (TaskTCB(себя), IommuAdmin, 2× IoResource — v0.14), на
    /// каждый инстанс — EP_CREATE + TaskTCB(ребёнка) + CAP_MINT(port и
    /// TCB → ребёнку), гибель ребёнка по контракту reaper'а
    /// (revoke_all → destroy), затем выход init (revoke_all(4 корней +
    /// 4 инстансных корня)). На v0.11-прогоне QEMU этот сценарий ловил
    /// KERNEL FAULT в CapabilityManager::revoke_node (children-голова
    /// указывала на уже отвязанный узел — UNLINKED_MARKER=1 в
    /// intrusive-collections): тест обязан проходить с активными
    /// debug-ассертами дерева деривации.
    #[test]
    fn two_instance_spawn_reap_cycle_then_init_revoke_all() {
        use crate::capability::{ActionPermissions, CapabilityBadge, CapabilityGate, MintSpec};

        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));

        // init (права от kinit): TaskTCB(себя) + IommuAdmin + 2× IoResource
        // (v0.14: сырые ресурсы вместо DeviceReference — Mmio + IoPort).
        let init = uuid_next();
        tasks.create(init, TaskPriority::DEFAULT).unwrap();
        grant_tcb(caps, tasks, init, init);
        caps.grant(
            tasks,
            init,
            CapabilityGate::new(
                ContainerACCCapability::IommuAdmin,
                ActionPermissions::all(),
                CapabilityBadge::FULL,
            ),
        )
        .unwrap();
        for kind in [
            crate::capability::IoResourceKind::Mmio {
                base: 0,
                len: 1 << 32,
            },
            crate::capability::IoResourceKind::IoPort {
                base: 0,
                len: u16::MAX,
            },
        ] {
            caps.grant(
                tasks,
                init,
                CapabilityGate::new(
                    ContainerACCCapability::IoResource { kind },
                    ActionPermissions::all(),
                    CapabilityBadge::FULL,
                ),
            )
            .unwrap();
        }

        // Два инстанса ПОДРЯД (v0.11: один и тот же образ, разные базы —
        // для дерева деривации важно: свои гейты/TCB-гранты на каждый).
        for _inst in 0..2 {
            let child = uuid_next();
            tasks.create(child, TaskPriority::DEFAULT).unwrap();

            // Демо spawn-сервера: EP_CREATE + TaskTCB(ребёнка) у init.
            let gate = caps
                .create_gate(tasks, init, ActionPermissions::all(), CapabilityBadge::FULL)
                .unwrap();
            let tcb_child = grant_tcb(caps, tasks, init, child);

            // CAP_MINT порта и TCB ребёнку (своя кухня + fast-path ответов).
            caps.mint(tasks, init, gate, child, &MintSpec::UNCHANGED)
                .unwrap();
            caps.mint(tasks, init, tcb_child, child, &MintSpec::UNCHANGED)
                .unwrap();

            // Гибель ребёнка — контракт Glue::reap_thread: домен Dead,
            // затем revoke_all → destroy («revoke_all -> destroy»).
            tasks.set_state(&child, TaskState::Dead).unwrap();
            let child_report = caps.revoke_all(tasks, child).unwrap();
            assert_eq!(child_report.revoked_slots, 2, "порт + TCB у ребёнка");
            // Инвариант 2 БЕЗ призраков (v0.11-баг): отвязка производной
            // от списка родителя обязна работать и в release — иначе в
            // children остаётся freed-слот, и повторное использование
            // адреса (второй инстанс) даёт KERNEL FAULT в intrusive-unlink.
            assert_eq!(
                caps.child_count_of(tasks, init, gate).unwrap(),
                0,
                "гейт {}: дети-призраки после отзыва",
                _inst
            );
            assert_eq!(
                caps.child_count_of(tasks, init, tcb_child).unwrap(),
                0,
                "tcb {}: дети-призраки после отзыва",
                _inst
            );
            tasks.destroy(child).unwrap();
        }

        // Выход init: домен Dead (TASK_EXIT), затем revoke_all корней:
        // 1×TaskTCB(self), IommuAdmin, 2×IoResource, 2×gate,
        // 2×TaskTCB(child) = 8.
        tasks.set_state(&init, TaskState::Dead).unwrap();
        let report = caps.revoke_all(tasks, init).unwrap();
        assert_eq!(
            report.revoked_slots, 8,
            "корни init: tcb-self, iommu, 2 io, 2 gates, 2 tcb-child"
        );
        tasks.destroy(init).unwrap();
    }
}
