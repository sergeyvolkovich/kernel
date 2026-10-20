// Тесты и host-утилиты гоняются на std (глобальный аллокатор — системный,
// slab-хуки — `capability::mem::host_hooks`); боевой крейт — no_std.
#![cfg_attr(not(any(test, feature = "host-hooks")), no_std)]

//! Универсальный интерфейсный слой ядра: менеджеры подсистем + фасады.
//!
//! Точка сборки ядра — [`GCTL`]: корневой фасад, объединяющий менеджеры
//! задач, capability, памяти и слой сисколов. Подсистемы связаны между
//! собой слабо (менеджеры зовут друг друга параметрами, не полями —
//! паттерн `CapabilityManager::*(&TcbManager)`), поэтому GCTL — владелец
//! и «витрина», а не god-object: методы делегируют, не решают.
//!
//! ```text
//!   GCTL<MMAP>
//!   ├─ task_manager: TcbManager                 задачи-домены + ПОТОКИ
//!   │        (L4: потоки — единицы планирования; scheduler-хуки)
//!   ├─ capability_manager: CapabilityManager    cspace, деривация, отзыв
//!   │        + endpoint'ы (GateObj с состоянием IPC)
//!   ├─ memory_manager: MemoryManager<MMAP, ARCPool>  фасады памяти (KPTI/PCID)
//!   │        + привязки задача→фасад (MemRouter для сисколов/IPC)
//!   ├─ device_manager: DeviceManager            реестр устройств: шины
//!   │        (pci/acpi, dtb — план) + экспорт capability
//!   │        + claims: DeviceClaimRegistry       эксклюзивные локи,
//!   │        hot-removal уведомления (ошибка ядра + IPC)
//!   ├─ ipc_manager: IpcManager                  L4-IPC: endpoint'ы,
//!   │        fast-path по ThreadID, exit-протокол (3 вида данных)
//!   ├─ shm_manager: ShmManager                  разделяемая память
//!   │        io_uring (регионы + SQ/CQ-кольца + doorbell)
//!   └─ syscalls: SyscallRegistry                таблица хендлеров сисколов
//!         └─ syscall_facade(): SyscallFacade<'_>  borrowed-view поверх
//!                           всех менеджеров (см. syscall::mod)
//! ```

extern crate alloc;

pub mod capability;
pub mod hal;
pub mod ipc;
pub mod mem;
pub mod syscall;
pub mod task;

use alloc::boxed::Box;

use thiserror::Error;

use crate::{
    capability::CapabilityManager,
    hal::device::{DeviceError, DeviceManager},
    hal::traits::mmap::MMAPInterface,
    ipc::{IpcManager, ShmManager},
    mem::{ARCPool, Arc, MemRouterImpl, MemoryManager},
    syscall::SyscallRegistry,
    task::TcbManager,
};

/// Ошибка сборки корневого фасада: отказ любого менеджера на старте.
///
/// Все варианты — «не смогли подняться»: памяти нет либо slab-инфраструктура
/// не инициализирована (host-хуки/kernel SlabPool). Диагностика — по варианту;
/// на боевой сборке старт ядра после этого не продолжается.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GctlError {
    #[error("task manager init failed: {0}")]
    Task(#[from] task::TaskError),
    #[error("capability manager init failed: {0}")]
    Capability(#[from] capability::CapabilityError),
    #[error("memory manager init failed: {0}")]
    Memory(#[from] hal::traits::mmap::MemErrorCode),
    #[error("syscall registry init failed: {0}")]
    Syscall(#[from] syscall::SyscallError),
    #[error("device subsystem error: {0}")]
    Device(#[from] DeviceError),
}

/// Корневой фасад ядра (Generic ConTroL): владелец менеджеров подсистем.
///
/// Порядок полей — порядок разрушения (дроп полей сверху вниз):
/// capability-менеджер гасится раньше реестра задач (`CapabilityManager`
/// держит lifetime-ссылку на задачи — см. его контракт), память — последней.
///
/// Менеджеры инициализируются пустыми: платформа наполняет их
/// (install_kmap / install_asid_allocator / install_scheduler / регистрация
/// хендлеров сисколов) до первого пользовательского контекста.
pub struct GCTL<MMAP: MMAPInterface> {
    /// Менеджер capability: cspace задач, гейты/endpoint'ы, линии прерываний.
    capability_manager: CapabilityManager,
    /// Реестр задач-доменов и потоков (L4).
    task_manager: TcbManager,
    /// Подсистема памяти: физический аллокатор + фасады адресных
    /// пространств (KMAP/KPTI + ASID/PCID) + привязки задача→фасад.
    memory_facade: MemoryManager<MMAP, ARCPool>,
    /// Реестр устройств + эксклюзивные локи (claim) с hot-removal.
    device_manager: DeviceManager,
    /// IPC L4: endpoint'ы, fast-path, exit-протокол (3 вида данных).
    ipc_manager: IpcManager,
    /// Разделяемая память io_uring: регионы + кольца + doorbell.
    shm_manager: ShmManager,
    /// Привязки IRQ→endpoint (L4 irq_attach: прерывания драйверов).
    irq_router: crate::hal::device::IrqRouter,
    /// Реестр хендлеров сисколов (см. `syscall::mod`); при сборке GCTL
    /// получает ДЕФОЛТНУЮ таблицу крейта (все встроенные хендлеры).
    syscalls: SyscallRegistry,
}

impl<MMAP: MMAPInterface> GCTL<MMAP> {
    /// Собрать ядро поверх разделяемого физического аллокатора
    /// (обычно `mem::install_p_allocator(..)` — одноразовая статика).
    pub fn new(p_allocator: Arc<ARCPool>) -> Result<Self, GctlError> {
        let syscalls = SyscallRegistry::new();
        // Дефолтная таблица: все встроенные хендлеры крейта уже на месте;
        // платформа может перезаписать слоты (reregister) или добавить
        // свои в зоне 0x80..0xFE.
        syscalls.install_default_table();
        Ok(Self {
            capability_manager: CapabilityManager::new()?,
            task_manager: TcbManager::new()?,
            memory_facade: MemoryManager::new(p_allocator.clone())?,
            device_manager: DeviceManager::new(),
            ipc_manager: IpcManager::new(),
            shm_manager: ShmManager::new(p_allocator),
            irq_router: crate::hal::device::IrqRouter::new(),
            syscalls,
        })
    }

    /// Менеджер capability (гранты, mint/send, отзыв).
    #[inline]
    pub fn capability_manager(&self) -> &CapabilityManager {
        &self.capability_manager
    }

    /// Реестр задач.
    #[inline]
    pub fn task_manager(&self) -> &TcbManager {
        &self.task_manager
    }

    /// Подсистема памяти (фасады, KMAP, пул ASID/PCID).
    #[inline]
    pub fn memory_manager(&self) -> &MemoryManager<MMAP, ARCPool> {
        &self.memory_facade
    }

    /// Подсистема памяти, изменяемый доступ (install_kmap и т.п.).
    #[inline]
    pub fn memory_manager_mut(&mut self) -> &mut MemoryManager<MMAP, ARCPool> {
        &mut self.memory_facade
    }

    /// Реестр устройств (перечисление шинами, доступ к записям).
    /// Подключение шин и rescan — [`Self::device_manager_mut`]; экспорт
    /// capability — `DeviceManager::export_capabilities(&tasks, &caps, ..)`
    /// (менеджеры связаны параметрами, не полями).
    #[inline]
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Реестр устройств, изменяемый доступ (register_bus / enumerate).
    #[inline]
    pub fn device_manager_mut(&mut self) -> &mut DeviceManager {
        &mut self.device_manager
    }

    /// IPC-менеджер (L4: endpoint'ы, fast-path, exit-протокол).
    #[inline]
    pub fn ipc_manager(&self) -> &IpcManager {
        &self.ipc_manager
    }

    /// SHM-менеджер (io_uring: регионы, кольца, doorbell).
    #[inline]
    pub fn shm_manager(&self) -> &ShmManager {
        &self.shm_manager
    }

    /// IRQ-роутер (привязки линий прерываний к endpoint'ам драйверов;
    /// событие — `irq_event` из верхнего полуобработчика прерываний).
    #[inline]
    pub fn irq_router(&self) -> &crate::hal::device::IrqRouter {
        &self.irq_router
    }

    /// Реестр хендлеров сисколов (регистрация — платформенный код).
    #[inline]
    pub fn syscall_registry(&self) -> &SyscallRegistry {
        &self.syscalls
    }

    /// Фасад сисколов над менеджерами ЭТОГО GCTL (borrowed-view: живёт,
    /// пока жива ссылка на GCTL, ничего не владеет).
    ///
    /// Точка входа для arch-глюя syscall-гейта: после входа в ядро
    /// (переключения таблиц по KPTI — контракт `SyscallPlatform`) глюй
    /// вызывает `dispatch[_number]` фасада на стеке гейта.
    ///
    /// `thread` — исполняющийся поток (L4): блокирующие сисколы (IPC,
    /// claim) паркуют его; глюй после хендлера проверяет состояние и
    /// переключает контекст вместо возврата (контракт `syscall::mod`).
    ///
    /// Роутер памяти (`MemRouter`) живёт в рамках вызова: стековая
    /// обёртка над `memory_facade`; для `'static`-фасада платформа
    /// строит роутер один раз над leaked-GCTL
    /// (`GCTL::leak_mem_router`).
    pub fn syscall_facade(&self) -> syscall::SyscallFacade<'_> {
        syscall::SyscallFacade::new(&self.task_manager, &self.capability_manager, &self.syscalls)
            .with_ipc(&self.ipc_manager)
            .with_shm(&self.shm_manager)
            .with_devices(&self.device_manager)
            .with_irq(&self.irq_router)
    }

    /// Паттерн локальной диспетчеризации с памятью (роутер — стековая
    /// обёртка, живёт в области вызова):
    /// ```ignore
    /// let router = MemRouterImpl::new(gctl.memory_manager());
    /// let facade = gctl.syscall_facade().with_memory(&router);
    /// facade.dispatch(cpu, task, thread, &args)
    /// ```
    pub fn mem_router(&self) -> MemRouterImpl<'_, MMAP> {
        MemRouterImpl::new(&self.memory_facade)
    }

    /// Leaked-роутер памяти для `'static`-фасада (платформа строит
    /// ядро как глобальный singleton: `Box::leak(Box::new(GCTL::new(..)))`
    /// -> `gctl.leak_mem_router()` -> фасад с памятью живёт вечно).
    pub fn leak_mem_router<'s>(&'s self) -> &'static dyn crate::mem::MemRouter
    where
        MMAP: 'static,
        's: 'static,
    {
        Box::leak(Box::new(MemRouterImpl::new(&self.memory_facade)))
            as &'static dyn crate::mem::MemRouter
    }

    /// Перечислить устройства И уведомить держателей локов о пропаже
    /// (оркестрация, которую платформа обязана выполнить после rescan:
    /// hot-removal = ядерная ошибка разбуженным претендентам + IPC
    /// DEVICE_LOST владельцам + снятие IRQ-привязок пропавших устройств).
    ///
    /// Возвращает отчёт перечисления; пути пропавших — в
    /// `device_manager().removed_since_last_scan()` (уже обработаны).
    pub fn rescan_devices(&mut self) -> Result<crate::hal::device::EnumerationReport, GctlError> {
        let report = self.device_manager.enumerate()?;
        let removed: alloc::vec::Vec<_> = self.device_manager.removed_since_last_scan().to_vec();
        for path in removed {
            // Привязки IRQ пропавшего устройства гаснут вместе с ним
            // (события больше не доставляются — линии нет).
            self.irq_router.detach_device(&path);
            let _ = self.device_manager.claims().on_device_removed(
                &self.task_manager,
                &self.capability_manager,
                &self.ipc_manager,
                &path,
            );
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use crate::mem::install_p_allocator;
    use crate::syscall::task::TaskSpawnHandler;
    use crate::syscall::{SyscallArgs, SyscallError, SyscallNumber};
    use crate::task::{TaskPriority, TaskState};

    use super::*;
    /// Детерминированно-уникальный TaskId для тестов: uuid без фичи v4 —
    /// генератора нет, счётчик процесса даёт достаточную уникальность.
    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    #[test]
    fn gctl_wires_managers_and_syscalls() {
        let p_alloc = install_p_allocator(make_llfree(2048));
        let gctl: GCTL<crate::mem::ufacade::tests::MockMmap> = GCTL::new(p_alloc).unwrap();

        // Менеджеры живы и пусты; IRQ-роутер подключён.
        assert_eq!(gctl.task_manager().count(), 0);
        assert!(gctl.capability_manager().total_count() == 0);
        assert!(gctl.memory_manager().kmap().is_empty());
        assert!(gctl.irq_router().is_empty());

        // Дефолтная таблица сисколов установлена сборкой GCTL: все
        // группы заняты, легаси-пример TASK_SPAWN (без права) — НЕТ.
        let reg = gctl.syscall_registry();
        assert!(!reg.is_empty());
        assert!(reg.handler(crate::syscall::nums::TASK_CREATE).is_some());
        assert!(reg.handler(crate::syscall::nums::IRQ_ACK).is_some());
        assert!(reg.handler(crate::syscall::nums::SELF_INFO).is_some());
        assert!(reg.handler(TaskSpawnHandler::SYSCALL).is_none());

        // Регистрируем легаси-хендлер-пример (слот свободен) и
        // диспетчеризуем через фасад GCTL.
        reg.register(TaskSpawnHandler::SYSCALL, &TaskSpawnHandler)
            .unwrap();

        let id = uuid_next();
        let v = id.as_u128();
        let args = SyscallArgs::new([
            TaskSpawnHandler::SYSCALL.as_u64() as usize,
            v as usize,
            (v >> 64) as usize,
            9,
            0,
            0,
        ]);
        let caller = uuid_next();
        let ret = gctl.syscall_facade().dispatch(0, caller, caller, &args);
        assert_eq!(ret, Ok(0));
        assert_eq!(
            gctl.task_manager().get(&id).unwrap().state,
            TaskState::Ready
        );
        assert_eq!(
            gctl.task_manager().get(&id).unwrap().priority,
            TaskPriority(9)
        );

        // Неизвестный номер — ENOSYS тем же маршрутом (вне таблицы).
        assert_eq!(
            gctl.syscall_facade().dispatch_number(
                0,
                caller,
                caller,
                SyscallNumber(999),
                &SyscallArgs::none()
            ),
            Err(SyscallError::NotSupported)
        );

        // Дефолтный SELF_INFO диспетчеризуется тем же маршрутом (слово 0
        // = task_id.lo вызывающего).
        let v = caller.as_u128();
        let ret = gctl.syscall_facade().dispatch_number(
            0,
            caller,
            caller,
            crate::syscall::nums::SELF_INFO,
            &SyscallArgs::new([0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(ret, Ok(v as usize));

        // Диспетчеризация через контекст хендлера: сискол создаёт задачу.
    }

    /// Мини-LLFree для GCTL-теста (та же схема, что в ufacade::tests).
    fn make_llfree(frames: usize) -> llfree::LLFree<'static> {
        use llfree::{Alloc, Classing, MetaData};
        let (cl, _) = Classing::simple(1);
        let sizes = llfree::LLFree::metadata_size(&cl, frames);
        let mut local = aligned_box::AlignedBox::slice_from_value(64, sizes.local, 0u8).unwrap();
        let mut trees = aligned_box::AlignedBox::slice_from_value(64, sizes.trees, 0u8).unwrap();
        let mut lower = aligned_box::AlignedBox::slice_from_value(64, sizes.lower, 0u8).unwrap();
        // SAFETY: буферы живут до конца процесса (владельческие хендлы
        // забыты ниже), срезы 'static на них корректны.
        let meta = unsafe {
            MetaData {
                local: core::slice::from_raw_parts_mut(local.as_mut_ptr(), local.len()),
                trees: core::slice::from_raw_parts_mut(trees.as_mut_ptr(), trees.len()),
                lower: core::slice::from_raw_parts_mut(lower.as_mut_ptr(), lower.len()),
            }
        };
        // Хендлы забываем: память не освобождается, срезы 'static честны.
        core::mem::forget((local, trees, lower));
        llfree::LLFree::new(frames, llfree::Init::FreeAll, &cl, meta).unwrap()
    }
}
