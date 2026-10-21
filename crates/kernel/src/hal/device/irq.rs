// ==== IRQ-роутер: привязка прерываний устройств к endpoint'ам (L4 irq_attach) ====
//
// L4-модель: драйвер не видит контроллер прерываний — прерывание
// устройства доставляется КАК СООБЩЕНИЕ. В гибридной модели крейта
// (endpoints + fast-path) носителем служит notification-endpoint
// (GateObj с буфером): ядро по событию на линии кладёт signal-слово
// (номер gsi), драйвер ждёт обычным IPC_RECV.
//
// Протокол (edge-семантика с pending-битом, как уведомления L4):
//   attach:  линия -> endpoint (одна привязка на линию; gsi обязан
//            принадлежать ресурсам ЖИВОГО устройства — произвольный GSI
//            привязать нельзя, право подтверждено DeviceReference-cap);
//   событие: pending = true + signal(gsi) в endpoint; пока pending не
//            снят, повторные события копятся ОДНИМ битом (уведомления
//            не теряются и не переполняют буфер — L4-семантика);
//   ack:     драйвер обработал — pending снят, линия снова взведена
//            (EOI платформы — контроллер маскирует до ACK, см.
//            IRQPlatform; крейт ведёт только логику привязок).
//
// Жизненный цикл: смерть задачи-владельца (detach_all_of) и
// hot-removal устройства (detach_device) снимают привязки — GCTL
// оркестрирует оба пути.
//
// Хранение — плоский Vec в RefCell: привязок мало (линии устройств),
// регистрация редкая (сетап драйвера), горячий путь (irq_event) —
// линейный scan по нескольким записям кэш-линии. Микроядерная простота
// против менеджерской общности.

use crate::sync::KSpin;

use alloc::vec::Vec;
use thiserror::Error;

use crate::capability::{CapabilityManager, ObjId};
use crate::hal::device::DeviceManager;
use crate::hal::device::traits::DeviceResource;
use crate::hal::types::DevicePath;
use crate::ipc::IpcManager;
use crate::task::{TaskId, TcbManager};

/// Отказ операции IRQ-роутера.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrqError {
    /// GSI не принадлежит ресурсам указанного (живого) устройства.
    #[error("gsi {0} is not a resource of the device")]
    InvalidGsi(u32),
    /// Устройство не найдено или удалено (hot-removal).
    #[error("device is gone")]
    DeviceGone,
    /// Линия уже привязана (одна привязка на линию).
    #[error("irq line already bound")]
    AlreadyBound,
    /// Привязки линии нет.
    #[error("irq binding not found")]
    NotFound,
    /// Операцию пытается совершить не владелец привязки.
    #[error("not the binding owner")]
    NotOwner,
    /// IPC-подсистема недоступна (событие недоставимо).
    #[error("ipc subsystem not available")]
    NoIpc,
}

/// Привязка линии прерывания.
struct IrqBinding {
    /// Линия (GSI / контроллерно-зависимый номер).
    gsi: u32,
    /// Устройство-источник (hot-removal снимает привязку).
    path: DevicePath,
    /// Задача-владелец (detached при её смерти).
    owner: TaskId,
    /// Endpoint доставки (notification GateObj).
    gate: ObjId,
    /// Событие, не подтверждённое ACK (уведомления копятся одним битом).
    pending: bool,
}

/// Роутер привязок IRQ -> endpoint.
pub struct IrqRouter {
    bindings: KSpin<Vec<IrqBinding>>,
}

impl Default for IrqRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqRouter {
    /// Пустой роутер (аллокаций нет — Vec растёт при первом attach).
    pub fn new() -> Self {
        Self {
            bindings: KSpin::new(Vec::new()),
        }
    }

    /// Привязать линию устройства к endpoint'у (L4 irq_attach).
    ///
    /// Валидация роутера: устройство живо, `gsi` — его Irq-ресурс;
    /// линия свободна. Право на УСТРОЙСТВО проверяет сискол-хендлер
    /// (DeviceReference-cap) — роутер получает уже целевые `path`/`gate`.
    pub fn attach(
        &self,
        devices: &DeviceManager,
        owner: TaskId,
        path: &DevicePath,
        gsi: u32,
        gate: ObjId,
    ) -> Result<(), IrqError> {
        let rec = devices.get_alive(path).ok_or(IrqError::DeviceGone)?;
        let belongs = rec
            .resources
            .iter()
            .any(|r| matches!(r, DeviceResource::Irq { gsi: g, .. } if *g == gsi));
        if !belongs {
            return Err(IrqError::InvalidGsi(gsi));
        }

        let mut bindings = self.bindings.lock();
        if bindings.iter().any(|b| b.gsi == gsi) {
            return Err(IrqError::AlreadyBound);
        }
        bindings.push(IrqBinding {
            gsi,
            path: path.clone(),
            owner,
            gate,
            pending: false,
        });
        Ok(())
    }

    /// Снять привязку линии (только владелец).
    pub fn detach(&self, gsi: u32, owner: TaskId) -> Result<(), IrqError> {
        let mut bindings = self.bindings.lock();
        let idx = bindings
            .iter()
            .position(|b| b.gsi == gsi)
            .ok_or(IrqError::NotFound)?;
        if bindings[idx].owner != owner {
            return Err(IrqError::NotOwner);
        }
        bindings.swap_remove(idx);
        Ok(())
    }

    /// Подтвердить обработку (EOI): pending снят, линия снова взведена.
    /// Возврат — был ли необработанный pending (ложный ACK — не ошибка:
    /// идемпотентность протокола важнее строгости).
    pub fn ack(&self, gsi: u32, owner: TaskId) -> Result<bool, IrqError> {
        let mut bindings = self.bindings.lock();
        let b = bindings
            .iter_mut()
            .find(|b| b.gsi == gsi)
            .ok_or(IrqError::NotFound)?;
        if b.owner != owner {
            return Err(IrqError::NotOwner);
        }
        let was = b.pending;
        b.pending = false;
        Ok(was)
    }

    /// Событие на линии (вызов платформы из верхнего полуобработчика).
    ///
    /// `Ok(false)` — линия не привязана (платформа решает сама: shared
    /// IRQ, spurious). `Ok(true)` — событие учтено: сигнал положен в
    /// endpoint или склеен с непогашенным pending. Переполнение буфера
    /// НЕ ошибка: pending взведён, драйвер дочитает предыдущее слово —
    /// семантика уведомлений L4 (события сливаются, не теряются).
    pub fn irq_event(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        ipc: &IpcManager,
        gsi: u32,
    ) -> Result<bool, IrqError> {
        // Захват привязки-копии ДО отпуска borrow: доставка заходит в
        // менеджеры (RefCell-реентери недопустимы).
        let (gate, was_pending) = {
            let bindings = self.bindings.lock();
            let Some(b) = bindings.iter().find(|b| b.gsi == gsi) else {
                return Ok(false);
            };
            if b.pending {
                // Склейка: слово уже в endpoint (или буфер полон —
                // драйвер дочитает), нового сигнала не нужно.
                return Ok(true);
            }
            (b.gate, false)
        };
        let _ = was_pending;

        // Сначала pending (событие учтено при любом исходе доставки)...
        if let Some(b) = self
            .bindings
            .lock()
            .iter_mut()
            .find(|b| b.gsi == gsi && b.gate == gate)
        {
            b.pending = true;
        }

        // ...затем доставка signal-слова (номер линии).
        let _ = ipc.signal(tasks, caps, gate, gsi as u64);
        Ok(true)
    }

    /// Снять все привязки устройства (hot-removal; GCTL::rescan_devices).
    /// Возврат — число снятых.
    pub fn detach_device(&self, path: &DevicePath) -> usize {
        let mut bindings = self.bindings.lock();
        let before = bindings.len();
        bindings.retain(|b| &b.path != path);
        before - bindings.len()
    }

    /// Снять все привязки задачи (TASK_EXIT / TASK_KILL каскад).
    /// Возврат — число снятых.
    pub fn detach_all_of(&self, owner: &TaskId) -> usize {
        let mut bindings = self.bindings.lock();
        let before = bindings.len();
        bindings.retain(|b| &b.owner != owner);
        before - bindings.len()
    }

    /// Число активных привязок (аудит/тесты).
    pub fn len(&self) -> usize {
        self.bindings.lock().len()
    }

    /// Привязок нет.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Снимок привязки для отладки: (gsi, owner, gate, pending).
    pub fn binding_of(&self, gsi: u32) -> Option<(u32, TaskId, ObjId, bool)> {
        self.bindings
            .lock()
            .iter()
            .find(|b| b.gsi == gsi)
            .map(|b| (b.gsi, b.owner, b.gate, b.pending))
    }
}

// ==== Тесты (host) ====

// ==== Тестовое окружение (общее для тестов irq.rs и syscall/device.rs) ====

#[cfg(test)]
pub(crate) mod tests_support {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::capability::{
        ActionPermissions, CapHandle, CapabilityBadge, CapabilityManager, ContainerACCCapability,
    };
    use crate::hal::device::DeviceManager;
    use crate::hal::device::traits::{
        BusDeviceData, BusEnumerator, DeviceResource, DeviceSink, DiscoveredDevice,
    };
    use crate::hal::types::{AcpiPath, DeviceInfo, DeviceKind, DevicePath, PhysAddr, PlatformId};
    use crate::ipc::IpcManager;
    use crate::task::{TaskId, TaskPriority, TcbManager};

    use super::IrqRouter;

    /// Шина с одним устройством: MMIO + IRQ(gsi=42).
    pub(crate) struct UartBus;

    impl BusEnumerator for UartBus {
        fn bus_name(&self) -> &str {
            "mock.uart"
        }

        fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError2> {
            sink.discovered(DiscoveredDevice {
                path: uart_path(),
                info: DeviceInfo::new(DeviceKind::Platform(PlatformId {
                    acpi_uid: None,
                    dt_path: None,
                })),
                resources: vec![
                    DeviceResource::Mmio {
                        base: PhysAddr(0x1000_0000),
                        len: 0x1000,
                    },
                    DeviceResource::Irq {
                        gsi: 42,
                        trigger: crate::hal::traits::irq::TriggerMode::Edge,
                        active_low: false,
                    },
                ],
                data: BusDeviceData::Acpi(crate::hal::device::acpi::AcpiDeviceData {
                    hid: Some(String::from("PNP0501")),
                    cids: Vec::new(),
                    uid: Some(1),
                    adr: None,
                    sta: Some(0x0F),
                    hpet: None,
                }),
                functional: true,
            });
            Ok(())
        }
    }

    /// Путь тестового устройства.
    pub(crate) fn uart_path() -> DevicePath {
        DevicePath::Acpi(AcpiPath::new("\\_SB.UART0"))
    }

    /// Готовый мир: менеджеры + устройство + владелец с dev-cap и endpoint'ом.
    pub(crate) struct IrqTestEnv {
        pub tasks: &'static TcbManager,
        pub caps: &'static CapabilityManager,
        pub devices: &'static DeviceManager,
        pub ipc: &'static IpcManager,
        pub router: &'static IrqRouter,
        pub owner: TaskId,
        /// ObjId endpoint'а владельца.
        pub gate: crate::capability::ObjId,
        /// Хендл DeviceReference в cspace владельца.
        pub dev_handle: CapHandle,
        /// Хендл Gate-cap endpoint'а.
        pub gate_handle: CapHandle,
    }

    pub(crate) fn irq_test_env() -> IrqTestEnv {
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));
        let router: &'static IrqRouter = Box::leak(Box::new(IrqRouter::new()));

        let mut dm = DeviceManager::new();
        dm.register_bus(&UartBus).unwrap();
        dm.enumerate().unwrap();
        let devices: &'static DeviceManager = Box::leak(Box::new(dm));

        let owner = {
            use core::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0x9000);
            TaskId::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
        };
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();

        // DeviceReference-cap владельцу.
        let dev_handle = devices
            .export_capability(
                tasks,
                caps,
                owner,
                &uart_path(),
                ActionPermissions::empty(),
                CapabilityBadge::FULL,
            )
            .unwrap();

        // Notification-endpoint (буфер) для доставки IRQ.
        let gate_handle = ipc
            .create_endpoint(
                tasks,
                caps,
                owner,
                8,
                ActionPermissions::all(),
                CapabilityBadge::FULL,
            )
            .unwrap();
        let view = caps.get(tasks, owner, gate_handle).unwrap();
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            panic!("endpoint-cap");
        };

        IrqTestEnv {
            tasks,
            caps,
            devices,
            ipc,
            router,
            owner,
            gate: gate_id,
            dev_handle,
            gate_handle,
        }
    }

    // Локальный алиас: имя ошибки шины в traits.
    use crate::hal::device::traits::BusError as BusError2;
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use alloc::boxed::Box;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::capability::{
        ActionPermissions, CapabilityBadge, CapabilityManager, ContainerACCCapability,
    };
    use crate::hal::device::DeviceManager;
    use crate::hal::device::traits::{BusEnumerator, DeviceSink, DiscoveredDevice};
    use crate::hal::types::{AcpiPath, DeviceInfo, DeviceKind, DevicePath, PhysAddr, PlatformId};
    use crate::ipc::IpcManager;
    use crate::task::{TaskPriority, TcbManager};

    use super::*;

    fn uuid_next() -> uuid::Uuid {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    /// Мок-шина с одним устройством: MMIO + IRQ(gsi=42).
    struct UartBus;

    fn uart_path() -> DevicePath {
        DevicePath::Acpi(AcpiPath::new("\\_SB.UART0"))
    }

    impl BusEnumerator for UartBus {
        fn bus_name(&self) -> &str {
            "mock.uart"
        }

        fn scan(
            &self,
            sink: &mut dyn DeviceSink,
        ) -> Result<(), crate::hal::device::traits::BusError> {
            let _ = format!("x");
            let _ = String::from("y");
            sink.discovered(DiscoveredDevice {
                path: uart_path(),
                info: DeviceInfo::new(DeviceKind::Platform(PlatformId {
                    acpi_uid: None,
                    dt_path: None,
                })),
                resources: vec![
                    DeviceResource::Mmio {
                        base: PhysAddr(0x1000_0000),
                        len: 0x1000,
                    },
                    DeviceResource::Irq {
                        gsi: 42,
                        trigger: crate::hal::traits::irq::TriggerMode::Edge,
                        active_low: false,
                    },
                ],
                data: crate::hal::device::traits::BusDeviceData::Acpi(
                    crate::hal::device::acpi::AcpiDeviceData {
                        hid: Some(String::from("PNP0501")),
                        cids: Vec::new(),
                        uid: Some(1),
                        adr: None,
                        sta: Some(0x0F),
                        hpet: None,
                    },
                ),
                functional: true,
            });
            Ok(())
        }
    }

    fn setup() -> (
        &'static TcbManager,
        &'static CapabilityManager,
        &'static DeviceManager,
        &'static IpcManager,
    ) {
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));

        let mut dm = DeviceManager::new();
        dm.register_bus(&UartBus).unwrap();
        dm.enumerate().unwrap();
        let devices: &'static DeviceManager = Box::leak(Box::new(dm));
        (tasks, caps, devices, ipc)
    }

    fn owner_with_ep(
        tasks: &TcbManager,
        caps: &CapabilityManager,
        ipc: &IpcManager,
    ) -> (TaskId, crate::capability::ObjId) {
        let owner = uuid_next();
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();
        // Notification-endpoint (буфер) для доставки IRQ.
        let h = ipc
            .create_endpoint(
                tasks,
                caps,
                owner,
                8,
                ActionPermissions::all(),
                CapabilityBadge::FULL,
            )
            .unwrap();
        let view = caps.get(tasks, owner, h).unwrap();
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            panic!("endpoint-cap");
        };
        (owner, gate_id)
    }

    #[test]
    fn attach_event_ack_detach_roundtrip() {
        let (tasks, caps, devices, ipc) = setup();
        let router = IrqRouter::new();
        let (owner, gate) = owner_with_ep(tasks, caps, ipc);

        // Чужой gsi — отказ (право подтверждать нечем).
        assert_eq!(
            router.attach(devices, owner, &uart_path(), 777, gate),
            Err(IrqError::InvalidGsi(777))
        );
        // Устройство-призрак.
        let ghost = DevicePath::Pci(crate::hal::types::Bdf::new(0, 3, 7, 0));
        assert_eq!(
            router.attach(devices, owner, &ghost, 42, gate),
            Err(IrqError::DeviceGone)
        );

        // Валидная привязка.
        router
            .attach(devices, owner, &uart_path(), 42, gate)
            .unwrap();
        assert_eq!(router.len(), 1);
        assert!(!router.binding_of(42).unwrap().3);

        // Событие: сигнал в endpoint, pending взведён.
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));
        assert!(router.binding_of(42).unwrap().3);

        // Повторное до ACK — склейка (одно уведомление).
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));

        // Непривязанная линия — не наша.
        assert_eq!(router.irq_event(tasks, caps, ipc, 555), Ok(false));

        // ACK владельцем: pending снят, линия снова взводится.
        assert_eq!(router.ack(42, owner), Ok(true));
        assert!(!router.binding_of(42).unwrap().3);
        assert_eq!(
            router.ack(42, owner),
            Ok(false),
            "повторный ACK — не ошибка"
        );

        // Событие после ACK — снова доставка.
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));

        // Чужой не ACK-ает и не отцепляет.
        let stranger = uuid_next();
        assert_eq!(router.ack(42, stranger), Err(IrqError::NotOwner));
        assert_eq!(router.detach(42, stranger), Err(IrqError::NotOwner));

        // Detach владельцем; повтор — NotFound.
        router.detach(42, owner).unwrap();
        assert_eq!(router.len(), 0);
        assert_eq!(router.ack(42, owner), Err(IrqError::NotFound));
    }

    #[test]
    fn one_binding_per_line_and_cascade_detaches() {
        let (tasks, caps, devices, ipc) = setup();
        let router = IrqRouter::new();
        let (owner, gate) = owner_with_ep(tasks, caps, ipc);
        let (owner2, gate2) = owner_with_ep(tasks, caps, ipc);
        let _ = owner;

        router
            .attach(devices, owner, &uart_path(), 42, gate)
            .unwrap();
        // Линия занята — второй драйвер не пролезает.
        assert_eq!(
            router.attach(devices, owner2, &uart_path(), 42, gate2),
            Err(IrqError::AlreadyBound)
        );

        // Hot-removal устройства: привязки сняты, событие — не наше.
        assert_eq!(router.detach_device(&uart_path()), 1);
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(false));

        // Повторная привязка к погашенному (alive=false) устройству — отказ.
        let mut dm = DeviceManager::new();
        dm.register_bus(&UartBus).unwrap();
        dm.enumerate().unwrap();
        // Погасим запись: повторный scan без устройства не делает записи
        // dead, пока enumerate не увидит пропажу; вместо этого проверяем
        // DeviceGone на несуществующем пути (стабильный инвариант).
        let ghost = DevicePath::Acpi(AcpiPath::new("\\_SB.NOPE"));
        assert_eq!(
            router.attach(&dm, owner2, &ghost, 42, gate2),
            Err(IrqError::DeviceGone)
        );

        // Смерть задачи: привязки сняты каскадом.
        router
            .attach(devices, owner2, &uart_path(), 42, gate2)
            .unwrap();
        assert_eq!(router.detach_all_of(&owner2), 1);
        assert!(router.is_empty());
    }

    #[test]
    fn delivered_word_reaches_endpoint_queue() {
        let (tasks, caps, devices, ipc) = setup();
        let router = IrqRouter::new();
        let (owner, gate) = owner_with_ep(tasks, caps, ipc);

        router
            .attach(devices, owner, &uart_path(), 42, gate)
            .unwrap();
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));

        // Signal лежит в буфере endpoint'а (никто не ждёт — Queued,
        // счётчик delivered считает только прямые доставки).
        let queued = caps
            .with_endpoint(gate, |ep| ep.queued())
            .expect("endpoint жив");
        assert_eq!(queued, 1, "signal-слово в очереди endpoint");

        // Склейка до ACK: второго слова не появится.
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));
        let queued = caps.with_endpoint(gate, |ep| ep.queued()).unwrap();
        assert_eq!(queued, 1, "pending-бит склеивает события");
    }
}
