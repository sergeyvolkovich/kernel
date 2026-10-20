// ==== Контракты перечисления устройств: шина, приёмник, HW-хуки ====
//
// Архитектурная точка инкапсуляции крейта (см. комментарий в
// `hal::traits::mod`): `DeviceManager` НЕ знает ни PCIe, ни ACPI, ни DTB.
// Он знает только два объектно-безопасных контракта:
//
// ```text
//   DeviceManager ────&'static dyn BusEnumerator────▶ шина №1 (pcie.0)
//        │  scan(sink)                                    │ PciBus<A: PciConfigAccess>
//        │◀─────────── DiscoveredDevice ──── DeviceSink ──┘   (generic PCIe-обходчик)
//        │
//        ├────────── dyn BusEnumerator ────────────────▶ шина №2 (acpi)
//        │                                                 │ AcpiBus<H: acpi::Handler>
//        └────────── (будущее: dtb, usb, ...) ◀────────── заменяемость
// ```
//
// * [`BusEnumerator`] — «обходчик» одной шины. Реализации: `pci::PciBus`
//   (generic поверх платформенных хуков [`PciConfigAccess`]), `acpi::AcpiBus`.
//   Добавление DTB = новый модуль с реализацией трейта, менеджер не меняется.
// * [`DeviceSink`] — приёмник результатов обхода: менеджер подставляет свой
//   коллектор, тесты — свой.
// * [`PciConfigAccess`] — ЕДИНСТВЕННАЯ точка соприкосновения PCIe-обходчика
//   с железом: доступ к конфигурационному пространству (ECAM/MMIO или
//   CF8/CFC-порты, в тестах — программная модель). Замена способа доступа
//   не трогает ни алгоритм обхода, ни менеджер.
//
// Микроядерный контракт (см. lib.rs): ядро только ПЕРЕЧИСЛЯЕТ устройства и
// выдаёт capability; программирование устройств (BAR, MSI, контроллеры) —
// ответственность юзерспейс-драйверов. Поэтому ни один контракт здесь не
// содержит операций «включить/настроить устройство»: обходчик читает
// конфигурационное пространство, но не пишет в него (кроме канонического
// save/restore при измерении размера BAR — см. `pci`).

use alloc::{boxed::Box, string::String, vec::Vec};
use core::any::Any;

use thiserror::Error;

use crate::hal::traits::irq::TriggerMode;
use crate::hal::types::{Bdf, DeviceInfo, DevicePath, PhysAddr};

// ==== Ошибки ====

/// Ошибка перечисления на уровне подсистемы устройств.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeviceError {
    /// Шина с таким именем не зарегистрирована.
    #[error("bus {0:?} is not registered")]
    UnknownBus(String),
    /// Шина с таким именем уже подключена.
    #[error("bus {0:?} is already registered")]
    BusAlreadyRegistered(String),
    /// Устройства с таким путём нет в реестре.
    #[error("device {0:?} not found in registry")]
    DeviceNotFound(crate::hal::types::DevicePath),
    /// Отказ обхода шины (внутренняя ошибка бекенда).
    #[error("bus {bus:?} scan failed: {reason}")]
    BusFailed { bus: String, reason: BusError },
    /// Отказ менеджера capability при экспорте устройства.
    #[error("capability export failed: {0}")]
    Capability(#[from] crate::capability::CapabilityError),
}

/// Ошибка обхода конкретной шины (бекенд-независимый словарь).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BusError {
    /// Обращение к пространству конфигурации не удалось (нет ECAM-маппинга,
    /// шина не отвечает, timeout).
    #[error("configuration space access failed")]
    ConfigAccess,
    /// Топология повреждена (например, мост зацикливает номера шин).
    #[error("broken bus topology")]
    BrokenTopology,
    /// Не хватает памяти под структуры обхода.
    #[error("out of memory during scan")]
    OutOfMemory,
    /// Бекенд не инициализирован (нет таблиц/маппингов) — вызовите init
    /// платформенного слоя до scan.
    #[error("bus backend is not initialized")]
    NotInitialized,
}

// ==== Ресурсы устройства ====

/// Ресурс, занятый устройством (декодирован из BAR / _CRS).
///
/// Формат сознательно узкий: юзерспейс-драйверу нужен адрес и длина,
/// остальное (тип Prefetchable, кэшируемость) приезжает в шино-специфичных
/// данных [`BusDeviceData`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceResource {
    /// Диапазон MMIO (device memory).
    Mmio { base: PhysAddr, len: u64 },
    /// Диапазон портов ввода-вывода (x86 legacy).
    IoPort { base: u16, len: u16 },
    /// Линия прерывания (GSI на ARM; на x86 — глобальный номер после
    /// маппинга через InterruptModel).
    Irq {
        gsi: u32,
        trigger: TriggerMode,
        /// Активный уровень: true — активный низкий.
        active_low: bool,
    },
}

impl DeviceResource {
    /// Пригодно для отображения драйверу (память или порты).
    pub fn addressable(&self) -> bool {
        matches!(
            self,
            DeviceResource::Mmio { .. } | DeviceResource::IoPort { .. }
        )
    }
}

// ==== Данные шино-специфичные ====

/// Непрозрачные данные чужого бекенда перечисления.
///
/// Менеджер их только хранит и отдаёт по запросу; интерпретация — право
/// владельца (юзерспейс-сервиса устройств или платформенного кода).
pub trait DeviceBusData: Any + Send + core::fmt::Debug {}

impl<T: Any + Send + core::fmt::Debug> DeviceBusData for T {}

/// Шино-специфичная «начинка» найденного устройства.
///
/// `Opaque` — канал расширения для бекендов вне крейта (в т.ч. будущего
/// DTB-обходчика): они прикладывают свои данные, не расширяя этот enum.
#[derive(Debug)]
#[non_exhaustive]
pub enum BusDeviceData {
    /// Данные функции PCI/PCIe (см. `pci::PciDeviceData`).
    Pci(crate::hal::device::pci::PciDeviceData),
    /// Данные узла ACPI (см. `acpi::AcpiDeviceData`).
    Acpi(crate::hal::device::acpi::AcpiDeviceData),
    /// Данные внешнего бекенда (заменяемый PCIe, DTB-обходчик, ...).
    Opaque(Box<dyn DeviceBusData>),
}

impl BusDeviceData {
    /// Downcast к конкретному типу данных бекенда.
    pub fn downcast_ref<T: DeviceBusData>(&self) -> Option<&T> {
        match self {
            BusDeviceData::Opaque(inner) => (inner.as_ref() as &dyn Any).downcast_ref::<T>(),
            _ => None,
        }
    }
}

// ==== Результат обхода ====

/// Устройство, найденное обходчиком шины за один проход.
///
/// Инварианты (контракт бекендов):
/// * `path` уникален в рамках системы и стабилен между rescan — это ключ
///   реестра [`crate::hal::device::DeviceManager`] и ключ capability
///   `DeviceReference`;
/// * `info.kind` согласован с `path` (PCI-путь ⇒ `DeviceKind::Pci`);
/// * обходчик НЕ выдаёт одно устройство дважды за один scan.
#[derive(Debug)]
pub struct DiscoveredDevice {
    /// Типизированная идентичность (ключ реестра и capability).
    pub path: DevicePath,
    /// Общая мета-информация (мастера DMA, когерентность, MSI-источник).
    pub info: DeviceInfo,
    /// Декодированные ресурсы (BAR / _CRS).
    pub resources: Vec<DeviceResource>,
    /// Шино-специфичные данные (прозрачны для менеджера).
    pub data: BusDeviceData,
    /// Устройство присутствует и функционально (ACPI `_STA` бит 3; PCI —
    /// true). Отсутствующие узлы namespace можно сообщать для полноты
    /// картины — экспорт capability их отфильтрует.
    pub functional: bool,
}

// ==== Приёмник результатов обхода ====

/// Приёмник устройств: менеджер подставляет коллектор rescan, платформенные
/// утилиты — свои. Обходчик вызывает [`Self::discovered`] на каждый найденный
/// девайс; порядок произвольный.
pub trait DeviceSink {
    fn discovered(&mut self, dev: DiscoveredDevice);
}

// ==== Обходчик шины ====

/// Обходчик одной шины (шинный бекенд перечисления).
///
/// Реализации крейта: `pci::PciBus` (generic PCIe), `acpi::AcpiBus`.
/// Внешние реализации (платформа, DTB в будущем) регистрируются в
/// [`crate::hal::device::DeviceManager`] без изменений менеджера —
/// это и есть точка заменяемости PCIe.
///
/// Методы принимают `&self` (как `SchedulerInterface`): бекенды живут как
/// `&'static dyn BusEnumerator`, изменяемое состояние — через interior
/// mutability (RefCell/атомики; однопоточный контракт ядра).
///
/// Контракт `scan`:
/// * за один вызов сообщает о ВСЕХ найденных устройствах через `sink`
///   (менеджер строит дифф с прошлым проходом: пропавшие гасятся);
/// * повторный scan той же топологии даёт то же множество `path`
///   (идемпотентность — тот же контракт, что у
///   `LIOMMUInterface::resolve_device`);
/// * `scan` не программирует устройства: только чтение конфигурации.
pub trait BusEnumerator {
    /// Стабильное имя шины (логи, адресация при rescan: "pcie.0", "acpi").
    fn bus_name(&self) -> &str;

    /// Пройти шину, сообщая о каждом устройстве через `sink`.
    fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError>;
}

// ==== HW-хуки: доступ к конфигурационному пространству PCI ====

/// Доступ к конфигурационному пространству PCI/PCIe — платформенные хуки.
///
/// Единственная точка соприкосновения generic-обходчика `pci::PciBus`
/// с железом. Реализации:
/// * ECAM/MMIO (MCFG: base + (bus << 20 | dev << 15 | fn << 12));
/// * legacy CF8/CFC (только сегмент 0, шина 0..=255);
/// * программная модель в тестах.
///
/// Контракт:
/// * чтение несуществующей функции возвращает `0xFFFF_FFFF` (vendor id
/// «нет устройства»), а НЕ ошибку — это нормальный результат проб;
/// * выравнивание: `offset` выровнен по `len`, `offset <= 0xFC` для 32 бит;
/// * бекенд отвечает за interior mutability (`&self` — как MMIO-запись).
pub trait PciConfigAccess {
    /// Прочитать 32-битное слово конфигурационного пространства.
    fn config_read32(&self, segment: u16, bdf: Bdf, offset: u8) -> u32;

    /// Прочитать 16-битное полуслово.
    fn config_read16(&self, segment: u16, bdf: Bdf, offset: u8) -> u16;

    /// Прочитать байт.
    fn config_read8(&self, segment: u16, bdf: Bdf, offset: u8) -> u8;

    /// Записать 32-битное слово. Нужен ТОЛЬКО для канонического
    /// save/restore при измерении размера BAR (см. `pci`): обходчик
    /// восстанавливает исходное значение немедленно.
    fn config_write32(&self, segment: u16, bdf: Bdf, offset: u8, value: u32);
}
