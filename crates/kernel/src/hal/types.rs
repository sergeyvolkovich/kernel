// Универсальные типы HAL: адреса, идентификаторы устройств, мета-информация.
//
// Ключевой тип — [`DevicePath`]: типизированная идентичность устройства,
// используемая как ключ реестра в `DeviceManager` и как ключ разрешения
// хендла в IOMMU (вместо неформализованных `&str` из прежнего API).
use alloc::{string::String, vec::Vec};

use core::fmt;

use bitflags::bitflags;

use crate::hal::traits::dma::Direction;
use crate::hal::traits::iommu::IommuId;
use crate::hal::traits::irq::MsiSource;

pub const PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItsId(pub u32);

// ==== Адреса ====

/// Физический адрес (с точки зрения CPU).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn offset(self, off: u64) -> Self {
        Self(self.0 + off)
    }

    pub const fn align_down(self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn align_up(self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    pub const fn is_aligned(self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }
}

// ==== Идентификаторы и типы устройств ====

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bdf {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Обратное преобразование из Requester ID (сегмент задаётся отдельно).
    pub fn from_requester_id(segment: u16, rid: u16) -> Self {
        Self {
            segment,
            bus: (rid >> 8) as u8,
            device: ((rid >> 3) & 0x1f) as u8,
            function: (rid & 0x7) as u8,
        }
    }

    pub const fn to_requester_id(&self) -> u16 {
        ((self.bus as u16) << 8)
            | (((self.device & 0x1f) as u16) << 3)
            | ((self.function & 0x7) as u16)
    }
}

impl fmt::Display for Bdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.segment, self.bus, self.device, self.function
        )
    }
}

/// AML-путь ACPI-устройства (например `\_SB.PCI0.GPV0`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AcpiPath(pub String);

impl AcpiPath {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AcpiPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Путь в device tree (например `/soc/serial@fe001000`).
///
/// Зарезервировано для будущей поддержки DTB (план платформы): обходчик
/// `dtb::DtbBus` будет строить эти пути и регистрировать устройства с
/// `DevicePath::Dt` — реестр устройств, capability-слой и сериализация
/// уже готовы к варианту, добавление — обратно совместимо.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DtPath(pub String);

impl DtPath {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DtPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Типизированная идентичность устройства.
///
/// Выполняет две роли:
/// 1. ключ записи в реестре `DeviceManager` (стабилен между rescan);
/// 2. ключ, по которому IOMMU разрешает устройство в хендл `DeviceId`.
///
/// Прежний API передавал строковые хендлы (`&str`), что не позволяло
/// различать PCI-функции и ACPI-узлы на уровне типов. `DevicePath`
/// закрывает эту дыру: вариант определяется статически.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DevicePath {
    /// PCI/PCIe функция: сегмент + шина + устройство + функция.
    Pci(Bdf),
    /// ACPI-устройство по AML-пути из namespace.
    Acpi(AcpiPath),
    /// Устройство device tree по пути узла (поддержка DTB — план).
    Dt(DtPath),
    /// Устройство, адресуемое на шине через StreamID (ARM) или
    /// Requester ID (x86) в контексте конкретного IOMMU.
    StreamId { iommu: IommuId, id: u32 },
}

impl fmt::Display for DevicePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevicePath::Pci(bdf) => write!(f, "pci:{bdf}"),
            DevicePath::Acpi(path) => write!(f, "acpi:{path}"),
            DevicePath::Dt(path) => write!(f, "dt:{path}"),
            DevicePath::StreamId { iommu, id } => write!(f, "stream:{id:#x}@iommu{}", iommu.0),
        }
    }
}

impl From<Bdf> for DevicePath {
    fn from(bdf: Bdf) -> Self {
        DevicePath::Pci(bdf)
    }
}

impl From<DtPath> for DevicePath {
    fn from(path: DtPath) -> Self {
        DevicePath::Dt(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlatformId {
    pub acpi_uid: Option<u32>,
    pub dt_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    Pci(Bdf),
    Platform(PlatformId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MasterId {
    pub iommu: IommuId,
    /// Идентификатор мастера на шине: x86 — Requester ID, ARM — StreamID.
    pub id: u32,
}

// ==== Мета-информация об устройстве ====

// Для `Debug`/`Clone` нужно, чтобы `MsiSource` их тоже реализовывал.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    pub masters: Vec<MasterId>,
    pub coherent: bool,
    pub msi: Option<MsiSource>,
}

impl DeviceInfo {
    pub fn new(kind: DeviceKind) -> Self {
        Self {
            kind,
            masters: Vec::new(),
            coherent: true,
            msi: None,
        }
    }

    pub fn with_master(mut self, master: MasterId) -> Self {
        self.masters.push(master);
        self
    }

    pub fn with_coherent(mut self, coherent: bool) -> Self {
        self.coherent = coherent;
        self
    }

    pub fn with_msi(mut self, msi: MsiSource) -> Self {
        self.msi = Some(msi);
        self
    }

    /// Первый (основной) master устройства.
    pub fn primary_master(&self) -> Option<MasterId> {
        self.masters.first().copied()
    }

    pub fn bdf(&self) -> Option<Bdf> {
        match &self.kind {
            DeviceKind::Pci(bdf) => Some(*bdf),
            DeviceKind::Platform(_) => None,
        }
    }

    /// Идентичность устройства, пригодная для IOMMU-разрешения.
    ///
    /// Для PCI-устройств путь восстанавливается из BDF напрямую.
    /// Для platform-устройств идентичность знает только конкретный
    /// бекенд перечисления: DTB-обходчик заполнит `dt_path` (и путь
    /// восстановится отсюда), ACPI-обходчик адресует устройства
    /// AML-путём — он живёт в `DevicePath::Acpi`, минуя этот метод.
    pub fn device_path(&self) -> Option<DevicePath> {
        match &self.kind {
            DeviceKind::Pci(bdf) => Some(DevicePath::Pci(*bdf)),
            DeviceKind::Platform(p) => p
                .dt_path
                .as_ref()
                .map(|s| DevicePath::Dt(DtPath(s.clone()))),
        }
    }
}

bitflags! {
    /// Права доступа устройства при отображении в IOMMU.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IommuProt: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        /// Обращения устройства когерентны с кэшами CPU (snoop).
        const CACHE = 1 << 2;
    }
}

impl IommuProt {
    /// Права, достаточные для заданного направления передачи.
    /// `ToDevice` -> устройство читает (READ), `FromDevice` -> пишет (WRITE).
    pub fn from_direction(dir: Direction, coherent: bool) -> Self {
        let mut prot = IommuProt::empty();
        if dir.device_reads() {
            prot |= IommuProt::READ;
        }
        if dir.device_writes() {
            prot |= IommuProt::WRITE;
        }
        if coherent {
            prot |= IommuProt::CACHE;
        }
        prot
    }
}
