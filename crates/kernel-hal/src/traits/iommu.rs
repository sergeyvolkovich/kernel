// ==== IOMMU: хендлы устройств и операции remapping ====
//
// Семантика хендлов (переработанная):
//
// 1. Устройство идентифицируется типизированным ключом [`DevicePath`]
//    (PCI — BDF, ACPI — AML-путь, шина — StreamID/RequesterID). Неформальные
//    строковые хендлы из прежнего API убраны: вариант пути фиксирован типом,
//    ошибки вида «передали AML-путь туда, где ждут BDF» ловятся компилятором.
//
// 2. `resolve_device` идемпотентен: повторное разрешение того же пути
//    возвращает тот же [`DeviceId`] (контракт обязателен для реализаций),
//    поэтому перечисление можно повторять (rescan) без утечки записей
//    таблиц устройств в IOMMU.
//
// 3. Трейт разделён на два уровня:
//    * [`ANIOMMUInterface`] — бекенд-независимые операции (map/unmap,
//      права, detach), объектно-безопасные и не привязанные к бекенду
//      перечисления. Через них работают DMA-подсистемы.
//    * [`LIOMMUInterface`] — связка с конкретным HW-бекендом: разрешение
//      `DevicePath` -> `DeviceId` на этапе перечисления устройств.
//
// 4. Хендл `DeviceId` — непрозрачный токен конкретного IOMMU. Он ничего
//    не значит без пары с `IommuId`; пара (`IommuId`, `DeviceId`) глобально
//    идентифицирует устройство в подсистеме remapping.

use crate::types::{DevicePath, IommuProt, PhysAddr};

// ==== Идентификаторы ====

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IommuId(pub u32);

/// Хендл устройства внутри конкретного IOMMU (непрозрачный токен).
///
/// Валиден только в паре с `IommuId` того контроллера, который его выдал.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u32);

// ==== Ошибки ====

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IommuError {
    OutOfMemory,
    InvalidIndex,
    InvalidConfig,
    HardwareTimeout,
    NotSupported,
    IommuNotPresent,
    RemappingDisabled,
    DeviceNotFound,
    /// Путь устройства не принадлежит ни одному известному master'у
    /// (например, BDF вне покрытых сегментов или AML-путь вне scope DRHD).
    UnknownDevicePath,
    /// `DeviceId` не привязан к контроллеру (уже освобождён или чужой).
    DeviceNotBound,
    /// Попытка отобразить уже занятый диапазон IOVA.
    IovaConflict,
    /// Попытка снять отображение, которого нет.
    MappingNotFound,
}

// ==== Trait: ANIOMMUInterface (безопасный для объектов, бекенд-независимый) ====
//
// Через этот трейт работают все DMA-подсистемы. Реализации не привязаны к
// конкретному бекенду перечисления устройств.

pub trait ANIOMMUInterface {
    /// Идентификатор этого контроллера (уникален в системе).
    fn iommu_id(&self) -> IommuId;

    /// Отобразить `count` подряд идущих физических страниц в адресное
    /// пространство устройства начиная с `iova` (страницы = `phys` + N).
    fn map_pages(
        &mut self,
        dev: DeviceId,
        iova: u64,
        phys: PhysAddr,
        count: usize,
        prot: IommuProt,
    ) -> Result<(), IommuError>;

    /// Снять отображение `count` страниц, начиная с `iova`.
    fn unmap_pages(&mut self, dev: DeviceId, iova: u64, count: usize) -> Result<(), IommuError>;

    /// Изменить права устройства (READ/WRITE/CACHE) на уже отображённые
    /// страницы.
    fn set_protection(&mut self, dev: DeviceId, prot: IommuProt) -> Result<(), IommuError>;

    /// Отвязать устройство от контроллера: страница-таблицы устройства
    /// освобождаются, трафик мастера далее не транслируется.
    fn detach_device(&mut self, dev: DeviceId) -> Result<(), IommuError>;
}

// ==== Trait: LIOMMUInterface (связка с конкретным HW-бекендом) ====
//
// Расширяет [`ANIOMMUInterface`] операциями, специфичными для конкретного
// бекенда перечисления. Параметр `Processor` — тип контекста бекенда
// (например, ACPI-таблицы или device tree), с которым IOMMU взаимодействует
// при разрешении устройств.

pub trait LIOMMUInterface: ANIOMMUInterface {
    /// Тип бекенда перечисления, у которого IOMMU запрашивает контекст
    /// (топология PCI, scope-устройства ACPI).
    type Processor;

    /// Инициализация состояния IOMMU по данным бекенда (например, поиск
    /// scope-устройств в ACPI или мостов для иерархии Requester ID).
    fn init_iommu_state(&mut self, processor: &Self::Processor);

    /// Разрешить типизированный путь устройства в хендл IOMMU.
    ///
    /// # Контракт
    /// * Идемпотентность: повторный вызов с тем же `path` возвращает
    ///   тот же `DeviceId`, не создавая новых записей.
    /// * Для моста PCIe подразумевается, что реализация учитывает
    ///   иерархию Requester ID (устройства за мостом наследуют/входят
    ///   в scope моста), либо возвращает [`IommuError::UnknownDevicePath`].
    fn resolve_device(
        &mut self,
        processor: &Self::Processor,
        path: &DevicePath,
    ) -> Result<DeviceId, IommuError>;
}
