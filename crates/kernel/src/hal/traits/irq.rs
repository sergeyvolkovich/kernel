// ==== IRQ: обработка прерываний, MSI и таблицы прерываний (IRTE) ====
//
// Иерархия трейтов:
// * `IRQPlatform` — платформенные хуки (enable/disable линии, программный
//   ввод/вывод MSI, доступ к контроллеру прерываний).
// * `GenericIRQInterface` — бекенд-независимый интерфейс для драйверов
//   (регистрация обработчиков, управление IRQ, MSI).
// * `InterruptRemapper` — перенаправление прерываний через IOMMU (IRTE).
// * `DirectIRQOps<P: IRQPlatform>` — обёртка, реализующая `GenericIRQInterface`
//   через платформенные хуки `IRQPlatform`.

use bitflags::bitflags;

use crate::hal::{
    traits::iommu::IommuError,
    types::{ItsId, PhysAddr},
};

// ==== Типы ====

/// Идентификатор линии прерываний (GSI или контроллерно-зависимый).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IrqId(pub u32);

/// Индекс записи IRTE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrteIndex(pub usize);

/// Диапазон IRTE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrteRange {
    pub start: IrteIndex,
    pub count: usize,
}

impl IrteRange {
    pub fn contains(&self, idx: IrteIndex) -> bool {
        idx.0 >= self.start.0 && idx.0 < self.start.0 + self.count
    }
}

/// MSI-сообщение (address + data для программирования устройства).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}

/// Источник MSI (ITS + device ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiSource {
    iommu_its: ItsId,
    device_id: u32,
}

impl MsiSource {
    pub const fn new(iommu_its: ItsId, device_id: u32) -> Self {
        Self {
            iommu_its,
            device_id,
        }
    }

    pub const fn its(&self) -> ItsId {
        self.iommu_its
    }

    pub const fn device_id(&self) -> u32 {
        self.device_id
    }
}

/// Источник прерывания (requester ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId {
    pub requester_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    Fixed = 0b000,
    LowestPriority = 0b001,
    Smi = 0b010,
    Nmi = 0b100,
    Init = 0b101,
    ExtInt = 0b111,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

/// Конфигурация IRTE (Interrupt Remapping Table Entry).
pub struct IrteConfig {
    pub vector: u8,
    pub dest: u32,
    pub delivery: DeliveryMode,
    pub trigger_mode: TriggerMode,
    pub is_masked: bool,
    pub source: SourceId,
    pub posted: Option<PhysAddr>,
}

pub struct ExceptionInfo {
    pub state: InteruptState,
    pub info: ExecptionType,
}

bitflags! {
    pub struct PageExceptionFlags : u8{

}
}

pub enum ExecptionType {
    PageException { flags: PageExceptionFlags },
}

pub struct InteruptState {
    pub exec_p: usize,
    pub exec_s: usize,
}

// ==== Trait: IRQPlatform (платформенные хуки) ====

pub trait IRQPlatform {
    /// Инициализация контроллера прерываний.
    fn init_interrupt_controller(&mut self) -> Result<(), IommuError>;

    /// Разрешить линию прерываний.
    fn enable_irq(&self, irq: IrqId) -> Result<(), IommuError>;

    /// Запретить линию прерываний.
    fn disable_irq(&self, irq: IrqId) -> Result<(), IommuError>;

    /// Программное MSI: вычислить address/data для заданного device_id.
    fn compose_msi(&self, source: MsiSource) -> Result<MsiMessage, IommuError>;

    /// Глобальное включение/выключение прерываний на CPU.
    fn enable_interrupts(&self);
    fn disable_interrupts(&self);

    fn register_exception_handler(&self, h: &'static dyn Fn(ExceptionInfo));
    fn register_interrupt_handler(&self, h: &'static dyn Fn(InteruptState, u32));
}

// ==== Trait: InterruptRemapper (перенаправление через IOMMU) ====

pub trait InterruptRemapper: Send + Sync {
    /// Выделяет `count` записей в таблице (IRTE). Для MSI-X count > 1.
    fn alloc_entries(&self, count: usize) -> Result<IrteRange, IommuError>;

    /// Настраивает конкретную запись таблицы.
    fn set_entry(&self, idx: IrteIndex, cfg: IrteConfig) -> Result<(), IommuError>;

    /// Маскирует/размаскирует запись (без изменения остальных полей).
    fn set_masked(&self, idx: IrteIndex, masked: bool) -> Result<(), IommuError>;

    /// Освобождает выделенный диапазон.
    fn free_entries(&self, range: IrteRange);

    /// Делает IEC (Interrupt Entry Cache) invalidation + ожидает завершения.
    fn flush_entry(&self, idx: IrteIndex);

    /// Инвалидирует весь кэш прерываний (Global IEC invalidation).
    fn flush_all(&self);

    /// Формирует address и data для конфигурирования MSI/MSI-X в устройстве.
    fn compose_msi(&self, idx: IrteIndex) -> MsiMessage;
}

// ==== Trait: IrqLineOps (внешние линии, v0.11) ====

/// Включение/выключение ВНЕШНИХ линий прерываний платформы
/// (x86_64: IOAPIC из MADT; IRQ_ATTACH возводит линию этим сервисом).
///
/// Модель L4: драйвер привязывает линию устройства к endpoint'у
/// (IrqRouter), ядро просит платформу «включить линию» — вектор и
/// целевой LAPIC выбирает ПЛАТФОРМА (x86_64: `VEC_EXTERNAL_BASE + pin`,
/// BSP), прерывание приходит в общий asm-вход и доставляется
/// glue-хуком `on_external_irq` как signal-слово (= gsi) в endpoint.
///
/// IOMMU: если IRQ-ремаппинг включён, платформа заводит IRTE под линию
/// (Intel: remapped-формат RTE по зарезервированному слоту 0x10+pin;
/// AMD: per-device IntTab IOAPIC, индекс = вектор) — семантика
/// прозрачна для сискол-слоя.
pub trait IrqLineOps: Send + Sync {
    /// Возвести линию GSI (размаскировать + запрограммировать RTE/IRTE).
    /// Возврат — назначенный вектор (для аудита; доставка — по маске
    /// векторов платформы). Триггер/полярность — из ресурса устройства;
    /// платформа сверяет их с Interrupt Source Overrides (MADT).
    fn enable_line(&self, gsi: u32, level: bool, active_low: bool) -> Result<u8, IommuError>;

    /// Замаскировать линию (IRQ_DETACH: событий больше нет, но конфиг
    /// линии сохраняется до следующего включения).
    fn disable_line(&self, gsi: u32) -> Result<(), IommuError>;
}
