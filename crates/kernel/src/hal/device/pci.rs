// ==== Generic обходчик PCI/PCIe (сменяемый бекенд шины) ====
//
// Полный алгоритм перечисления функций с рекурсивным спуском через
// PCI-мосты, декодированием BAR (включая 64-битные), expansion ROM,
// списком capabilities (MSI/MSI-X) и окнами мостов.
//
// Инкапсуляция (требование «PCIe можно заменить»):
// ```text
//   DeviceManager ──▶ dyn BusEnumerator ◀── PciBus<A: PciConfigAccess>
//                                            │
//                                            └── A: ECAM / CF8-CFC / мок
// ```
// * менеджер видит только `BusEnumerator` — модуль `pci` можно заменить
//   целиком (собственный обходчик, PCI Express только через ACPI _PRT и
//   т.д.) или добавить рядом конкурентный бекенд;
// * алгоритм обхода не знает о железе: ВСЕ обращения к конфигурационному
//   пространству идут через [`PciConfigAccess`] — платформа подставляет
//   ECAM (MCFG), legacy-порты или программную модель в тестах;
// * обходчик ничего не программрует: не трогает command register,
//   не назначает номера шин (это право юзерспейс-драйвера шины);
//   единственная запись в конфигурацию — канонический save/restore при
//   измерении размера BAR (см. `bar_size`).
//
// Микроядерность: результат обхода — только данные (`PciDeviceData`,
// ресурсы), которые менеджер положит в реестр и экспортирует как
// capability `DeviceReference`. Включение памяти/шины, программирование
// MSI иBAR — юзерспейс.

use alloc::{string::String, vec::Vec};

use crate::hal::device::traits::{
    BusDeviceData, BusEnumerator, BusError, DeviceResource, DeviceSink, DiscoveredDevice,
    PciConfigAccess,
};
use crate::hal::traits::irq::MsiSource;
use crate::hal::types::{Bdf, DeviceInfo, DeviceKind, ItsId, PhysAddr};

// ==== Смещения конфигурационного пространства ====

const REG_VENDOR_DEVICE: u8 = 0x00;
const REG_COMMAND_STATUS: u8 = 0x04;
const REG_REVISION_CLASS: u8 = 0x08;
const REG_HEADER_TYPE: u8 = 0x0E;
const REG_BAR0: u8 = 0x10;
const REG_SUBSYSTEM: u8 = 0x2C;
const REG_ROM: u8 = 0x30;
const REG_CAPABILITIES: u8 = 0x34;
const REG_IRQ: u8 = 0x3C;
/// Мост (type 1): primary/secondary/subordinate bus.
const REG_BRIDGE_BUSES: u8 = 0x18;
/// Мост: io base/limit (8 бит каждый).
const REG_BRIDGE_IO: u8 = 0x1C;
/// Мост: memory base/limit (16 бит каждое, выровнено на 1 МБ).
const REG_BRIDGE_MEM: u8 = 0x20;
/// Мост: prefetchable base/limit.
const REG_BRIDGE_PREFETCH: u8 = 0x24;
/// Мост: старшие 32 бита prefetchable base/limit.
const REG_BRIDGE_PREFETCH_HI: u8 = 0x28;
/// Мост: expansion ROM.
const REG_BRIDGE_ROM: u8 = 0x38;

/// Идентификаторы capabilities, которые распознает обходчик.
pub mod capability_id {
    pub const PCI_MSI: u8 = 0x05;
    pub const PCI_PCIE: u8 = 0x10;
    pub const PCI_MSIX: u8 = 0x11;
}

/// Максимальный номер шины (на шину отводится 8 бит).
const MAX_BUS: u16 = 256;

// ==== Данные функции ====

/// Тип заголовка конфигурационного пространства.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciHeaderType {
    /// Обычное устройство (type 0): 6 BAR, subsystem, ROM.
    Standard,
    /// PCI-PCI мост (type 1): 2 BAR, окна шины, ROM.
    Bridge,
    /// CardBus (type 2) и прочее: данные не декодируются.
    Other(u8),
}

impl PciHeaderType {
    fn from_raw(raw: u8) -> Self {
        match raw & 0x7F {
            0x00 => Self::Standard,
            0x01 => Self::Bridge,
            other => Self::Other(other),
        }
    }
}

/// Декодированный BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBar {
    /// Вид адреса.
    pub kind: PciBarKind,
    /// Базовый адрес (0 — BAR не реализован или отключен).
    pub base: u64,
    /// Размер в байтах (степень двойки у корректного BAR).
    pub size: u64,
    /// Prefetchable MMIO (только для памяти).
    pub prefetchable: bool,
}

/// Вид BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBarKind {
    /// Порты ввода-вывода (16-битное пространство x86).
    Io,
    /// 32-битная память.
    Mem32,
    /// 64-битная память (занимает два соседних слота BAR).
    Mem64,
}

/// MSI capability (0x05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiInfo {
    /// 64-битные адреса сообщений.
    pub is_64bit: bool,
    /// log2 максимального числа векторов, которые умеет устройство (0..=5).
    pub multiple_message_capable: u8,
    /// Per-vector masking (PCI 2.3+).
    pub per_vector_masking: bool,
}

/// MSI-X capability (0x11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixInfo {
    /// Число записей таблицы (уже +1 к полю в конфигурации).
    pub table_size: u16,
    /// BAR, в котором лежит таблица (индекс 0..5).
    pub table_bir: u8,
    /// Смещение таблицы внутри BAR.
    pub table_offset: u32,
    /// BAR с Pending Bit Array.
    pub pba_bir: u8,
    /// Смещение PBA внутри BAR.
    pub pba_offset: u32,
}

/// PCIe capability (0x10): линия звена — скорость/ширина.
///
/// Читается, но не программируется: настройка линков (target speed,
/// retrain) — право юзерспейс-драйвера шины; ядро только сообщает
/// состояние (диагностика топологии, выбор политик драйверов).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciExpressInfo {
    /// Версия PCIe capability (обычно 1..2).
    pub version: u8,
    /// Тип порта/устройства (bits 7:4 capabilities): 0 = endpoint,
    /// 4 = root port, 6..7 = downstream/upstream switch port, 0xC = RC.
    pub port_type: u8,
    /// Максимальная скорость звена (1 = 2.5GT/s, 2 = 5, 3 = 8, 4 = 16).
    pub max_link_speed: u8,
    /// Максимальная ширина звена (1/2/4/8/16 линий).
    pub max_link_width: u8,
    /// Текущая согласованая скорость (link status).
    pub cur_link_speed: u8,
    /// Согласованная ширина звена.
    pub cur_link_width: u8,
}

/// Окна адресации PCI-моста (type 1).
///
/// НЕ выкладываются в `resources` записи моста: окно — диапазон, в котором
/// живут РЕСУРСЫ ДЕТЕЙ (двойной учёт при экспорте недопустим); юзерспейс-
/// драйвер шины читает окна отсюда при настройке иерархии.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeWindows {
    /// Диапазон портов IO (базовые байты io base/limit, гранулярность 4K).
    pub io: Option<(u16, u16)>,
    /// Диапазон 32-битной памяти (гранулярность 1 МБ).
    pub memory: Option<(u32, u32)>,
    /// Диапазон prefetchable памяти (64-битный, если старшие слова не нуль).
    pub prefetchable: Option<(u64, u64)>,
    /// Номера шин: (primary, secondary, subordinate).
    pub buses: (u8, u8, u8),
}

/// PCI-специфичные данные функции: всё, что юзерспейс-драйвер читает из
/// конфигурационного пространства, минус программирование.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciDeviceData {
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    /// Класс устройства: (class, subclass, prog_if).
    pub class: (u8, u8, u8),
    pub header_type: PciHeaderType,
    /// Бит 7 header type функции 0: устройство многофункциональное.
    pub multifunction: bool,
    /// Command register (только прочитанное состояние; обход не включает биты).
    pub command: u16,
    /// Status register.
    pub status: u16,
    /// Subsystem vendor/device (type 0).
    pub subsystem: Option<(u16, u16)>,
    /// Декодированные BAR (пропущенные слоты 64-битных BAR не попадают).
    pub bars: Vec<PciBar>,
    /// Expansion ROM: (база, размер).
    pub rom: Option<(u64, u64)>,
    /// Пройденный список capabilities: (id, смещение в конфигурации).
    pub capabilities: Vec<(u8, u8)>,
    pub msi: Option<MsiInfo>,
    pub msix: Option<MsixInfo>,
    /// PCIe capability (0x10): линия звена (только PCIe-устройства).
    pub pcie: Option<PciExpressInfo>,
    /// Окна моста (только type 1).
    pub bridge: Option<BridgeWindows>,
    /// Interrupt Pin (0 — не использует IRQ, 1..=4 = INTA..INTD).
    pub irq_pin: u8,
    /// Interrupt Line ( legacy routing; на ARM бессмысленно).
    pub irq_line: u8,
}

// ==== Обходчик ====

/// Корневая шина, с которой начинается обход сегмента.
///
/// Источник — платформа: MCFG (ECAM-сегменты), ACPI `_SB.PCIx._BBN` или
/// фиксированная топология.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciRootBus {
    pub segment: u16,
    pub bus: u8,
}

/// Generic обходчик PCI/PCIe: `BusEnumerator` поверх [`PciConfigAccess`].
///
/// Заменяемость: платформа собирает `PciBus` со своими корнями и своим
/// способом доступа к конфигурации; с точки зрения `DeviceManager` это
/// просто ещё один `dyn BusEnumerator` с именем `bus_name`.
pub struct PciBus<A: PciConfigAccess> {
    access: A,
    name: String,
    roots: Vec<PciRootBus>,
    /// ITS для `DeviceInfo::msi` (`None` — MSI компонирует платформа сама,
    /// например x86 через INTx/APIC).
    msi_its: Option<ItsId>,
}

impl<A: PciConfigAccess> PciBus<A> {
    /// Собрать обходчик. `name` — уникальное имя для менеджера ("pcie.0").
    pub fn new(
        name: impl Into<String>,
        access: A,
        roots: Vec<PciRootBus>,
        msi_its: Option<ItsId>,
    ) -> Self {
        Self {
            access,
            name: name.into(),
            roots,
            msi_its,
        }
    }

    /// Платформенный бекенд доступа (для внешней настройки до scan).
    pub fn access(&self) -> &A {
        &self.access
    }

    /// Прочитать vendor id функции (0xFFFF — функции нет).
    fn vendor(&self, segment: u16, bdf: Bdf) -> u16 {
        self.access.config_read32(segment, bdf, REG_VENDOR_DEVICE) as u16
    }

    /// Обойти одну шину (рекурсивно спускаясь в мосты).
    ///
    /// `visited` — номера шин, уже пройденные в ЭТОМ сегменте (защита от
    /// битых мостов, зацикливающих номера шин).
    fn scan_bus(&self, segment: u16, bus: u8, visited: &mut Vec<bool>, sink: &mut dyn DeviceSink) {
        if visited[bus as usize] {
            return; // уже проходили (общий subordinate у соседних мостов)
        }
        visited[bus as usize] = true;

        for device in 0u8..32 {
            let f0 = Bdf::new(segment, bus, device, 0);
            if self.vendor(segment, f0) == 0xFFFF {
                continue; // устройства нет — функций тоже
            }
            // Многофункциональность определяет функция 0 (бит 7 header type).
            let multifunction = self.access.config_read8(segment, f0, REG_HEADER_TYPE) & 0x80 != 0;
            let functions = if multifunction { 8 } else { 1 };

            for function in 0u8..functions {
                let bdf = Bdf::new(segment, bus, device, function);
                if self.vendor(segment, bdf) == 0xFFFF {
                    continue;
                }
                let data = self.probe_function(segment, bdf, multifunction);
                let secondary = data.bridge.map(|w| w.buses.1).unwrap_or(0);

                let mut info = DeviceInfo::new(DeviceKind::Pci(bdf));
                if data.msix.is_some() || data.msi.is_some() {
                    if let Some(its) = self.msi_its {
                        info = info.with_msi(MsiSource::new(its, bdf.to_requester_id() as u32));
                    }
                }
                let resources = Self::resources_of(&data);
                // Функция отвечает на чтение — считаем присутствующей (полный
                // статус питания — забота юзерспейс-драйвера).
                sink.discovered(DiscoveredDevice {
                    path: crate::hal::types::DevicePath::Pci(bdf),
                    info,
                    resources,
                    data: BusDeviceData::Pci(data),
                    functional: true,
                });

                // Спуск в подчинённую шину моста. secondary == 0 — шина
                // ещё не настроена BIOS'ом или мост выключен: спуск запрещён
                // (0 = сама корневая шина, иначе цикл).
                if secondary != 0 {
                    self.scan_bus(segment, secondary, visited, sink);
                }
            }
        }
    }

    /// Прочитать и декодировать всю функцию.
    fn probe_function(&self, segment: u16, bdf: Bdf, multifunction: bool) -> PciDeviceData {
        let a = &self.access;

        let vd = a.config_read32(segment, bdf, REG_VENDOR_DEVICE);
        let cs = a.config_read32(segment, bdf, REG_COMMAND_STATUS);
        let rc = a.config_read32(segment, bdf, REG_REVISION_CLASS);
        let ht = a.config_read8(segment, bdf, REG_HEADER_TYPE);
        let header_type = PciHeaderType::from_raw(ht);
        // Слово 0x04: младшие 16 бит — command, старшие — status.
        let command = cs as u16;
        let status = (cs >> 16) as u16;
        let irq = a.config_read32(segment, bdf, REG_IRQ);

        let mut data = PciDeviceData {
            vendor_id: vd as u16,
            device_id: (vd >> 16) as u16,
            revision: rc as u8,
            class: ((rc >> 24) as u8, (rc >> 16) as u8, (rc >> 8) as u8),
            header_type,
            multifunction,
            command,
            status,
            subsystem: None,
            bars: Vec::new(),
            rom: None,
            capabilities: Vec::new(),
            msi: None,
            msix: None,
            pcie: None,
            bridge: None,
            irq_pin: (irq >> 8) as u8,
            irq_line: irq as u8,
        };

        // Список capabilities (если бит 4 status).
        let has_caps = status & 0x10 != 0;
        let cap_base = REG_CAPABILITIES;
        if has_caps {
            self.walk_capabilities(segment, bdf, cap_base, &mut data);
        }

        match header_type {
            PciHeaderType::Standard => {
                let sub = a.config_read32(segment, bdf, REG_SUBSYSTEM);
                data.subsystem = Some((sub as u16, (sub >> 16) as u16));
                self.decode_bars(segment, bdf, REG_BAR0, 6, &mut data);
                data.rom = self
                    .bar_size32(segment, bdf, REG_ROM, !0x7FF)
                    .map(|(b, s)| (b, s));
            }
            PciHeaderType::Bridge => {
                self.decode_bars(segment, bdf, REG_BAR0, 2, &mut data);
                let buses = a.config_read32(segment, bdf, REG_BRIDGE_BUSES);
                let io_regs = a.config_read32(segment, bdf, REG_BRIDGE_IO);
                let mem_regs = a.config_read32(segment, bdf, REG_BRIDGE_MEM);
                let pre_regs = a.config_read32(segment, bdf, REG_BRIDGE_PREFETCH);
                // Prefetch base/limit upper — два отдельных 32-битных регистра.
                let pre_base_hi = a.config_read32(segment, bdf, REG_BRIDGE_PREFETCH_HI);
                let pre_limit_hi = a.config_read32(segment, bdf, REG_BRIDGE_PREFETCH_HI + 4);
                data.rom = self
                    .bar_size32(segment, bdf, REG_BRIDGE_ROM, !0x7FF)
                    .map(|(b, s)| (b, s));

                // Окна моста. Адресные поля регистров выровнены на гранулярность
                // (IO — 4 КиБ, память — 1 МиБ); младшие биты — атрибуты.
                // IO base/limit: 8-битные регистры (0x1C/0x1D), адрес — биты 15:12.
                let io_base_f = (io_regs & 0xF0) as u16;
                let io_limit_f = ((io_regs >> 8) & 0xF0) as u16;
                // Memory base/limit: 16-битные регистры (0x20/0x22), адрес — биты 31:20.
                let mem_base_f = (mem_regs & 0xFFF0) as u32;
                let mem_limit_f = ((mem_regs >> 16) & 0xFFF0) as u32;
                // Prefetchable: как memory, плюс старшие 32 бита.
                let pre_base_f = (pre_regs & 0xFFF0) as u32;
                let pre_limit_f = ((pre_regs >> 16) & 0xFFF0) as u32;

                data.bridge = Some(BridgeWindows {
                    io: (io_base_f != 0 || io_limit_f != 0)
                        .then_some((io_base_f, io_limit_f.wrapping_add(0x0FFF))),
                    memory: (mem_base_f != 0 || mem_limit_f != 0)
                        .then_some((mem_base_f << 16, (mem_limit_f << 16) | 0xF_FFFF)),
                    prefetchable: (pre_base_f != 0 || pre_limit_f != 0).then_some((
                        ((pre_base_f << 16) as u64) | ((pre_base_hi as u64) << 32),
                        (((pre_limit_f << 16) | 0xF_FFFF) as u64) | ((pre_limit_hi as u64) << 32),
                    )),
                    buses: (buses as u8, (buses >> 8) as u8, (buses >> 16) as u8),
                });
            }
            PciHeaderType::Other(_) => {
                // CardBus и экзотика: минимальные данные, без декодирования.
            }
        }
        data
    }

    /// Пройти список capabilities (PCI 2.2+), вытаскивая MSI/MSI-X.
    ///
    /// Ограничение глубины — 48 шагов (защита от битого связного списка).
    fn walk_capabilities(&self, segment: u16, bdf: Bdf, cap_ptr: u8, data: &mut PciDeviceData) {
        let a = &self.access;
        let mut ptr = a.config_read8(segment, bdf, cap_ptr) & 0xFC;
        for _ in 0..48 {
            if ptr == 0 {
                return;
            }
            let id = a.config_read8(segment, bdf, ptr);
            let next = a.config_read8(segment, bdf, ptr + 1) & 0xFC;
            data.capabilities.push((id, ptr));

            match id {
                capability_id::PCI_MSI => {
                    let ctrl = a.config_read16(segment, bdf, ptr + 2);
                    data.msi = Some(MsiInfo {
                        is_64bit: ctrl & 0x0080 != 0,
                        multiple_message_capable: ((ctrl >> 1) & 0x7) as u8,
                        per_vector_masking: ctrl & 0x0100 != 0,
                    });
                }
                capability_id::PCI_MSIX => {
                    let ctrl = a.config_read16(segment, bdf, ptr + 2);
                    let table = a.config_read32(segment, bdf, ptr + 4);
                    let pba = a.config_read32(segment, bdf, ptr + 8);
                    data.msix = Some(MsixInfo {
                        table_size: (ctrl & 0x07FF) + 1,
                        table_bir: (table & 0x7) as u8,
                        table_offset: table & !0x7,
                        pba_bir: (pba & 0x7) as u8,
                        pba_offset: pba & !0x7,
                    });
                }
                capability_id::PCI_PCIE => {
                    // Capabilities (ptr+2): версия bits 3:0, тип порта
                    // bits 7:4. Link caps (ptr+0x0C) / status (ptr+0x10,
                    // старшие 16 слова ctrl|status).
                    let caps = a.config_read16(segment, bdf, ptr + 2);
                    let link_caps = a.config_read32(segment, bdf, ptr + 0x0C);
                    let link_ctrl_status = a.config_read32(segment, bdf, ptr + 0x10);
                    let status = (link_ctrl_status >> 16) as u32;
                    data.pcie = Some(PciExpressInfo {
                        version: (caps & 0xF) as u8,
                        port_type: ((caps >> 4) & 0xF) as u8,
                        max_link_speed: (link_caps & 0xF) as u8,
                        max_link_width: ((link_caps >> 4) & 0x3F) as u8,
                        cur_link_speed: (status & 0xF) as u8,
                        cur_link_width: ((status >> 4) & 0x3F) as u8,
                    });
                }
                _ => {}
            }
            ptr = next;
        }
    }

    /// Декодировать `count` BAR, начиная со смещения `off` (0x10 / 0x18).
    ///
    /// 64-битный BAR занимает два слота: второй пропускается. Измерение
    /// размера — каноническим зондом «записали все единицы, прочитали
    /// маску, восстановили» (см. `bar_size32`/`bar_size64`): единственная
    /// запись в конфигурационное пространство за весь обход.
    fn decode_bars(&self, segment: u16, bdf: Bdf, off: u8, count: u8, data: &mut PciDeviceData) {
        let mut slot = 0u8;
        while slot < count {
            let bar_off = off + slot * 4;
            let (kind, base, size, prefetchable, slots) = self.decode_bar(segment, bdf, bar_off);
            if size > 0 {
                data.bars.push(PciBar {
                    kind,
                    base,
                    size,
                    prefetchable,
                });
            }
            slot += slots;
        }
    }

    /// Декодировать один BAR по смещению. Возвращает (вид, база, размер,
    /// prefetchable, сколько слотов занято: 1 или 2 для 64-битной памяти).
    fn decode_bar(&self, segment: u16, bdf: Bdf, off: u8) -> (PciBarKind, u64, u64, bool, u8) {
        let a = &self.access;
        let orig = a.config_read32(segment, bdf, off);
        if orig == 0 {
            return (PciBarKind::Mem32, 0, 0, false, 1);
        }

        if orig & 0x1 == 0 {
            // Память.
            let is_64 = (orig >> 1) & 0x3 == 0x2;
            let prefetchable = orig & 0x8 != 0;
            if is_64 {
                let (base, size) = self.bar_size64(segment, bdf, off);
                (PciBarKind::Mem64, base, size, prefetchable, 2)
            } else {
                match self.bar_size32(segment, bdf, off, !0xF) {
                    Some((base, size)) => (PciBarKind::Mem32, base, size, prefetchable, 1),
                    // Зонд вернул нуль — BAR не реализован.
                    None => (PciBarKind::Mem32, 0, 0, false, 1),
                }
            }
        } else {
            // Порты ввода-вывода.
            match self.bar_size32(segment, bdf, off, !0x3) {
                Some((base, size)) => (PciBarKind::Io, base, size, false, 1),
                None => (PciBarKind::Io, 0, 0, false, 1),
            }
        }
    }

    /// Измерить 32-битный регистр размера: зонд all-ones с восстановлением.
    ///
    /// `mask` — неинформационные младшие бита (0xF у памяти, 0x3 у IO,
    /// 0x7FF у ROM). Возвращает (база, размер). Размер считается в
    /// 32-БИТНОМ пространстве регистра: zero-расширение маски до u64
    /// дало бы гигантские размеры (старшие биты «не реализованы»).
    fn bar_size32(&self, segment: u16, bdf: Bdf, off: u8, mask: u32) -> Option<(u64, u64)> {
        let a = &self.access;
        let orig = a.config_read32(segment, bdf, off);
        if orig == 0 {
            return None;
        }
        a.config_write32(segment, bdf, off, u32::MAX);
        let probed = a.config_read32(segment, bdf, off);
        a.config_write32(segment, bdf, off, orig);
        let size_mask = probed & mask;
        if size_mask == 0 {
            return None; // не реализован (читается как нуль)
        }
        let size32 = (!size_mask).wrapping_add(1); // арифметика u32!
        Some((
            (orig & mask) as u64,
            if size32 == 0 {
                u32::MAX as u64 + 1
            } else {
                size32 as u64
            },
        ))
    }

    /// Измерение 64-битного BAR (пара слотов).
    fn bar_size64(&self, segment: u16, bdf: Bdf, off: u8) -> (u64, u64) {
        let a = &self.access;
        let orig_lo = a.config_read32(segment, bdf, off);
        let orig_hi = a.config_read32(segment, bdf, off + 4);

        a.config_write32(segment, bdf, off, u32::MAX);
        a.config_write32(segment, bdf, off + 4, u32::MAX);
        let probed_lo = a.config_read32(segment, bdf, off);
        let probed_hi = a.config_read32(segment, bdf, off + 4);
        a.config_write32(segment, bdf, off, orig_lo);
        a.config_write32(segment, bdf, off + 4, orig_hi);

        let probed = (probed_hi as u64) << 32 | (probed_lo & !0xF) as u64;
        let size = (!probed).wrapping_add(1);
        let base = (orig_hi as u64) << 32 | (orig_lo & !0xF) as u64;
        (base, size)
    }

    /// Ресурсы функции для реестра (BAR + ROM как MMIO/IO).
    fn resources_of(data: &PciDeviceData) -> Vec<DeviceResource> {
        let mut out = Vec::with_capacity(data.bars.len() + 1);
        for bar in &data.bars {
            if bar.size == 0 {
                continue;
            }
            match bar.kind {
                PciBarKind::Io => out.push(DeviceResource::IoPort {
                    base: bar.base as u16,
                    len: bar.size as u16,
                }),
                PciBarKind::Mem32 | PciBarKind::Mem64 => out.push(DeviceResource::Mmio {
                    base: PhysAddr(bar.base),
                    len: bar.size,
                }),
            }
        }
        if let Some((base, size)) = data.rom {
            out.push(DeviceResource::Mmio {
                base: PhysAddr(base),
                len: size,
            });
        }
        out
    }
}

impl<A: PciConfigAccess> BusEnumerator for PciBus<A> {
    fn bus_name(&self) -> &str {
        &self.name
    }

    fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError> {
        // Отмеченные шины — на сегмент: один и тот же номер шины в разных
        // сегментах независим.
        let mut visited_segments: Vec<(u16, Vec<bool>)> = Vec::new();
        for root in &self.roots {
            if !visited_segments.iter().any(|(seg, _)| *seg == root.segment) {
                visited_segments.push((root.segment, alloc::vec![false; MAX_BUS as usize]));
            }
            let idx = visited_segments
                .iter()
                .position(|(seg, _)| *seg == root.segment)
                .expect("только что вставили");
            // Две шины: неизменяемый обходчик и mut-коллектор посещённых шин.
            let (seg, visited) = &mut visited_segments[idx];
            self.scan_bus(*seg, root.bus, visited, sink);
        }
        Ok(())
    }
}

// ==== Тесты: программная модель конфигурационного пространства ====

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

    /// Мок конфигурационного пространства: 4 КиБ на функцию + модель
    /// регистров размера BAR (как в железе: запись -> чтение возвращает
    /// только реализованные АДРЕСНЫЕ биты, флаговые младшие биты читаются
    /// всегда). Пространство — за RefCell: контракт
    /// `PciConfigAccess::config_write32(&self, ..)` соответствует записи
    /// в MMIO-регистр (побочный эффект без &mut).
    struct MockPci {
        space: RefCell<BTreeMap<(u16, u16), [u32; 1024]>>,
        /// (bdf_bits, offset/4) -> (маска адресных бит, фиксированные флаги).
        masks: BTreeMap<(u16, usize), (u32, u32)>,
    }

    fn bdf_bits(bdf: Bdf) -> u16 {
        ((bdf.bus as u16) << 8) | ((bdf.device as u16) << 3) | bdf.function as u16
    }

    impl MockPci {
        fn new() -> Self {
            Self {
                space: RefCell::new(BTreeMap::new()),
                masks: BTreeMap::new(),
            }
        }

        /// Добавить функцию.
        fn add(&mut self, segment: u16, bdf: Bdf, vendor: u16, device: u16) {
            let mut space = self.space.borrow_mut();
            let entry = space.entry((segment, bdf_bits(bdf))).or_insert([0; 1024]);
            entry[0] = (vendor as u32) | ((device as u32) << 16);
        }

        /// Записать 32-битный регистр конфигурационного пространства.
        fn w(&mut self, segment: u16, bdf: Bdf, offset: u8, value: u32) {
            let mut space = self.space.borrow_mut();
            space.get_mut(&(segment, bdf_bits(bdf))).unwrap()[offset as usize / 4] = value;
        }

        /// Назначить BAR: база + размер + флаги (0x0/0x4/0x8/0xC у памяти,
        /// 0x1 у IO). Модель: чтение = (записанное & маска) | фиксированные
        /// флаги — как в реальном железе при зондировании all-ones.
        fn bar(&mut self, segment: u16, bdf: Bdf, slot: u8, base: u32, size: u32, flags: u32) {
            let bits = bdf_bits(bdf);
            let off = 0x10 + slot as usize * 4;
            self.w(segment, bdf, off as u8, base | flags);
            self.masks
                .insert((bits, off / 4), (!(size - 1), flags & 0xF));
        }
    }

    impl PciConfigAccess for MockPci {
        fn config_read32(&self, segment: u16, bdf: Bdf, offset: u8) -> u32 {
            let space = self.space.borrow();
            let Some(regs) = space.get(&(segment, bdf_bits(bdf))) else {
                return u32::MAX; // функции нет
            };
            let raw = regs[offset as usize / 4];
            match self.masks.get(&(bdf_bits(bdf), offset as usize / 4)) {
                // BAR: реализованные адресные биты + постоянные флаги.
                Some((mask, fixed)) => (raw & mask) | fixed,
                None => raw,
            }
        }

        fn config_read16(&self, segment: u16, bdf: Bdf, offset: u8) -> u16 {
            let word = self.config_read32(segment, bdf, offset & !0x3);
            ((word >> ((offset & 0x2) * 8)) & 0xFFFF) as u16
        }

        fn config_read8(&self, segment: u16, bdf: Bdf, offset: u8) -> u8 {
            let word = self.config_read32(segment, bdf, offset & !0x3);
            (word >> ((offset & 0x3) * 8)) as u8
        }

        fn config_write32(&self, segment: u16, bdf: Bdf, offset: u8, value: u32) {
            let mut space = self.space.borrow_mut();
            if let Some(regs) = space.get_mut(&(segment, bdf_bits(bdf))) {
                regs[offset as usize / 4] = value;
            }
        }
    }

    /// Собрать тестовую топологию:
    ///
    /// ```text
    /// seg0 bus0: dev0 host-bridge, dev1 root-port (secondary 1)
    /// seg0 bus1: dev0 NIC (MSI-X, BAR0 mmio + BAR1 io), dev2 audio x2 fn,
    ///            dev3 bridge (secondary 2)
    /// seg0 bus2: dev0 NVMe (64-битный prefetchable BAR0)
    /// seg1 bus0: dev0 отдельный сегмент (изоляция сегментов)
    /// ```
    fn make_topology() -> MockPci {
        let mut m = MockPci::new();

        // host bridge 0:0:0.0 (class 06:00:00)
        m.add(0, Bdf::new(0, 0, 0, 0), 0x8086, 0x1237);
        m.w(0, Bdf::new(0, 0, 0, 0), 0x08, 0x06 << 24);

        // root port 0:0:1.0 (type 1, class 06:04:00, secondary bus 1)
        m.add(0, Bdf::new(0, 0, 1, 0), 0x8086, 0x29C0);
        m.w(0, Bdf::new(0, 0, 1, 0), 0x08, (0x06 << 24) | (0x04 << 16));
        m.w(0, Bdf::new(0, 0, 1, 0), 0x0C, 0x01 << 16); // header type: мост
        m.w(0, Bdf::new(0, 0, 1, 0), 0x18, 0x01_01_00); // sub=1, sec=1, prim=0
        m.w(0, Bdf::new(0, 0, 1, 0), 0x20, 0xFFF0_F000); // mem window 0xF0000000..0xFFFFFFFF

        // NIC 0:1:0.0 (virtio, class 02:00:00, MSI-X cap на 0x40)
        let nic = Bdf::new(0, 1, 0, 0);
        m.add(0, nic, 0x1AF4, 0x1000);
        m.w(0, nic, 0x08, 0x02 << 24);
        m.w(0, nic, 0x04, 0x0010 << 16); // status: capabilities list
        m.w(0, nic, 0x34, 0x40); // cap ptr
        m.w(0, nic, 0x40, 0x0007_6011); // id=MSI-X, next=0x60, ctrl: 8 записей
        m.w(0, nic, 0x44, 0x0000_0001); // table: BAR1, offset 0
        m.w(0, nic, 0x48, 0x0000_2001); // pba: BAR1, offset 0x2000
        // PCIe capability на 0x60 (next=0): версия 2, endpoint, x4 @ 5GT/s.
        // Слово 0x60: id=0x10 (байт 0), next=0x00 (байт 1),
        // caps = 0x0002 (v2, endpoint) в старших 16 битах слова.
        m.w(0, nic, 0x60, 0x0002_0010);
        // Link caps (ptr+0x0C): скорость 2 (5GT/s), ширина 4 линии.
        m.w(0, nic, 0x6C, (2u32) | (4u32 << 4));
        // Link status (старшие 16 слова ptr+0x10): 5GT/s x4 согласовано.
        m.w(0, nic, 0x70, ((2u32) | (4u32 << 4)) << 16);
        m.bar(0, nic, 0, 0xF000_0000, 0x1000, 0x0); // mmio32 4K
        m.bar(0, nic, 1, 0x0000_C000, 0x20, 0x1); // io 32 байта

        // многофункциональное аудио 0:1:2.0 и .1
        m.add(0, Bdf::new(0, 1, 2, 0), 0x8086, 0x2668);
        m.w(0, Bdf::new(0, 1, 2, 0), 0x08, (0x04 << 24) | (0x01 << 16));
        m.w(0, Bdf::new(0, 1, 2, 0), 0x0C, 0x80 << 16); // multifunction
        m.add(0, Bdf::new(0, 1, 2, 1), 0x8086, 0x2669);
        m.w(0, Bdf::new(0, 1, 2, 1), 0x08, (0x04 << 24) | (0x03 << 16));

        // мост 0:1:3.0 (secondary 2)
        m.add(0, Bdf::new(0, 1, 3, 0), 0x8086, 0x2448);
        m.w(0, Bdf::new(0, 1, 3, 0), 0x08, (0x06 << 24) | (0x04 << 16));
        m.w(0, Bdf::new(0, 1, 3, 0), 0x0C, 0x01 << 16);
        m.w(0, Bdf::new(0, 1, 3, 0), 0x18, 0x02_02_01); // sub=2, sec=2, prim=1

        // NVMe 0:2:0.0 (64-битный prefetchable BAR0 16K)
        let nvme = Bdf::new(0, 2, 0, 0);
        m.add(0, nvme, 0x144D, 0xA808);
        m.w(0, nvme, 0x08, (0x01 << 24) | (0x08 << 16));
        m.bar(0, nvme, 0, 0xE000_0000, 0x4000, 0x4 | 0x8); // mem64, prefetch
        // Верхняя половина 64-битного BAR: все биты «реализованы» (нулевые).
        m.masks.insert((bdf_bits(nvme), 0x14 / 4), (!0u32, 0));

        // отдельный сегмент 1
        m.add(1, Bdf::new(1, 0, 0, 0), 0x10DE, 0x0A34);
        m.w(1, Bdf::new(1, 0, 0, 0), 0x08, 0x03 << 24);

        m
    }

    fn run_pci_scan(m: MockPci) -> Vec<DiscoveredDevice> {
        struct Collector(Vec<DiscoveredDevice>);
        impl DeviceSink for Collector {
            fn discovered(&mut self, dev: DiscoveredDevice) {
                self.0.push(dev);
            }
        }
        let bus = PciBus::new(
            "pcie.0",
            m,
            alloc::vec![
                PciRootBus { segment: 0, bus: 0 },
                PciRootBus { segment: 1, bus: 0 }
            ],
            Some(ItsId(0)),
        );
        let mut sink = Collector(Vec::new());
        bus.scan(&mut sink).unwrap();
        sink.0
    }

    fn sorted_paths(found: &[DiscoveredDevice]) -> Vec<String> {
        let mut paths: Vec<String> = found.iter().map(|d| alloc::format!("{}", d.path)).collect();
        paths.sort();
        paths
    }

    #[test]
    fn scan_finds_full_topology() {
        let found = run_pci_scan(make_topology());
        assert_eq!(
            sorted_paths(&found),
            vec![
                "pci:0000:00:00.0", // host bridge
                "pci:0000:00:01.0", // root port
                "pci:0000:01:00.0", // NIC
                "pci:0000:01:02.0", // audio fn0
                "pci:0000:01:02.1", // audio fn1
                "pci:0000:01:03.0", // bridge
                "pci:0000:02:00.0", // nvme за мостом
                "pci:0001:00:00.0", // сегмент 1
            ]
        );
    }

    #[test]
    fn nic_bars_and_msix_decoded() {
        let found = run_pci_scan(make_topology());
        let nic = found
            .iter()
            .find(|d| d.path == crate::hal::types::DevicePath::Pci(Bdf::new(0, 1, 0, 0)))
            .unwrap();
        let BusDeviceData::Pci(data) = &nic.data else {
            panic!("NIC обязан нести Pci-данные");
        };

        // BAR0: mmio32 4K @ 0xF000_0000; BAR1: io 32 байта @ 0xC000.
        assert_eq!(data.bars.len(), 2);
        assert_eq!(
            data.bars[0],
            PciBar {
                kind: PciBarKind::Mem32,
                base: 0xF000_0000,
                size: 0x1000,
                prefetchable: false,
            }
        );
        assert_eq!(data.bars[1].kind, PciBarKind::Io);
        assert_eq!(data.bars[1].base, 0xC000);
        assert_eq!(data.bars[1].size, 0x20);

        // MSI-X: 8 записей (контрол 7), таблица и PBA на BAR1.
        let msix = data.msix.expect("MSI-X обязан быть найден");
        assert_eq!(msix.table_size, 8);
        assert_eq!(msix.table_bir, 1);
        assert_eq!(msix.table_offset, 0);
        assert_eq!(msix.pba_bir, 1);
        assert_eq!(msix.pba_offset, 0x2000);

        // PCIe capability (0x10) на 0x60: v2 endpoint, звено 5GT/s x4
        // (согласовано и максимум).
        let pcie = data.pcie.expect("PCIe capability обязана быть найдена");
        assert_eq!(pcie.version, 2);
        assert_eq!(pcie.port_type, 0); // endpoint
        assert_eq!(pcie.max_link_speed, 2);
        assert_eq!(pcie.max_link_width, 4);
        assert_eq!(pcie.cur_link_speed, 2);
        assert_eq!(pcie.cur_link_width, 4);
        // Оба capability пройдены списком: MSI-X и PCIe.
        assert_eq!(data.capabilities.len(), 2);

        // Ресурсы реестра: mmio + io.
        assert_eq!(nic.resources.len(), 2);
        assert!(nic.resources.iter().any(|r| matches!(
            r,
            DeviceResource::Mmio { base, len }
                if base.as_u64() == 0xF000_0000 && *len == 0x1000
        )));

        // MSI-источник заполнен: its=0, rid = bus<<8|dev<<3|fn = 0x100.
        assert_eq!(nic.info.msi.map(|s| s.device_id()), Some(0x100));
        assert_eq!(nic.info.msi.map(|s| s.its().0), Some(0));
    }

    #[test]
    fn bridge_recursion_and_windows() {
        let found = run_pci_scan(make_topology());
        let rp = found
            .iter()
            .find(|d| d.path == crate::hal::types::DevicePath::Pci(Bdf::new(0, 0, 1, 0)))
            .unwrap();
        let BusDeviceData::Pci(data) = &rp.data else {
            panic!()
        };
        let bridge = data.bridge.expect("root port — мост");
        assert_eq!(bridge.buses, (0, 1, 1));
        assert_eq!(bridge.memory, Some((0xF000_0000, 0xFFFF_FFFF)));
        assert_eq!(bridge.io, None); // окно IO не сконфигурировано
        assert_eq!(bridge.prefetchable, None);

        // NVMe за вложенным мостом: 64-битный prefetchable BAR 16K.
        let nvme = found
            .iter()
            .find(|d| d.path == crate::hal::types::DevicePath::Pci(Bdf::new(0, 2, 0, 0)))
            .unwrap();
        let BusDeviceData::Pci(data) = &nvme.data else {
            panic!()
        };
        assert_eq!(data.bars.len(), 1);
        assert_eq!(data.bars[0].kind, PciBarKind::Mem64);
        assert_eq!(data.bars[0].base, 0xE000_0000);
        assert_eq!(data.bars[0].size, 0x4000);
        assert!(data.bars[0].prefetchable);
        assert!(data.capabilities.is_empty()); // status без бита caps
    }

    #[test]
    fn scan_is_idempotent() {
        // Контракт rescan: два прохода дают одно и то же множество путей.
        let first = run_pci_scan(make_topology());
        let second = run_pci_scan(make_topology());
        assert_eq!(sorted_paths(&first), sorted_paths(&second));
    }

    #[test]
    fn bar_probe_restores_original_value() {
        // Зондирование размера (all-ones) обязано восстанавливать исходное
        // значение BAR: после scan конфигурация не разрушена.
        let mut m = MockPci::new();
        let dev = Bdf::new(0, 0, 7, 0);
        m.add(0, dev, 0x1234, 0x5678);
        m.bar(0, dev, 0, 0xABCD_0000, 0x2000, 0x0);

        let bus = PciBus::new("t", m, alloc::vec![PciRootBus { segment: 0, bus: 0 }], None);
        struct Collector(Vec<DiscoveredDevice>);
        impl DeviceSink for Collector {
            fn discovered(&mut self, dev: DiscoveredDevice) {
                self.0.push(dev);
            }
        }
        let mut sink = Collector(Vec::new());
        bus.scan(&mut sink).unwrap();

        // BAR восстановлен, размер измерен верно.
        assert_eq!(bus.access().config_read32(0, dev, 0x10), 0xABCD_0000);
        assert_eq!(sink.0.len(), 1);
        let BusDeviceData::Pci(data) = &sink.0[0].data else {
            panic!()
        };
        assert_eq!(data.bars.len(), 1);
        assert_eq!(data.bars[0].size, 0x2000);
        assert_eq!(data.bars[0].base, 0xABCD_0000);
    }
}
