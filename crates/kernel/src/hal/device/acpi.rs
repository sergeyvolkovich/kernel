// ==== ACPI-обходчик встроенных устройств (сменяемый бекенд шины) ====
//
// Перечисление platform-устройств по ACPI: обход AML-namespace (DSDT/SSDT,
// загруженные `acpi::aml::Interpreter`), чтение идентичности (_HID/_CID),
// статуса (_STA), адресов (_ADR, для узлов PCI-мостов) и ресурсов (_CRS),
// плюс обогащение HPET данными одноимённой таблицы.
//
// Инкапсуляция: для `DeviceManager` это просто `dyn BusEnumerator` с именем
// "acpi". Весь acpi-специфичный код живёт здесь; добавление DTB-обходчика
// (план платформы) — новый модуль с реализацией того же трейта, менеджер и
// capability-слой не меняются.
//
// Микроядерность: обходчик ВЫПОЛНЯЕТ только методы чтения идентичности
// (_HID/_CID/_UID/_ADR/_STA/_CRS) — без этого перечисление ACPI невозможно
// (идентичность часто вычисляется методами). Никакого программирования:
// _INI/_REG/_SRS не вызываются, op-region хендлеры не регистрируются,
// контроллеры не настраиваются. Ядро отдаёт юзерспейсу СНИМОК устройства
// (путь + ресурсы + идентичность) и capability на него; всё остальное —
// ACPI-менеджер и драйверы в userspace.
//
// AML-интерпретатор — тяжеловат для микроядра, но это цена «честного»
// перечисления ACPI; альтернатива (парсинг только статических объектов)
// не видит устройств с динамическими _HID/_CRS. Крейт `acpi` изолирован
// в этом модуле и не протекает в контракты (`BusEnumerator`,
// `DiscoveredDevice`): при желании его можно заменить на юзерспейс-AML
// сервис, оставив только RSDP→таблицы глюю платформы.

use alloc::{string::String, vec::Vec};

use acpi::aml::Interpreter;
use acpi::aml::namespace::{AmlName, NamespaceLevelKind};
use acpi::aml::object::Object;
use acpi::aml::resource as amlres;
use acpi::aml::resource::resource_descriptor_list;
use acpi::platform::AcpiPlatform;

use crate::hal::device::traits::{
    BusDeviceData, BusEnumerator, BusError, DeviceResource, DeviceSink, DiscoveredDevice,
};
use crate::hal::traits::irq::TriggerMode;
use crate::hal::types::{AcpiPath, DeviceInfo, DeviceKind, PhysAddr, PlatformId};

// ==== Известные PNP ID (для сопоставления юзерспейс-драйверами) ====

/// High Precision Event Timer.
pub const HID_HPET: &str = "PNP0103";
/// PCI root bridge (конвенция ACPI 1.0, встречается до сих пор).
pub const HID_PCI_ROOT: &str = "PNP0A03";
/// PCI Express root bridge.
pub const HID_PCIE_ROOT: &str = "PNP0A08";
/// Embedded Controller.
pub const HID_EMBEDDED_CONTROLLER: &str = "PNP0C09";
/// 16550-совместимый UART.
pub const HID_UART_16550: &str = "PNP0501";
/// Клавиатура i8042.
pub const HID_KEYBOARD_8042: &str = "PNP0303";
/// Мышь PS/2.
pub const HID_MOUSE_PS2: &str = "PNP0F13";

// ==== Данные ====

/// ACPI-специфичные данные устройства.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpiDeviceData {
    /// `_HID`: строка (EisaId расжат в "PNPxxxx") или числовой PNP ID.
    pub hid: Option<String>,
    /// `_CID`: совместимые ID (пакет или скаляр).
    pub cids: Vec<String>,
    /// `_UID` (числовой; строковые UID не поддерживаются — их использует
    /// малая часть прошивок, см. план юзерспейс-ACPI-менеджера).
    pub uid: Option<u64>,
    /// `_ADR`: адрес на шине родителя. Для узлов PCI —
    /// `(device << 16) | function` (см. [`decode_pci_adr`]).
    pub adr: Option<u64>,
    /// `_STA` (сырое значение; `None` — метода нет, по спеке 0x0F).
    pub sta: Option<u32>,
    /// Данные таблицы HPET (только для устройства с [`HID_HPET`]).
    pub hpet: Option<HpetData>,
}

impl AcpiDeviceData {
    /// Устройство функционально (`_STA` бит 3; отсутствие `_STA`
    /// трактуется как 0x0F — присутствует и работает).
    pub fn functional(&self) -> bool {
        self.sta.map(|s| s & 0x08 != 0).unwrap_or(true)
    }
}

/// Данные таблицы HPET (снимок; программирование — юзерспейс).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpetData {
    pub hpet_number: u8,
    pub hardware_rev: u8,
    /// Число таймеров-компараторов (без основного счётчика).
    pub num_comparators: u8,
    pub main_counter_is_64bits: bool,
    /// Режим Legacy PIC Replacement доступен.
    pub legacy_irq_capable: bool,
    pub pci_vendor_id: u16,
    /// Минимальные тики без потери прерываний (период в фемтосекундах
    /// делённый на 2^15 — поле Clock Tick из таблицы).
    pub clock_tick_unit: u16,
    /// Базовый адрес регистра HPET (дублируется в resources).
    pub base_address: u64,
    pub page_protection: HpetPageProtection,
}

/// Гарантия защиты страниц за пределами базового адреса HPET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpetPageProtection {
    None,
    Protected4K,
    Protected64K,
    Other,
}

impl HpetData {
    /// Сериализуемое представление защиты страниц (0..=3 — как в таблице).
    pub fn page_protection_word(&self) -> u64 {
        match self.page_protection {
            HpetPageProtection::None => 0,
            HpetPageProtection::Protected4K => 1,
            HpetPageProtection::Protected64K => 2,
            HpetPageProtection::Other => 3,
        }
    }
}

// ==== Чистые преобразования (тест без ACPI-таблиц) ====

/// Расжать числовой EisaId (`_HID`/`_CID` как Integer) в строку "PNPxxxx".
///
/// Кодирование ACPI: 3 старшие буквы по 5 бит (A=1..Z=26), 4 младшие
/// шестнадцатеричные цифры по 4 бита.
pub fn eisa_id_to_string(raw: u64) -> Option<String> {
    // then_some вычисляет значение EAGERLY — b-1 при b==0 дал бы underflow,
    // поэтому явный if (b ∈ 1..=26 — валидные коды букв A..Z).
    let letter = |bits: u64| -> Option<char> {
        let b = bits as u8;
        if (1..=26).contains(&b) {
            Some((b - 1 + b'A') as char)
        } else {
            None
        }
    };
    let digits = raw & 0xFFFF;
    Some(alloc::format!(
        "{}{}{}{:04X}",
        letter((raw >> 26) & 0x1F)?,
        letter((raw >> 21) & 0x1F)?,
        letter((raw >> 16) & 0x1F)?,
        digits
    ))
}

/// Декодировать `_ADR` PCI-узла: `(device, function)`.
///
/// Конвенция ACPI для шины PCI: `_ADR = (Device << 16) | Function`; номер
/// ШИНЫ не входит в `_ADR` — он определяется скоупом узла (корневой мост
/// или вышестоящий PCI-мост). Юзерспейс-драйвер шины сопоставляет пару
/// `(device, function)` с BDF, зная шину родителя.
pub fn decode_pci_adr(adr: u64) -> (u16, u8) {
    (((adr >> 16) & 0xFFFF) as u16, (adr & 0xFF) as u8)
}

/// Перевести дескриптор `_CRS` (крейт `acpi`) в ресурс реестра.
///
/// Не-адресуемое (DMA, шины) отбрасывается: юзерспейс перечитает _CRS
/// через ACPI-менеджер, если ему нужны экзотические дескрипторы.
pub fn map_acpi_resource(r: amlres::Resource) -> Option<DeviceResource> {
    match r {
        amlres::Resource::AddressSpace(d) => match d.resource_type {
            amlres::AddressSpaceResourceType::MemoryRange => Some(DeviceResource::Mmio {
                base: PhysAddr(d.address_range.0),
                len: d.length,
            }),
            amlres::AddressSpaceResourceType::IORange => Some(DeviceResource::IoPort {
                base: d.address_range.0 as u16,
                len: d.length as u16,
            }),
            amlres::AddressSpaceResourceType::BusNumberRange => None,
        },
        amlres::Resource::MemoryRange(amlres::MemoryRangeDescriptor::FixedLocation {
            is_writable: _,
            base_address,
            range_length,
        }) => Some(DeviceResource::Mmio {
            base: PhysAddr(base_address as u64),
            len: range_length as u64,
        }),
        amlres::Resource::IOPort(d) => Some(DeviceResource::IoPort {
            base: d.memory_range.0,
            len: d.range_length as u16,
        }),
        amlres::Resource::Irq(d) => Some(DeviceResource::Irq {
            gsi: d.irq,
            trigger: match d.trigger {
                amlres::InterruptTrigger::Edge => TriggerMode::Edge,
                amlres::InterruptTrigger::Level => TriggerMode::Level,
            },
            active_low: matches!(d.polarity, amlres::InterruptPolarity::ActiveLow),
        }),
        amlres::Resource::Dma(_) => None,
    }
}

// ==== Обходчик ====

/// ACPI-обходчик: `BusEnumerator` поверх `AcpiPlatform` + `Interpreter`.
///
/// Платформа (kernel glue) добывает RSDP и строит `AcpiTables` через свой
/// `acpi::Handler`, поднимает `AcpiPlatform` и передаёт его сюда; всё
/// остальное (DSDT/SSDT, namespace, _STA/_CRS) делает обходчик.
pub struct AcpiBus<H: acpi::Handler> {
    name: String,
    platform: AcpiPlatform<H>,
    interpreter: Interpreter<H>,
}

impl<H: acpi::Handler> AcpiBus<H> {
    /// Собрать обходчик: загружает DSDT/SSDT в namespace интерпретатора.
    ///
    /// Отказ ([`BusError::NotInitialized`]) — битые AML-таблицы; ядро
    /// может продолжить без ACPI-шины (регистрируют её опционально).
    pub fn new(name: impl Into<String>, platform: AcpiPlatform<H>) -> Result<Self, BusError> {
        let interpreter =
            Interpreter::new_from_platform(&platform).map_err(|_| BusError::NotInitialized)?;
        Ok(Self {
            name: name.into(),
            platform,
            interpreter,
        })
    }

    /// Платформенные данные (interrupt model, pm timer) для kernel glue.
    pub fn platform(&self) -> &AcpiPlatform<H> {
        &self.platform
    }

    /// AML-интерпретатор (юзерспейс-ACPI-менеджер будет обращаться к нему
    /// через IPC-хендлеры — план платформы).
    pub fn interpreter(&self) -> &Interpreter<H> {
        &self.interpreter
    }

    /// Собрать AML-пути всех устройств namespace (без выполнения методов:
    /// traverse читает только структуру дерева).
    fn collect_device_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();
        let mut ns = self.interpreter.namespace.lock();
        // Ошибки обхода отдельных веток не прерывают перечисление.
        let _ = ns.traverse(|name, level| {
            if level.kind == NamespaceLevelKind::Device {
                paths.push(name.as_string());
            }
            Ok(true) // всегда спускаемся: устройства бывают вложены в scopes
        });
        paths
    }

    /// AML-имя метода на устройстве: "\_SB.DEV0._HID".
    fn aml_name(path: &str, method: &str) -> Option<AmlName> {
        alloc::format!("{path}.{method}").parse::<AmlName>().ok()
    }

    /// Вычислить объект (метод или константу) на устройстве.
    fn eval(&self, path: &str, method: &str) -> Option<acpi::aml::object::WrappedObject> {
        let name = Self::aml_name(path, method)?;
        self.interpreter
            .evaluate_if_present(name, Vec::new())
            .ok()
            .flatten()
    }

    fn eval_integer(&self, path: &str, method: &str) -> Option<u64> {
        match &*self.eval(path, method)? {
            Object::Integer(v) => Some(*v),
            _ => None,
        }
    }

    fn eval_hid(&self, path: &str) -> Option<String> {
        match &*self.eval(path, "_HID")? {
            Object::String(s) => Some(s.clone()),
            Object::Integer(eisa) => eisa_id_to_string(*eisa),
            _ => None,
        }
    }

    fn eval_cids(&self, path: &str) -> Vec<String> {
        let Some(obj) = self.eval(path, "_CID") else {
            return Vec::new();
        };
        let as_id = |o: &acpi::aml::object::WrappedObject| match &**o {
            Object::String(s) => Some(s.clone()),
            Object::Integer(eisa) => eisa_id_to_string(*eisa),
            _ => None,
        };
        match &*obj {
            Object::Package(items) => items.iter().filter_map(as_id).collect(),
            Object::String(s) => alloc::vec![s.clone()],
            Object::Integer(eisa) => eisa_id_to_string(*eisa).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    fn eval_resources(&self, path: &str) -> Vec<DeviceResource> {
        let Some(obj) = self.eval(path, "_CRS") else {
            return Vec::new();
        };
        match resource_descriptor_list(obj) {
            Ok(list) => list.into_iter().filter_map(map_acpi_resource).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Снять устройство по пути. `None` — узел без идентичности
    /// (нет ни _HID, ни _CID: контейнеры, мосты PCI — их покрывает
    /// PCI-обходчик по BDF).
    fn probe(&self, path: &str) -> Option<(AcpiDeviceData, Vec<DeviceResource>)> {
        let hid = self.eval_hid(path);
        let cids = self.eval_cids(path);
        if hid.is_none() && cids.is_empty() {
            return None;
        }
        let data = AcpiDeviceData {
            hid,
            cids,
            uid: self.eval_integer(path, "_UID"),
            adr: self.eval_integer(path, "_ADR"),
            sta: self.eval_integer(path, "_STA").map(|s| s as u32),
            hpet: None,
        };
        Some((data, self.eval_resources(path)))
    }

    /// Снять таблицу HPET в данные устройства (None — таблицы нет).
    fn hpet_from_table(&self) -> Option<HpetData> {
        let info = acpi::HpetInfo::new(&self.platform.tables).ok()?;
        Some(HpetData {
            hpet_number: info.hpet_number,
            hardware_rev: info.hardware_rev,
            num_comparators: info.num_comparators,
            main_counter_is_64bits: info.main_counter_is_64bits,
            legacy_irq_capable: info.legacy_irq_capable,
            pci_vendor_id: info.pci_vendor_id,
            clock_tick_unit: info.clock_tick_unit,
            base_address: info.base_address as u64,
            page_protection: match info.page_protection {
                acpi::sdt::hpet::PageProtection::None => HpetPageProtection::None,
                acpi::sdt::hpet::PageProtection::Protected4K => HpetPageProtection::Protected4K,
                acpi::sdt::hpet::PageProtection::Protected64K => HpetPageProtection::Protected64K,
                acpi::sdt::hpet::PageProtection::Other => HpetPageProtection::Other,
            },
        })
    }

    fn platform_info(data: &AcpiDeviceData) -> DeviceInfo {
        DeviceInfo::new(DeviceKind::Platform(PlatformId {
            acpi_uid: data.uid.map(|u| u as u32),
            dt_path: None,
        }))
    }
}

impl<H: acpi::Handler> BusEnumerator for AcpiBus<H> {
    fn bus_name(&self) -> &str {
        &self.name
    }

    fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError> {
        // 1. Namespace: собрать пути, снять свойства каждого устройства.
        let paths = self.collect_device_paths();
        let mut hpet_reported = false;
        for path in paths {
            let Some((mut data, resources)) = self.probe(&path) else {
                continue;
            };

            // HPET-узел namespace: обогатить данными таблицы HPET.
            if data.hid.as_deref() == Some(HID_HPET) {
                data.hpet = self.hpet_from_table();
                hpet_reported = data.hpet.is_some() || hpet_reported;
            }

            let functional = data.functional();
            sink.discovered(DiscoveredDevice {
                path: crate::hal::types::DevicePath::Acpi(AcpiPath::new(&path)),
                info: Self::platform_info(&data),
                resources,
                data: BusDeviceData::Acpi(data),
                functional,
            });
        }

        // 2. HPET есть в таблицах, но не в namespace (прошивки так умеют):
        //    синтезируем запись со стабильным путём "\HPET".
        if !hpet_reported {
            if let Some(hpet) = self.hpet_from_table() {
                let data = AcpiDeviceData {
                    hid: Some(String::from(HID_HPET)),
                    cids: Vec::new(),
                    uid: Some(hpet.hpet_number as u64),
                    adr: None,
                    sta: Some(0x0F),
                    hpet: Some(hpet),
                };
                let resources = alloc::vec![DeviceResource::Mmio {
                    base: PhysAddr(hpet.base_address),
                    len: 1024, // стандартный размер блока регистров HPET
                }];
                sink.discovered(DiscoveredDevice {
                    path: crate::hal::types::DevicePath::Acpi(AcpiPath::new("\\HPET")),
                    info: Self::platform_info(&data),
                    resources,
                    data: BusDeviceData::Acpi(data),
                    functional: true,
                });
            }
        }
        Ok(())
    }
}

// ==== Тесты ====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eisa_id_decode() {
        // EisaId("PNP0103") == 0x41D00103 (кодирование из спеки ACPI:
        // 3 буквы по 5 бит + 4 шестнадцатеричные цифры).
        assert_eq!(eisa_id_to_string(0x41D0_0103).as_deref(), Some("PNP0103"));
        assert_eq!(eisa_id_to_string(0x41D0_0501).as_deref(), Some("PNP0501"));
        // Буква с нулевым кодом — невалидный ID.
        assert_eq!(eisa_id_to_string(0x0000_0103), None);
        // Бит 31 — вне полей букв, игнорируется декодером.
        assert_eq!(
            eisa_id_to_string(0x41D0_0103 | (1 << 31)).as_deref(),
            Some("PNP0103")
        );
    }

    #[test]
    fn pci_adr_decode() {
        // _ADR = (Device << 16) | Function.
        assert_eq!(decode_pci_adr(0x0008_0000), (8, 0));
        assert_eq!(decode_pci_adr(0x001F_0002), (0x1F, 2));
    }

    #[test]
    fn resource_mapping() {
        // Fixed memory (Memory32Fixed) -> MMIO.
        let r = map_acpi_resource(amlres::Resource::MemoryRange(
            amlres::MemoryRangeDescriptor::FixedLocation {
                is_writable: true,
                base_address: 0xFED0_0000,
                range_length: 0x400,
            },
        ));
        assert!(matches!(
            r,
            Some(DeviceResource::Mmio { base, len })
                if base.as_u64() == 0xFED0_0000 && len == 0x400
        ));

        // Address space IO -> порты.
        let r = map_acpi_resource(amlres::Resource::AddressSpace(
            amlres::AddressSpaceDescriptor {
                resource_type: amlres::AddressSpaceResourceType::IORange,
                is_maximum_address_fixed: true,
                is_minimum_address_fixed: true,
                decode_type: amlres::AddressSpaceDecodeType::Additive,
                granularity: 0,
                address_range: (0x60, 0x64),
                translation_offset: 0,
                length: 5,
            },
        ));
        assert_eq!(r, Some(DeviceResource::IoPort { base: 0x60, len: 5 }));

        // IRQ с polarity/trigger.
        let r = map_acpi_resource(amlres::Resource::Irq(amlres::IrqDescriptor {
            is_consumer: true,
            trigger: amlres::InterruptTrigger::Edge,
            polarity: amlres::InterruptPolarity::ActiveHigh,
            is_shared: false,
            is_wake_capable: false,
            irq: 9,
        }));
        assert!(matches!(
            r,
            Some(DeviceResource::Irq {
                gsi: 9,
                trigger: TriggerMode::Edge,
                active_low: false
            })
        ));

        // Шинные номера и DMA в реестр не попадают.
        assert_eq!(
            map_acpi_resource(amlres::Resource::AddressSpace(
                amlres::AddressSpaceDescriptor {
                    resource_type: amlres::AddressSpaceResourceType::BusNumberRange,
                    is_maximum_address_fixed: false,
                    is_minimum_address_fixed: false,
                    decode_type: amlres::AddressSpaceDecodeType::Additive,
                    granularity: 0,
                    address_range: (0, 0xFF),
                    translation_offset: 0,
                    length: 0x100,
                }
            )),
            None
        );
    }

    #[test]
    fn sta_functional_semantics() {
        let mk = |sta: Option<u32>| AcpiDeviceData {
            hid: Some(String::from("PNP0103")),
            cids: Vec::new(),
            uid: None,
            adr: None,
            sta,
            hpet: None,
        };
        // Нет _STA — считается функциональным (спека: 0x0F).
        assert!(mk(None).functional());
        // Бит 3: функционален.
        assert!(mk(Some(0x0F)).functional());
        assert!(mk(Some(0x08)).functional());
        // Не функционален (присутствует, но сломан/выключен).
        assert!(!mk(Some(0x01)).functional());
        assert!(!mk(Some(0x00)).functional());
    }
}

// ==== Интеграционный тест: рукотворные ACPI-таблицы ====
//
// Полный путь `AcpiBus::scan` на настоящем AML: RSDP -> XSDT -> (FADT,
// MADT, HPET) + DSDT с двумя устройствами:
//   * \_SB.HPET — _HID EisaId("PNP0103") + _CRS Memory32Fixed + таблица HPET
//     (проверка обогащения узла namespace данными таблицы);
//   * \_SB.UART — _HID строкой + _CID числовым EisaId + _CRS IOPort
//     (проверка обоих представлений идентичности).
#[cfg(test)]
mod tables_tests {
    use super::*;
    use acpi::{AcpiTables, Handler, PhysicalMapping, sdt::SdtHeader};
    use alloc::boxed::Box;
    use core::ptr::NonNull;

    /// Фейковая физическая память: единственный статичный буфер, таблицы
    /// раскладываются по фиксированным адресам. Handler Clone — указатель.
    #[derive(Clone)]
    struct FakeHandler {
        base: *const u8,
        len: usize,
    }

    // SAFETY: буфер живёт вечно (Box::leak), указатель валиден всё время.
    unsafe impl Send for FakeHandler {}
    unsafe impl Sync for FakeHandler {}

    const OFF_RSDP: usize = 0x1000;
    const OFF_XSDT: usize = 0x2000;
    const OFF_FADT: usize = 0x3000;
    const OFF_MADT: usize = 0x4000;
    const OFF_HPET: usize = 0x5000;
    const OFF_DSDT: usize = 0x6000;

    impl acpi::Handler for FakeHandler {
        unsafe fn map_physical_region<T>(
            &self,
            physical_address: usize,
            size: usize,
        ) -> PhysicalMapping<Self, T> {
            assert!(
                physical_address + size <= self.len,
                "выход за фейковую память"
            );
            // SAFETY: адрес внутри вечного буфера; T выровнен по построению
            // (таблицы кладутся по выровненным смещениям).
            let ptr = unsafe { self.base.add(physical_address) as *mut T };
            PhysicalMapping {
                physical_start: physical_address,
                virtual_start: NonNull::new_unchecked(ptr),
                region_length: size,
                mapped_length: size,
                handler: self.clone(),
            }
        }

        fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {}

        fn read_u8(&self, _address: usize) -> u8 {
            0
        }
        fn read_u16(&self, _address: usize) -> u16 {
            0
        }
        fn read_u32(&self, _address: usize) -> u32 {
            0
        }
        fn read_u64(&self, _address: usize) -> u64 {
            0
        }
        fn write_u8(&self, _address: usize, _value: u8) {}
        fn write_u16(&self, _address: usize, _value: u16) {}
        fn write_u32(&self, _address: usize, _value: u32) {}
        fn write_u64(&self, _address: usize, _value: u64) {}

        fn read_io_u8(&self, _port: u16) -> u8 {
            0
        }
        fn read_io_u16(&self, _port: u16) -> u16 {
            0
        }
        fn read_io_u32(&self, _port: u16) -> u32 {
            0
        }
        fn write_io_u8(&self, _port: u16, _value: u8) {}
        fn write_io_u16(&self, _port: u16, _value: u16) {}
        fn write_io_u32(&self, _port: u16, _value: u32) {}

        fn read_pci_u8(&self, _address: acpi::PciAddress, _offset: u16) -> u8 {
            0
        }
        fn read_pci_u16(&self, _address: acpi::PciAddress, _offset: u16) -> u16 {
            0
        }
        fn read_pci_u32(&self, _address: acpi::PciAddress, _offset: u16) -> u32 {
            0
        }
        fn write_pci_u8(&self, _address: acpi::PciAddress, _offset: u16, _value: u8) {}
        fn write_pci_u16(&self, _address: acpi::PciAddress, _offset: u16, _value: u16) {}
        fn write_pci_u32(&self, _address: acpi::PciAddress, _offset: u16, _value: u32) {}

        fn nanos_since_boot(&self) -> u64 {
            0
        }

        fn stall(&self, _microseconds: u64) {}
        fn sleep(&self, _milliseconds: u64) {}
        fn create_mutex(&self) -> acpi::Handle {
            acpi::Handle(0)
        }
        fn acquire(&self, _mutex: acpi::Handle, _timeout: u16) -> Result<(), acpi::aml::AmlError> {
            Ok(())
        }
        fn release(&self, _mutex: acpi::Handle) {}
    }

    // ---- Сборка таблиц ----

    /// Заголовок SDT (36 байт): длина и чексумма дополняются в `finish`.
    fn sdt_header(out: &mut Vec<u8>, sig: &[u8; 4], revision: u8) {
        out.extend_from_slice(sig);
        out.extend_from_slice(&[0; 4]); // length (placeholder)
        out.push(revision);
        out.push(0); // checksum (placeholder)
        out.extend_from_slice(b"TSTTST"); // OEM id
        out.extend_from_slice(b"TSTTABLE"); // OEM table id
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(b"TSTT"); // creator id
        out.extend_from_slice(&1u32.to_le_bytes());
    }

    fn finish_sdt(out: &mut Vec<u8>) -> Vec<u8> {
        let len = out.len() as u32;
        out[4..8].copy_from_slice(&len.to_le_bytes());
        let sum = out.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        out[9] = sum.wrapping_neg();
        core::mem::take(out)
    }

    fn push_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// XSDT с указателями на FADT/MADT/HPET.
    fn build_xsdt() -> Vec<u8> {
        let mut t = Vec::new();
        sdt_header(&mut t, b"XSDT", 1);
        for off in [OFF_FADT, OFF_MADT, OFF_HPET] {
            push_u64(&mut t, off as u64);
        }
        finish_sdt(&mut t)
    }

    /// FADT (rev 3): только DSDT-адреса, PM-блоки нулевые.
    fn build_fadt() -> Vec<u8> {
        let mut t = Vec::new();
        sdt_header(&mut t, b"FACP", 3);
        t.resize(36 + 128, 0);
        // firmware_ctrl (36) = 0; dsdt_address (40):
        t[40..44].copy_from_slice(&(OFF_DSDT as u32).to_le_bytes());
        // x_dsdt (140):
        t.resize(148, 0);
        t[140..148].copy_from_slice(&(OFF_DSDT as u64).to_le_bytes());
        t.resize(268, 0);
        finish_sdt(&mut t)
    }

    /// MADT: один включённый LocalApic.
    ///
    /// Разметка крейта: header(36) + local_apic_address u32 + flags u32,
    /// записи — с offset 44 (иначе итератор читает нулевую длину и зацикливается).
    fn build_madt() -> Vec<u8> {
        let mut t = Vec::new();
        sdt_header(&mut t, b"APIC", 3);
        push_u32(&mut t, 0); // local apic address (u32!)
        push_u32(&mut t, 0); // flags
        t.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]); // LocalApic: proc=0, apic=0
        push_u32(&mut t, 1); // enabled
        assert_eq!(t.len(), 36 + 4 + 4 + 8);
        finish_sdt(&mut t)
    }

    /// HPET-таблица: MMIO 0xFED00000, 3 компаратора, 64-битный счётчик.
    fn build_hpet() -> Vec<u8> {
        let mut t = Vec::new();
        sdt_header(&mut t, b"HPET", 1);
        // event_timer_block_id: rev=1 | comparators=3<<8 | 64bit=1<<13
        // | legacy=1<<15 | vendor=0x8086<<16.
        push_u32(
            &mut t,
            1 | (3 << 8) | (1 << 13) | (1 << 15) | (0x8086 << 16),
        );
        // RawGenericAddress: system memory, 0xFED00000.
        t.push(0); // address space = system memory
        t.push(0); // bit width
        t.push(0); // bit offset
        t.push(0); // access size
        push_u64(&mut t, 0xFED0_0000);
        t.push(0); // hpet number
        push_u16(&mut t, 0x0DEA); // clock tick unit
        t.push(1); // page protection: 4K
        finish_sdt(&mut t)
    }

    /// DSDT: Scope(\_SB) { Device(HPET) {...} Device(UART) {...} }.
    ///
    /// AML собирается вручную; PkgLength — в кодировке интерпретатора
    /// крейта (lead-байт: биты 7:6 — число доп. байт, биты 3:0 — младшие
    /// разряды длины).
    fn build_dsdt() -> Vec<u8> {
        let mut aml: Vec<u8> = Vec::new();

        // -- Device(HPET) --
        let mut hpet_body: Vec<u8> = Vec::new();
        // Name(_HID, EisaId("PNP0103")) — Integer 0x41D00103.
        hpet_body.extend_from_slice(&[0x08, 0x5F, 0x48, 0x49, 0x44, 0x0C]);
        push_u32(&mut hpet_body, 0x41D0_0103);
        // Name(_UID, Zero).
        hpet_body.extend_from_slice(&[0x08, 0x5F, 0x55, 0x49, 0x44, 0x00]);
        // Method(_STA) { Return(0x0F) }: PkgLength = 1+4+1+3 = 9
        // (кодировка включает сам байт PkgLength).
        hpet_body.extend_from_slice(&[0x14, 0x09, 0x5F, 0x53, 0x54, 0x41, 0x00, 0xA4, 0x0A, 0x0F]);
        // Name(_CRS, Buffer(14) { Memory32Fixed(RW, 0xFED00000, 0x400) EndTag }).
        // Buffer: PkgLength = 1 + 2 (выражение размера) + 14 = 17.
        hpet_body.extend_from_slice(&[0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x11, 0x0A, 0x0E]);
        hpet_body.extend_from_slice(&[0x86, 0x09, 0x00, 0x01]);
        push_u32(&mut hpet_body, 0xFED0_0000);
        push_u32(&mut hpet_body, 0x400);
        hpet_body.extend_from_slice(&[0x79, 0x00]); // EndTag

        // DeviceOp: 5B 82 PkgLength NameSeg body.
        assert_eq!(hpet_body.len(), 49);
        // PkgLength = 1 (сам байт) + 4 (NameSeg) + 49 = 54.
        aml.extend_from_slice(&[0x5B, 0x82, 1 + 4 + 49]);
        aml.extend_from_slice(b"HPET");
        aml.extend_from_slice(&hpet_body);

        // -- Device(UART) --
        let mut uart_body: Vec<u8> = Vec::new();
        // Name(_HID, "PNP0501") — строкой.
        uart_body.extend_from_slice(&[0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D]);
        uart_body.extend_from_slice(b"PNP0501\0");
        // Name(_CID, EisaId("PNP0501")) — Integer 0x41D00501.
        uart_body.extend_from_slice(&[0x08, 0x5F, 0x43, 0x49, 0x44, 0x0C]);
        push_u32(&mut uart_body, 0x41D0_0501);
        // Method(_STA) { Return(0x0F) }: PkgLength = 9.
        uart_body.extend_from_slice(&[0x14, 0x09, 0x5F, 0x53, 0x54, 0x41, 0x00, 0xA4, 0x0A, 0x0F]);
        // Name(_CRS, Buffer(10) { IOPort(0x3F8, 4) EndTag }).
        // Buffer: PkgLength = 1 + 2 + 10 = 13.
        uart_body.extend_from_slice(&[0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x0D, 0x0A, 0x0A]);
        uart_body.extend_from_slice(&[0x47, 0x01]);
        push_u16(&mut uart_body, 0x3F8);
        push_u16(&mut uart_body, 0x3F8);
        uart_body.extend_from_slice(&[0x01, 0x04, 0x79, 0x00]);

        assert_eq!(uart_body.len(), 53);
        // PkgLength = 1 + 4 + 53 = 58.
        aml.extend_from_slice(&[0x5B, 0x82, 1 + 4 + 53]);
        aml.extend_from_slice(b"UART");
        aml.extend_from_slice(&uart_body);

        // -- Scope(\_SB) --
        // PkgLength (2 байта кодирования) + имя (5) + устройства
        // (3 + 4 + 49) и (3 + 4 + 53): опкод+PkgLength+NameSeg+тело.
        let scope_len = 2 + 5 + (3 + 4 + 49) + (3 + 4 + 53);
        assert_eq!(scope_len, 123);
        let mut dsdt = Vec::new();
        sdt_header(&mut dsdt, b"DSDT", 2);
        dsdt.push(0x10); // ScopeOp
        dsdt.push(0x40 | (scope_len & 0xF)); // PkgLength, 2 байта
        dsdt.push((scope_len >> 4) as u8);
        dsdt.extend_from_slice(&[0x5C, 0x5F, 0x53, 0x42, 0x5F]); // \_SB_
        dsdt.extend_from_slice(&aml);
        finish_sdt(&mut dsdt)
    }

    /// Собрать образ памяти с таблицами.
    fn build_image() -> &'static [u8] {
        let mut image = vec![0u8; 1 << 20];

        // RSDP v2.
        let mut rsdp = Vec::new();
        rsdp.extend_from_slice(b"RSD PTR ");
        rsdp.push(0); // checksum
        rsdp.extend_from_slice(b"TSTTST");
        rsdp.push(2); // revision
        push_u32(&mut rsdp, 0); // rsdt address (не используется при rev >= 2)
        push_u32(&mut rsdp, 36); // length
        push_u64(&mut rsdp, OFF_XSDT as u64);
        rsdp.push(0); // extended checksum
        rsdp.extend_from_slice(&[0; 3]);
        assert_eq!(rsdp.len(), 36);
        // Основная чексумма: сумма первых 20 байт == 0.
        let sum: u8 = rsdp[..20].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        rsdp[8] = sum.wrapping_neg();
        // Расширенная: сумма всех 36 байт == 0.
        let sum: u8 = rsdp.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        rsdp[32] = sum.wrapping_neg();

        for (off, table) in [
            (OFF_RSDP, rsdp),
            (OFF_XSDT, build_xsdt()),
            (OFF_FADT, build_fadt()),
            (OFF_MADT, build_madt()),
            (OFF_HPET, build_hpet()),
            (OFF_DSDT, build_dsdt()),
        ] {
            image[off..off + table.len()].copy_from_slice(&table);
        }

        Box::leak(image.into_boxed_slice())
    }

    struct Collector(Vec<DiscoveredDevice>);
    impl crate::hal::device::traits::DeviceSink for Collector {
        fn discovered(&mut self, dev: DiscoveredDevice) {
            self.0.push(dev);
        }
    }

    #[test]
    fn acpi_bus_enumerates_real_aml_tables() {
        let mem = build_image();
        let handler = FakeHandler {
            base: mem.as_ptr(),
            len: mem.len(),
        };

        // SAFETY: RSDP по OFF_RSDP корректен (собран выше).
        let tables = unsafe { AcpiTables::from_rsdp(handler.clone(), OFF_RSDP) }
            .expect("RSDP/XSDT обязаны собираться");
        let platform = AcpiPlatform::new(tables, handler).expect("FADT+MADT обязаны парситься");
        let bus = AcpiBus::new("acpi", platform).expect("DSDT обязан загрузиться");

        let mut sink = Collector(Vec::new());
        bus.scan(&mut sink).expect("scan обязан проходить");
        let found = sink.0;

        // Два устройства namespace; синтетический \HPET не появился
        // (PNP0103 найден в namespace).
        assert_eq!(found.len(), 2, "устройства: {found:?}");
        assert!(
            found
                .iter()
                .all(|d| !d.path.to_string().starts_with("acpi:\\HPET"))
        );

        // --- HPET: обогащён данными таблицы, путь namespace. ---
        let hpet = found
            .iter()
            .find(|d| {
                matches!(
                    &d.data,
                    BusDeviceData::Acpi(a) if a.hid.as_deref() == Some(HID_HPET)
                )
            })
            .expect("HPET обязан найтись по _HID");
        let BusDeviceData::Acpi(hdata) = &hpet.data else {
            panic!()
        };
        let hpet_table = hdata
            .hpet
            .as_ref()
            .expect("таблица HPET обязана подтянуться");
        assert_eq!(hpet_table.base_address, 0xFED0_0000);
        assert_eq!(hpet_table.num_comparators, 3);
        assert!(hpet_table.main_counter_is_64bits);
        assert!(hpet_table.legacy_irq_capable);
        assert_eq!(hpet_table.pci_vendor_id, 0x8086);
        assert_eq!(hpet_table.page_protection, HpetPageProtection::Protected4K);
        assert_eq!(hpet_table.clock_tick_unit, 0x0DEA);
        // EisaId-целое расжато в "PNP0103".
        assert_eq!(hdata.hid.as_deref(), Some("PNP0103"));
        assert_eq!(hdata.uid, Some(0)); // Name(_UID, Zero)
        assert!(hdata.functional()); // _STA = 0x0F
        // Ресурс из _CRS: Memory32Fixed.
        assert!(hpet.resources.iter().any(|r| matches!(
            r,
            DeviceResource::Mmio { base, len }
                if base.as_u64() == 0xFED0_0000 && *len == 0x400
        )));

        // --- UART: HID строкой, CID числом, IO-ресурс. ---
        let uart = found
            .iter()
            .find(|d| {
                matches!(
                    &d.data,
                    BusDeviceData::Acpi(a) if a.hid.as_deref() == Some("PNP0501")
                )
            })
            .expect("UART обязан найтись по строковому _HID");
        let BusDeviceData::Acpi(udata) = &uart.data else {
            panic!()
        };
        assert_eq!(udata.hid.as_deref(), Some("PNP0501"));
        // _CID числом (EisaId) расжат в ту же строку.
        assert!(udata.cids.iter().any(|c| c == "PNP0501"));
        assert!(uart.resources.iter().any(|r| matches!(
            r,
            DeviceResource::IoPort { base, len } if *base == 0x3F8 && *len == 4
        )));
        assert!(uart.functional);

        // Пути — AML-пути namespace.
        assert!(hpet.path.to_string().ends_with("HPET"));
        assert!(uart.path.to_string().ends_with("UART"));

        // Идемпотентность rescan: второй проход — то же множество.
        let mut sink2 = Collector(Vec::new());
        bus.scan(&mut sink2).unwrap();
        let mut p1: Vec<String> = found.iter().map(|d| d.path.to_string()).collect();
        let mut p2: Vec<String> = sink2.0.iter().map(|d| d.path.to_string()).collect();
        p1.sort();
        p2.sort();
        assert_eq!(p1, p2);
    }
}
