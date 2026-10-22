// ==== BOOT_INFO: переносимый протокол загрузки ====
//
// Единая структура, которую загрузочный стаб (UEFI на x86_64; в будущем —
// любой другой) передаёт ядру на входе. Протокол переносим по построению:
//
//   * фиксированная раскладка `repr(C)` + магия + версия + поле `size`:
//     ядро может отказаться от слишком новой/старой версии, не читая
//     остальное; будущие поля дописываются в ХВОСТ, старые не двигаются;
//   * никаких ссылок/строк/аллокаций: только плоские массивы фиксированной
//     длины и физические адреса — структура живёт в памяти, принадлежащей
//     загрузчику, и читается ядром ДО инициализации кучи;
//   * firmware-агностично: `FirmwareTables` — enum-подобные поля для ACPI
//     (RSDP) и DTB, ядро сам парсит таблицы (MADT/MCFG/DMAR) — протокол
//     загрузки не навязывает семантику прошивки;
//   * boot_state (v2): переменные загрузки key=value из boot_cfg.xml —
//     ядро их НЕ интерпретирует (это не конфигурация ядра): транзитом
//     уходят init-серверу в стартовом IPC; XML живёт только в заглушке;
//   * адреса ВСЕГДА физические: на входе в ядро CR3 ещё может быть
//     прошивочный (или стабовый) — ядро отображает BootInfo в своё
//     physmap и читает оттуда.
//
// Передача: платформенный ABI. x86_64: стаб кладёт физ. адрес структуры
// в RDI и прыгает на entry ядра; ядро прочитает его через identity/physmap.
#![cfg_attr(not(test), no_std)]

use core::mem::size_of;

// ───────────────────────────── Константы протокола ─────────────────────────────

/// Магия протокола: "KNBI" (Kernel Boot Info) в младших 32 битах слова.
pub const BOOTINFO_MAGIC: u64 = 0x4B4E_4249_0000_0001;
/// Поддерживаемая версия структур этой сборки (v2: дописан boot_state).
pub const BOOTINFO_VERSION: u32 = 2;
/// Максимум записей карты памяти (UEFI даёт ~десятки; запас на NUMA-фьючерсы).
pub const MAX_MEMORY_REGIONS: usize = 64;
/// Максимум модулей (init-сервер и последующие; L4-образ: модули корня).
pub const MAX_MODULES: usize = 8;
/// Фиксированный размер cmdline-блока.
pub const CMDLINE_LEN: usize = 128;
/// Максимум boot_state-переменных (v2; хвост структуры).
pub const MAX_BOOT_STATE: usize = 16;
/// Имя boot_state-переменной (ASCIIZ внутри фиксированного поля).
pub const BOOT_STATE_NAME_LEN: usize = 32;
/// Значение boot_state-переменной (ASCIIZ внутри фиксированного поля).
pub const BOOT_STATE_VALUE_LEN: usize = 96;

// ───────────────────────────── Типы записей ─────────────────────────────

/// Назначение региона памяти по мнению прошивки/стаба.
///
/// `Available` — можно отдавать физическому аллокатору ядра (LLFree).
/// Остальные — зарезервированы: `Kernel`/`Modules`/`BootInfo` — образ ядра
/// и модули (ядро само знает их адреса, но карта должна быть полной),
/// `Reserved` — прошивка/аппаратные нужды (MMIO-отверстия, SMM, ACPI NVS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryKind {
    Available = 0,
    Reserved = 1,
    AcpiReclaim = 2,
    AcpiNvs = 3,
    Kernel = 4,
    Modules = 5,
    BootInfo = 6,
}

impl MemoryKind {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Available),
            1 => Some(Self::Reserved),
            2 => Some(Self::AcpiReclaim),
            3 => Some(Self::AcpiNvs),
            4 => Some(Self::Kernel),
            5 => Some(Self::Modules),
            6 => Some(Self::BootInfo),
            _ => None,
        }
    }
}

/// Непрерывный физический регион.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryRegion {
    /// Физическая база (выровнена на страницу).
    pub base: u64,
    /// Длина в байтах (кратна странице).
    pub len: u64,
    pub kind: MemoryKind,
}

/// Модуль, загруженный стабом (init-сервер и прочие; blob как есть).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ModuleInfo {
    /// Физический база blob (выровнена на страницу).
    pub base: u64,
    /// Длина в байтах.
    pub len: u64,
    /// Имя/командная строка модуля (ASCIIZ внутри фиксированного поля).
    pub name: [u8; 32],
}

impl ModuleInfo {
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        // SAFETY: имя пишется стабом из ASCII-строк; даже если это не так —
        // отрезаем по нулевому байту и валидируем ниже.
        let bytes = &self.name[..end];
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// Переменная состояния загрузки (v2): key/value-пара строками.
///
/// Это «переменные загрузки» из boot_cfg.xml (boot_state) заглушки:
/// заглушка их разбирает (crate bootcfg), ядро — НЕТ (это не
/// конфигурация ядра). Судьба переменных — транзит в init-сервер
/// стартовым IPC (argc/argv-протокол v0.3), где их смысл определяет
/// сам init. Обе стороны — ASCIZ-строки: переносимо без соглашений
/// о кодировке типов между заглушкой, ядром и init.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BootStateVar {
    /// Имя переменной (ASCIIZ внутри фиксированного поля).
    pub name: [u8; BOOT_STATE_NAME_LEN],
    /// Значение (ASCIIZ внутри фиксированного поля).
    pub value: [u8; BOOT_STATE_VALUE_LEN],
}

impl BootStateVar {
    /// ASCIIZ-отрез поля (общий хелпер).
    fn asciz(field: &[u8]) -> &str {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        core::str::from_utf8(&field[..end]).unwrap_or("")
    }

    /// Имя переменной.
    pub fn name_str(&self) -> &str {
        Self::asciz(&self.name)
    }

    /// Значение переменной.
    pub fn value_str(&self) -> &str {
        Self::asciz(&self.value)
    }

    /// Заполнить из строк (заглушка/хост-утилиты); `None` — переполнение
    /// фиксированных полей протокола (вызывающий обязан отказаться от
    /// молчаливого обрезания: усечённое имя — потерянная переменная).
    pub fn from_strs(name: &str, value: &str) -> Option<Self> {
        if name.len() >= BOOT_STATE_NAME_LEN || value.len() >= BOOT_STATE_VALUE_LEN {
            return None;
        }
        let mut var = Self {
            name: [0; BOOT_STATE_NAME_LEN],
            value: [0; BOOT_STATE_VALUE_LEN],
        };
        var.name[..name.len()].copy_from_slice(name.as_bytes());
        var.value[..value.len()].copy_from_slice(value.as_bytes());
        Some(var)
    }
}

/// Указатели на таблицы прошивки. Ни одна платформа не обязана заполнять
/// оба поля: ARM-будущее принесёт DTB, x86_64 — RSDP.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FirmwareTables {
    /// Физический адрес RSDP (ACPI x86_64); 0 — нет ACPI.
    pub rsdp: u64,
    /// Физический адрес DTB (ARM и пр.); 0 — нет DTB.
    pub dtb: u64,
}

/// Образ ядра по мнению стаба (для physmap и отладки; карта памяти
/// дублирует эти регионы с kind = Kernel).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KernelImage {
    /// Физический база образа ядра (первый PT_LOAD).
    pub phys_base: u64,
    /// Виртуальный адрес точки входа (линк-адрес; high-half на x86_64).
    pub virt_entry: u64,
    /// Полная длина образа в байтах.
    pub len: u64,
}

// ───────────────────────────── Главная структура ─────────────────────────────

/// Структура протокола загрузки.
///
/// Раскладка фиксирована версией протокола (текущая — v2): поля НИКОГДА
/// не переупорядочиваются и не меняют тип; расширения — только
/// дописыванием в конец + bump версии.
/// `size` позволяет ядру проверить, что структура не обрезана.
#[repr(C)]
pub struct BootInfo {
    /// Всегда [`BOOTINFO_MAGIC`].
    pub magic: u64,
    /// Версия структур-источника (ядро сверяет со своей).
    pub version: u32,
    /// `size_of::<BootInfo>()` на стороне писателя.
    pub size: u32,
    /// Число валидных записей `memory`.
    pub memory_count: u32,
    /// Число валидных записей `modules`.
    pub module_count: u32,
    /// Зарезервировано (выравнивание/будущее); читателю игнорировать.
    pub _reserved: u32,
    /// Полная физическая карта от прошивки (после ExitBootServices).
    pub memory: [MemoryRegion; MAX_MEMORY_REGIONS],
    /// Модули; [0] — init-сервер по договорённости протокола.
    pub modules: [ModuleInfo; MAX_MODULES],
    /// Таблицы прошивки.
    pub firmware: FirmwareTables,
    /// Образ ядра.
    pub kernel: KernelImage,
    /// Командная строка ядра (ASCIIZ).
    pub cmdline: [u8; CMDLINE_LEN],

    // ==== v2 (допись в хвост; поля v1 не двигаются) ====
    /// Число валидных записей `state` (boot_state-переменные).
    pub state_count: u32,
    /// Зарезервировано (выравнивание/будущее); читателю игнорировать.
    pub _reserved2: u32,
    /// Переменные состояния загрузки: boot_cfg.xml заглушки -> init.
    pub state: [BootStateVar; MAX_BOOT_STATE],
}

impl BootInfo {
    /// Нулевая структура (стаб наполняет полями).
    pub const EMPTY: BootInfo = BootInfo {
        magic: BOOTINFO_MAGIC,
        version: BOOTINFO_VERSION,
        size: size_of::<BootInfo>() as u32,
        memory_count: 0,
        module_count: 0,
        _reserved: 0,
        memory: [MemoryRegion {
            base: 0,
            len: 0,
            kind: MemoryKind::Reserved,
        }; MAX_MEMORY_REGIONS],
        modules: [ModuleInfo {
            base: 0,
            len: 0,
            name: [0; 32],
        }; MAX_MODULES],
        firmware: FirmwareTables { rsdp: 0, dtb: 0 },
        kernel: KernelImage {
            phys_base: 0,
            virt_entry: 0,
            len: 0,
        },
        cmdline: [0; CMDLINE_LEN],
        state_count: 0,
        _reserved2: 0,
        state: [BootStateVar {
            name: [0; BOOT_STATE_NAME_LEN],
            value: [0; BOOT_STATE_VALUE_LEN],
        }; MAX_BOOT_STATE],
    };

    /// Проверка протокола: магия, версия, размер, число записей.
    ///
    /// `Ok(())` — можно читать; `Err(reason)` — протокол не наш, ядро
    /// обязано отказаться грузиться (молчаливое чтение чужой раскладки —
    /// дыра, а не совместимость).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.magic != BOOTINFO_MAGIC {
            return Err("bad magic");
        }
        if self.version != BOOTINFO_VERSION {
            return Err("version mismatch");
        }
        if self.size as usize != size_of::<BootInfo>() {
            return Err("size mismatch");
        }
        if self.memory_count as usize > MAX_MEMORY_REGIONS {
            return Err("memory_count out of range");
        }
        if self.module_count as usize > MAX_MODULES {
            return Err("module_count out of range");
        }
        if self.state_count as usize > MAX_BOOT_STATE {
            return Err("state_count out of range");
        }
        Ok(())
    }

    /// Валидный срез карты памяти.
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        let n = (self.memory_count as usize).min(MAX_MEMORY_REGIONS);
        &self.memory[..n]
    }

    /// Валидный срез модулей.
    pub fn modules(&self) -> &[ModuleInfo] {
        let n = (self.module_count as usize).min(MAX_MODULES);
        &self.modules[..n]
    }

    /// init-сервер (модуль [0] по договорённости протокола), если есть.
    pub fn init_module(&self) -> Option<&ModuleInfo> {
        self.modules().first()
    }

    /// cmdline как &str (ASCIIZ-отрез).
    pub fn cmdline_str(&self) -> &str {
        let end = self
            .cmdline
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(CMDLINE_LEN);
        core::str::from_utf8(&self.cmdline[..end]).unwrap_or("")
    }

    /// Валидный срез boot_state-переменных.
    pub fn state_vars(&self) -> &[BootStateVar] {
        let n = (self.state_count as usize).min(MAX_BOOT_STATE);
        &self.state[..n]
    }

    /// Значение boot_state-переменной по имени (первое совпадение).
    ///
    /// Пользователь — код платформы/отладки: сам протокол не придаёт
    /// переменным семантики (см. [`BootStateVar`]).
    pub fn state_value(&self, name: &str) -> Option<&str> {
        self.state_vars()
            .iter()
            .find(|v| v.name_str() == name)
            .map(|v| v.value_str())
    }

    /// Суммарный объём доступной (Available) памяти в байтах.
    pub fn available_bytes(&self) -> u64 {
        self.memory_regions()
            .iter()
            .filter(|r| r.kind == MemoryKind::Available)
            .map(|r| r.len)
            .sum()
    }
}

// Плоская структура читается чужим кодом — подтверждаем тривиальность
// перемещения между границами крейтов.
// SAFETY-обоснование: нет ссылок, только POD-поля.
unsafe impl Send for BootInfo {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_validates_and_layout_is_stable() {
        assert_eq!(BootInfo::EMPTY.validate(), Ok(()));
        assert_eq!(BootInfo::EMPTY.state_count, 0);
        assert!(BootInfo::EMPTY.state_vars().is_empty());
        assert!(BootInfo::EMPTY.init_module().is_none());
        // Стабильность раскладки протокола: BootStateVar = 32 + 96 байт.
        assert_eq!(size_of::<BootStateVar>(), 128);
    }

    #[test]
    fn state_roundtrip_and_lookup() {
        let mut bi = BootInfo::EMPTY;
        bi.state[0] = BootStateVar::from_strs("console", "com1").unwrap();
        bi.state[1] = BootStateVar::from_strs("root", "nvme0").unwrap();
        bi.state_count = 2;
        assert_eq!(bi.validate(), Ok(()));
        assert_eq!(bi.state_vars().len(), 2);
        assert_eq!(bi.state_value("console"), Some("com1"));
        assert_eq!(bi.state_value("root"), Some("nvme0"));
        assert_eq!(bi.state_value("missing"), None);
        assert_eq!(bi.state[1].name_str(), "root");
        assert_eq!(bi.state[1].value_str(), "nvme0");
    }

    #[test]
    fn from_strs_rejects_overflow() {
        let long_value = "x".repeat(BOOT_STATE_VALUE_LEN);
        assert!(BootStateVar::from_strs("k", &long_value).is_none());
        let long_name = "n".repeat(BOOT_STATE_NAME_LEN);
        assert!(BootStateVar::from_strs(&long_name, "v").is_none());
        // На границе (len-1) — влезает.
        assert!(BootStateVar::from_strs(&"n".repeat(BOOT_STATE_NAME_LEN - 1), "v").is_some());
    }

    #[test]
    fn validate_rejects_version_and_range() {
        let mut bi = BootInfo::EMPTY;
        bi.version = 1;
        assert_eq!(bi.validate(), Err("version mismatch"));

        let mut bi = BootInfo::EMPTY;
        bi.state_count = (MAX_BOOT_STATE as u32) + 1;
        assert_eq!(bi.validate(), Err("state_count out of range"));

        let mut bi = BootInfo::EMPTY;
        bi.size = 7;
        assert_eq!(bi.validate(), Err("size mismatch"));

        let mut bi = BootInfo::EMPTY;
        bi.magic = 0;
        assert_eq!(bi.validate(), Err("bad magic"));
    }

    /// Регрессия v0.5.2 (порча boot_state в QEMU): писатель (заглушка)
    /// выделял РОВНО 1 страницу под BootInfo, а обнуление перед заполнением
    /// шло на size_of::<BootInfo>() (~4.2 КиБ) — вылезало за границу
    /// выделенного и затирало соседний пул UEFI (на практике обнулился
    /// String значения var[1]: «test_mode=qemu» пришёл как «test_mode=»).
    /// Контракт: писатель обязан выделять ceil(size/4096) страниц. Тест
    /// фиксирует точную раскладку — любое её изменение (легитимный рост
    /// полей/лимитов) обязано идти с bump версии протокола и ОСОЗНАННЫМ
    /// пересчётом страниц у всех писателей.
    #[test]
    fn bootinfo_size_frozen_writers_must_round_up_pages() {
        const PAGE: usize = 4096;
        let total = size_of::<BootInfo>();
        // Фиксация (см. поля выше): header 28+4pad, memory 64*24, modules
        // 8*48, firmware 16, kernel 24, cmdline 128, v2-хвост 8+2048.
        assert_eq!(total, 4176);
        // Дисциплина страниц: ровно 2 страницы (4096 < 4176 <= 8192).
        assert_eq!(total.div_ceil(PAGE), 2);
    }
}
