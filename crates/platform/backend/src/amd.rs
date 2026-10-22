// ==== AMD-Vi (AMD IOMMU): драйвер DMA-ремаппинга (IVRS/IVHD + Device Table + командный буфер + v1-таблицы) ====
//
// Форматы таблиц/регистров/команд/событий — крейт `amd-iommu` (zero-copy,
// no_std); драйвер (MMIO, последовательности включения, командный буфер,
// v1-таблицы) — наш. Исполнение контрактов ядра:
//
//   * `ANIOMMUInterface`/`LIOMMUInterface` (`hal::traits::iommu`) —
//     map/unmap/set_protection/detach + resolve_device;
//   * `syscall::iommu::IommuService` — объектно-безопасная поверхность
//     для сисколов IOMMU_*, через агрегатор `crate::iommu::IommuAgg`
//     (установка в X86Platform::run рядом с VT-d).
//
// Модель (v0.7, v1 host mode — не v2/GCR3/Guest, без PASID):
//
//   * IVHD из IVRS: MMIO-база = Base Address IVHD, сегмент; покрытие из
//     device-записей (Select/Range/Alias); запись 01h (All) = весь сегмент.
//     QEMU генерирует IVHD типов 10h и 11h с Select-записями всех устройств
//     шины 0 (+ Special для IOAPIC при intremap; мы не задаём IV в DTE);
//   * Device Table: 2 МиБ (LLfree order-9, Class(1)), 65536 DTE × 32 байта;
//     индекс = DeviceID = BDF (q35: bus<<8 | dev<<3 | fn);
//   * DTE: V|TV|Mode=Level4|HPT-root|DomainID + IR|IW. Права DTE
//     AND-ятся с правами листовых PTE → оба в 1 (управление в PTE);
//     q3 = 0, reserved-биты чисты (QEMU: amdvi_validate_dte); DomainID < 256
//     (QEMU: q1 bit8 — reserved; 256 доменов v0.7 хватает с запасом);
//   * v1-таблицы (4 уровня, NextLevel): каталог PR|NextLevel<<9|PA,
//     лист PR|IR|IW|PA (крейт v1_table/v1_page); без больших страниц;
//   * инвалидации — ТОЛЬКО командным буфером (256 записей):
//     INVALIDATE_DEVTAB_ENTRY + INVALIDATE_IOMMU_PAGES (S=1, Address[51:12]
//     из единиц → весь домен) + COMPLETION_WAIT (store-тег + поллинг слова
//     статуса, таймаут 100 мс по LAPIC-часам). Регистровых аналогов CCMD
//     у AMD нет — командный буфер обязателен (как QI у VT-d);
//   * домены: DomainID на каждое устройство attach (изоляция по умолчанию);
//     IOVA-диспетчеризация — вызывающий задаёт адрес (L4-подобный ABI);
//   * event log: включаем, дрейним при каждом sync (диагностика
//     IO_PAGE_FAULT и illegal-command). QEMU-курьёз: эмулятор не двигает
//     MMIO-хвост event log — на QEMU дрейн пуст; на реальном железе работает;
//   * IRQ-ремаппинг (v0.8): per-device IRTE-таблица (v1, 128-бит)
//     из DTE: IV=1 + IntTabLen=4 (16 записей) + IntTabPtr + IntCtl=10b
//     (remap on). Инвалидация — INVALIDATE_DEVTAB_ENTRY (DTE) и
//     INVALIDATE_INTERRUPT_TABLE (IRTE) командным буфером;
//   * AMD-Vi (зеркально VT-d): DeviceID = BDF; мульти-IOMMU (v0.8) —
//     ВСЕ IVHD с уникальными MMIO-базами (QEMU дублирует 10h/11h —
//     это одна единица).
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use spin::Mutex;

use amd_iommu::cmd::{Command, CompletionWait, InvalidateDevTabEntry, InvalidateIommuPages};
use amd_iommu::dte::{DeviceTableEntry, PagingMode};
use amd_iommu::events::{Event, EventCode};
use amd_iommu::irte::{IntType, Irte};
use amd_iommu::ivrs::{DeviceEntry, DeviceType, EntryType, Ivhd, IvrsTable};
use amd_iommu::pagetables;
use amd_iommu::regs::{self, BufferBase, Control, DeviceTableBase, Status};

use kernel_hal::traits::iommu::{ANIOMMUInterface, DeviceId, IommuError, LIOMMUInterface};
use kernel_hal::types::{Bdf, DevicePath, IommuProt};
use pkg_generic_interface::syscall::iommu::IommuService;

use crate::iommu::{Mmio, free_page, zero_huge, zero_page};
use crate::memory::phys_ptr;

/// Записей в командном буфере и event log (16 байт/запись; одна страница;
/// length order N=8 → 2^(N+4) = 4096 байт = 256 записей).
const CMD_ENTRIES: usize = 256;
const EVT_ENTRIES: usize = 256;
/// Записей в Device Table: 2 МиБ / 32 байта (size code 511).
const DEVTAB_ENTRIES: u64 = 65536;
/// Предел IOVA: 4 уровня v1-таблиц = 48 бит (зеркально AGAW48 VT-d).
const IOVA_LIMIT: u64 = 1 << 48;
/// «Все страницы домена» для INVALIDATE_IOMMU_PAGES: S=1, Address[51:12] из
/// единиц — размер задаётся первым нулевым битом адреса (бит 52 → весь домен).
const INV_ALL_ADDR: u64 = 0x000f_ffff_ffff_f000;
/// Размер v1 huge-листа (лист уровня 2, NextLevel=0).
const V1_HUGEP: u64 = 512 * 4096;
/// QEMU-инвариант: sb-devid «устройства IOAPIC» для ремаппинга линий
/// (hw/i386/amd_iommu.h: AMDVI_IOAPIC_SB_DEVID = PCI_BUILD_BDF(0, 0x14<<3));
/// спека AMD берёт его из IVHD-special 48h (variety 01h) — что QEMU и
/// кладёт. Дефолт — на случай записи без special.
const IOAPIC_SB_DEVID: u16 = 0x00A0;
/// Записей IRTE в per-device таблице устройств (IntTabLen=4 → 2^4 = 16,
/// базовый 32-битный формат — 64 байта).
const IRTE_PER_DEV: usize = 16;

// ───────────────────── v1-таблицы (4 уровня, NextLevel) ─────────────────────

/// Слот листовой PTE (уровень 1) для IOVA; create — выделять каталоги.
fn pt_slot(root: u64, iova: u64, create: bool) -> Option<*mut u64> {
    pt_slot_level(root, iova, 1, create)
}

/// Слот записи на заданном уровне (2 = лист-кандидат для huge, 1 = PTE);
/// create — выделять промежуточные каталоги. v0.8: huge-лист 2 МиБ —
/// запись уровня 2 с NextLevel=0 (спека v1: размер листа задаётся уровнем).
fn pt_slot_level(root: u64, iova: u64, level: u32, create: bool) -> Option<*mut u64> {
    let mut table = root;
    // SAFETY-контракт цикла: `table` — физика выровненной страницы из
    // zero_page (владение — домен), physmap покрывает.
    for lvl in (level..=4u32).rev() {
        let shift = 12 + 9 * (lvl - 1);
        let idx = ((iova >> shift) & 0x1FF) as usize;
        // SAFETY: см. контракт цикла.
        let entry = unsafe { phys_ptr::<u64>(table).add(idx) };
        if lvl == level {
            return Some(entry);
        }
        // SAFETY: как выше.
        let val = unsafe { entry.read_volatile() };
        if val & 1 == 0 {
            if !create {
                return None;
            }
            let child = zero_page()?;
            // v1-каталог: PR | NextLevel = уровень потомка | PA.
            // SAFETY: запись нового потомка в нашу таблицу.
            unsafe { entry.write_volatile(pagetables::v1_table(child, (lvl - 1) as u8)) };
            table = child;
        } else {
            table = val & 0x000f_ffff_ffff_f000;
        }
    }
    unreachable!("уровни исчерпаны")
}

/// Права листовой PTE из протекта: IR/IW (биты 61/62 v1-листа).
/// Пустой протект — минимально читаемая (иначе walk не пройдёт; как vtd).
fn pte_prot(prot: IommuProt) -> (bool, bool) {
    let r = prot.contains(IommuProt::READ);
    let w = prot.contains(IommuProt::WRITE);
    if !r && !w { (true, false) } else { (r, w) }
}

/// Освободить все таблицы домена (проход по промежуточным уровням 4..2;
/// листовые PTE — страницы уровня 1).
fn pt_free(root: u64) {
    fn walk(table: u64, level: u32) {
        for i in 0..512usize {
            // SAFETY: таблица наша (домен), physmap покрывает.
            let val = unsafe { phys_ptr::<u64>(table).add(i).read_volatile() };
            if val & 1 == 0 {
                continue;
            }
            // v0.8: лист (NextLevel=0) — НЕ таблица, физика принадлежит
            // отображению (huge-лист уровня 2 — тот же случай).
            if level > 1 && (val >> 9) & 7 == 0 {
                continue;
            }
            let child = val & 0x000f_ffff_ffff_f000;
            if level > 2 {
                walk(child, level - 1);
            }
            free_page(child);
        }
    }
    walk(root, 4);
    free_page(root);
}

// ───────────────────── Домены/устройства ─────────────────────

/// Домен изоляции: корень v1-таблиц + карта IOVA-отображений.
struct Domain {
    pt_root: u64,
    /// iova -> (phys, pages, prot, huge). v0.8: раскладка таблиц
    /// детерминированно повторяет проход map (unmap/protect идентичны).
    mappings: BTreeMap<u64, (u64, usize, IommuProt, bool)>,
}

/// Привязка DeviceId -> (DeviceID железа, домен, IRTE-таблица).
#[derive(Clone, Copy)]
struct DevBind {
    devid: u16,
    domid: u16,
    /// Физика per-device IRTE-таблицы (0 — IRQ-ремаппинг не поднят).
    irq_phys: u64,
}

// ───────────────────── Драйвер ─────────────────────

/// Состояние драйвера AMD-Vi — ОДИН контроллер (одна IVHD-единица);
/// мульти-IOMMU — несколько AmdVi в [`AmdDriver`] (v0.8).
pub struct AmdVi {
    mmio: Mmio,
    segment: u16,
    /// Тип IVHD (10h/11h/40h) — для версии архитектуры в ENUM.
    ivhd_type: EntryType,
    /// Запись 01h (All): IVHD покрывает весь сегмент.
    coverage_all: bool,
    /// DeviceID-диапазоны из device-записей IVHD (Select/Range/Alias).
    coverage: Vec<(u16, u16)>,
    /// Device Table: 2 МиБ, физика.
    devtab_phys: u64,
    cmd_phys: u64,
    /// Индекс следующей записи командного буфера (256 записей).
    cmd_idx: usize,
    evt_phys: u64,
    /// Наш указатель чтения event log (голова; хвост пишет IOMMU).
    evt_idx: usize,
    /// Физика слова статуса COMPLETION_WAIT + счётчик тегов.
    wait_phys: u64,
    wait_tag: u32,
    domains: BTreeMap<u16, Domain>,
    devices: BTreeMap<u32, DevBind>,
    next_domid: u16,
    next_dev: u32,
    /// v0.8: IRQ-ремаппинг — DTE attach'ей получают IV/IntTabLen/
    /// IntTabPtr/IntCtl=10b (v1 IRTE — базовая архитектура, гейт только
    /// успешность attach с такими DTE на данном железе/эмуляторе).
    ir_enabled: bool,
    /// v0.11: DeviceID «устройства IOAPIC» — через его DTE IOMMU ремапит
    /// линии (QEMU кладёт в IVHD-special 00:14.0 — AMDVI_IOAPIC_SB_DEVID;
    /// спека — handle записи 48h, variety 01h).
    ioapic_devid: u16,
    /// v0.11: IntTab «устройства IOAPIC» (ленивая страница; индекс в ней —
    /// ВЕКТОР линии, QEMU читает по (data & 0x7ff) << 2).
    ioapic_irq_phys: u64,
    /// v0.8: v1-листья уровня 2 (huge 2 МиБ) — спека v1: размер листа
    /// задаётся уровнем (NextLevel=0 на уровне 2).
    huge_ok: bool,
}

impl AmdVi {
    // ==== Командный буфер ====

    /// Отправить команду в буфер (без ожидания).
    fn cmd_submit(&mut self, cmd: &Command) {
        let words = cmd.words();
        // SAFETY: буфер — наша страница, physmap покрывает.
        unsafe {
            let slot = phys_ptr::<u32>(self.cmd_phys).add(self.cmd_idx * 4);
            slot.write_volatile(words[0]);
            slot.add(1).write_volatile(words[1]);
            slot.add(2).write_volatile(words[2]);
            slot.add(3).write_volatile(words[3]);
        }
        self.cmd_idx = (self.cmd_idx + 1) % CMD_ENTRIES;
        // Мембар: эмулятор/железо обязаны увидеть запись ДО хвоста.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // Хвост = смещение (в байтах) следующей свободной записи.
        self.mmio
            .write32(regs::CMD_TAIL, (self.cmd_idx * 16) as u32);
    }

    /// Отправить COMPLETION_WAIT (store-тег) и дождаться записи статуса
    /// (поллинг слова; таймаут 100 мс). Перед ожиданием — дрейн event log.
    fn cmd_sync(&mut self) -> Result<(), IommuError> {
        self.drain_events();
        self.wait_tag = self.wait_tag.wrapping_add(1);
        if self.wait_tag == 0 {
            self.wait_tag = 1;
        }
        // SAFETY: слово статуса — наша страница.
        unsafe { phys_ptr::<u64>(self.wait_phys).write_volatile(0) };
        // Мембар: команда обязана увидеть обнулённый статус ПОСЛЕ нас.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let cw = CompletionWait::new().with_store(self.wait_phys, self.wait_tag as u64);
        self.cmd_submit(&Command::CompletionWait(cw));
        let deadline = crate::lapic::uptime_ns() + 100_000_000;
        let mut polls: u32 = 0;
        loop {
            // SAFETY: слово статуса — наша страница.
            let v = unsafe { phys_ptr::<u64>(self.wait_phys).read_volatile() };
            polls = polls.wrapping_add(1);
            if v == self.wait_tag as u64 {
                return Ok(());
            }
            if crate::lapic::uptime_ns() > deadline {
                crate::kprintln!(
                    "amdvi: cmd_sync TIMEOUT: tag={} read={:#x} polls={}",
                    self.wait_tag,
                    v,
                    polls
                );
                return Err(IommuError::HardwareTimeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Инвалидация DTE устройства + всех страниц домена + синхронизация.
    /// Единый «безопасный» набор после любой мутации структур (v0.7 не
    /// гонится за минимальностью — зеркально vtd::invalidate_all).
    fn invalidate_all(&mut self, devid: u16, domid: u16) -> Result<(), IommuError> {
        self.cmd_submit(&Command::InvalidateDevTabEntry(InvalidateDevTabEntry {
            device_id: devid,
        }));
        self.cmd_submit(&Command::InvalidateIommuPages(InvalidateIommuPages {
            domain_id: domid,
            pasid: 0,
            addr: INV_ALL_ADDR,
            size: true,
            pde: false,
            guest_nested: false,
        }));
        self.cmd_sync()
    }

    /// Дрейн event log: печать и продвижение головы. Не более EVT_ENTRIES
    /// за вызов (страховка от «залипшего» хвоста; QEMU хвост не двигает —
    /// дрейн честно пуст, работает на реальном железе).
    fn drain_events(&mut self) {
        for _ in 0..EVT_ENTRIES {
            // SAFETY: MMIO-регистр, только чтение.
            let tail = self.mmio.read32(regs::EVT_TAIL) as usize;
            if tail / 16 % EVT_ENTRIES == self.evt_idx {
                return;
            }
            // SAFETY: event log — наша страница.
            let words = unsafe {
                let p = phys_ptr::<u32>(self.evt_phys).add(self.evt_idx * 4);
                [
                    p.read_volatile(),
                    p.add(1).read_volatile(),
                    p.add(2).read_volatile(),
                    p.add(3).read_volatile(),
                ]
            };
            let ev = Event::from_words(words);
            match ev {
                Event::PageFault(f) => crate::kprintln!(
                    "amdvi: EVT IO_PAGE_FAULT dev={:#06x} dom={:#06x} addr={:#x} {}{}{}",
                    f.device_id,
                    f.domain_id,
                    f.addr,
                    if f.write { "W" } else { "R" },
                    if f.permission { " PE" } else { "" },
                    if f.present { " PR" } else { "" }
                ),
                Event::Raw { code, words } => crate::kprintln!(
                    "amdvi: EVT code={:#04x} ({}) devid={:#06x} addr={:#x} w1={:#010x}",
                    code.0,
                    event_code_name(code),
                    words[0] & 0xffff,
                    ((words[3] as u64) << 32) | words[2] as u64,
                    words[1]
                ),
            }
            self.evt_idx = (self.evt_idx + 1) % EVT_ENTRIES;
            // SAFETY: MMIO-запись в наш регистр головы event log.
            self.mmio
                .write32(regs::EVT_HEAD, (self.evt_idx * 16) as u32);
        }
    }

    // ==== Device Table ====

    /// Записать 32-байтовый DTE (4 qword) по DeviceID.
    fn write_dte(&self, devid: u16, dte: DeviceTableEntry) {
        let off = devid as usize * 32;
        // SAFETY: Device Table — наш 2 МиБ-кусок (order-9), physmap покрывает.
        unsafe {
            let p = phys_ptr::<u64>(self.devtab_phys).add(off / 8);
            p.write_volatile(dte.q0);
            p.add(1).write_volatile(dte.q1);
            p.add(2).write_volatile(dte.q2);
            p.add(3).write_volatile(dte.q3);
        }
    }

    // ==== Включение/выключение ====

    /// Инициализация по IVHD: MMIO-декод, таблицы/буферы, включение.
    fn init(ivhd: &Ivhd) -> Result<Self, IommuError> {
        let base = ivhd.base_address();
        if base == 0 || base >= 0x1_0000_0000 {
            return Err(IommuError::InvalidConfig); // вне physmap (v0.7)
        }
        let mmio = Mmio::new(base);
        // EFR MMIO (0030h): у 10h-IVHD может отсутствовать — читаем как
        // есть (QEMU отдаёт образ расширенных возможностей; не гейтимся).
        let efr = mmio.read64(regs::EXT_FEATURES);
        let ivhd_type = ivhd.entry_type();
        crate::kprintln!(
            "amdvi: IVHD type={:?} base={:#x} seg={} caps={:#x} efr={:#x}",
            ivhd_type,
            base,
            ivhd.segment(),
            ivhd.capability_offset(),
            efr
        );

        // Покрытие: device-записи IVHD (Select/Range/Alias; All = сегмент).
        // ACPI-HID — не DMA-агент; Special 48h — тоже, НО запись IOAPIC
        // (variety 01h) — исключение для ремаппинга линий (v0.11).
        let mut coverage = Vec::new();
        let mut coverage_all = false;
        let mut range_start: Option<u16> = None;
        let mut ioapic_devid: Option<u16> = None;
        for dev in ivhd.devices() {
            match dev {
                DeviceEntry::Short {
                    ty: DeviceType::All,
                    ..
                } => coverage_all = true,
                DeviceEntry::Short {
                    ty: DeviceType::Select,
                    device_id,
                    ..
                } => coverage.push((device_id, device_id)),
                DeviceEntry::Short {
                    ty: DeviceType::StartOfRange,
                    device_id,
                    ..
                } => range_start = Some(device_id),
                DeviceEntry::Short {
                    ty: DeviceType::EndOfRange,
                    device_id,
                    ..
                } => {
                    if let Some(a) = range_start.take() {
                        coverage.push((a, device_id));
                    }
                }
                DeviceEntry::Long {
                    ty: DeviceType::AliasSelect | DeviceType::ExtendedSelect,
                    device_id,
                    ..
                } => coverage.push((device_id, device_id)),
                DeviceEntry::Long {
                    ty: DeviceType::AliasStartOfRange | DeviceType::ExtendedStartOfRange,
                    device_id,
                    ..
                } => range_start = Some(device_id),
                // Special 48h: IOAPIC (variety 01h) — его DeviceID идёт в
                // DTE-ремаппинг линий; HPET (02h) и прочие — мимо.
                //
                // DevID спец-записи — байт 5 (payload[1], спека: биты
                // 47:40), НЕ DevIDa-поле байтов 1..3 — оно для 48h
                // зарезервировано (общий device_id-аксессор крейта читает
                // ровно его — для спец-записей это 0). QEMU кладёт сюда
                // AMDVI_IOAPIC_SB_DEVID (acpi-build.c: IOAPIC_SB_DEVID =
                // BDF(0, 00:14.0) = 0x00A0), и тот же devid подставляет
                // в RUNTIME-запросе ремаппинга линий (amd_iommu.c: sid =
                // AMDVI_IOAPIC_SB_DEVID при неспецифицированном attrs).
                // Прошлая версия читала DevIDa → devid=0 → QEMU находил
                // IR-off в DTE[0xA0] и ПРОПУСКАЛ линию мимо IRTE
                // (беззвучный passthrough — ремаппинг не упражнялся).
                DeviceEntry::Long {
                    ty: DeviceType::Special,
                    payload,
                    ..
                } => {
                    // payload = байты 4..8 записи: [handle][devid lo][devid
                    // hi][variety]. Variety 01h — IOAPIC.
                    if payload[3] == 1 {
                        ioapic_devid = Some(u16::from_le_bytes([payload[1], payload[2]]));
                    }
                }
                // ACPI-HID (F0h)/Unknown — не DMA-агенты.
                _ => {}
            }
        }
        if let Some(d) = ioapic_devid {
            crate::kprintln!("amdvi: IVHD special: IOAPIC devid={:#06x}", d);
        }
        // Дефолт — инвариант QEMU (AMDVI_IOAPIC_SB_DEVID = 00:14.0): без
        // записи 48h линии ремапятся «от него» (hw/i386/amd_iommu.h).
        let ioapic_devid = ioapic_devid.unwrap_or(IOAPIC_SB_DEVID);
        crate::kprintln!(
            "amdvi: IVHD coverage: all={} entries={}",
            coverage_all,
            coverage.len()
        );

        // Таблицы/буферы (до включения чего-либо).
        let devtab_phys = zero_huge().ok_or(IommuError::OutOfMemory)?; // 2 МиБ
        let cmd_phys = zero_page().ok_or(IommuError::OutOfMemory)?;
        let evt_phys = zero_page().ok_or(IommuError::OutOfMemory)?;
        let wait_phys = zero_page().ok_or(IommuError::OutOfMemory)?;

        // Базы: DTBA (size code 511 → 2 МиБ = 65536 DTE), CBBA/ELBA
        // (order 8 → 4096 байт = 256 записей по 16 байт).
        mmio.write64(
            regs::DEV_TABLE_BASE,
            DeviceTableBase::new(devtab_phys, (DEVTAB_ENTRIES / 128 - 1) as u16).bits(),
        );
        mmio.write64(regs::CMD_BUF_BASE, BufferBase::new(cmd_phys, 8).bits());
        mmio.write64(regs::EVT_BUF_BASE, BufferBase::new(evt_phys, 8).bits());
        // Головы/хвосты в ноль (свежий старт; QEMU ждёт именно записи).
        mmio.write32(regs::CMD_HEAD, 0);
        mmio.write32(regs::CMD_TAIL, 0);
        mmio.write32(regs::EVT_HEAD, 0);
        mmio.write32(regs::EVT_TAIL, 0);

        // Флаги IVHD → Control (Linux-подобно): HtTunEn(0)/PassPW(1)/
        // ResPassPW(2)/Coherent(5) IVHD ↔ биты Control 1/8/9/10.
        let f = ivhd.flags();
        let mut ctrl = Control::EVT_LOG_EN | Control::CMD_BUF_EN;
        if f & 0x01 != 0 {
            ctrl |= Control::HT_TUN_EN;
        }
        if f & 0x02 != 0 {
            ctrl |= Control::PASSPW_EN;
        }
        if f & 0x04 != 0 {
            ctrl |= Control::RESPASSPW_EN;
        }
        if f & 0x20 != 0 {
            ctrl |= Control::COHERENT_EN;
        }

        // Шаг 1: буферы/лог БЕЗ включения трансляции (спека: IOMMU_EN
        // ставится последним). QEMU гасит Run-биты, пока IOMMU_EN=0
        // (cmdbuf_enabled = enabled && CMD_BUF_EN) — таймаут здесь
        // не фатален, финальная проверка после шага 2.
        mmio.write64(regs::CONTROL, ctrl.bits());
        wait_status(mmio, Status::CMD_BUF_RUN | Status::EVT_RUN, 10);

        // Шаг 2: IOMMU_EN — теперь Run-биты обязаны подняться (и по спеке,
        // и в QEMU: состояние пересчитывается одной записью).
        mmio.write64(regs::CONTROL, ctrl.union(Control::IOMMU_EN).bits());
        if !wait_status(mmio, Status::CMD_BUF_RUN | Status::EVT_RUN, 100) {
            crate::kprintln!(
                "amdvi: buffers did not start: status={:#x}",
                mmio.read64(regs::STATUS)
            );
            return Err(IommuError::HardwareTimeout);
        }
        // Страховка: IOMMU_EN прилип (read-back Control).
        if mmio.read64(regs::CONTROL) & Control::IOMMU_EN.bits() == 0 {
            return Err(IommuError::HardwareTimeout);
        }

        let mut amd = AmdVi {
            mmio,
            segment: ivhd.segment(),
            ivhd_type,
            coverage_all,
            coverage,
            devtab_phys,
            cmd_phys,
            cmd_idx: 0,
            evt_phys,
            evt_idx: 0,
            wait_phys,
            wait_tag: 0,
            domains: BTreeMap::new(),
            devices: BTreeMap::new(),
            next_domid: 1,
            next_dev: 1,
            ir_enabled: true,
            ioapic_devid,
            ioapic_irq_phys: 0,
            huge_ok: true,
        };
        // Чистый старт кэшей (глобальная инвалидация) + первый sync.
        amd.cmd_submit(&Command::InvalidateIommuAll);
        amd.cmd_sync()?;
        crate::kprintln!(
            "amdvi: translation enabled (devtab={} entries, cmd/evt={} entries, huge=2MiB, irte/dev={})",
            DEVTAB_ENTRIES,
            CMD_ENTRIES,
            IRTE_PER_DEV
        );
        Ok(amd)
    }

    // ==== Операции устройства ====

    fn attach_bdf(&mut self, bdf: Bdf) -> Result<u32, IommuError> {
        // Покрытие: IVHD All или точные диапазоны (сегмент IVHD).
        if bdf.segment != self.segment {
            return Err(IommuError::UnknownDevicePath);
        }
        let devid = bdf.to_requester_id();
        if !self.coverage_all && !self.coverage.iter().any(|&(a, b)| devid >= a && devid <= b) {
            crate::kprintln!(
                "amdvi: attach {} rejected: devid={:#06x} all={} coverage={:#x?}",
                bdf,
                devid,
                self.coverage_all,
                self.coverage
            );
            return Err(IommuError::UnknownDevicePath);
        }
        // Идемпотентность: повторный attach того же устройства — тот же DeviceId.
        if let Some((&id, _)) = self.devices.iter().find(|(_, b)| b.devid == devid) {
            return Ok(id);
        }
        // Домен и идентификаторы. DomainID < 256: QEMU валидирует q1 bit8
        // как reserved (amdvi_validate_dte) — больше и не нужно v0.7.
        if self.next_domid >= 256 {
            return Err(IommuError::OutOfMemory);
        }
        let domid = self.next_domid;
        self.next_domid += 1;
        let dev = self.next_dev;
        if dev == 0 {
            return Err(IommuError::OutOfMemory);
        }
        self.next_dev += 1;
        let root = zero_page().ok_or(IommuError::OutOfMemory)?;

        // v0.8: per-device IRTE-таблица (v1, 128-бит): IV=1 + IntTabLen=4
        // (16 записей) + IntTabPtr + IntCtl=10b (remap on). Права IR/IW —
        // AND с правами листовых PTE → оба в 1; q3 = 0 (reserved чисты).
        let irq_phys = if self.ir_enabled {
            zero_page().ok_or(IommuError::OutOfMemory)?
        } else {
            0
        };
        let mut dte = DeviceTableEntry::new()
            .with_valid(true)
            .with_translation_valid(true)
            .with_paging_mode(PagingMode::Level4)
            .with_host_page_table_root(root)
            .with_domain_id(domid)
            .with_ir(true)
            .with_iw(true);
        if self.ir_enabled {
            dte = dte
                .with_interrupt_map_valid(true)
                .with_interrupt_table_len(4)
                .with_interrupt_table_ptr(irq_phys)
                .with_int_ctl(2); // IntCtl=10b: remap on
        }
        self.write_dte(devid, dte);
        // Видимость DTE до команды INVALIDATE_DEVTAB_ENTRY.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        self.domains.insert(
            domid,
            Domain {
                pt_root: root,
                mappings: BTreeMap::new(),
            },
        );
        self.devices.insert(
            dev,
            DevBind {
                devid,
                domid,
                irq_phys,
            },
        );
        self.invalidate_all(devid, domid)?;
        crate::kprintln!(
            "amdvi: attach {} -> dev {} devid={:#06x} domid {}",
            bdf,
            dev,
            devid,
            domid
        );
        Ok(dev)
    }

    fn bind_of(&self, dev: u32) -> Result<(DevBind, u64), IommuError> {
        let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
        let dom = self
            .domains
            .get(&bind.domid)
            .ok_or(IommuError::DeviceNotBound)?;
        Ok((*bind, dom.pt_root))
    }

    fn map(
        &mut self,
        dev: u32,
        iova: u64,
        phys: u64,
        count: usize,
        prot: IommuProt,
    ) -> Result<(), IommuError> {
        if iova % 4096 != 0 || phys % 4096 != 0 || count == 0 {
            return Err(IommuError::InvalidConfig);
        }
        if iova + (count as u64) * 4096 > IOVA_LIMIT {
            return Err(IommuError::InvalidConfig); // вне 4-уровневых таблиц
        }
        let (bind, root) = self.bind_of(dev)?;
        // Конфликт IOVA: пересечение с существующими диапазонами домена.
        {
            let dom = self
                .domains
                .get(&bind.domid)
                .ok_or(IommuError::DeviceNotBound)?;
            let end = iova + (count as u64) * 4096;
            for (&base, &(_, pages, _, _)) in &dom.mappings {
                let bend = base + (pages as u64) * 4096;
                if base < end && iova < bend {
                    return Err(IommuError::IovaConflict);
                }
            }
        }
        let (r, w) = pte_prot(prot);
        // v0.8: раскладка — детерминированный проход (как vtd): 2 МиБ-
        // выровненный кусок >= 512 стр → v1-лист уровня 2 (NextLevel=0 —
        // размер задаётся уровнем), остальное — 4К PTE уровня 1.
        let mut used_huge = false;
        let mut i = 0u64;
        while i < count as u64 {
            let a = iova + i * 4096;
            let p = phys + i * 4096;
            let left = count as u64 - i;
            if self.huge_ok && left >= 512 && a % V1_HUGEP == 0 && p % V1_HUGEP == 0 {
                let slot = pt_slot_level(root, a, 2, true).ok_or(IommuError::OutOfMemory)?;
                // v1-лист уровня 2: PR | IR | IW | PA, NextLevel=0.
                // SAFETY: слот — запись домена (наш).
                unsafe { slot.write_volatile(pagetables::v1_page(p, r, w)) };
                i += 512;
                used_huge = true;
                crate::kprintln!("amdvi: map huge 2MiB iova={:#x} -> phys={:#x}", a, p);
            } else {
                let slot = pt_slot(root, a, true).ok_or(IommuError::OutOfMemory)?;
                // v1-лист: PR | IR | IW | PA.
                // SAFETY: слот — листовая PTE домена (наш).
                unsafe { slot.write_volatile(pagetables::v1_page(p, r, w)) };
                i += 1;
            }
        }
        let dom = self
            .domains
            .get_mut(&bind.domid)
            .ok_or(IommuError::DeviceNotBound)?;
        dom.mappings.insert(iova, (phys, count, prot, used_huge));
        self.invalidate_all(bind.devid, bind.domid)
    }

    fn unmap(&mut self, dev: u32, iova: u64, count: usize) -> Result<(), IommuError> {
        if iova % 4096 != 0 || count == 0 {
            return Err(IommuError::InvalidConfig);
        }
        let (bind, root) = self.bind_of(dev)?;
        // v0.8: точное снятие — (iova, count) обязан совпадать с записью
        // карты (частичное — v0.9; как vtd). Раскладка повторяет map.
        let rec = {
            let dom = self
                .domains
                .get(&bind.domid)
                .ok_or(IommuError::DeviceNotBound)?;
            dom.mappings.get(&iova).copied()
        };
        let Some((phys, pages, _prot, _huge)) = rec else {
            return Err(IommuError::MappingNotFound);
        };
        if pages != count {
            return Err(IommuError::InvalidConfig);
        }
        let mut i = 0u64;
        while i < count as u64 {
            let a = iova + i * 4096;
            let p = phys + i * 4096;
            let left = count as u64 - i;
            if self.huge_ok && left >= 512 && a % V1_HUGEP == 0 && p % V1_HUGEP == 0 {
                if let Some(slot) = pt_slot_level(root, a, 2, false) {
                    // SAFETY: слот — запись домена (наш).
                    unsafe { slot.write_volatile(0) };
                }
                i += 512;
            } else {
                if let Some(slot) = pt_slot(root, a, false) {
                    // SAFETY: слот — листовая PTE домена (наш).
                    unsafe { slot.write_volatile(0) };
                }
                i += 1;
            }
        }
        self.domains
            .get_mut(&bind.domid)
            .ok_or(IommuError::DeviceNotBound)?
            .mappings
            .remove(&iova);
        self.invalidate_all(bind.devid, bind.domid)
    }

    fn set_protection(&mut self, dev: u32, prot: IommuProt) -> Result<(), IommuError> {
        let (bind, root) = self.bind_of(dev)?;
        let ranges: Vec<(u64, u64, usize)> = {
            let dom = self
                .domains
                .get(&bind.domid)
                .ok_or(IommuError::DeviceNotBound)?;
            dom.mappings
                .iter()
                .map(|(&k, &(p, n, _, _))| (k, p, n))
                .collect()
        };
        let (r, w) = pte_prot(prot);
        for (iova, phys, pages) in ranges {
            let mut i = 0u64;
            while i < pages as u64 {
                let a = iova + i * 4096;
                let p = phys + i * 4096;
                let left = pages as u64 - i;
                if self.huge_ok && left >= 512 && a % V1_HUGEP == 0 && p % V1_HUGEP == 0 {
                    if let Some(slot) = pt_slot_level(root, a, 2, false) {
                        // SAFETY: слот — запись домена (наш).
                        unsafe { slot.write_volatile(pagetables::v1_page(p, r, w)) };
                    }
                    i += 512;
                } else {
                    if let Some(slot) = pt_slot(root, a, false) {
                        // SAFETY: слот — листовая PTE домена (наш).
                        unsafe { slot.write_volatile(pagetables::v1_page(p, r, w)) };
                    }
                    i += 1;
                }
            }
        }
        let dom = self
            .domains
            .get_mut(&bind.domid)
            .ok_or(IommuError::DeviceNotBound)?;
        for e in dom.mappings.values_mut() {
            e.2 = prot;
        }
        self.invalidate_all(bind.devid, bind.domid)
    }

    fn detach(&mut self, dev: u32) -> Result<(), IommuError> {
        let bind = self
            .devices
            .remove(&dev)
            .ok_or(IommuError::DeviceNotBound)?;
        // DTE -> not present (V=0: QEMU переводит трафик в identity; на
        // реальном железе — target abort/фолт, как у VT-d без контекста).
        self.write_dte(bind.devid, DeviceTableEntry::new());
        // Видимость сброса DTE до INVALIDATE_DEVTAB_ENTRY.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // v0.8: per-device IRTE-таблица — в пул (DTE уже погашен).
        if bind.irq_phys != 0 {
            self.cmd_submit(&Command::InvalidateInterruptTable(InvalidateDevTabEntry {
                device_id: bind.devid,
            }));
            free_page(bind.irq_phys);
        }
        // Таблицы домена — в пул (только если устройств домена не осталось).
        let still_used = self.devices.values().any(|b| b.domid == bind.domid);
        if !still_used {
            if let Some(dom) = self.domains.remove(&bind.domid) {
                pt_free(dom.pt_root);
            }
        }
        self.invalidate_all(bind.devid, bind.domid)
    }

    // ==== IRQ-ремаппинг (v0.8) ====

    /// Записать БАЗОВУЮ (32-битную) v1-IRTE по индексу per-device таблицы.
    ///
    /// Спека (amd-iommu/irte.rs, table 20) и QEMU (amdvi_get_irte: читает
    /// слово по смещению `(data & 0x7ff) << 2`) — запись таблицы имеет
    /// stride 4 байта, не 16. Баг v0.8: запись шла с 16-байтным шагом
    /// (скан занятости читал по правильному) — не проявлялся, пока
    /// доставка прерываний ЧЕРЕЗ IRTE не упражнялась; исправлено в v0.11
    /// перед первым реальным прогоном (IOAPIC).
    fn write_irte(&self, irq_phys: u64, idx: usize, irte: Option<Irte>) {
        let word = match irte {
            Some(i) => i.words()[0],
            None => 0,
        };
        // SAFETY: IRTE-таблица — наша страница, 4 байта на запись.
        unsafe {
            phys_ptr::<u32>(irq_phys).add(idx).write_volatile(word);
        }
    }

    /// Запрограммировать IRTE (v1): RemapEn|Valid|IntType|DM|dest|vector.
    /// Индекс 0 — резерв (системный «нет handle»): выделяем из 1..=15.
    fn irq_map(&mut self, dev: u32, vector: u8, dest: u8, flags: u8) -> Result<u32, IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        if !(0x10..=0xFE).contains(&vector) {
            return Err(IommuError::InvalidConfig);
        }
        let bind = self.bind_of(dev)?.0;
        if bind.irq_phys == 0 {
            return Err(IommuError::RemappingDisabled);
        }
        // Первый свободный слот (RemapEn=0), индекс 0 — резерв.
        let mut idx = None;
        for i in 1..IRTE_PER_DEV {
            // SAFETY: IRTE-таблица — наша страница.
            let used = unsafe { phys_ptr::<u32>(bind.irq_phys).add(i).read_volatile() & 1 != 0 };
            if !used {
                idx = Some(i);
                break;
            }
        }
        let idx = idx.ok_or(IommuError::OutOfMemory)?;
        let irte = Irte::new()
            .with_remap_enable(true)
            .with_int_type(IntType::Fixed)
            .with_destination_mode(flags & 2 != 0)
            .with_destination(dest)
            .with_vector(vector);
        self.write_irte(bind.irq_phys, idx, Some(irte));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // IRCache — INVALIDATE_INTERRUPT_TABLE устройства + sync.
        self.cmd_submit(&Command::InvalidateInterruptTable(InvalidateDevTabEntry {
            device_id: bind.devid,
        }));
        self.cmd_sync()?;
        crate::kprintln!(
            "amdvi: irte dev={} idx={} vec={:#x} dst={:#x} lvl={} log={}",
            dev,
            idx,
            vector,
            dest,
            flags & 1 != 0,
            flags & 2 != 0
        );
        Ok(idx as u32)
    }

    /// Погасить IRTE по handle (проверяем занятость и валидность).
    fn irq_unmap(&mut self, dev: u32, handle: u32) -> Result<(), IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        let bind = self.bind_of(dev)?.0;
        if bind.irq_phys == 0 {
            return Err(IommuError::RemappingDisabled);
        }
        let idx = handle as usize;
        if idx == 0 || idx >= IRTE_PER_DEV {
            return Err(IommuError::InvalidConfig);
        }
        // SAFETY: IRTE-таблица — наша страница.
        let used = unsafe { phys_ptr::<u32>(bind.irq_phys).add(idx).read_volatile() & 1 != 0 };
        if !used {
            return Err(IommuError::InvalidConfig);
        }
        self.write_irte(bind.irq_phys, idx, None);
        self.cmd_submit(&Command::InvalidateInterruptTable(InvalidateDevTabEntry {
            device_id: bind.devid,
        }));
        self.cmd_sync()
    }

    // ==== IOAPIC-ремаппинг линий (v0.11) ====

    /// Лениво возвести DTE «устройства IOAPIC»: IV=1 + IntTabLen=7
    /// (128 базовых 32-битных записей — до вектора 0x7F) + IntCtl=10b
    /// (remap). IOAPIC — не DMA-агент: поля трансляции не заполняются.
    fn ioapic_inttab_setup(&mut self) -> Result<u64, IommuError> {
        if self.ioapic_irq_phys != 0 {
            return Ok(self.ioapic_irq_phys);
        }
        let phys = zero_page().ok_or(IommuError::OutOfMemory)?;
        let dte = DeviceTableEntry::new()
            .with_valid(true)
            .with_interrupt_map_valid(true)
            .with_interrupt_table_len(7)
            .with_interrupt_table_ptr(phys)
            .with_int_ctl(2); // IntCtl=10b: remap on
        self.write_dte(self.ioapic_devid, dte);
        // Видимость DTE до инвалидации кэша.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.cmd_submit(&Command::InvalidateDevTabEntry(InvalidateDevTabEntry {
            device_id: self.ioapic_devid,
        }));
        self.cmd_sync()?;
        self.ioapic_irq_phys = phys;
        crate::kprintln!(
            "amdvi: ioapic inttab devid={:#06x} phys={:#x} entries=128",
            self.ioapic_devid,
            phys
        );
        Ok(phys)
    }

    /// IRTE линии IOAPIC: индекс = ВЕКТОР (QEMU: `(data & 0x7ff) << 2` от
    /// сообщения линии; спека: IntTab «устройства IOAPIC», базовый формат).
    /// Триггер/полярность линия несёт в обычном формате RTE — тут только
    /// вектор/назначение.
    fn ioapic_irte(&mut self, vector: u8, dest: u8) -> Result<(), IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        if !(0x10..=0x7F).contains(&vector) {
            return Err(IommuError::InvalidConfig);
        }
        let irq_phys = self.ioapic_inttab_setup()?;
        let irte = Irte::new()
            .with_remap_enable(true)
            .with_int_type(IntType::Fixed)
            .with_destination_mode(false)
            .with_destination(dest)
            .with_vector(vector);
        self.write_irte(irq_phys, vector as usize, Some(irte));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // IRCache — INVALIDATE_INTERRUPT_TABLE устройства-IOAPIC + sync.
        self.cmd_submit(&Command::InvalidateInterruptTable(InvalidateDevTabEntry {
            device_id: self.ioapic_devid,
        }));
        self.cmd_sync()?;
        crate::kprintln!(
            "amdvi: ioapic irte devid={:#06x} vec={:#x} dst={:#x}",
            self.ioapic_devid,
            vector,
            dest
        );
        Ok(())
    }
}

/// Дождаться битов STATUS (поллинг ~1 мс шагами, TSC-таймаут). Требуем ВСЕ
/// биты сразу (CmdBufRun и EvtRun поднимаются одной записью Control).
fn wait_status(mmio: Mmio, bits: Status, ms: u64) -> bool {
    let deadline = crate::lapic::uptime_ns() + ms * 1_000_000;
    loop {
        let s = Status::new(mmio.read64(regs::STATUS));
        if s.contains(bits) {
            return true;
        }
        if crate::lapic::uptime_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Короткое имя кода события для диагностической печати.
fn event_code_name(code: EventCode) -> &'static str {
    match code {
        EventCode::ILLEGAL_DEVICE => "ILLEGAL_DEVICE",
        EventCode::IO_PAGE_FAULT => "IO_PAGE_FAULT",
        EventCode::DEV_TAB_HARDWARE_ERROR => "DEV_TAB_HW_ERROR",
        EventCode::PAGE_TAB_HARDWARE_ERROR => "PAGE_TAB_HW_ERROR",
        EventCode::ILLEGAL_COMMAND_ERROR => "ILLEGAL_COMMAND",
        EventCode::COMMAND_HARDWARE_ERROR => "COMMAND_HW_ERROR",
        EventCode::IOTLB_INV_TIMEOUT => "IOTLB_INV_TIMEOUT",
        EventCode::INVALID_DEVICE_REQUEST => "INVALID_DEV_REQ",
        EventCode::INVALID_PPR_REQUEST => "INVALID_PPR_REQ",
        EventCode::RMP_FAULT => "RMP_FAULT",
        EventCode::RMP_HARDWARE_ERROR => "RMP_HW_ERROR",
        EventCode(_) => "reserved",
    }
}

// ───────────────────── КОНТРАКТ ЯДРА: IOMMU ─────────────────────

/// Драйвер AMD-Vi — ВСЕ поднятые IVHD-единицы (мульти-IOMMU, v0.8).
/// HAL-путь неймспейсит DeviceId парой (контроллер << 20 | локальный id)
/// — как `crate::vtd`; сисколы передают контроллер отдельным аргументом.
pub struct AmdDriver {
    inner: Mutex<Vec<AmdVi>>,
    /// Порядковый номер драйвера-вендора (IommuId).
    id: u32,
    /// Готовность (init прошёл; ставится один раз до старта AP).
    ready: AtomicBool,
}

impl AmdDriver {
    const fn new(id: u32) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            id,
            ready: AtomicBool::new(false),
        }
    }

    /// Пометить готовым (try_init после успешных AmdVi::init).
    fn mark_ready(&self) {
        self.ready.store(true, AtomicOrdering::Release);
    }

    /// Готовность (для агрегатора `crate::iommu`).
    pub fn is_ready(&self) -> bool {
        self.ready.load(AtomicOrdering::Acquire)
    }

    /// Число живых контроллеров (для агрегатора и IommuService).
    pub fn controller_count(&self) -> usize {
        if self.ready.load(AtomicOrdering::Acquire) {
            self.inner.lock().len()
        } else {
            0
        }
    }
}

/// HAL-неймспейс DeviceId: (контроллер << 20) | (локальный id & 0xF_FFFF).
fn hal_dev_id(ctrl: u32, local: u32) -> u32 {
    (ctrl << 20) | (local & 0xF_FFFF)
}

/// Информация о контроллере для IOMMU_ENUM (сискол).
#[derive(Debug, Clone, Copy)]
pub struct AmdInfo {
    /// Версия архитектуры из типа IVHD: 10h → 1.0, 11h/40h → 2.0.
    pub version: u16,
    pub include_all: bool,
    /// v0.8: IRQ-ремаппинг (IntCtl=10b в DTE attach'ей).
    pub irq_remap: bool,
}

impl AmdDriver {
    fn info(&self, ctrl: u32) -> Option<AmdInfo> {
        let g = self.inner.lock();
        g.get(ctrl as usize).map(|a| AmdInfo {
            version: match a.ivhd_type {
                EntryType::IvhdType11 | EntryType::IvhdType40 => 0x0200,
                _ => 0x0100,
            },
            include_all: a.coverage_all,
            irq_remap: a.ir_enabled,
        })
    }
}

impl ANIOMMUInterface for AmdDriver {
    fn iommu_id(&self) -> kernel_hal::traits::iommu::IommuId {
        kernel_hal::traits::iommu::IommuId(self.id)
    }

    fn map_pages(
        &mut self,
        dev: DeviceId,
        iova: u64,
        phys: kernel_hal::types::PhysAddr,
        count: usize,
        prot: IommuProt,
    ) -> Result<(), IommuError> {
        let ctrl = dev.0 >> 20;
        let local = dev.0 & 0xF_FFFF;
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .map(local, iova, phys.0, count, prot)
    }

    fn unmap_pages(&mut self, dev: DeviceId, iova: u64, count: usize) -> Result<(), IommuError> {
        let ctrl = dev.0 >> 20;
        let local = dev.0 & 0xF_FFFF;
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .unmap(local, iova, count)
    }

    fn set_protection(&mut self, dev: DeviceId, prot: IommuProt) -> Result<(), IommuError> {
        let ctrl = dev.0 >> 20;
        let local = dev.0 & 0xF_FFFF;
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .set_protection(local, prot)
    }

    fn detach_device(&mut self, dev: DeviceId) -> Result<(), IommuError> {
        let ctrl = dev.0 >> 20;
        let local = dev.0 & 0xF_FFFF;
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .detach(local)
    }
}

/// Контекст перечисления для resolve_device (сегмент IVHD).
pub struct IvhdScope {
    pub segment: u16,
}

impl LIOMMUInterface for AmdDriver {
    type Processor = IvhdScope;

    fn init_iommu_state(&mut self, _processor: &Self::Processor) {
        // Состояние строится при обнаружении IVHD (try_init); сюда
        // попадают только будущие динамические расширения.
    }

    fn resolve_device(
        &mut self,
        processor: &Self::Processor,
        path: &DevicePath,
    ) -> Result<DeviceId, IommuError> {
        let bdf = match path {
            DevicePath::Pci(bdf) => *bdf,
            _ => return Err(IommuError::UnknownDevicePath),
        };
        if bdf.segment != processor.segment {
            return Err(IommuError::UnknownDevicePath);
        }
        // v0.8: мульти-IOMMU — первый контроллер с подходящим coverage.
        let mut g = self.inner.lock();
        for (ctrl, unit) in g.iter_mut().enumerate() {
            if let Ok(local) = unit.attach_bdf(bdf) {
                return Ok(DeviceId(hal_dev_id(ctrl as u32, local)));
            }
        }
        Err(IommuError::UnknownDevicePath)
    }
}

// ───────────────────── Сервис сисколов (для агрегатора) ─────────────────────

/// Драйвер AMD-Vi (все IVHD-единицы); IommuId(1), 0 = «нет».
pub static AMD0: AmdDriver = AmdDriver::new(1);

impl IommuService for AmdDriver {
    fn controller_count(&self) -> usize {
        AmdDriver::controller_count(self)
    }

    fn controller_info(
        &self,
        idx: u32,
    ) -> Result<pkg_generic_interface::syscall::iommu::IommuInfo, IommuError> {
        if !self.is_ready() {
            return Err(IommuError::InvalidIndex);
        }
        let i = self.info(idx).ok_or(IommuError::InvalidIndex)?;
        Ok(pkg_generic_interface::syscall::iommu::IommuInfo {
            version: i.version,
            // 4 уровня v1-таблиц = 48-бит IOVA (зеркально AGAW48 VT-d).
            mgaw_bits: 48,
            agaw48: true,
            // Командный буфер обязателен у AMD-Vi (аналог QI VT-d).
            queued_inval: true,
            // DTE TV=0 = pass-through режим (не используем, информативно).
            pass_through: true,
            include_all: i.include_all,
            irq_remap: i.irq_remap,
            // v1-листья уровня 2 — спека v1 (NextLevel=0 задаёт размер).
            large_pages: true,
        })
    }

    fn attach(&self, ctrl: u32, bus: u8, device: u8, function: u8) -> Result<u32, IommuError> {
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .attach_bdf(Bdf::new(0, bus, device, function))
    }

    fn map_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        phys: u64,
        pages: usize,
        prot: u8,
    ) -> Result<(), IommuError> {
        let prot = IommuProt::from_bits_truncate(prot);
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .map(device, iova, phys, pages, prot)
    }

    fn unmap_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        pages: usize,
    ) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .unmap(device, iova, pages)
    }

    fn detach(&self, ctrl: u32, device: u32) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .detach(device)
    }

    fn irq_map(
        &self,
        ctrl: u32,
        device: u32,
        vector: u8,
        dest: u8,
        flags: u8,
    ) -> Result<u32, IommuError> {
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .irq_map(device, vector, dest, flags)
    }

    fn irq_unmap(&self, ctrl: u32, device: u32, handle: u32) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.get_mut(ctrl as usize)
            .ok_or(IommuError::InvalidIndex)?
            .irq_unmap(device, handle)
    }
}

// ───────────────────── Запуск (через iommu::init_and_install) ─────────────────────

/// Поиск IVRS -> ВСЕ IVHD с уникальными MMIO-базами -> init каждой ->
/// пометка готовности. Мульти-IOMMU (v0.8): QEMU генерирует IVHD 10h и
/// 11h ОДНОЙ единицы (одинаковая база) — дедуп по базе; на реальном
/// железе с несколькими IOMMU каждый IVHD становится контроллером.
/// Вызывается ПОСЛЕ kinit (пулы/куча подняты), ДО release_aps.
pub fn try_init() -> bool {
    // Пул не поднят (ранний fatal-путь run()) — тихо уходим.
    if pkg_generic_interface::mem::gallocator::frames().is_none() {
        return false;
    }
    let rsdp = crate::smp::topology().rsdp_phys;
    if rsdp == 0 {
        crate::kprintln!("amdvi: no RSDP — IOMMU unavailable");
        return false;
    }
    let found = crate::smp::find_table(rsdp, b"IVRS", |p, n| {
        let mut out = [0u8; 8];
        // SAFETY: physmap покрывает таблицы прошивки.
        let src = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(p), n) };
        out[..n].copy_from_slice(&src[..n]);
        out
    });
    let (phys, len) = match found {
        Ok(x) => x,
        Err(_) => {
            crate::kprintln!("amdvi: no IVRS table (QEMU: -device amd-iommu)");
            return false;
        }
    };
    // SAFETY: таблица прошивки живёт всю сессию.
    let slice = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(phys), len) };
    let ivrs = match IvrsTable::new(slice) {
        Ok(t) => t,
        Err(e) => {
            crate::kprintln!("amdvi: IVRS parse failed: {:?}", e);
            return false;
        }
    };
    // Все IVHD-единицы (мульти-IOMMU v0.8); дубликаты MMIO-базы (QEMU
    // кладёт 10h+11h одной единицы) — одна физическая единица.
    let mut made: Vec<AmdVi> = Vec::new();
    let mut seen_bases: Vec<u64> = Vec::new();
    let mut units = 0usize;
    for ivhd in ivrs.ivhd_units() {
        units += 1;
        if seen_bases.contains(&ivhd.base_address()) {
            crate::kprintln!(
                "amdvi: duplicate IVHD base={:#x} — skipped",
                ivhd.base_address()
            );
            continue;
        }
        seen_bases.push(ivhd.base_address());
        match AmdVi::init(&ivhd) {
            Ok(a) => {
                crate::kprintln!("amdvi[{}]: unit up", made.len());
                made.push(a);
            }
            Err(e) => {
                crate::kprintln!("amdvi: unit init failed: {:?} (skipped)", e);
            }
        }
    }
    if made.is_empty() {
        if units == 0 {
            // Диагностика: IVRS валиден (сигнатура/чексумма), но блоки
            // не распознаны. Известная причина — IVRS BLOCKS_OFFSET=44 в
            // старых ревизиях amd-iommu (спека/блоки с offset 48):
            // нужен iommu-rs с фиксом (см. патч-серию), затем
            // `cargo update -p amd-iommu`.
            crate::kprintln!(
                "amdvi: IVRS without IVHD units (len={}; check amd-iommu crate: IVRS blocks at +48)",
                len
            );
        }
        return false;
    }
    *AMD0.inner.lock() = made;
    // Готовность: ставим ПОСЛЕ заполнения (release_aps ещё не было —
    // конкурентов нет).
    AMD0.mark_ready();
    true
}

// ───────────────────── IOAPIC-поверхность драйвера (v0.11) ─────────────────────

/// Завести IRTE для линии IOAPIC (единый интерфейс для ioapic.rs; единица
/// 0 — QEMU amd-iommu один, линия ремапится первым контроллером).
pub fn ioapic_irte(vector: u8, dest: u8) -> Result<(), IommuError> {
    let mut g = AMD0.inner.lock();
    match g.get_mut(0) {
        Some(v) => v.ioapic_irte(vector, dest),
        None => Err(IommuError::IommuNotPresent),
    }
}

/// IRQ-ремаппинг включён хоть на одной единице AMD (ioapic.rs выбирает
/// вендора ремаппинга; Intel приоритетнее — remapped-RTE формат).
pub fn irq_remap_enabled() -> bool {
    let g = AMD0.inner.lock();
    g.first().is_some_and(|v| v.ir_enabled)
}
