// ==== Intel VT-d: драйвер DMA-ремаппинга (DMAR/DRHD + QI + SSPT) ====
//
// Форматы таблиц/регистров — крейт `intel-iommu` (zero-copy, no_std);
// драйвер (MMIO, последовательности включения, очередь инвалидаций,
// second-stage таблицы) — наш. Исполнение контрактов ядра:
//
//   * `ANIOMMUInterface`/`LIOMMUInterface` (`hal::traits::iommu`) —
//     map/unmap/set_protection/detach + resolve_device;
//   * `syscall::iommu::IommuService` — объектно-безопасная поверхность
//     для сисколов (IOMMU_ENUM/ATTACH/MAP/UNMAP/DETACH), устанавливается
//     в X86Platform::run.
//
// Модель (v0.6, legacy mode — не scalable):
//
//   * DRHD из DMAR (предпочтителен INCLUDE_PCI_ALL): MMIO-регистры
//     через physmap; VER/CAP/ECAP декодируются крейтом;
//   * root table (4K) -> context table на шину -> context entry на
//     devfn: P|TT=SecondStage|SSPTPTR|DID|AGAW48 (SAGAW bit2 — обязателен,
//     проверяем при init);
//   * second-stage (EPT-подобные, 4 уровня): 4K-страницы, R|W (+X по
//     протекту) — без больших страниц (SSLPS не используем);
//   * инвалидации — ТОЛЬКО через Queued Invalidation (ECAP.QI обязателен):
//     дескрипторы context-cache/IOTLB + wait(status-write) с поллингом
//     слова-статуса; регистровый CCMD/IOTLB-путь не реализуем;
//   * домены: DID на каждое устройство attach (изоляция по умолчанию);
//     IOVA-диспетчеризация — вызывающий задаёт адрес (L4-подобный ABI);
//   * RAM-ограничение: все таблицы из ядрового LLFree-пула, физика
//     < 4 GiB (physmap; QEMU-масштаб), кадры возвращаются при detach.
//
// AMD-Vi (IVRS) — детект по DMAR-отсутствию; поддержка не в v0.6
// (честный NotSupported). IRQ-ремаппинг (IRTE/IRTA) — следующая итерация:
// включаем ТОЛЬКО DMA-часть (TE), IRE не трогаем.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use spin::Mutex;

use intel_iommu::context::{AddrWidth, ContextEntry, RootEntry, TransType};
use intel_iommu::dmar::{DmarTable, Drhd};
use intel_iommu::qi::{Granularity, QiCc, QiDesc, QiIotlb, QiWait};
use intel_iommu::regs::{self, Cap, Ecap, Gcmd, Gsts, Version};

use pkg_generic_interface::hal::traits::iommu::{
    ANIOMMUInterface, DeviceId, IommuError, LIOMMUInterface,
};
use pkg_generic_interface::hal::types::{Bdf, DevicePath, IommuProt};
use pkg_generic_interface::syscall::iommu::IommuService;

use crate::memory::phys_ptr;

// ───────────────────── MMIO (physmap, volatile) ─────────────────────

/// Блок регистров DRHD.
#[derive(Clone, Copy)]
struct Mmio {
    base: u64,
}

impl Mmio {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: physmap покрывает MMIO DRHD (< 4 GiB), выравнивание 4.
        unsafe { phys_ptr::<u32>(self.base + off).read_volatile() }
    }
    fn read64(&self, off: u64) -> u64 {
        // SAFETY: как read32, выравнивание 8.
        unsafe { phys_ptr::<u64>(self.base + off).read_volatile() }
    }
    fn write32(&self, off: u64, v: u32) {
        // SAFETY: как read32.
        unsafe { phys_ptr::<u32>(self.base + off).write_volatile(v) };
    }
    fn write64(&self, off: u64, v: u64) {
        // SAFETY: как read64.
        unsafe { phys_ptr::<u64>(self.base + off).write_volatile(v) };
    }
}

// ───────────────────── Кадры (ядровый LLFree) ─────────────────────

/// Выделить обнулённую страницу (физика). None — пул не поднят/кончился.
fn zero_page() -> Option<u64> {
    let frames = pkg_generic_interface::mem::gallocator::frames()?;
    let (_, fid) = frames.alloc(0, llfree::Class(0), None).ok()?;
    let phys = fid.0 as u64 * 4096;
    // SAFETY: кадр наш, physmap покрывает.
    unsafe { core::ptr::write_bytes(phys_ptr::<u8>(phys), 0, 4096) };
    Some(phys)
}

/// Вернуть страницу в пул.
fn free_page(phys: u64) {
    if let Some(frames) = pkg_generic_interface::mem::gallocator::frames() {
        let fid = llfree::FrameId((phys / 4096) as usize);
        frames.free(fid, 0, llfree::Class(0), None);
    }
}

// ───────────────────── Second-stage таблицы (EPT-подобные, 4 уровня) ─────────────────────

/// SS-PTE: R(0) W(1) X(2); промежуточные — R|W (проход доступен).
const SSPTE_RW: u64 = 0b011;
const SSPTE_R: u64 = 0b001;
const SSPTE_X: u64 = 0b100;

fn sspte_prot(prot: IommuProt) -> u64 {
    let mut e = 0u64;
    if prot.contains(IommuProt::READ) {
        e |= SSPTE_R;
    }
    if prot.contains(IommuProt::WRITE) {
        e |= SSPTE_W_BIT;
    }
    if e == 0 {
        e = SSPTE_R; // пустой протект = минимально читаемая (иначе walk не пройдёт)
    }
    e
}
const SSPTE_W_BIT: u64 = 0b010;

/// Уровни AGAW48: биты IOVA 47:39 / 38:30 / 29:21 / 20:12.
fn sspt_slot(root: u64, iova: u64, create: bool) -> Option<*mut u64> {
    let mut table = root;
    // SAFETY-контракт цикла: `table` — физика выровненной страницы из
    // zero_page (владение — домен), physmap покрывает.
    for level in (1..=4u32).rev() {
        let shift = 12 + 9 * (level - 1);
        let idx = ((iova >> shift) & 0x1FF) as usize;
        // SAFETY: см. контракт цикла.
        let entry = unsafe { phys_ptr::<u64>(table).add(idx) };
        // SAFETY: как выше.
        let val = unsafe { entry.read_volatile() };
        if level == 1 {
            return Some(entry);
        }
        if val & 0xFFF == 0 {
            if !create {
                return None;
            }
            let child = zero_page()?;
            // SAFETY: запись нового потомка в нашу таблицу.
            unsafe { entry.write_volatile(child | SSPTE_RW) };
            table = child;
        } else {
            table = val & !0xFFF;
        }
    }
    unreachable!("4 уровня исчерпаны")
}

/// Освободить все таблицы домена (проход по промежуточным уровням).
fn sspt_free(root: u64) {
    // Рекурсивный проход уровней 4..2 (1-й — листовые PTE, не таблицы).
    fn walk(table: u64, level: u32) {
        for i in 0..512usize {
            // SAFETY: таблица наша (домен), physmap покрывает.
            let val = unsafe { phys_ptr::<u64>(table).add(i).read_volatile() };
            if val & 0xFFF == 0 {
                continue;
            }
            let child = val & !0xFFF;
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

/// Домен изоляции: second-stage корень + карта IOVA-отображений.
struct Domain {
    sspt_root: u64,
    /// iova -> (phys, pages, prot).
    mappings: BTreeMap<u64, (u64, usize, IommuProt)>,
}

/// Привязка DeviceId -> (BDF, домен).
struct DevBind {
    bdf: Bdf,
    did: u16,
}

// ───────────────────── Драйвер ─────────────────────

/// Состояние драйвера VT-d (один DRHD; мульти-DRHD — v0.7).
pub struct Vtd {
    mmio: Mmio,
    ver: Version,
    cap: Cap,
    ecap: Ecap,
    segment: u16,
    include_all: bool,
    /// Device scope DRHD: (rid_start, rid_end) — упрощённо v0.6: точные
    /// endpoints (мосты-иерархии — расширение).
    scope_rids: Vec<(u16, u16)>,
    root_phys: u64,
    qi_phys: u64,
    /// Индекс следующего дескриптора в QI-очереди (256 записей).
    qi_idx: usize,
    /// Физика слова статуса wait-дескрипторов + счётчик тегов.
    wait_phys: u64,
    wait_tag: u32,
    domains: BTreeMap<u16, Domain>,
    devices: BTreeMap<u32, DevBind>,
    next_did: u16,
    next_dev: u32,
}

const QI_ENTRIES: usize = 256;

impl Vtd {
    // ==== Очередь инвалидаций ====

    /// Отправить дескриптор в QI (без ожидания).
    fn qi_submit(&mut self, desc: &QiDesc) {
        let words = desc.words();
        // SAFETY: очередь — наша страница, physmap покрывает.
        unsafe {
            let slot = phys_ptr::<u64>(self.qi_phys).add(self.qi_idx * 2);
            slot.write_volatile(words[0]);
            slot.add(1).write_volatile(words[1]);
        }
        self.qi_idx = (self.qi_idx + 1) % QI_ENTRIES;
        // Хвост = индекс СЛЕДУЮЩЕГО свободного слота (в единицах 16 байт).
        self.mmio.write32(regs::IQT, (self.qi_idx as u32) << 4);
    }

    /// Отправить wait-дескриптор и дождаться записи статуса
    /// (status-write + поллинг тега; таймаут по TSC — 100 мс).
    fn qi_sync(&mut self) -> Result<(), IommuError> {
        self.wait_tag = self.wait_tag.wrapping_add(1);
        let tag = self.wait_tag;
        if tag == 0 {
            self.wait_tag = 1;
        }
        // SAFETY: слово статуса — наша страница.
        unsafe { phys_ptr::<u32>(self.wait_phys).write_volatile(0) };
        // Мембар: дескриптор обязан увидеть обнулённый статус ПОСЛЕ нас.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let wait = QiWait::status_write(self.wait_phys, self.wait_tag);
        self.qi_submit(&QiDesc::Wait(wait));
        let deadline = crate::lapic::uptime_ns() + 100_000_000;
        let mut polls: u32 = 0;
        loop {
            // SAFETY: слово статуса — наша страница.
            let v = unsafe { phys_ptr::<u32>(self.wait_phys).read_volatile() };
            polls = polls.wrapping_add(1);
            if v == self.wait_tag {
                return Ok(());
            }
            if crate::lapic::uptime_ns() > deadline {
                crate::kprintln!(
                    "vtd: qi_sync TIMEOUT: tag={} read={:#x} polls={}",
                    self.wait_tag,
                    v,
                    polls
                );
                return Err(IommuError::HardwareTimeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Инвалидация контекстного кэша (глобально) + IOTLB (домен/глобально)
    /// + синхронизация. Единый «безопасный» набор после любой мутации
    /// структур (v0.6 не гонится за минимальностью инвалидаций).
    fn invalidate_all(&mut self, did: u16) -> Result<(), IommuError> {
        let cc = QiCc::new(Granularity::Global, 0, 0, 0);
        self.qi_submit(&QiDesc::ContextCache(cc));
        let iotlb = QiIotlb::new(Granularity::Domain, did, 0, 0);
        self.qi_submit(&QiDesc::Iotlb(iotlb));
        self.qi_sync()
    }

    // ==== Таблицы контекстов ====

    /// Слот context entry (16 байт) для BDF; create — выделить таблицу.
    fn context_slot(&mut self, bdf: &Bdf) -> Result<*mut ContextEntry, IommuError> {
        let bus = bdf.bus as usize;
        // SAFETY: root-таблица наша, physmap покрывает.
        let root_ent = unsafe { phys_ptr::<RootEntry>(self.root_phys).add(bus) };
        // SAFETY: как выше.
        if unsafe { root_ent.read_volatile() }.present() {
            let ct = unsafe { root_ent.read_volatile() }.context_table();
            let devfn = ((bdf.device as usize) << 3) | (bdf.function as usize & 7);
            // SAFETY: context-таблица наша.
            return Ok(unsafe { phys_ptr::<ContextEntry>(ct).add(devfn) });
        }
        let table = zero_page().ok_or(IommuError::OutOfMemory)?;
        // SAFETY: запись в root-таблицу нашу.
        unsafe { root_ent.write_volatile(RootEntry::new(table)) };
        let devfn = ((bdf.device as usize) << 3) | (bdf.function as usize & 7);
        // SAFETY: свежая обнулённая таблица.
        Ok(unsafe { phys_ptr::<ContextEntry>(table).add(devfn) })
    }

    // ==== Включение/выключение ====

    /// Инициализация по DRHD: MMIO-декод, таблицы, QI, включение TE.
    fn init(drhd: &Drhd) -> Result<Self, IommuError> {
        let mmio = Mmio {
            base: drhd.register_base(),
        };
        if drhd.register_base() >= 0x1_0000_0000 {
            return Err(IommuError::InvalidConfig); // вне physmap (v0.6)
        }
        let ver = Version::new(mmio.read32(regs::VER));
        let cap = Cap::new(mmio.read64(regs::CAP));
        let ecap = Ecap::new(mmio.read64(regs::ECAP));
        crate::kprintln!(
            "vtd: DRHD seg{} base={:#x} ver {}.{} sagaw={:#x} qi={} pt={}",
            drhd.segment(),
            drhd.register_base(),
            ver.major,
            ver.minor,
            cap.sagaw(),
            ecap.queued_inval(),
            ecap.pass_through()
        );
        // Требования v0.6: QI-инвалидации + AGAW48 (4 уровня) + legacy mode.
        if !ecap.queued_inval() {
            return Err(IommuError::NotSupported); // регистровый путь не реализуем
        }
        if cap.sagaw() & (1 << 2) == 0 {
            return Err(IommuError::NotSupported); // нет 48-бит AGAW
        }

        // Таблицы/очередь (до включения чего-либо).
        let root_phys = zero_page().ok_or(IommuError::OutOfMemory)?;
        let qi_phys = zero_page().ok_or(IommuError::OutOfMemory)?;
        let wait_phys = zero_page().ok_or(IommuError::OutOfMemory)?;

        // RTADDR (TTM=0 legacy) + SRTP.
        mmio.write64(regs::RTADDR, root_phys);
        mmio.write32(regs::GCMD, Gcmd::SRTP.bits());
        if !wait_gsts(mmio, Gsts::RTPS, 100) {
            return Err(IommuError::HardwareTimeout);
        }

        // QI: IQA = база | QS=0 (256 записей = 2^(0+8)); IQT=0; QIE.
        mmio.write64(regs::IQA, qi_phys);
        mmio.write32(regs::IQT, 0);
        mmio.write32(regs::GCMD, Gcmd::QIE.bits());
        if !wait_gsts(mmio, Gsts::QIES, 100) {
            return Err(IommuError::HardwareTimeout);
        }

        let mut vtd = Vtd {
            mmio,
            ver,
            cap,
            ecap,
            segment: drhd.segment(),
            include_all: drhd.include_pci_all(),
            scope_rids: Vec::new(),
            root_phys,
            qi_phys,
            qi_idx: 0,
            wait_phys,
            wait_tag: 0,
            domains: BTreeMap::new(),
            devices: BTreeMap::new(),
            next_did: 1,
            next_dev: 1,
        };
        // Scope DRHD: endpoints (типы 1..3 — endpoint/bridge/...). v0.6
        // покрывает точные RID; иерархии мостов — расширение.
        for sc in drhd.scopes() {
            if let Some(rid) = sc.first_source_id() {
                vtd.scope_rids.push((rid, rid));
            }
        }

        // Первичная инвалидация кэшей (чистый старт) + включение DMA-TE.
        vtd.invalidate_all(0)?;
        // ВАЖНО (баг v0.6.1): каждый бит GCMD — ЗАПРОС на изменение.
        // Запись ENABLE без бита QIE означала «выключи QI» — QEMU гасил
        // очередную инвалидацию (vtd_inv_qi_enable enabled 0), и все
        // последующие qi_sync таймаутили (EIO на ATTACH). Включаем
        // трансляцию, ПОДДЕРЖИВАЯ QIE; SRTP — one-shot, повтор не нужен.
        vtd.mmio
            .write32(regs::GCMD, (Gcmd::ENABLE | Gcmd::QIE).bits());
        if !wait_gsts(vtd.mmio, Gsts::TES, 100) || !wait_gsts(vtd.mmio, Gsts::QIES, 100) {
            return Err(IommuError::HardwareTimeout);
        }
        crate::kprintln!(
            "vtd: translation enabled (domains={})",
            vtd.cap.domain_ids()
        );
        Ok(vtd)
    }

    // ==== Операции устройства ====

    fn attach_bdf(&mut self, bdf: Bdf) -> Result<u32, IommuError> {
        // Покрытие: INCLUDE_PCI_ALL или точный scope (сегмент DRHD).
        if bdf.segment != self.segment {
            return Err(IommuError::UnknownDevicePath);
        }
        let rid = bdf.to_requester_id();
        if !self.include_all && !self.scope_rids.iter().any(|&(a, b)| rid >= a && rid <= b) {
            crate::kprintln!(
                "vtd: attach {} rejected: rid={:#x} include_all={} scopes={:#x?}",
                bdf,
                rid,
                self.include_all,
                self.scope_rids
            );
            return Err(IommuError::UnknownDevicePath);
        }
        // Идемпотентность: повторный attach того же BDF — тот же DeviceId.
        if let Some((&id, _)) = self.devices.iter().find(|(_, b)| b.bdf == bdf) {
            return Ok(id);
        }
        // Домен и идентификаторы.
        let did = self.next_did;
        if did as u32 >= self.cap.domain_ids() {
            return Err(IommuError::OutOfMemory);
        }
        self.next_did += 1;
        let dev = self.next_dev;
        if dev == 0 {
            return Err(IommuError::OutOfMemory);
        }
        self.next_dev += 1;
        let sspt = zero_page().ok_or(IommuError::OutOfMemory)?;

        // Context entry: P | TT=SecondStage | SSPTPTR | DID | AGAW48.
        let slot = self.context_slot(&bdf)?;
        let entry = ContextEntry::new()
            .with_present(true)
            .with_fault_disable(false)
            .with_translation_type(TransType::SecondStage)
            .with_second_stage_ptr(sspt)
            .with_address_width(AddrWidth::Agaw48)
            .with_domain_id(did);
        // SAFETY: слот context-таблицы наш.
        unsafe { slot.write_volatile(entry) };

        self.domains.insert(
            did,
            Domain {
                sspt_root: sspt,
                mappings: BTreeMap::new(),
            },
        );
        self.devices.insert(dev, DevBind { bdf, did });
        self.invalidate_all(did)?;
        crate::kprintln!("vtd: attach {} -> dev {} did {}", bdf, dev, did);
        Ok(dev)
    }

    fn did_of(&self, dev: u32) -> Result<(u16, u64), IommuError> {
        let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
        let dom = self
            .domains
            .get(&bind.did)
            .ok_or(IommuError::DeviceNotBound)?;
        Ok((bind.did, dom.sspt_root))
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
        if iova + (count as u64) * 4096 > (1u64 << 48) {
            return Err(IommuError::InvalidConfig); // вне AGAW48
        }
        let (did, root) = {
            let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
            let dom = self
                .domains
                .get(&bind.did)
                .ok_or(IommuError::DeviceNotBound)?;
            (bind.did, dom.sspt_root)
        };
        // Конфликт IOVA: пересечение с существующими диапазонами домена.
        {
            let dom = self.domains.get(&did).ok_or(IommuError::DeviceNotBound)?;
            let end = iova + (count as u64) * 4096;
            for (&base, &(_, pages, _)) in &dom.mappings {
                let bend = base + (pages as u64) * 4096;
                if base < end && iova < bend {
                    return Err(IommuError::IovaConflict);
                }
            }
        }
        for i in 0..count as u64 {
            let slot = sspt_slot(root, iova + i * 4096, true).ok_or(IommuError::OutOfMemory)?;
            // SAFETY: слот — leaf PTE домена (наш).
            unsafe { slot.write_volatile((phys + i * 4096) | sspte_prot(prot)) };
        }
        let dom = self
            .domains
            .get_mut(&did)
            .ok_or(IommuError::DeviceNotBound)?;
        dom.mappings.insert(iova, (phys, count, prot));
        self.invalidate_all(did)
    }

    fn unmap(&mut self, dev: u32, iova: u64, count: usize) -> Result<(), IommuError> {
        if iova % 4096 != 0 || count == 0 {
            return Err(IommuError::InvalidConfig);
        }
        let (did, root) = {
            let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
            let dom = self
                .domains
                .get(&bind.did)
                .ok_or(IommuError::DeviceNotBound)?;
            (bind.did, dom.sspt_root)
        };
        let had = {
            let dom = self.domains.get(&did).ok_or(IommuError::DeviceNotBound)?;
            dom.mappings.contains_key(&iova)
        };
        if !had {
            return Err(IommuError::MappingNotFound);
        }
        for i in 0..count as u64 {
            if let Some(slot) = sspt_slot(root, iova + i * 4096, false) {
                // SAFETY: слот — leaf PTE домена (наш).
                unsafe { slot.write_volatile(0) };
            }
        }
        let dom = self
            .domains
            .get_mut(&did)
            .ok_or(IommuError::DeviceNotBound)?;
        // Полное снятие диапазона (частичное — v0.7 с реестром под-страниц).
        if let Some((_, pages, _)) = dom.mappings.remove(&iova) {
            if pages < count {
                // Снято больше, чем было: вернуть в карту хвост (не терять).
                dom.mappings.insert(
                    iova + (pages as u64) * 4096,
                    (0, count - pages, IommuProt::READ),
                );
            }
        }
        self.invalidate_all(did)
    }

    fn set_protection(&mut self, dev: u32, prot: IommuProt) -> Result<(), IommuError> {
        let (did, root) = {
            let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
            let dom = self
                .domains
                .get(&bind.did)
                .ok_or(IommuError::DeviceNotBound)?;
            (bind.did, dom.sspt_root)
        };
        let ranges: Vec<(u64, u64, usize)> = {
            let dom = self.domains.get(&did).ok_or(IommuError::DeviceNotBound)?;
            dom.mappings
                .iter()
                .map(|(&k, &(p, n, _))| (k, p, n))
                .collect()
        };
        for (iova, phys, pages) in ranges {
            for i in 0..pages as u64 {
                if let Some(slot) = sspt_slot(root, iova + i * 4096, false) {
                    // SAFETY: слот — leaf PTE домена (наш).
                    unsafe { slot.write_volatile((phys + i * 4096) | sspte_prot(prot)) };
                }
            }
        }
        let dom = self
            .domains
            .get_mut(&did)
            .ok_or(IommuError::DeviceNotBound)?;
        for e in dom.mappings.values_mut() {
            e.2 = prot;
        }
        self.invalidate_all(did)
    }

    fn detach(&mut self, dev: u32) -> Result<(), IommuError> {
        let bind = self
            .devices
            .remove(&dev)
            .ok_or(IommuError::DeviceNotBound)?;
        // Context entry -> not present.
        let slot = self.context_slot(&bind.bdf)?;
        // SAFETY: слот наш.
        unsafe { slot.write_volatile(ContextEntry::new()) };
        // Таблицы домена — в пул (только если устройств домена не осталось).
        let still_used = self.devices.values().any(|b| b.did == bind.did);
        if !still_used {
            if let Some(dom) = self.domains.remove(&bind.did) {
                sspt_free(dom.sspt_root);
            }
        }
        self.invalidate_all(bind.did)
    }
}

/// Дождаться установки битов GSTS (попытки по ~1 мс, TSC-таймаут).
fn wait_gsts(mmio: Mmio, bits: Gsts, ms: u64) -> bool {
    let deadline = crate::lapic::uptime_ns() + ms * 1_000_000;
    while mmio.read32(regs::GSTS as u64) & bits.bits() == 0 {
        if crate::lapic::uptime_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

// ───────────────────── КОНТРАКТ ЯДРА: IOMMU ─────────────────────

/// Драйвер как единица LIOMMUInterface.
pub struct VtdDriver {
    inner: Mutex<Option<Vtd>>,
    /// Порядковый номер контроллера (IommuId).
    id: u32,
    /// Готовность (init прошёл; ставится один раз до старта AP).
    ready: AtomicBool,
}

impl VtdDriver {
    const fn new(id: u32) -> Self {
        Self {
            inner: Mutex::new(None),
            id,
            ready: AtomicBool::new(false),
        }
    }

    /// Пометить готовым (init_and_install после успешного Vtd::init).
    fn mark_ready(&self) {
        self.ready.store(true, AtomicOrdering::Release);
    }
}

/// Информация о контроллере для IOMMU_ENUM (сискол).
#[derive(Debug, Clone, Copy)]
pub struct VtdInfo {
    pub major: u8,
    pub minor: u8,
    pub agaw48: bool,
    pub qi: bool,
    pub pass_through: bool,
    pub include_all: bool,
    pub mgaw: u32,
    pub domains: u32,
}

impl VtdDriver {
    fn info(&self) -> Option<VtdInfo> {
        let g = self.inner.lock();
        g.as_ref().map(|v| VtdInfo {
            major: v.ver.major,
            minor: v.ver.minor,
            agaw48: v.cap.sagaw() & (1 << 2) != 0,
            qi: v.ecap.queued_inval(),
            pass_through: v.ecap.pass_through(),
            include_all: v.include_all,
            mgaw: v.cap.mgaw(),
            domains: v.cap.domain_ids(),
        })
    }
}

impl ANIOMMUInterface for VtdDriver {
    fn iommu_id(&self) -> pkg_generic_interface::hal::traits::iommu::IommuId {
        pkg_generic_interface::hal::traits::iommu::IommuId(self.id)
    }

    fn map_pages(
        &mut self,
        dev: DeviceId,
        iova: u64,
        phys: pkg_generic_interface::hal::types::PhysAddr,
        count: usize,
        prot: IommuProt,
    ) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .map(dev.0, iova, phys.0, count, prot)
    }

    fn unmap_pages(&mut self, dev: DeviceId, iova: u64, count: usize) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .unmap(dev.0, iova, count)
    }

    fn set_protection(&mut self, dev: DeviceId, prot: IommuProt) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .set_protection(dev.0, prot)
    }

    fn detach_device(&mut self, dev: DeviceId) -> Result<(), IommuError> {
        let mut g = self.inner.lock();
        g.as_mut().ok_or(IommuError::IommuNotPresent)?.detach(dev.0)
    }
}

/// Контекст перечисления для resolve_device (сегмент DRHD).
pub struct DmarScope {
    pub segment: u16,
}

impl LIOMMUInterface for VtdDriver {
    type Processor = DmarScope;

    fn init_iommu_state(&mut self, _processor: &Self::Processor) {
        // Состояние строится при обнаружении DRHD (init_and_install);
        // сюда попадают только будущие динамические расширения.
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
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .attach_bdf(bdf)
            .map(DeviceId)
    }
}

// ───────────────────── Сервис сисколов ─────────────────────

/// Единственный контроллер v0.6 (IommuId(1)); 0 = «нет».
pub static VTD0: VtdDriver = VtdDriver::new(1);

impl IommuService for VtdDriver {
    fn controller_count(&self) -> usize {
        if self.ready.load(AtomicOrdering::Acquire) {
            1
        } else {
            0
        }
    }

    fn controller_info(
        &self,
        idx: u32,
    ) -> Result<pkg_generic_interface::syscall::iommu::IommuInfo, IommuError> {
        if idx != 0 || !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let i = self.info().ok_or(IommuError::IommuNotPresent)?;
        Ok(pkg_generic_interface::syscall::iommu::IommuInfo {
            version: ((i.major as u16) << 8) | i.minor as u16,
            mgaw_bits: i.mgaw as u8,
            agaw48: i.agaw48,
            queued_inval: i.qi,
            pass_through: i.pass_through,
            include_all: i.include_all,
        })
    }

    fn attach(&self, ctrl: u32, bus: u8, device: u8, function: u8) -> Result<u32, IommuError> {
        if ctrl != 0 || !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
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
        if ctrl != 0 || !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let prot = IommuProt::from_bits_truncate(prot);
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .map(device, iova, phys, pages, prot)
    }

    fn unmap_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        pages: usize,
    ) -> Result<(), IommuError> {
        if ctrl != 0 || !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .unmap(device, iova, pages)
    }

    fn detach(&self, ctrl: u32, device: u32) -> Result<(), IommuError> {
        if ctrl != 0 || !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let mut g = self.inner.lock();
        g.as_mut()
            .ok_or(IommuError::IommuNotPresent)?
            .detach(device)
    }
}

// ───────────────────── Запуск (X86Platform::run) ─────────────────────

/// Поиск DMAR -> первый пригодный DRHD -> init драйвера -> установка
/// сервиса сисколов. Вызывается ПОСЛЕ kinit (пулы/куча подняты), ДО
/// release_aps (конкуренции ещё нет — APы припаркованы).
pub fn init_and_install() {
    // Пул не поднят (ранний fatal-путь run()) — тихо уходим: сисколы
    // ответят ENOSYS.
    if pkg_generic_interface::mem::gallocator::frames().is_none() {
        return;
    }
    let rsdp = crate::smp::topology().rsdp_phys;
    if rsdp == 0 {
        crate::kprintln!("vtd: no RSDP — IOMMU unavailable");
        return;
    }
    let found = crate::smp::find_table(rsdp, b"DMAR", |p, n| {
        let mut out = [0u8; 8];
        // SAFETY: physmap покрывает таблицы прошивки.
        let src = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(p), n) };
        out[..n].copy_from_slice(&src[..n]);
        out
    });
    let (phys, len) = match found {
        Ok(x) => x,
        Err(_) => {
            crate::kprintln!("vtd: no DMAR table — IOMMU unavailable (QEMU: -device intel-iommu)");
            return;
        }
    };
    // SAFETY: таблица прошивки живёт всю сессию.
    let slice = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(phys), len) };
    let dmar = match DmarTable::new(slice) {
        Ok(d) => d,
        Err(e) => {
            crate::kprintln!("vtd: DMAR parse failed: {:?}", e);
            return;
        }
    };
    // Предпочитаем INCLUDE_PCI_ALL DRHD; иначе первый.
    let drhds: Vec<Drhd> = dmar.drhd_units().collect();
    for d in &drhds {
        crate::kprintln!(
            "vtd: DMAR DRHD seg={:#x} include_all={} scopes={}",
            d.segment(),
            d.include_pci_all(),
            d.scopes().count()
        );
    }
    let pick = drhds
        .iter()
        .find(|d| d.include_pci_all())
        .or_else(|| drhds.first());
    let drhd = match pick {
        Some(d) => *d,
        None => {
            crate::kprintln!("vtd: DMAR without DRHD units");
            return;
        }
    };
    match Vtd::init(&drhd) {
        Ok(v) => {
            *VTD0.inner.lock() = Some(v);
            // Готовность сервиса: помечаем ПОСЛЕ заполнения (release_aps
            // ещё не было — конкурентов нет).
            VTD0.mark_ready();
            // Связка с syscall-слоем: без этого SERVICE=None и все
            // IOMMU_* отвечают ENOSYS (баг v0.6.1: печатали «syscalls
            // live», но Once не заполняли — init видел «no controllers»).
            pkg_generic_interface::syscall::iommu::install_iommu_service(&VTD0);
            crate::kprintln!("vtd: IommuService installed (IOMMU_* syscalls live)");
        }
        Err(e) => {
            crate::kprintln!("vtd: init failed: {:?} (IOMMU syscalls -> ENOSYS)", e);
        }
    }
}
