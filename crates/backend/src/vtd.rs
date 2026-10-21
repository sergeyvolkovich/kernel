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
// AMD-Vi (IVRS) — драйвер-собрат `backend/amd.rs`; выбор вендора и
// установка сервиса сисколов — агрегатор `crate::iommu`. IRQ-ремаппинг
// (IRTE/IRTA) — v0.8: IRTA+SIRTP+IEC-флеш+IRE (Intel); мульти-IOMMU —
// ВСЕ DRHD-единицы поднимаются и индексируются (IommuService.ctrl).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use spin::Mutex;

use intel_iommu::context::{AddrWidth, ContextEntry, RootEntry, TransType};
use intel_iommu::dmar::{DmarTable, Drhd};
use intel_iommu::irte::{DeliveryMode, Irte, SourceQualifier, SourceValidationType};
use intel_iommu::qi::{Granularity, QiCc, QiDesc, QiIec, QiIotlb, QiWait};
use intel_iommu::regs::{self, Cap, Ecap, Gcmd, Gsts, Irta, Version};

use pkg_generic_interface::hal::traits::iommu::{
    ANIOMMUInterface, DeviceId, IommuError, LIOMMUInterface,
};
use pkg_generic_interface::hal::types::{Bdf, DevicePath, IommuProt};
use pkg_generic_interface::syscall::iommu::IommuService;

use crate::iommu::{Mmio, free_page, zero_page};
use crate::memory::phys_ptr;

// ───────────────────── Second-stage таблицы (EPT-подобные, 4 уровня) ─────────────────────

/// SS-PTE: R(0) W(1) X(2); промежуточные — R|W (проход доступен).
const SSPTE_RW: u64 = 0b011;
const SSPTE_R: u64 = 0b001;
const SSPTE_X: u64 = 0b100;

/// Бит large-page листа уровня 2 (SS-PDE → 2 МиБ, v0.8).
const SSPDE_HUGE: u64 = 0b1000_0000;
/// Размер huge-листа SS-PDE (уровень 2).
const SS_HUGEP: u64 = 512 * 4096;
/// Записей IRTE в IRTA (v0.8): S=7 → 2^(7+1) = 256 × 16 байт = 4 КиБ.
const IRTE_COUNT: usize = 256;

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

/// Слот листовой PTE (уровень 1) для IOVA; create — выделять каталоги.
fn sspt_slot(root: u64, iova: u64, create: bool) -> Option<*mut u64> {
    sspt_slot_level(root, iova, 1, create)
}

/// Слот записи на заданном уровне (2 = SS-PDE для huge-листа, 1 = PTE);
/// create — выделять промежуточные каталоги. v0.8: уровень фиксируем
/// явно — huge-лист 2 МиБ пишется в PDE уровня 2, минуя уровень 1.
/// Уровни AGAW48: биты IOVA 47:39 / 38:30 / 29:21 / 20:12.
fn sspt_slot_level(root: u64, iova: u64, level: u32, create: bool) -> Option<*mut u64> {
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
    unreachable!("уровни исчерпаны")
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
            // v0.8: huge-лист уровня 2 (бит PS) — НЕ таблица: физика за
            // ним принадлежит отображению и в пул не возвращается.
            if level == 2 && val & SSPDE_HUGE != 0 {
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
    /// iova -> (phys, pages, prot, huge). v0.8: раскладка таблиц
    /// детерминированно повторяет проход map — unmap/set_protection
    /// идентичны (huge-флаг информативен, обход — по той же геометрии).
    mappings: BTreeMap<u64, (u64, usize, IommuProt, bool)>,
}

/// Привязка DeviceId -> (BDF, домен).
struct DevBind {
    bdf: Bdf,
    did: u16,
}

// ───────────────────── Драйвер ─────────────────────

/// Состояние драйвера VT-d — ОДИН контроллер (одна DRHD-единица);
/// мульти-IOMMU — несколько Vtd в [`VtdDriver`] (v0.8).
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
    // v0.8: IRQ-ремаппинг (глобальная IRTA этого контроллера).
    irta_phys: u64,
    /// IRE включён (ECAP.IR был и последовательность прошла).
    ir_enabled: bool,
    /// Занятость IRTE-слотов (IRTE_COUNT; резервы — 0 и 0x10..=0x25).
    ir_used: Vec<bool>,
    /// Устройство -> выделенные ему IRTE-индексы (погашение по handle).
    dev_irqs: BTreeMap<u32, Vec<u16>>,
    /// v0.8: 2 МиБ huge-листья поддерживаются (CAP.SSLPS bit0) и работают.
    huge_ok: bool,
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
        let mmio = Mmio::new(drhd.register_base());
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
            irta_phys: 0,
            ir_enabled: false,
            ir_used: Vec::new(),
            dev_irqs: BTreeMap::new(),
            huge_ok: cap.sslps() & 0b01 != 0,
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
            "vtd: translation enabled (domains={}, huge_pages={})",
            vtd.cap.domain_ids(),
            vtd.huge_ok
        );

        // v0.8: IRQ-ремаппинг — IRTA (256 IRTE = 4 КиБ) -> SIRTP ->
        // IEC-флеш (QI) -> IRE. КАЖДЫЙ бит GCMD — ЗАПРОС (баг v0.6.1):
        // вместе с one-shot SIRTP/IRE держим уже включённые ENABLE|QIE,
        // иначе погасим трансляцию/очередь. EIME=0: ядро в xAPIC-режиме,
        // 8-битные APIC-ID (EIM не нужен).
        if vtd.ecap.intr_remap() {
            let irta = zero_page().ok_or(IommuError::OutOfMemory)?;
            vtd.mmio.write64(regs::IRTA, Irta::new(irta, 7, false).0);
            vtd.mmio
                .write32(regs::GCMD, (Gcmd::ENABLE | Gcmd::QIE | Gcmd::SIRTP).bits());
            if !wait_gsts(vtd.mmio, Gsts::IRTPS, 100) {
                crate::kprintln!("vtd: SIRTP timeout — IRQ-ремаппинг выключен");
                free_page(irta);
            } else {
                // IEC (interrupt-entry cache) — глобальный флеш ДО IRE.
                vtd.qi_submit(&QiDesc::Iec(QiIec::new(true, 0, 0)));
                vtd.qi_sync()?;
                vtd.mmio
                    .write32(regs::GCMD, (Gcmd::ENABLE | Gcmd::QIE | Gcmd::IRE).bits());
                if !wait_gsts(vtd.mmio, Gsts::IRES, 100) {
                    crate::kprintln!("vtd: IRE timeout — IRQ-ремаппинг выключен");
                    free_page(irta);
                } else {
                    vtd.irta_phys = irta;
                    vtd.ir_enabled = true;
                    vtd.ir_used = alloc::vec![false; IRTE_COUNT];
                    crate::kprintln!("vtd: interrupt remapping enabled (irte={})", IRTE_COUNT);
                }
            }
        } else {
            crate::kprintln!("vtd: ECAP.IR=0 — IRQ-ремаппинг недоступен");
        }
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
            for (&base, &(_, pages, _, _)) in &dom.mappings {
                let bend = base + (pages as u64) * 4096;
                if base < end && iova < bend {
                    return Err(IommuError::IovaConflict);
                }
            }
        }
        // v0.8: раскладка — детерминированный проход: 2 МиБ-выровненный
        // кусок >= 512 стр при huge_ok пишется ОДНИМ SS-PDE (huge-лист),
        // остальное — 4К PTE. Раскладка одинакова у map/unmap/protect —
        // записи обходятся без хранения зеркала таблиц.
        let mut used_huge = false;
        let mut i = 0u64;
        while i < count as u64 {
            let a = iova + i * 4096;
            let p = phys + i * 4096;
            let left = count as u64 - i;
            if self.huge_ok && left >= 512 && a % SS_HUGEP == 0 && p % SS_HUGEP == 0 {
                let slot = sspt_slot_level(root, a, 2, true).ok_or(IommuError::OutOfMemory)?;
                // SAFETY: слот — SS-PDE домена (наш).
                unsafe { slot.write_volatile(p | SSPDE_HUGE | sspte_prot(prot)) };
                i += 512;
                used_huge = true;
                crate::kprintln!("vtd: map huge 2MiB iova={:#x} -> phys={:#x}", a, p);
            } else {
                let slot = sspt_slot(root, a, true).ok_or(IommuError::OutOfMemory)?;
                // SAFETY: слот — leaf PTE домена (наш).
                unsafe { slot.write_volatile(p | sspte_prot(prot)) };
                i += 1;
            }
        }
        let dom = self
            .domains
            .get_mut(&did)
            .ok_or(IommuError::DeviceNotBound)?;
        dom.mappings.insert(iova, (phys, count, prot, used_huge));
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
        // v0.8: точное снятие — (iova, count) обязан совпадать с записью
        // карты (частичное снятие с расщеплением huge-листьев — v0.9;
        // см. CHANGES). Раскладка повторяет map — обход без зеркала.
        let rec = {
            let dom = self.domains.get(&did).ok_or(IommuError::DeviceNotBound)?;
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
            if self.huge_ok && left >= 512 && a % SS_HUGEP == 0 && p % SS_HUGEP == 0 {
                if let Some(slot) = sspt_slot_level(root, a, 2, false) {
                    // SAFETY: слот — SS-PDE домена (наш).
                    unsafe { slot.write_volatile(0) };
                }
                i += 512;
            } else {
                if let Some(slot) = sspt_slot(root, a, false) {
                    // SAFETY: слот — leaf PTE домена (наш).
                    unsafe { slot.write_volatile(0) };
                }
                i += 1;
            }
        }
        self.domains
            .get_mut(&did)
            .ok_or(IommuError::DeviceNotBound)?
            .mappings
            .remove(&iova);
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
                .map(|(&k, &(p, n, _, _))| (k, p, n))
                .collect()
        };
        for (iova, phys, pages) in ranges {
            let mut i = 0u64;
            while i < pages as u64 {
                let a = iova + i * 4096;
                let p = phys + i * 4096;
                let left = pages as u64 - i;
                if self.huge_ok && left >= 512 && a % SS_HUGEP == 0 && p % SS_HUGEP == 0 {
                    if let Some(slot) = sspt_slot_level(root, a, 2, false) {
                        // SAFETY: слот — SS-PDE домена (наш).
                        unsafe { slot.write_volatile(p | SSPDE_HUGE | sspte_prot(prot)) };
                    }
                    i += 512;
                } else {
                    if let Some(slot) = sspt_slot(root, a, false) {
                        // SAFETY: слот — leaf PTE домена (наш).
                        unsafe { slot.write_volatile(p | sspte_prot(prot)) };
                    }
                    i += 1;
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
        // v0.8: IRTE устройства гасим (handle'ы больше не действуют).
        if self.ir_enabled {
            let handles = self.dev_irqs.remove(&dev).unwrap_or_default();
            for idx in handles {
                // SAFETY: IRT — наша страница.
                unsafe {
                    let p = phys_ptr::<u64>(self.irta_phys).add(idx as usize * 2);
                    p.write_volatile(0);
                    p.add(1).write_volatile(0);
                }
                if (idx as usize) < IRTE_COUNT {
                    self.ir_used[idx as usize] = false;
                }
            }
            // IEC-флеш — гасим кэш записей погашенного устройства.
            self.qi_submit(&QiDesc::Iec(QiIec::new(true, 0, 0)));
            self.qi_sync()?;
        }
        // Таблицы домена — в пул (только если устройств домена не осталось).
        let still_used = self.devices.values().any(|b| b.did == bind.did);
        if !still_used {
            if let Some(dom) = self.domains.remove(&bind.did) {
                sspt_free(dom.sspt_root);
            }
        }
        self.invalidate_all(bind.did)
    }

    // ==== IRQ-ремаппинг (v0.8) ====

    /// Занят ли IRTE-слот (резервы: 0 — системный «нет handle»,
    /// 0x10..=0x25 — диапазон IOAPIC по спеке (0x10+pin), не выдаём).
    fn irte_slot_free(&self, idx: u16) -> bool {
        idx != 0 && !(0x10..=0x25).contains(&idx) && !self.ir_used[idx as usize]
    }

    /// Запрограммировать IRTE (remapped-формат): P|vector|dest|SVT-проверка
    /// источника по RID устройства. Возврат — handle (индекс IRTE).
    fn irq_map(&mut self, dev: u32, vector: u8, dest: u8, flags: u8) -> Result<u32, IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        if !(0x10..=0xFE).contains(&vector) {
            return Err(IommuError::InvalidConfig);
        }
        let bind = self.devices.get(&dev).ok_or(IommuError::DeviceNotBound)?;
        let rid = bind.bdf.to_requester_id();
        let idx = (0..IRTE_COUNT as u16)
            .find(|&i| self.irte_slot_free(i))
            .ok_or(IommuError::OutOfMemory)? as usize;
        let irte = Irte::new_remapped()
            .with_present(true)
            .with_trigger_mode_level(flags & 1 != 0)
            .with_destination_mode_logical(flags & 2 != 0)
            .with_delivery_mode(DeliveryMode::Fixed)
            .with_vector(vector)
            .with_destination(dest as u32)
            .with_source_id(rid)
            // SVT=11b (VerifyFull) + SQ=01b: шина+устройство обязаны
            // совпасть, функция игнорируется (мосты подменяют function
            // часть RID при пробросе — сверка не ломается).
            .with_source_qualifier(SourceQualifier::IgnoreFunction)
            .with_source_validation(SourceValidationType::VerifyFull);
        let w = irte.words();
        // SAFETY: IRT — наша страница, 16 байт на IRTE.
        unsafe {
            let p = phys_ptr::<u64>(self.irta_phys).add(idx * 2);
            p.write_volatile(w[0]);
            p.add(1).write_volatile(w[1]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // IEC — выборочная инвалидация одного IRTE (IM=0: 2^0 = 1 запись).
        self.qi_submit(&QiDesc::Iec(QiIec::new(false, idx as u16, 0)));
        self.qi_sync()?;
        self.ir_used[idx] = true;
        self.dev_irqs.entry(dev).or_default().push(idx as u16);
        crate::kprintln!(
            "vtd: irte dev={} idx={} vec={:#x} dst={:#x} lvl={} log={}",
            dev,
            idx,
            vector,
            dest,
            flags & 1 != 0,
            flags & 2 != 0
        );
        Ok(idx as u32)
    }

    /// Погасить IRTE по handle (только владелец).
    fn irq_unmap(&mut self, dev: u32, handle: u32) -> Result<(), IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        let idx = handle as usize;
        if idx >= IRTE_COUNT || !self.ir_used[idx] {
            return Err(IommuError::InvalidConfig);
        }
        let owns = self
            .dev_irqs
            .get(&dev)
            .is_some_and(|v| v.contains(&(idx as u16)));
        if !owns {
            return Err(IommuError::DeviceNotBound);
        }
        // SAFETY: IRT — наша страница.
        unsafe {
            let p = phys_ptr::<u64>(self.irta_phys).add(idx * 2);
            p.write_volatile(0);
            p.add(1).write_volatile(0);
        }
        self.qi_submit(&QiDesc::Iec(QiIec::new(false, idx as u16, 0)));
        self.qi_sync()?;
        self.ir_used[idx] = false;
        if let Some(v) = self.dev_irqs.get_mut(&dev) {
            v.retain(|&x| x != idx as u16);
        }
        Ok(())
    }

    /// v0.11, IOAPIC: IRTE линии `pin` в Зарезервированном слоте 0x10+pin
    /// (спека VT-d: индексы 0x10..0x25 — IOxAPIC lines; irte_slot_free
    /// их не выдаёт устройствам — слоты принадлежат этому пути).
    ///
    /// SVT=00b (NoValidation): у remapped-запроса от IOxAPIC нет
    /// requester-id (источник — сам контроллер линий) — проверка
    /// источника по спеке не выполняется. Вектор/назначение — как у
    /// обычного remapped-прерывания: IOAPIC RTE в remapped-формате
    /// несёт только handle (индекс этой записи) и триггер.
    fn ioapic_irte(
        &mut self,
        pin: u8,
        vector: u8,
        dest: u8,
        level: bool,
    ) -> Result<(), IommuError> {
        if !self.ir_enabled {
            return Err(IommuError::RemappingDisabled);
        }
        if pin as u16 + 0x10 > 0x25 {
            // Зарезервированный диапазон кончился (q35 хватает на все
            // 22+2 линии; расширение — инвентарь слотов v0.12).
            return Err(IommuError::InvalidConfig);
        }
        if !(0x10..=0xFE).contains(&vector) {
            return Err(IommuError::InvalidConfig);
        }
        let idx = (0x10 + pin as u16) as usize;
        let irte = Irte::new_remapped()
            .with_present(true)
            .with_trigger_mode_level(level)
            .with_destination_mode_logical(false)
            .with_delivery_mode(DeliveryMode::Fixed)
            .with_vector(vector)
            .with_destination(dest as u32)
            // SVT=00b: источника (requester-id) у IOxAPIC-запроса нет.
            .with_source_validation(SourceValidationType::NoValidation);
        let w = irte.words();
        // SAFETY: IRT — наша страница, 16 байт на IRTE.
        unsafe {
            let p = phys_ptr::<u64>(self.irta_phys).add(idx * 2);
            p.write_volatile(w[0]);
            p.add(1).write_volatile(w[1]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // IEC — выборочная инвалидация одной записи.
        self.qi_submit(&QiDesc::Iec(QiIec::new(false, idx as u16, 0)));
        self.qi_sync()?;
        self.ir_used[idx] = true;
        crate::kprintln!(
            "vtd: ioapic irte pin={} idx={} vec={:#x} dst={:#x} lvl={}",
            pin,
            idx,
            vector,
            dest,
            level
        );
        Ok(())
    }
}

// ───────────────────── IOAPIC-поверхность драйвера (v0.11) ─────────────────────

/// Завести IRTE для линии IOAPIC (единый интерфейс для ioapic.rs).
///
/// Единица 0: QEMU intel-iommu перехватывает IOxAPIC-запросы единицей,
/// охватывающей контроллер (в наших прогонах — первый DRHD); мульти-
/// IOMMU с несколькими IOAPIC в разных сегментах — v0.12+ (инвентарь).
pub fn ioapic_irte(pin: u8, vector: u8, dest: u8, level: bool) -> Result<(), IommuError> {
    let mut g = VTD0.inner.lock();
    match g.get_mut(0) {
        Some(v) => v.ioapic_irte(pin, vector, dest, level),
        None => Err(IommuError::IommuNotPresent),
    }
}

/// IRQ-ремаппинг включён хоть на одной единице Intel (ioapic.rs решает,
/// каким вендором ремапить линию; Intel приоритетнее: remapped-RTE).
pub fn irq_remap_enabled() -> bool {
    let g = VTD0.inner.lock();
    g.first().is_some_and(|v| v.ir_enabled)
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

/// Драйвер Intel VT-d — ВСЕ поднятые DRHD-единицы (мульти-IOMMU, v0.8).
/// HAL-путь (ANIOMMUInterface) неймспейсит DeviceId парой
/// (контроллер << 20 | локальный id) — операции знают контроллер;
/// сисколы передают контроллер ОТДЕЛЬНЫМ аргументом и работают
/// с локальными id (ABI v0.6 не меняется).
pub struct VtdDriver {
    inner: Mutex<Vec<Vtd>>,
    /// Порядковый номер драйвера-вендора (IommuId).
    id: u32,
    /// Готовность (init прошёл; ставится один раз до старта AP).
    ready: AtomicBool,
}

impl VtdDriver {
    const fn new(id: u32) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            id,
            ready: AtomicBool::new(false),
        }
    }

    /// Пометить готовым (try_init после успешных Vtd::init).
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
pub struct VtdInfo {
    pub major: u8,
    pub minor: u8,
    pub agaw48: bool,
    pub qi: bool,
    pub pass_through: bool,
    pub include_all: bool,
    pub mgaw: u32,
    pub domains: u32,
    /// v0.8: IRQ-ремаппинг включён.
    pub irq_remap: bool,
    /// v0.8: 2 МиБ huge-листья работают.
    pub large_pages: bool,
}

impl VtdDriver {
    fn info(&self, ctrl: u32) -> Option<VtdInfo> {
        let g = self.inner.lock();
        g.get(ctrl as usize).map(|v| VtdInfo {
            major: v.ver.major,
            minor: v.ver.minor,
            agaw48: v.cap.sagaw() & (1 << 2) != 0,
            qi: v.ecap.queued_inval(),
            pass_through: v.ecap.pass_through(),
            include_all: v.include_all,
            mgaw: v.cap.mgaw(),
            domains: v.cap.domain_ids(),
            irq_remap: v.ir_enabled,
            large_pages: v.huge_ok,
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
        // v0.8: мульти-IOMMU — перебираем контроллеры, побеждает первый,
        // чей coverage (scope/INCLUDE_PCI_ALL) принимает BDF; DeviceId
        // неймспейсится контроллером (см. hal_dev_id).
        let mut g = self.inner.lock();
        for (ctrl, unit) in g.iter_mut().enumerate() {
            if let Ok(local) = unit.attach_bdf(bdf) {
                return Ok(DeviceId(hal_dev_id(ctrl as u32, local)));
            }
        }
        Err(IommuError::UnknownDevicePath)
    }
}

// ───────────────────── Сервис сисколов ─────────────────────

/// Драйвер Intel VT-d (все DRHD-единицы); IommuId(1), 0 = «нет».
pub static VTD0: VtdDriver = VtdDriver::new(1);

impl IommuService for VtdDriver {
    fn controller_count(&self) -> usize {
        VtdDriver::controller_count(self)
    }

    fn controller_info(
        &self,
        idx: u32,
    ) -> Result<pkg_generic_interface::syscall::iommu::IommuInfo, IommuError> {
        if !self.ready.load(AtomicOrdering::Acquire) {
            return Err(IommuError::InvalidIndex);
        }
        let i = self.info(idx).ok_or(IommuError::InvalidIndex)?;
        Ok(pkg_generic_interface::syscall::iommu::IommuInfo {
            version: ((i.major as u16) << 8) | i.minor as u16,
            mgaw_bits: i.mgaw as u8,
            agaw48: i.agaw48,
            queued_inval: i.qi,
            pass_through: i.pass_through,
            include_all: i.include_all,
            irq_remap: i.irq_remap,
            large_pages: i.large_pages,
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

/// Поиск DMAR -> ВСЕ DRHD-единицы -> init каждой -> пометка готовности.
/// Мульти-IOMMU (v0.8): единицы поднимаются независимо, индексируются
/// по порядку в DMAR; attach маршрутизируется coverage-проверкой.
/// Вызывается ПОСЛЕ kinit (пулы/куча подняты), ДО release_aps
/// (конкуренции ещё нет). Возврат — готовность.
pub fn try_init() -> bool {
    // Пул не поднят (ранний fatal-путь run()) — тихо уходим: сисколы
    // ответят ENOSYS.
    if pkg_generic_interface::mem::gallocator::frames().is_none() {
        return false;
    }
    let rsdp = crate::smp::topology().rsdp_phys;
    if rsdp == 0 {
        crate::kprintln!("vtd: no RSDP — IOMMU unavailable");
        return false;
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
            crate::kprintln!("vtd: no DMAR table (QEMU: -device intel-iommu)");
            return false;
        }
    };
    // SAFETY: таблица прошивки живёт всю сессию.
    let slice = unsafe { core::slice::from_raw_parts(phys_ptr::<u8>(phys), len) };
    let dmar = match DmarTable::new(slice) {
        Ok(d) => d,
        Err(e) => {
            crate::kprintln!("vtd: DMAR parse failed: {:?}", e);
            return false;
        }
    };
    // Все DRHD-единицы (мульти-IOMMU v0.8); дубликаты MMIO-базы —
    // одна физическая единица — поднимаем один раз.
    let drhds: Vec<Drhd> = dmar.drhd_units().collect();
    let mut made: Vec<Vtd> = Vec::new();
    let mut seen_bases: Vec<u64> = Vec::new();
    for d in &drhds {
        crate::kprintln!(
            "vtd: DMAR DRHD seg={:#x} include_all={} scopes={}",
            d.segment(),
            d.include_pci_all(),
            d.scopes().count()
        );
        if seen_bases.contains(&d.register_base()) {
            crate::kprintln!(
                "vtd: duplicate DRHD base={:#x} — skipped",
                d.register_base()
            );
            continue;
        }
        seen_bases.push(d.register_base());
        match Vtd::init(d) {
            Ok(v) => {
                crate::kprintln!("vtd[{}]: unit up", made.len());
                made.push(v);
            }
            Err(e) => {
                crate::kprintln!("vtd: unit init failed: {:?} (skipped)", e);
            }
        }
    }
    if made.is_empty() {
        crate::kprintln!("vtd: DMAR without usable DRHD units");
        return false;
    }
    *VTD0.inner.lock() = made;
    // Готовность: помечаем ПОСЛЕ заполнения (release_aps ещё не было —
    // конкурентов нет).
    VTD0.mark_ready();
    true
}
