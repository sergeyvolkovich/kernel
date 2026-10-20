// ==== Менеджер устройств: реестр + rescan + экспорт capability ====
//
// Роль в микроядре (см. lib.rs): ядро ПЕРЕЧИСЛЯЕТ устройства (через
// сменные бекенды-шины [`BusEnumerator`]) и ВЫДАЁТ на них capability
// `DeviceReference`. Никакого программирования устройств здесь нет:
// драйверы живут в юзерспейсе и работают по capability, выданной
// менеджером (см. `export_capabilities`).
//
// ```text
//   DeviceManager
//   ├─ buses: [&'static dyn BusEnumerator]   сменные бекенды: pci::PciBus,
//   │                                        acpi::AcpiBus, (будущее) dtb::DtbBus
//   └─ records: Vec<DeviceRecord>            реестр: путь → снимок устройства
//          ключ = DevicePath (тот же, что в ContainerACCCapability::DeviceReference)
// ```
//
// Заменяемость PCIe (требование инкапсуляции): менеджер не знает ни одной
// шины. `pci::PciBus` — ЛИСТ, подключаемый через `register_bus`; его можно
// убрать, переписать или подсунуть другую реализацию `BusEnumerator` —
// ни реестр, ни capability-слой, ни GCTL не меняются.
//
// Rescan-семантика (контракт, согласованный с `LIOMMUInterface::
// resolve_device`): повторное перечисление идемпотентно — путь, который
// стабильно виден шиной, сохраняет запись; устройство, пропавшее между
// проходами, помечается `alive = false` (запись НЕ удаляется: capability
// на него «бессмертна» по дизайну capability-слоя, юзерспейс отзывает её
// через revoke; повторное появление оживляет запись).

pub mod acpi;
pub mod claim;
pub mod irq;
pub mod pci;
pub mod traits;

use alloc::{string::String, vec::Vec};

use crate::capability::{
    ActionPermissions, CapHandle, CapabilityBadge, CapabilityGate, CapabilityManager,
    ContainerACCCapability,
};
use crate::hal::types::{DevicePath, MasterId};
use crate::task::{TaskId, TcbManager};

pub use claim::{
    ClaimError, ClaimOutcome, ClaimStatus, DEVICE_GONE_RET, DEVICE_LOST_TAG, DeviceClaimRegistry,
    DeviceLock,
};
pub use irq::{IrqError, IrqRouter};
pub use traits::{
    BusDeviceData, BusEnumerator, BusError, DeviceError, DeviceResource, DeviceSink,
    DiscoveredDevice, PciConfigAccess,
};

// ==== Запись реестра ====

/// Снимок устройства в реестре: всё, что ядро знает об устройстве после
/// перечисления. Данные только читаются юзерспейсом; программирование —
// вне ядра.
#[derive(Debug)]
pub struct DeviceRecord {
    /// Идентичность (ключ реестра и capability `DeviceReference`).
    pub path: DevicePath,
    /// Имя шины, сообщившей устройство ("pcie.0", "acpi").
    pub bus: String,
    /// Общая мета-информация (мастера DMA, когерентность, MSI-источник).
    pub info: crate::hal::types::DeviceInfo,
    /// Декодированные ресурсы (BAR / _CRS).
    pub resources: Vec<DeviceResource>,
    /// Шино-специфичные данные (PCI-конфигурация, ACPI-идентичность).
    pub data: BusDeviceData,
    /// Устройство функционально (ACPI `_STA` бит 3; PCI — true).
    pub functional: bool,
    /// Устройство виделось последним rescan-ом. `false` — пропало;
    /// повторное появление вернёт true, запись живёт в реестре дальше.
    pub alive: bool,
    /// Эпоха скана, в которой устройство видели последний раз.
    scan_epoch: u64,
}

impl DeviceRecord {
    /// Права-подресурсы устройства для badge capability: бит на каждый
    /// адресуемый ресурс (BAR/MMIO/IO) — семантика «номера BAR» из
    /// документации `CapabilityBadge`.
    pub fn resource_badge(&self) -> CapabilityBadge {
        let mut bits = 0u64;
        for (i, r) in self.resources.iter().enumerate() {
            if i >= 64 {
                break;
            }
            if r.addressable() {
                bits |= 1 << i;
            }
        }
        CapabilityBadge::from_bits(bits)
    }
}

/// Отчёт одного перечисления.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnumerationReport {
    /// Сколько шин сканировано.
    pub buses: usize,
    /// Новые записи.
    pub discovered: usize,
    /// Обновлённые записи (устройство виделось повторно).
    pub updated: usize,
    /// Записи, пропавшие в этом проходе (переведены в `alive = false`).
    pub missing: usize,
    /// Живых записей по итогам прохода.
    pub alive: usize,
}

// ==== Коллектор скана ====

/// Приёмник устройств одного прохода шины: копит найденное, чтобы менеджер
/// смержил в реестр после освобождения заимствования шины.
struct ScanCollector {
    seen: Vec<DiscoveredDevice>,
}

impl DeviceSink for ScanCollector {
    fn discovered(&mut self, dev: DiscoveredDevice) {
        self.seen.push(dev);
    }
}

// ==== Менеджер ====

/// Реестр устройств поверх сменных шин-бекендов.
///
/// Порядок подключения (платформенный код):
/// ```ignore
/// let mut dm = DeviceManager::new();
/// dm.register_bus(&PCI_BUS);        // &'static PciBus<..> (leak/статика)
/// dm.register_bus(&ACPI_BUS);
/// dm.enumerate()?;                  // разовый проход на старте
/// dm.export_capabilities(&tasks, &caps, root_task, perms)?;
/// ```
///
/// Синхронизация: однопоточный контракт крейта (менеджеры сериализуются
/// внешне, как TcbManager/CapabilityManager); шины сами отвечают за свою
/// внутреннюю реентерабельность (`&'static dyn` + interior mutability).
pub struct DeviceManager {
    buses: Vec<&'static dyn BusEnumerator>,
    records: Vec<DeviceRecord>,
    /// Монотонный счётчик проходов (эпоха живости записей).
    epoch: u64,
    /// Реестр эксклюзивных локов устройств (claim/release + hot-removal).
    claims: DeviceClaimRegistry,
    /// Устройства, переведённые в `alive = false` последним проходом
    /// (hot-removal diff): платформа/GCTL читает списком и зовёт
    /// `claims.on_device_removed` для каждого (контракт уведомления
    /// держателей локов: ошибка ядра + IPC).
    last_removed: Vec<DevicePath>,
}

impl DeviceManager {
    /// Пустой реестр без шин.
    pub fn new() -> Self {
        Self {
            buses: Vec::new(),
            records: Vec::new(),
            epoch: 0,
            claims: DeviceClaimRegistry::new(),
            last_removed: Vec::new(),
        }
    }

    /// Реестр локов (claim/release/hot-removal-уведомления).
    #[inline]
    pub fn claims(&self) -> &DeviceClaimRegistry {
        &self.claims
    }

    /// Реестр локов, изменяемый доступ.
    #[inline]
    pub fn claims_mut(&mut self) -> &mut DeviceClaimRegistry {
        &mut self.claims
    }

    /// Устройства, пропавшие в последнем проходе (hot-removal diff).
    /// Держатели локов ещё НЕ уведомлены — вызовите `claims_mut()
    /// .on_device_removed(tasks, caps, ipc, path)` для каждого (или
    /// GCTL::rescan_devices, который делает это сам).
    pub fn removed_since_last_scan(&self) -> &[DevicePath] {
        &self.last_removed
    }

    // ==== Шины ====

    /// Подключить шину-бекенд. Замена PCIe = регистрация другого
    /// `BusEnumerator` под другим (или тем же) именем — менеджеру всё равно.
    ///
    /// Повторное имя — [`DeviceError::BusAlreadyRegistered`].
    pub fn register_bus(&mut self, bus: &'static dyn BusEnumerator) -> Result<(), DeviceError> {
        if self.buses.iter().any(|b| b.bus_name() == bus.bus_name()) {
            return Err(DeviceError::BusAlreadyRegistered(String::from(
                bus.bus_name(),
            )));
        }
        self.buses.push(bus);
        Ok(())
    }

    /// Отключить шину по имени. Записи шины НЕ удаляются — следующий
    /// [`Self::enumerate`] пометит их `alive = false` (пропавшими).
    /// Возвращает, была ли шина зарегистрирована.
    pub fn unregister_bus(&mut self, name: &str) -> bool {
        let before = self.buses.len();
        self.buses.retain(|b| b.bus_name() != name);
        before != self.buses.len()
    }

    /// Имена подключённых шин.
    pub fn buses(&self) -> impl Iterator<Item = &str> {
        self.buses.iter().map(|b| b.bus_name())
    }

    // ==== Перечисление ====

    /// Пройти ВСЕ зарегистрированные шины и смержить результаты.
    ///
    /// Идемпотентность: стабильная топология даёт стабильный реестр;
    /// записи не дублируются (ключ — `DevicePath`). Отказ одной шины
    /// прерывает проход с [`DeviceError::BusFailed`] — записи уже
    /// смерженных шин сохраняются (частичный rescan лучше полного
    /// отката: реестр — снимок, не транзакция).
    pub fn enumerate(&mut self) -> Result<EnumerationReport, DeviceError> {
        self.epoch += 1;
        let mut report = EnumerationReport {
            buses: self.buses.len(),
            ..EnumerationReport::default()
        };

        // Проходы шин собираем сначала (иммутабельный borrow), мержим
        // потом — конфликт заимствований с merge_scan(&mut self).
        let mut scans: Vec<(String, Vec<DiscoveredDevice>)> = Vec::new();
        for bus in &self.buses {
            let mut collector = ScanCollector { seen: Vec::new() };
            match bus.scan(&mut collector) {
                Ok(()) => scans.push((String::from(bus.bus_name()), collector.seen)),
                Err(reason) => {
                    return Err(DeviceError::BusFailed {
                        bus: String::from(bus.bus_name()),
                        reason,
                    });
                }
            }
        }
        for (bus_name, seen) in scans {
            let (new, updated) = self.merge_scan(&bus_name, seen);
            report.discovered += new;
            report.updated += updated;
        }

        // Пропавшие: не видены в ЭТОЙ эпохе (все шины прошли).
        // Hot-removal diff — держатели локов уведомляет GCTL/платформа.
        self.last_removed.clear();
        for rec in &mut self.records {
            if rec.alive && rec.scan_epoch != self.epoch {
                rec.alive = false;
                report.missing += 1;
                self.last_removed.push(rec.path.clone());
            }
        }
        report.alive = self.records.iter().filter(|r| r.alive).count();
        Ok(report)
    }

    /// Перейти одну шину по имени (rescan после hotplug/замены бекенда).
    /// Записи ДРУГИХ шин не затрагиваются.
    pub fn rescan_bus(&mut self, name: &str) -> Result<EnumerationReport, DeviceError> {
        let Some(bus) = self.buses.iter().copied().find(|b| b.bus_name() == name) else {
            return Err(DeviceError::UnknownBus(String::from(name)));
        };
        self.epoch += 1;
        let mut report = EnumerationReport {
            buses: 1,
            ..EnumerationReport::default()
        };
        let mut collector = ScanCollector { seen: Vec::new() };
        bus.scan(&mut collector)
            .map_err(|reason| DeviceError::BusFailed {
                bus: String::from(name),
                reason,
            })?;
        let (new, updated) = self.merge_scan(name, collector.seen);
        report.discovered = new;
        report.updated = updated;
        self.last_removed.clear();
        for rec in &mut self.records {
            if rec.bus == name && rec.alive && rec.scan_epoch != self.epoch {
                rec.alive = false;
                report.missing += 1;
                self.last_removed.push(rec.path.clone());
            }
        }
        report.alive = self.records.iter().filter(|r| r.alive).count();
        Ok(report)
    }

    /// Влить проход одной шины в реестр. Возвращает (новых, обновлённых).
    fn merge_scan(&mut self, bus: &str, seen: Vec<DiscoveredDevice>) -> (usize, usize) {
        let mut new = 0;
        let mut updated = 0;
        for dev in seen {
            match self.records.iter_mut().find(|r| r.path == dev.path) {
                Some(rec) => {
                    // Повторное появление после hot-removal: «отравление»
                    // лока снимается (устройство снова можно клеймить).
                    let revived = !rec.alive;
                    rec.bus = String::from(bus);
                    rec.info = dev.info;
                    rec.resources = dev.resources;
                    rec.data = dev.data;
                    rec.functional = dev.functional;
                    rec.alive = true;
                    rec.scan_epoch = self.epoch;
                    updated += 1;
                    if revived {
                        self.claims.device_alive_again(&dev.path);
                    }
                }
                None => {
                    self.records.push(DeviceRecord {
                        path: dev.path,
                        bus: String::from(bus),
                        info: dev.info,
                        resources: dev.resources,
                        data: dev.data,
                        functional: dev.functional,
                        alive: true,
                        scan_epoch: self.epoch,
                    });
                    new += 1;
                }
            }
        }
        (new, updated)
    }

    // ==== Доступ ====

    /// Запись по пути (вне зависимости от живости).
    pub fn get(&self, path: &DevicePath) -> Option<&DeviceRecord> {
        self.records.iter().find(|r| &r.path == path)
    }

    /// Живая запись по пути.
    pub fn get_alive(&self, path: &DevicePath) -> Option<&DeviceRecord> {
        self.get(path).filter(|r| r.alive)
    }

    /// Все записи (в порядке нахождения).
    pub fn records(&self) -> &[DeviceRecord] {
        &self.records
    }

    /// Число записей (живых и погашенных).
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Число живых записей.
    pub fn alive_count(&self) -> usize {
        self.records.iter().filter(|r| r.alive).count()
    }

    /// Правка записей на месте (редкий путь): заполнение мастеров DMA
    /// платформой после перечисления (`IOMMU::resolve_device`), annotate
    /// отладочными пометками и т.п.
    pub fn for_each_record_mut(&mut self, mut f: impl FnMut(&mut DeviceRecord)) {
        for rec in &mut self.records {
            f(rec);
        }
    }

    /// Заполнить `DeviceInfo::masters` через резолвер IOMMU (контракт
    /// `LIOMMUInterface::resolve_device`): для каждой живой записи.
    pub fn attach_masters(&mut self, mut resolve: impl FnMut(&DevicePath) -> Vec<MasterId>) {
        let mut paths: Vec<DevicePath> = self
            .records
            .iter()
            .filter(|r| r.alive)
            .map(|r| r.path.clone())
            .collect();
        for path in paths.drain(..) {
            let masters = resolve(&path);
            if let Some(rec) = self.records.iter_mut().find(|r| r.path == path) {
                rec.info.masters = masters;
            }
        }
    }

    // ==== Экспорт capability ====

    /// Выдать `owner`-у корневую capability `DeviceReference` на КАЖДОЕ
    /// живое устройство реестра (точка входа доверия микроядра: root-задача
    /// дальше раздаёт производные драйверам через mint/send).
    ///
    /// Badge — [`DeviceRecord::resource_badge`] (бит на адресуемый ресурс:
    /// семантика «номера BAR» из документации `CapabilityBadge`); права —
    /// `perms` + стандартные Send/Mint не добавляются автоматически.
    /// Повторный вызов выдаёт НОВЫЕ хендлы (гранты аддитивны): старые
    /// отзываются юзерспейсом через revoke — ядро не дедуплицирует.
    pub fn export_capabilities(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        owner: TaskId,
        perms: ActionPermissions,
    ) -> Result<Vec<(DevicePath, CapHandle)>, DeviceError> {
        self.export_capabilities_with(tasks, caps, owner, perms, DeviceRecord::resource_badge)
    }

    /// [`Self::export_capabilities`] с кастомной политикой badge
    /// (например, `|_| CapabilityBadge::FULL` для полного доверия root-у).
    pub fn export_capabilities_with(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        owner: TaskId,
        perms: ActionPermissions,
        badge_of: impl Fn(&DeviceRecord) -> CapabilityBadge,
    ) -> Result<Vec<(DevicePath, CapHandle)>, DeviceError> {
        let mut out = Vec::new();
        for rec in &self.records {
            if !rec.alive {
                continue;
            }
            let gate = CapabilityGate::new(
                ContainerACCCapability::DeviceReference {
                    dev_path: rec.path.clone(),
                },
                perms,
                badge_of(rec),
            );
            let handle = caps.grant(tasks, owner, gate)?;
            out.push((rec.path.clone(), handle));
        }
        Ok(out)
    }

    /// Выдать capability на ОДНО устройство (живое; иначе — NotFound).
    pub fn export_capability(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        owner: TaskId,
        path: &DevicePath,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Result<CapHandle, DeviceError> {
        let Some(rec) = self.get_alive(path) else {
            return Err(DeviceError::DeviceNotFound(path.clone()));
        };
        let gate = CapabilityGate::new(
            ContainerACCCapability::DeviceReference {
                dev_path: rec.path.clone(),
            },
            perms,
            badge,
        );
        Ok(caps.grant(tasks, owner, gate)?)
    }

    // ==== Сериализация для юзерспейса ====

    /// Снимок записи в массиве u64-слов — протокол метаданных для
    /// юзерспейса (сисколл-хендлер `syscall::device` / bootinfo).
    ///
    /// Формат (версия 1; все поля little-endian-порядком слов):
    /// ```text
    /// w0: total_words:u32 | fmt_version=1:u8 <<32 | kind:u8 <<40
    ///     kind: 1=Pci, 2=Acpi, 3=StreamId, 4=Dt
    /// w1: flags: bit0 functional, bit1 alive, bit2 coherent, bit3 msi
    ///     | n_resources:u8 <<8 | n_masters:u8 <<16
    /// w2..: идентификация (по kind, см. `record_words`)
    /// затем: ресурсы — по 3 слова (kind | base | len),
    /// мастера — по 1 слову (iommu:u32 | id:u32).
    /// ```
    /// Ресурс: слово A = kind(1=mmio,2=io,3=irq) | триггер<<8 | active_low<<9,
    /// слово B = base (или GSI), слово C = len (0 для IRQ).
    pub fn record_words(&self, path: &DevicePath, out: &mut Vec<u64>) -> Result<(), DeviceError> {
        let Some(rec) = self.get(path) else {
            return Err(DeviceError::DeviceNotFound(path.clone()));
        };

        let kind: u8 = match &rec.path {
            DevicePath::Pci(_) => 1,
            DevicePath::Acpi(_) => 2,
            DevicePath::StreamId { .. } => 3,
            DevicePath::Dt(_) => 4,
        };
        let flags = (rec.functional as u64)
            | ((rec.alive as u64) << 1)
            | ((rec.info.coherent as u64) << 2)
            | (rec.info.msi.is_some() as u64) << 3;
        let body_start = out.len();
        out.push(0); // w0 — total_words, заполним в конце
        out.push(
            flags | ((rec.resources.len() as u64) << 8) | ((rec.info.masters.len() as u64) << 16),
        );

        // Идентификация (шино-специфичная).
        match &rec.data {
            BusDeviceData::Pci(pci) => {
                out.push(
                    pci.vendor_id as u64
                        | (pci.device_id as u64) << 16
                        | (pci.revision as u64) << 32
                        | (pci.class.2 as u64) << 40
                        | (pci.class.1 as u64) << 48
                        | (pci.class.0 as u64) << 56,
                );
                out.push(
                    pci.subsystem.map_or(0, |s| s.0 as u64 | (s.1 as u64) << 16)
                        | (pci.irq_pin as u64) << 32
                        | (pci.irq_line as u64) << 40
                        | (pci.multifunction as u64) << 56,
                );
                out.push(
                    pci.bars.len() as u64
                        | ((pci.msix.is_some() as u64) << 8)
                        | ((pci.pcie.is_some() as u64) << 9),
                );
                // BAR-ы: 3 слова (kind|prefetch, base, size).
                for bar in &pci.bars {
                    let kind = match bar.kind {
                        pci::PciBarKind::Io => 1u64,
                        pci::PciBarKind::Mem32 => 2u64,
                        pci::PciBarKind::Mem64 => 3u64,
                    };
                    out.push(kind | ((bar.prefetchable as u64) << 8));
                    out.push(bar.base);
                    out.push(bar.size);
                }
                if let Some(msix) = &pci.msix {
                    out.push(msix.table_size as u64);
                    out.push(msix.table_bir as u64 | (msix.table_offset as u64) << 8);
                    out.push(msix.pba_bir as u64 | (msix.pba_offset as u64) << 8);
                }
                // PCIe capability: одно слово — версия/порт/скорости/ширины.
                if let Some(pcie) = &pci.pcie {
                    out.push(
                        pcie.version as u64
                            | (pcie.port_type as u64) << 4
                            | (pcie.max_link_speed as u64) << 8
                            | (pcie.max_link_width as u64) << 12
                            | (pcie.cur_link_speed as u64) << 20
                            | (pcie.cur_link_width as u64) << 24,
                    );
                }
            }
            BusDeviceData::Acpi(acpi_data) => {
                // HID упаковывается в одно слово, если влезает (PNP ID ≤ 8 байт).
                out.push(pack_str8(acpi_data.hid.as_deref()));
                out.push(acpi_data.uid.unwrap_or(0));
                out.push(acpi_data.adr.unwrap_or(0));
                out.push(
                    acpi_data.sta.unwrap_or(0x0F) as u64
                        | ((acpi_data.hpet.is_some() as u64) << 32)
                        | ((acpi_data.cids.len() as u64) << 40),
                );
                for cid in &acpi_data.cids {
                    out.push(pack_str8(Some(cid.as_str())));
                }
                if let Some(hpet) = &acpi_data.hpet {
                    out.push(hpet.base_address);
                    out.push(
                        hpet.num_comparators as u64
                            | (hpet.main_counter_is_64bits as u64) << 8
                            | (hpet.legacy_irq_capable as u64) << 9
                            | (hpet.clock_tick_unit as u64) << 16
                            | (hpet.page_protection_word() << 48),
                    );
                }
            }
            BusDeviceData::Opaque(_) => {
                // Непрозрачный бекенд: только общий каркас (путь уже в kind).
            }
        }

        // Ресурсы.
        for r in &rec.resources {
            match r {
                DeviceResource::Mmio { base, len } => {
                    out.push(1);
                    out.push(base.as_u64());
                    out.push(*len);
                }
                DeviceResource::IoPort { base, len } => {
                    out.push(2);
                    out.push(*base as u64);
                    out.push(*len as u64);
                }
                DeviceResource::Irq {
                    gsi,
                    trigger,
                    active_low,
                } => {
                    let trigger = (*trigger as u64) << 8; // 0=Edge, 1=Level
                    out.push(3 | trigger | (*active_low as u64) << 9);
                    out.push(*gsi as u64);
                    out.push(0);
                }
            }
        }

        // Мастера DMA.
        for m in &rec.info.masters {
            out.push(m.iommu.0 as u64 | ((m.id as u64) << 32));
        }

        // w0: total + версия + kind.
        let total = (out.len() - body_start) as u64;
        out[body_start] = total | (1u64 << 32) | ((kind as u64) << 40);
        Ok(())
    }
}

/// Упаковать строку в u64 (до 8 байт ASCII, добитая нулями; 0 — None/длиннее).
fn pack_str8(s: Option<&str>) -> u64 {
    let Some(s) = s else { return 0 };
    if s.len() > 8 || !s.is_ascii() {
        return 0;
    }
    let mut packed = 0u64;
    for (i, b) in s.bytes().enumerate() {
        packed |= (b as u64) << (i * 8);
    }
    packed
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ==== Тесты ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::device::pci::PciDeviceData;
    use crate::hal::types::{Bdf, DeviceKind, PhysAddr};

    /// Сценарная шина: выдаёт scripted-наборы устройств по номеру прохода.
    /// (AtomicUsize: static требует Sync; Cell — не Sync.)
    struct MockBus {
        name: &'static str,
        rounds: core::sync::atomic::AtomicUsize,
        scripts: &'static [&'static [(&'static str, bool)]],
    }

    impl MockBus {
        /// Путь вида "acpi:\DEV{i}" — стабильный и уникальный.
        fn dev_path(tag: &str) -> DevicePath {
            DevicePath::Acpi(crate::hal::types::AcpiPath::new(alloc::format!(
                "\\_SB.{tag}"
            )))
        }
    }

    impl BusEnumerator for MockBus {
        fn bus_name(&self) -> &str {
            self.name
        }

        fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError> {
            use core::sync::atomic::Ordering;
            let round = self.rounds.fetch_add(1, Ordering::Relaxed);
            let Some(round_set) = self.scripts.get(round) else {
                return Ok(()); // дальше пусто
            };
            for (tag, functional) in round_set.iter() {
                let info = crate::hal::types::DeviceInfo::new(DeviceKind::Platform(
                    crate::hal::types::PlatformId {
                        acpi_uid: None,
                        dt_path: None,
                    },
                ));
                sink.discovered(DiscoveredDevice {
                    path: Self::dev_path(tag),
                    info,
                    resources: alloc::vec![DeviceResource::Mmio {
                        base: PhysAddr(0x1000),
                        len: 0x100,
                    }],
                    data: BusDeviceData::Acpi(crate::hal::device::acpi::AcpiDeviceData {
                        hid: Some(String::from("PNP0501")),
                        cids: Vec::new(),
                        uid: Some(1),
                        adr: None,
                        sta: Some(0x0F),
                        hpet: None,
                    }),
                    functional: *functional,
                });
            }
            Ok(())
        }
    }

    static BUS_A: MockBus = MockBus {
        name: "mock.a",
        rounds: core::sync::atomic::AtomicUsize::new(0),
        // проход 1: DEV1, DEV2; проход 2: только DEV1 (DEV2 пропала);
        // проход 3: DEV1 + DEV3.
        scripts: &[
            &[("DEV1", true), ("DEV2", true)],
            &[("DEV1", true)],
            &[("DEV1", true), ("DEV3", true)],
        ],
    };

    fn mmio_resource() -> DeviceResource {
        DeviceResource::Mmio {
            base: PhysAddr(0x1000),
            len: 0x100,
        }
    }

    #[test]
    fn rescan_diff_semantics() {
        let mut dm = DeviceManager::new();
        dm.register_bus(&BUS_A).unwrap();
        assert_eq!(dm.buses().collect::<Vec<_>>(), vec!["mock.a"]);

        // Проход 1: два новых.
        let r = dm.enumerate().unwrap();
        assert_eq!((r.discovered, r.updated, r.missing, r.alive), (2, 0, 0, 2));
        assert!(dm.get_alive(&MockBus::dev_path("DEV1")).is_some());
        assert!(dm.get_alive(&MockBus::dev_path("DEV2")).is_some());

        // Проход 2: DEV1 обновлён, DEV2 пропала (запись остаётся, но dead).
        let r = dm.enumerate().unwrap();
        assert_eq!((r.discovered, r.updated, r.missing, r.alive), (0, 1, 1, 1));
        assert!(dm.get(&MockBus::dev_path("DEV2")).unwrap().alive == false);
        assert_eq!(dm.count(), 2);

        // Проход 3: DEV3 новый; DEV2 всё ещё в реестре (dead).
        let r = dm.enumerate().unwrap();
        assert_eq!((r.discovered, r.updated, r.missing, r.alive), (1, 1, 0, 2));
        assert_eq!(dm.alive_count(), 2);
        assert_eq!(dm.count(), 3);
    }

    #[test]
    fn duplicate_bus_name_rejected() {
        let mut dm = DeviceManager::new();
        dm.register_bus(&BUS_A).unwrap();
        assert!(matches!(
            dm.register_bus(&BUS_A),
            Err(DeviceError::BusAlreadyRegistered(_))
        ));
        assert!(dm.unregister_bus("mock.a"));
        assert!(!dm.unregister_bus("mock.a"));
    }

    /// Полный путь: перечисление -> экспорт capability -> resolve.
    /// Инфраструктура задач/capability — поверх host-хуков slab (cfg(test));
    /// физический пул нужен только MemoryManager, здесь его нет.
    #[test]
    fn export_capabilities_end_to_end() {
        use crate::task::TaskPriority;

        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();

        let uuid_next = || {
            use core::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0xBEEF_0000);
            uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
        };
        let owner = uuid_next();
        tasks.create(owner, TaskPriority(1)).unwrap();

        // Реестр с одной живой записью.
        let mut dm = DeviceManager::new();
        static BUS_EXPORT: MockBus = MockBus {
            name: "mock.export",
            rounds: core::sync::atomic::AtomicUsize::new(0),
            scripts: &[&[("UART", true)]],
        };
        dm.register_bus(&BUS_EXPORT).unwrap();
        dm.enumerate().unwrap();

        // Экспорт: право Send+Mint, badge — бит на ресурс.
        let perms = ActionPermissions::Send | ActionPermissions::Mint;
        let granted = dm.export_capabilities(&tasks, &caps, owner, perms).unwrap();
        assert_eq!(granted.len(), 1);
        let (path, handle) = &granted[0];
        assert_eq!(*path, MockBus::dev_path("UART"));

        // Хендл резолвится в DeviceReference с тем же путём и правами.
        let view = caps.get(&tasks, owner, *handle).unwrap();
        assert_eq!(
            view.cap_ref,
            ContainerACCCapability::DeviceReference {
                dev_path: path.clone()
            }
        );
        assert_eq!(view.perms, perms);
        assert_eq!(view.badge, CapabilityBadge::from_bits(1)); // один mmio-ресурс

        // Одно устройство — точечный экспорт; мёртвый путь — NotFound.
        let h2 = dm
            .export_capability(&tasks, &caps, owner, path, perms, CapabilityBadge::FULL)
            .unwrap();
        assert_ne!(h2, *handle);
        let dead = MockBus::dev_path("NOPE");
        assert!(matches!(
            dm.export_capability(&tasks, &caps, owner, &dead, perms, CapabilityBadge::FULL),
            Err(DeviceError::DeviceNotFound(_))
        ));

        // Контракт разрушения ядра: revoke_all до дропа TcbManager
        // (его Drop проверяет пустые cspace).
        caps.revoke_all(&tasks, owner).unwrap();
        assert_eq!(caps.total_count(), 0);
    }

    #[test]
    fn resource_badge_bits_per_resource() {
        let mut dm = DeviceManager::new();
        static BUS_BADGE: MockBus = MockBus {
            name: "mock.badge",
            rounds: core::sync::atomic::AtomicUsize::new(0),
            scripts: &[&[("DEV", true)]],
        };
        dm.register_bus(&BUS_BADGE).unwrap();
        dm.enumerate().unwrap();
        let rec = dm.get_alive(&MockBus::dev_path("DEV")).unwrap();
        // Сценарная шина выдаёт один MMIO-ресурс → бит 0.
        assert_eq!(rec.resource_badge(), CapabilityBadge::from_bits(1));
        assert_eq!(rec.resources, vec![mmio_resource()]);
    }

    #[test]
    fn record_words_snapshot() {
        let mut dm = DeviceManager::new();
        static BUS_WORDS: MockBus = MockBus {
            name: "mock.words",
            rounds: core::sync::atomic::AtomicUsize::new(0),
            scripts: &[&[("HPET", true)]],
        };
        dm.register_bus(&BUS_WORDS).unwrap();
        dm.enumerate().unwrap();

        let mut words = Vec::new();
        dm.record_words(&MockBus::dev_path("HPET"), &mut words)
            .unwrap();
        // w0: total | version 1 | kind 2 (Acpi).
        assert_eq!((words[0] >> 32) & 0xFF, 1);
        assert_eq!((words[0] >> 40) & 0xFF, 2);
        assert_eq!((words[0] & 0xFFFF_FFFF) as usize, words.len());
        // w1: functional|alive|coherent установлены, 1 ресурс.
        assert_eq!(words[1] & 0xF, 0b0111);
        assert_eq!((words[1] >> 8) & 0xFF, 1);
        // HID "PNP0501" упакован в слово.
        assert_eq!(words[2].to_le_bytes(), *b"PNP0501\0");

        // Мёртвый путь — отказ.
        let mut scratch = Vec::new();
        let dead = MockBus::dev_path("NOPE");
        assert!(matches!(
            dm.record_words(&dead, &mut scratch),
            Err(DeviceError::DeviceNotFound(_))
        ));
    }

    /// PCI-запись сериализуется с kind=1 и барами.
    #[test]
    fn record_words_pci() {
        let mut dm = DeviceManager::new();
        let path = DevicePath::Pci(Bdf::new(0, 1, 2, 3));
        let data = PciDeviceData {
            vendor_id: 0x1AF4,
            device_id: 0x1000,
            revision: 1,
            class: (0x02, 0x00, 0x00),
            header_type: crate::hal::device::pci::PciHeaderType::Standard,
            multifunction: false,
            command: 0,
            status: 0x10,
            subsystem: Some((0x1AF4, 0x1100)),
            bars: alloc::vec![crate::hal::device::pci::PciBar {
                kind: crate::hal::device::pci::PciBarKind::Mem32,
                base: 0xF000_0000,
                size: 0x1000,
                prefetchable: false,
            }],
            rom: None,
            capabilities: alloc::vec![],
            msi: None,
            msix: None,
            pcie: None,
            bridge: None,
            irq_pin: 1,
            irq_line: 11,
        };
        // Вставляем запись напрямую (белый ход: merge_scan приватен, но
        // тест в том же модуле).
        dm.records.push(DeviceRecord {
            path: path.clone(),
            bus: String::from("test"),
            info: crate::hal::types::DeviceInfo::new(DeviceKind::Pci(Bdf::new(0, 1, 2, 3))),
            resources: alloc::vec![DeviceResource::Mmio {
                base: PhysAddr(0xF000_0000),
                len: 0x1000,
            }],
            data: BusDeviceData::Pci(data),
            functional: true,
            alive: true,
            scan_epoch: 1,
        });

        let mut words = Vec::new();
        dm.record_words(&path, &mut words).unwrap();
        assert_eq!((words[0] >> 40) & 0xFF, 1); // kind=Pci
        assert_eq!(words[2] & 0xFFFF, 0x1AF4); // vendor
        assert_eq!((words[2] >> 16) & 0xFFFF, 0x1000); // device
    }
}
