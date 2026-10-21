// ==== Фасад device-метаданных: capability -> снимок устройства ====
//
// Микроядерный контракт (см. `hal::device`): ядро перечисляет устройства и
// выдаёт capability `DeviceReference`; этот хендлер — ЕДИНСТВЕННОЕ, что
// нужно юзерспейс-драйверу помимо самой capability: прочитать снятые ядром
// метаданные (BAR-ы, MSI-X, ресурсы `_CRS`, HPET-параметры).
//
// Хендлер сознательно примитивен:
//   1. проверить хендл вызывающего (capability обязан быть DeviceReference);
//   2. спросить `DeviceManager::record_words` (чистая сериализация);
//   3. отдать слово по индексу.
// Никакой логики устройств, никакого программирования — «всё сложное в
// юзерспейсе». Формат слова — стабильный протокол версии 1 (документация
// `DeviceManager::record_words`); слово 0 содержит total_words.
//
// Это ПРИМЕР-хендлер (как `TaskSpawnHandler`): платформа регистрирует его
// в `SyscallRegistry` опционально — или раздаёт метаданные через bootinfo/
// IPC-сервер (когда появится подсистема IPC), протокол слов тот же.

use alloc::vec::Vec;

use crate::capability::{CapHandle, ContainerACCCapability};
use crate::hal::device::traits::DeviceResource;
use crate::hal::device::{ClaimOutcome, IrqError, IrqRouter};
use crate::hal::types::DevicePath;
use crate::syscall::nums;

use super::SyscallHandler;
use super::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};

/// Флаг try-режима claim (не блокироваться при занятом устройстве).
pub const CLAIM_FLAG_TRY: usize = 1;

/// Перевод ошибок IRQ-роутера в errno-словарь сисколов.
impl From<IrqError> for SyscallError {
    fn from(e: IrqError) -> Self {
        match e {
            IrqError::InvalidGsi(_) => Self::InvalidArgument,
            IrqError::DeviceGone => Self::DeviceGone,
            IrqError::AlreadyBound => Self::AlreadyExists,
            IrqError::NotFound => Self::NotFound,
            IrqError::NotOwner => Self::MissingRight,
            IrqError::NoIpc => Self::Internal,
        }
    }
}

/// Сискол чтения метаданных устройства по capability.
///
/// ABI (сырые слова, как у `TaskSpawnHandler`):
/// ```text
/// arg0 = номер сискола (диспетчеризует реестр)
/// arg1 = CapHandle.DeviceReference вызывающего
/// arg2 = индекс слова снимка (0..total_words)
/// ret  = слово; слово 0 = total_words | fmt_version<<32 | kind<<40
/// ```
/// Индекс за пределами — ENOENT; чужой/протухший хендл — EBADF (анти-side-
/// channel политика capability-слоя). Чтение не требует прав Send/Mint:
/// владение capability уже доказывает доступ.
///
/// v0.4: хендлер — юнит-структура (реестр устройств берётся из ctx — тот же
/// экземпляр, что у фасада/GCTL; раньше — поле `&'static DeviceManager`).
pub struct DeviceInfoHandler;

impl DeviceInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_INFO;
}

impl SyscallHandler for DeviceInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        // 1. Идентификация: хендл обязан быть DeviceReference вызывающего.
        let handle = CapHandle(args.arg(1) as u64);
        let word_index = args.arg(2);
        let view = ctx
            .caps
            .get(ctx.tasks, ctx.task, handle)
            .ok_or(SyscallError::InvalidHandle)?;
        let ContainerACCCapability::DeviceReference { dev_path } = &view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };

        // 2. Снимок записи (включая погашенные: alive=false виден в слове 1).
        let mut words = Vec::new();
        devices
            .record_words(dev_path, &mut words)
            .map_err(|_| SyscallError::NotFound)?;

        // 3. Слово по индексу; за пределами — ENOENT (total известен из w0).
        let Some(word) = words.get(word_index) else {
            return Err(SyscallError::NotFound);
        };
        Ok(*word as usize)
    }
}

// ==== Claim-хендлеры: эксклюзивное использование устройств ====

/// Резолв DeviceReference-capability в путь устройства.
fn device_path_of(
    ctx: &SyscallCtx<'_>,
    handle: CapHandle,
) -> Result<crate::hal::types::DevicePath, SyscallError> {
    let view = ctx.resolve(handle)?;
    match &view.cap_ref {
        ContainerACCCapability::DeviceReference { dev_path } => Ok(dev_path.clone()),
        _ => Err(SyscallError::InvalidArgument),
    }
}

/// Эксклюзивный claim устройства (одна задача одновременно).
///
/// ABI: arg1 = хендл DeviceReference, arg2 = флаги (bit0 = try),
/// arg3 = хендл notify-endpoint (0 — без уведомлений о потере).
/// Занято другой задачей: try — EINVAL, иначе поток блокируется в
/// очереди планировщика (возврат при release/удалении устройства).
pub struct DeviceClaimHandler;

impl DeviceClaimHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_CLAIM;
}

impl SyscallHandler for DeviceClaimHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let handle = CapHandle(args.arg(1) as u64);
        let try_mode = args.arg(2) & CLAIM_FLAG_TRY != 0;
        let notify = args.arg(3);

        let path = device_path_of(ctx, handle)?;
        // Живость устройства: удалённое (hot-removal) — ошибка от ядра.
        let alive = devices.get_alive(&path).is_some();
        // Notify-endpoint: резолв хендла Gate (0 — не регистрировать).
        let notify_gate = if notify != 0 {
            let view = ctx.resolve(CapHandle(notify as u64))?;
            match &view.cap_ref {
                ContainerACCCapability::Gate { gate_id } => Some(*gate_id),
                _ => return Err(SyscallError::InvalidArgument),
            }
        } else {
            None
        };

        let mode = if try_mode {
            crate::ipc::BlockMode::Try
        } else {
            crate::ipc::BlockMode::Blocking
        };
        match devices.claims().claim(
            ctx.tasks,
            &path,
            alive,
            ctx.task,
            ctx.thread,
            notify_gate,
            mode,
        ) {
            Ok(ClaimOutcome::Acquired) => Ok(0),
            // Поток заблокирован: возврат материализуется при release
            // (syscall_ret = 0) или удалении устройства (ENXIO).
            // SMP v0.12: защёлка — гейт уходит в диспетчеризацию без
            // повторного (racy) чтения состояния потока.
            Ok(ClaimOutcome::Blocked) => {
                crate::syscall::record_block_latch(ctx.cpu);
                Ok(0)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Отпустить лок (только владелец). ABI: arg1 = хендл устройства.
pub struct DeviceReleaseHandler;

impl DeviceReleaseHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_RELEASE;
}

impl SyscallHandler for DeviceReleaseHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let handle = CapHandle(args.arg(1) as u64);
        let path = device_path_of(ctx, handle)?;
        devices
            .claims()
            .release(ctx.tasks, &path, Some(ctx.task))
            .map_err(SyscallError::from)?;
        Ok(0)
    }
}

/// Статус лока слова по индексу: 0 = занятость (1/0), 1..2 = owner(lo, hi),
/// 3 = waiters, 4 = gone. ABI: arg1 = хендл, arg2 = индекс.
pub struct DeviceClaimStatusHandler;

impl DeviceClaimStatusHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_CLAIM_STATUS;
}

impl SyscallHandler for DeviceClaimStatusHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let handle = CapHandle(args.arg(1) as u64);
        let index = args.arg(2);
        let path = device_path_of(ctx, handle)?;
        let status = devices
            .claims()
            .status(ctx.tasks, &path)
            .ok_or(SyscallError::NotFound)?;

        let owner = status.owner.unwrap_or_else(uuid::Uuid::nil);
        let ov = owner.as_u128();
        let words = [
            status.owner.is_some() as u64,
            ov as u64,
            (ov >> 64) as u64,
            status.waiters as u64,
            status.gone as u64,
        ];
        words
            .get(index)
            .map(|w| *w as usize)
            .ok_or(SyscallError::NotFound)
    }
}

// ==== Обзор реестра и ресурсы устройств (v0.4) ====

/// Компактное слово 0 пути устройства (общая кодировка DEVICE_ENUM и
/// CAP_INFO). Pci — bdf-биты (segment|bus|dev|fn), StreamId —
/// (iommu:u32 | id:u32), Acpi/Dt — FNV-1a хэш строки пути.
pub(crate) fn path_word0(path: &DevicePath) -> u64 {
    match path {
        DevicePath::Pci(bdf) => {
            ((bdf.segment as u64) << 48)
                | ((bdf.bus as u64) << 40)
                | ((bdf.device as u64) << 32)
                | (bdf.function as u64)
        }
        DevicePath::StreamId { iommu, id } => ((iommu.0 as u64) << 32) | *id as u64,
        DevicePath::Acpi(p) => fnv1a(p.as_str().as_bytes()),
        DevicePath::Dt(p) => fnv1a(p.0.as_bytes()),
    }
}

/// FNV-1a: дёшево, стабильно, различает пути лучше суммы байтов.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Слово 1 пути: для StreamId — id (слово 0 — iommu), для Acpi/Dt —
/// длина строки; Pci — 0 (всё в слове 0).
fn path_word1(path: &DevicePath) -> u64 {
    match path {
        DevicePath::StreamId { id, .. } => *id as u64,
        DevicePath::Acpi(p) => p.as_str().len() as u64,
        DevicePath::Dt(p) => p.0.len() as u64,
        DevicePath::Pci(_) => 0,
    }
}

/// Слово-код вида пути (DEVICE_ENUM/CAP_INFO-кодировка).
fn path_kind_word(path: &DevicePath) -> u64 {
    match path {
        DevicePath::Pci(_) => 1,
        DevicePath::Acpi(_) => 2,
        DevicePath::StreamId { .. } => 3,
        DevicePath::Dt(_) => 4,
    }
}

/// Обзор реестра ЖИВЫХ устройств (devmon после rescan связывает записи с
/// capability через CAP_LIST/CAP_INFO).
///
/// Слова по индексу: 0 = число живых; далее по 4 слова на устройство
/// (порядок реестра): (kind, path_w0, path_w1, flags).
/// flags: bit0 = msi_source, bit1 = functional.
/// ABI: arg1 = индекс слова.
pub struct DeviceEnumHandler;

impl DeviceEnumHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_ENUM;
}

impl SyscallHandler for DeviceEnumHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let alive: Vec<&crate::hal::device::DeviceRecord> =
            devices.records().iter().filter(|r| r.alive).collect();

        let idx = args.arg(1);
        if idx == 0 {
            return Ok(alive.len());
        }
        let item = (idx - 1) / 4;
        let part = (idx - 1) % 4;
        let Some(rec) = alive.get(item) else {
            return Err(SyscallError::NotFound);
        };
        let flags = (rec.info.msi.is_some() as u64) | ((rec.functional as u64) << 1);
        let words = [
            path_kind_word(&rec.path),
            path_word0(&rec.path),
            path_word1(&rec.path),
            flags,
        ];
        Ok(words[part] as usize)
    }
}

/// Отображение MMIO-ресурса устройства (BAR) в пространство вызывающего.
///
/// Требует DeviceReference + ЗАХВАТ устройства вызывающим (claim): чужой
/// BAR не отображается даже с capability — эксклюзивность доступа к
/// железу гарантирует лок. Кадры внешние (не из пула): снятие —
/// MEM_FREE по адресу (флаг external — учёт фасада).
///
/// ABI: arg1 = хендл устройства, arg2 = индекс ресурса (порядок
/// `DeviceRecord::resources`), arg3 = биты MMAPMemoryFlags (0 = дефолт
/// RW без кэша — device-nocache). Возврат: виртуальный адрес.
pub struct DeviceMapRegionHandler;

impl DeviceMapRegionHandler {
    pub const SYSCALL: SyscallNumber = nums::DEVICE_MAP_REGION;
}

impl SyscallHandler for DeviceMapRegionHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let memory = ctx.memory.ok_or(SyscallError::NotSupported)?;

        let handle = CapHandle(args.arg(1) as u64);
        let res_index = args.arg(2);
        let path = device_path_of(ctx, handle)?;

        // Живое устройство + ресурс — MMIO.
        let rec = devices.get_alive(&path).ok_or(SyscallError::DeviceGone)?;
        let Some(DeviceResource::Mmio { base, len }) = rec.resources.get(res_index) else {
            return Err(SyscallError::InvalidArgument);
        };

        // Право на ЖЕЛЕЗО: устройство захвачено вызывающим (лок есть и
        // он наш; отсутствие лока — не «устройство пропало», а «не твоё»:
        // живость уже проверена get_alive выше).
        let claimed_by_caller = devices
            .claims()
            .status(ctx.tasks, &path)
            .is_some_and(|st| st.owner == Some(ctx.task));
        if !claimed_by_caller {
            return Err(SyscallError::MissingRight);
        }

        // Флаги: 0 — дефолт device-nocache (RW, без CACHEABLE).
        let flags = match args.arg(3) {
            0 => crate::hal::traits::mmap::MMAPMemoryFlags::RW,
            bits => {
                let f = crate::hal::traits::mmap::MMAPMemoryFlags::from_bits_retain(bits as u8);
                f.validate().map_err(SyscallError::from)?;
                f
            }
        };

        let pages = len.div_ceil(4096) as usize;
        let vaddr = memory.map_external(
            ctx.task,
            crate::hal::traits::mmap::PhysADDR(base.0 as usize),
            pages,
            flags,
        )?;
        Ok(vaddr.0)
    }
}

// ==== IRQ-хендлеры: прерывания как сообщения (L4 irq_attach) ====

// ───────────────────── Сервис внешних линий (v0.11) ─────────────────────

use crate::hal::traits::irq::IrqLineOps;

static IRQ_LINES: spin::Once<&'static dyn IrqLineOps> = spin::Once::new();

/// Установка платформенного сервиса внешних линий (x86_64: IOAPIC —
/// backend ставит в ioapic::init; до установки IRQ_ATTACH работает,
/// но линия не возводится — события не придут).
pub fn install_irq_line_service(ops: &'static dyn IrqLineOps) {
    IRQ_LINES.call_once(|| ops);
}

/// Установленный сервис (None — платформа без внешних линий).
fn irq_lines() -> Option<&'static dyn IrqLineOps> {
    IRQ_LINES.get().copied()
}

/// Привязка IRQ устройства к notification-endpoint'у.
///
/// ABI: arg1 = хендл DeviceReference, arg2 = gsi,
/// arg3 = хендл Gate (endpoint с буфером). Возврат: 0.
///
/// v0.11: после привязки ядро возводит линию платформой (IOAPIC RTE +
/// IRTE ремаппинга, если IOMMU IR включён): прерывание становится
/// signal-сообщением в endpoint. Отказ возведения откатывает привязку.
pub struct IrqAttachHandler;

impl IrqAttachHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_ATTACH;
}

impl SyscallHandler for IrqAttachHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let devices = ctx.devices.ok_or(SyscallError::NotSupported)?;
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;

        let handle = CapHandle(args.arg(1) as u64);
        let gsi = args.arg(2) as u32;
        let path = device_path_of(ctx, handle)?;

        // Endpoint: хендл Gate вызывающего.
        let gate_handle = CapHandle(args.arg(3) as u64);
        let view = ctx.resolve(gate_handle)?;
        let ContainerACCCapability::Gate { gate_id } = &view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };

        irq.attach(devices, ctx.task, &path, gsi, *gate_id)?;

        // v0.11: платформа возводит линию. Триггер/полярность — из
        // ресурса устройства (шину переспрашивать не нужно: ресурс
        // декодирован перечислителем; MADT ISO в бекенде уточнит).
        let (level, active_low) = match devices.get_alive(&path) {
            Some(rec) => {
                let mut l = false;
                let mut al = false;
                for r in rec.resources.iter() {
                    if let crate::hal::device::traits::DeviceResource::Irq {
                        gsi: g,
                        trigger,
                        active_low: a,
                    } = r
                    {
                        if *g == gsi {
                            l = matches!(trigger, crate::hal::traits::irq::TriggerMode::Level);
                            al = *a;
                        }
                    }
                }
                (l, al)
            }
            None => (false, false),
        };
        if let Some(ops) = irq_lines() {
            if let Err(e) = ops.enable_line(gsi, level, active_low) {
                // Линия не встала — привязка бессмысленна (события
                // не придут): откат и честный отказ.
                let _ = irq.detach(gsi, ctx.task);
                return Err(SyscallError::from_iommu(e));
            }
        }
        Ok(0)
    }
}

/// Снятие привязки (владелец). ABI: arg1 = gsi.
///
/// v0.11: привязки нет — линия платформы маскируется.
pub struct IrqDetachHandler;

impl IrqDetachHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_DETACH;
}

impl SyscallHandler for IrqDetachHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;
        let gsi = args.arg(1) as u32;
        irq.detach(gsi, ctx.task)?;
        if let Some(ops) = irq_lines() {
            let _ = ops.disable_line(gsi);
        }
        Ok(0)
    }
}

/// Подтверждение обработки (EOI). ABI: arg1 = gsi. Возврат: был ли
/// необработанный pending (0/1).
pub struct IrqAckHandler;

impl IrqAckHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_ACK;
}

impl SyscallHandler for IrqAckHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;
        let gsi = args.arg(1) as u32;
        Ok(irq.ack(gsi, ctx.task)? as usize)
    }
}

// ───────────────────────────── Тесты (host) ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ActionPermissions, CapabilityManager};
    use crate::hal::device::DeviceManager;
    use crate::hal::device::traits::{
        BusDeviceData, BusEnumerator, BusError, DeviceSink, DiscoveredDevice,
    };
    use crate::hal::types::{AcpiPath, DeviceInfo, DeviceKind, DevicePath, PlatformId};
    use crate::task::{TaskPriority, TcbManager};

    /// Одна статичная шина с одним устройством "\_SB.UART0".
    struct UartBus;

    impl BusEnumerator for UartBus {
        fn bus_name(&self) -> &str {
            "test.uart"
        }

        fn scan(&self, sink: &mut dyn DeviceSink) -> Result<(), BusError> {
            sink.discovered(DiscoveredDevice {
                path: DevicePath::Acpi(AcpiPath::new("\\_SB.UART0")),
                info: DeviceInfo::new(DeviceKind::Platform(PlatformId {
                    acpi_uid: Some(3),
                    dt_path: None,
                })),
                resources: alloc::vec![crate::hal::device::traits::DeviceResource::Mmio {
                    base: crate::hal::types::PhysAddr(0xFED0_0000),
                    len: 0x1000,
                }],
                data: BusDeviceData::Acpi(crate::hal::device::acpi::AcpiDeviceData {
                    hid: Some(alloc::string::String::from("PNP0501")),
                    cids: alloc::vec![],
                    uid: Some(3),
                    adr: None,
                    sta: Some(0x0F),
                    hpet: None,
                }),
                functional: true,
            });
            Ok(())
        }
    }

    fn make_llfree(frames: usize) -> llfree::LLFree<'static> {
        use llfree::{Alloc, Classing, MetaData};
        let (cl, _) = Classing::simple(1);
        let sizes = llfree::LLFree::metadata_size(&cl, frames);
        let mut local = aligned_box::AlignedBox::slice_from_value(64, sizes.local, 0u8).unwrap();
        let mut trees = aligned_box::AlignedBox::slice_from_value(64, sizes.trees, 0u8).unwrap();
        let mut lower = aligned_box::AlignedBox::slice_from_value(64, sizes.lower, 0u8).unwrap();
        let meta = unsafe {
            MetaData {
                local: core::slice::from_raw_parts_mut(local.as_mut_ptr(), local.len()),
                trees: core::slice::from_raw_parts_mut(trees.as_mut_ptr(), trees.len()),
                lower: core::slice::from_raw_parts_mut(lower.as_mut_ptr(), lower.len()),
            }
        };
        core::mem::forget((local, trees, lower));
        llfree::LLFree::new(frames, llfree::Init::FreeAll, &cl, meta).unwrap()
    }

    #[test]
    fn device_info_roundtrip() {
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();

        let task = uuid::Uuid::from_u128(0xABCD_0001);
        tasks.create(task, TaskPriority(1)).unwrap();

        let mut devices = DeviceManager::new();
        devices.register_bus(&UartBus).unwrap();
        devices.enumerate().unwrap();
        let handle = devices
            .export_capability(
                &tasks,
                &caps,
                task,
                &DevicePath::Acpi(AcpiPath::new("\\_SB.UART0")),
                ActionPermissions::empty(),
                crate::capability::CapabilityBadge::FULL,
            )
            .unwrap();

        // v0.4: хендлер — юнит; реестр устройств подаётся контекстом.
        let handler = DeviceInfoHandler;
        let devices_leak: &'static DeviceManager = Box::leak(Box::new(devices));

        let mut ctx = SyscallCtx::core(0, task, &tasks, &caps).with_devices(devices_leak);

        // Слово 0: total | version | kind=2 (Acpi).
        let args = SyscallArgs::new([
            DeviceInfoHandler::SYSCALL.as_u64() as usize,
            handle.bits() as usize,
            0,
            0,
            0,
            0,
        ]);
        let w0 = handler.invoke(&mut ctx, &args).unwrap() as u64;
        let total = (w0 & 0xFFFF_FFFF) as usize;
        assert_eq!((w0 >> 32) & 0xFF, 1); // версия формата
        assert_eq!((w0 >> 40) & 0xFF, 2); // kind = Acpi
        assert!(total >= 6);

        // HID упакован в слово 2: "PNP0501".
        let args = SyscallArgs::new([
            DeviceInfoHandler::SYSCALL.as_u64() as usize,
            handle.bits() as usize,
            2,
            0,
            0,
            0,
        ]);
        assert_eq!(
            handler.invoke(&mut ctx, &args).unwrap().to_le_bytes(),
            *b"PNP0501\0"
        );

        // Индекс за пределами — ENOENT.
        let args = SyscallArgs::new([
            DeviceInfoHandler::SYSCALL.as_u64() as usize,
            handle.bits() as usize,
            total + 5,
            0,
            0,
            0,
        ]);
        assert_eq!(handler.invoke(&mut ctx, &args), Err(SyscallError::NotFound));

        // Чужой хендл — EBADF.
        let bad = SyscallArgs::new([
            DeviceInfoHandler::SYSCALL.as_u64() as usize,
            0xDEAD_BEEF,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(
            handler.invoke(&mut ctx, &bad),
            Err(SyscallError::InvalidHandle)
        );

        // Контракт разрушения: cspace пуст до дропа TcbManager.
        caps.revoke_all(&tasks, task).unwrap();
        assert_eq!(caps.total_count(), 0);
    }

    #[test]
    fn device_enum_words() {
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let task = uuid::Uuid::from_u128(0xABCD_0002);
        tasks.create(task, TaskPriority(1)).unwrap();

        let mut devices = DeviceManager::new();
        devices.register_bus(&UartBus).unwrap();
        devices.enumerate().unwrap();
        let devices: &'static DeviceManager = Box::leak(Box::new(devices));

        let handler = DeviceEnumHandler;
        let mut ctx = SyscallCtx::core(0, task, &tasks, &caps).with_devices(devices);
        let args = |i: usize| SyscallArgs::new([0, i, 0, 0, 0, 0]);

        // Одно живое устройство, 4 слова + счётчик.
        assert_eq!(handler.invoke(&mut ctx, &args(0)).unwrap(), 1);
        let kind = handler.invoke(&mut ctx, &args(1)).unwrap() as u64;
        assert_eq!(kind, 2, "Acpi");
        let _hash = handler.invoke(&mut ctx, &args(2)).unwrap() as u64;
        let len = handler.invoke(&mut ctx, &args(3)).unwrap() as u64;
        assert_eq!(len, "\\_SB.UART0".len() as u64);
        let flags = handler.invoke(&mut ctx, &args(4)).unwrap() as u64;
        assert_eq!(flags, 0b10, "functional, без msi");
        // За пределами — NotFound.
        assert_eq!(
            handler.invoke(&mut ctx, &args(5)),
            Err(SyscallError::NotFound)
        );

        // Хэш-слово стабильно (FNV-1a той же строки через path_word0).
        let path = DevicePath::Acpi(AcpiPath::new("\\_SB.UART0"));
        assert_eq!(_hash, path_word0(&path));
    }

    #[test]
    fn map_region_requires_claim_and_maps_mmio() {
        use crate::hal::traits::mmap::{MMAPMemoryFlags, PhysADDR, VirtualADDR};
        use crate::mem::MemRouter;

        struct FakeRouter;
        impl MemRouter for FakeRouter {
            fn alloc_region(
                &self,
                _task: crate::task::TaskId,
                _pages: usize,
                _flags: MMAPMemoryFlags,
            ) -> Result<VirtualADDR, crate::hal::traits::mmap::MemErrorCode> {
                unreachable!("map_region не аллоцирует")
            }
            fn free_region(
                &self,
                _task: crate::task::TaskId,
                _vaddr: VirtualADDR,
            ) -> Result<(), crate::hal::traits::mmap::MemErrorCode> {
                unreachable!()
            }
            fn map_external(
                &self,
                _task: crate::task::TaskId,
                paddr: PhysADDR,
                pages: usize,
                _flags: MMAPMemoryFlags,
            ) -> Result<VirtualADDR, crate::hal::traits::mmap::MemErrorCode> {
                // BAR uart-устройства: base 0xFED0_0000, 0x1000 = 1 страница.
                assert_eq!(paddr.0, 0xFED0_0000);
                assert_eq!(pages, 1);
                Ok(VirtualADDR(0x5000))
            }
            fn region_at(
                &self,
                _task: crate::task::TaskId,
                _vaddr: VirtualADDR,
            ) -> Option<(VirtualADDR, PhysADDR, usize)> {
                None
            }
            fn transfer(
                &self,
                _dst: crate::task::TaskId,
                _dst_hint: usize,
                _src: crate::task::TaskId,
                _src_vaddr: usize,
                _pages: usize,
                _grant: bool,
                _flags: MMAPMemoryFlags,
            ) -> Result<usize, crate::hal::traits::mmap::MemErrorCode> {
                unreachable!()
            }
            fn map_external_at(
                &self,
                _dst: crate::task::TaskId,
                _src: crate::task::TaskId,
                _src_vaddr: usize,
                _dst_vaddr: usize,
                _pages: usize,
                _flags: MMAPMemoryFlags,
            ) -> Result<usize, crate::hal::traits::mmap::MemErrorCode> {
                unreachable!("map_at не нужен map_region-тесту")
            }
        }

        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let task = uuid::Uuid::from_u128(0xABCD_0003);
        tasks.create(task, TaskPriority(1)).unwrap();

        let mut devices = DeviceManager::new();
        devices.register_bus(&UartBus).unwrap();
        devices.enumerate().unwrap();
        let handle = devices
            .export_capability(
                &tasks,
                &caps,
                task,
                &DevicePath::Acpi(AcpiPath::new("\\_SB.UART0")),
                ActionPermissions::empty(),
                crate::capability::CapabilityBadge::FULL,
            )
            .unwrap();
        let devices: &'static DeviceManager = Box::leak(Box::new(devices));
        let router: &'static FakeRouter = Box::leak(Box::new(FakeRouter));

        let handler = DeviceMapRegionHandler;
        let mut ctx = SyscallCtx::core(0, task, &tasks, &caps)
            .with_devices(devices)
            .with_memory(router);
        let args = |h: u64, idx: usize| SyscallArgs::new([0, h as usize, idx, 0, 0, 0]);

        // Без claim — MissingRight (никакого BAR чужому/незахваченному).
        assert_eq!(
            handler.invoke(&mut ctx, &args(handle.bits(), 0)),
            Err(SyscallError::MissingRight)
        );

        // Захват (try) — теперь отображение работает.
        devices
            .claims()
            .claim(
                &tasks,
                &DevicePath::Acpi(AcpiPath::new("\\_SB.UART0")),
                true,
                task,
                task,
                None,
                crate::ipc::BlockMode::Try,
            )
            .unwrap();
        let vaddr = handler.invoke(&mut ctx, &args(handle.bits(), 0)).unwrap();
        assert_eq!(vaddr, 0x5000);

        // Индекс не-MMIO ресурса / за пределами — EINVAL.
        assert_eq!(
            handler.invoke(&mut ctx, &args(handle.bits(), 1)),
            Err(SyscallError::InvalidArgument)
        );

        // Контракт разрушения: cspace пуст до дропа TcbManager.
        caps.revoke_all(&tasks, task).unwrap();
        assert_eq!(caps.total_count(), 0);
    }

    #[test]
    fn irq_syscalls_route_router() {
        use crate::hal::device::irq::tests_support::{IrqTestEnv, irq_test_env};

        let env = irq_test_env();
        let IrqTestEnv {
            tasks,
            caps,
            devices,
            ipc,
            router,
            owner,
            gate,
            dev_handle,
            ..
        } = env;

        let mut ctx = SyscallCtx::core(0, owner, tasks, caps)
            .with_devices(devices)
            .with_ipc(ipc)
            .with_irq(router);

        let attach = IrqAttachHandler;
        let detach = IrqDetachHandler;
        let ack = IrqAckHandler;
        let gate_handle = env.gate_handle;

        // attach: capability-путь + gsi + gate-хендл.
        let args = SyscallArgs::new([
            0,
            dev_handle.bits() as usize,
            42,
            gate_handle.bits() as usize,
            0,
            0,
        ]);
        assert_eq!(attach.invoke(&mut ctx, &args), Ok(0));
        assert_eq!(router.len(), 1);

        // Событие и ACK через сисколы.
        assert_eq!(router.irq_event(tasks, caps, ipc, 42), Ok(true));
        let args = SyscallArgs::new([0, 42, 0, 0, 0, 0]);
        assert_eq!(ack.invoke(&mut ctx, &args), Ok(1));
        assert_eq!(ack.invoke(&mut ctx, &args), Ok(0));

        // Чужой gsi — EINVAL.
        let args = SyscallArgs::new([
            0,
            dev_handle.bits() as usize,
            777,
            gate_handle.bits() as usize,
            0,
            0,
        ]);
        assert_eq!(
            attach.invoke(&mut ctx, &args),
            Err(SyscallError::InvalidArgument)
        );

        // Detach.
        let args = SyscallArgs::new([0, 42, 0, 0, 0, 0]);
        assert_eq!(detach.invoke(&mut ctx, &args), Ok(0));
        assert!(router.is_empty());
    }
}
