// ==== IOMMU-сисколы (группа 0x80) + сервисный контракт платформы ====
//
// Поверхность DMA-ремаппинга для драйверов пользовательского режима:
// ENUM (обзор контроллеров) -> ATTACH (BDF -> DeviceId, домен изоляции)
// -> MAP/UNMAP (IOVA-диапазоны устройства) -> DETACH.
//
// Сервис — глобальная установка (Once), как TimeSource/DebugSink:
// реальное железо (x86_64: backend::vtd::VTD0) ставится платформой в
// X86Platform::run; без установленного сервиса все хендлеры — ENOSYS
// (честный отказ, не паника).
//
// Права (v0.6): BDF передаётся напрямую, claim-гейт устройства —
// следующая итерация (политика: IOMMU-операции на устройстве требуют
// живой claim того же BDF; сейчас доверяем вызывающему домену).

use spin::Once;

use crate::hal::traits::iommu::IommuError;
use crate::syscall::types::{SyscallArgs, SyscallError, SyscallNumber, SyscallRet};
use crate::syscall::{SyscallCtx, SyscallHandler};

// ───────────────────── Сервис (установка платформой) ─────────────────────

/// Обзор контроллера для IOMMU_ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuInfo {
    /// Версия архитектуры: (major << 8) | minor.
    pub version: u16,
    /// Максимальная ширина адреса (MGAW), бит.
    pub mgaw_bits: u8,
    /// Поддержка 48-бит AGAW (4 уровня second-stage).
    pub agaw48: bool,
    /// Queued invalidations (обязателен для нашего драйвера).
    pub queued_inval: bool,
    /// Pass-through TT (не используется v0.6, информативно).
    pub pass_through: bool,
    /// DRHD покрывает весь сегмент (INCLUDE_PCI_ALL).
    pub include_all: bool,
    /// IRQ-ремаппинг включён (v0.8: IRTA/IRTE живут, контроллер
    /// принимает IOMMU_IRQ_*).
    pub irq_remap: bool,
    /// Крупные страницы (2 МиБ) поддерживаются и используются драйвером
    /// для выровненных отображений (v0.8).
    pub large_pages: bool,
}

/// Объектно-безопасный сервис DMA-ремаппинга (реализация — платформа).
pub trait IommuService: Send + Sync {
    /// Число контроллеров (0 — IOMMU недоступен).
    fn controller_count(&self) -> usize;

    /// Обзор контроллера по индексу (0-based).
    fn controller_info(&self, idx: u32) -> Result<IommuInfo, IommuError>;

    /// Привязать устройство (BDF) к контроллеру: домен изоляции,
    /// непрозрачный DeviceId для последующих операций. Идемпотентно.
    fn attach(&self, ctrl: u32, bus: u8, device: u8, function: u8) -> Result<u32, IommuError>;

    /// Отобразить физические страницы в IOVA-пространство устройства.
    fn map_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        phys: u64,
        pages: usize,
        prot: u8,
    ) -> Result<(), IommuError>;

    /// Снять отображение IOVA-диапазона.
    fn unmap_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        pages: usize,
    ) -> Result<(), IommuError>;

    /// Отвязать устройство (контекстный вход гасится, таблицы домена
    /// освобождаются, если устройств домена не осталось).
    fn detach(&self, ctrl: u32, device: u32) -> Result<(), IommuError>;

    /// Запрограммировать IRTE устройства (IRQ-ремаппинг, v0.8):
    /// remapped-запись vector/dest. Возврат — handle (индекс IRTE,
    /// ненулевой: 0 — сисьмный «нет handle»), драйвер устройства
    /// кладёт его в MSI-адрес. Без включённого IR — RemappingDisabled.
    /// `flags`: bit0 = level-triggered, bit1 = logical destination mode.
    fn irq_map(
        &self,
        ctrl: u32,
        device: u32,
        vector: u8,
        dest: u8,
        flags: u8,
    ) -> Result<u32, IommuError>;

    /// Погасить IRTE по handle (IRR сбрасывается, кэш инвалидируется).
    fn irq_unmap(&self, ctrl: u32, device: u32, handle: u32) -> Result<(), IommuError>;
}

struct ServiceAnchor(&'static dyn IommuService);

unsafe impl Send for ServiceAnchor {}
unsafe impl Sync for ServiceAnchor {}

static SERVICE: Once<ServiceAnchor> = Once::new();

/// Установить сервис (одноразово; повторные вызовы игнорируются).
pub fn install_iommu_service(svc: &'static dyn IommuService) -> Option<&'static dyn IommuService> {
    Some(SERVICE.call_once(|| ServiceAnchor(svc)).0)
}

/// Установленный сервис (None — IOMMU-сисколы ENOSYS).
pub fn service() -> Option<&'static dyn IommuService> {
    SERVICE.get().map(|a| a.0)
}

// ───────────────────── Ошибки ─────────────────────

impl SyscallError {
    fn from_iommu(e: IommuError) -> Self {
        // IommuError не в системной таблице errno — переводим в
        // ближайшие значения; расширение таблицы — при появлении
        // реальных драйверов.
        match e {
            IommuError::OutOfMemory => SyscallError::OutOfMemory,
            IommuError::IovaConflict => SyscallError::AlreadyExists,
            IommuError::MappingNotFound
            | IommuError::DeviceNotBound
            | IommuError::UnknownDevicePath
            | IommuError::DeviceNotFound => SyscallError::NotFound,
            IommuError::InvalidIndex | IommuError::InvalidConfig => SyscallError::InvalidArgument,
            IommuError::HardwareTimeout => SyscallError::Internal,
            IommuError::NotSupported
            | IommuError::IommuNotPresent
            | IommuError::RemappingDisabled => SyscallError::NotSupported,
        }
    }
}

// ───────────────────── Хендлеры ─────────────────────

/// IOMMU_ENUM (0x80): обзор подсистемы.
///
/// ABI: arg1 = индекс контроллера; 0xFFFF_FFFF — число контроллеров.
/// Возврат для индекса: слово флагов — bit0 agaw48, bit1 queued_inval,
/// bit2 pass_through, bit3 include_all; arg2 = version, arg3 = mgaw
/// (чтение по индексу слова: arg1 = индекс, arg2 = 0..3 — упрощено:
/// единый вызов возвращает флаги, повторный с arg2=1 — version и т.д.
/// НЕ так: см. ABI ниже).
///
/// Финальный ABI (слова результата по arg2):
///   arg2=0 -> флаги (bit0..5) | (mgaw << 8); v0.8: bit4 = irq_remap,
///             bit5 = large_pages (2 МиБ)
///   arg2=1 -> version ((major<<8)|minor)
///   arg2=2 -> 1 (число доменов не экспортируем — v0.6)
pub struct IommuEnumHandler;

impl IommuEnumHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_ENUM;
}

impl SyscallHandler for IommuEnumHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let idx = args.arg(1) as u64;
        if idx == 0xFFFF_FFFF {
            return Ok(svc.controller_count());
        }
        let idx = idx as u32;
        let info = svc.controller_info(idx).map_err(SyscallError::from_iommu)?;
        let word = args.arg(2);
        Ok(match word {
            0 => {
                (info.mgaw_bits as usize) << 8
                    | (info.agaw48 as usize)
                    | (info.queued_inval as usize) << 1
                    | (info.pass_through as usize) << 2
                    | (info.include_all as usize) << 3
                    | (info.irq_remap as usize) << 4
                    | (info.large_pages as usize) << 5
            }
            1 => info.version as usize,
            _ => return Err(SyscallError::InvalidArgument),
        })
    }
}

/// IOMMU_ATTACH (0x81): BDF -> DeviceId (домен изоляции).
///
/// ABI: arg1 = контроллер (0-based), arg2 = bus, arg3 = device,
/// arg4 = function. Возврат: DeviceId.
pub struct IommuAttachHandler;

impl IommuAttachHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_ATTACH;
}

impl SyscallHandler for IommuAttachHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let bus = args.arg(2) as u8;
        let dev = args.arg(3) as u8;
        let fnc = args.arg(4) as u8;
        svc.attach(ctrl, bus, dev, fnc)
            .map(|id| id as usize)
            .map_err(SyscallError::from_iommu)
    }
}

/// IOMMU_MAP (0x82): физические страницы -> IOVA устройства.
///
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = iova (4K-выровнен),
/// arg4 = phys (4K-выровнен), arg5 = (pages:u32) | (prot:u8 << 32)
/// (prot: bit0 READ, bit1 WRITE, bit2 CACHE).
pub struct IommuMapHandler;

impl IommuMapHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_MAP;
}

impl SyscallHandler for IommuMapHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let dev = args.arg(2) as u32;
        let iova = args.arg(3) as u64;
        let phys = args.arg(4) as u64;
        let packed = args.arg(5) as u64;
        let pages = (packed & 0xFFFF_FFFF) as usize;
        let prot = (packed >> 32) as u8;
        svc.map_pages(ctrl, dev, iova, phys, pages, prot)
            .map(|_| 0)
            .map_err(SyscallError::from_iommu)
    }
}

/// IOMMU_UNMAP (0x83): снять IOVA-диапазон.
///
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = iova, arg4 = pages.
pub struct IommuUnmapHandler;

impl IommuUnmapHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_UNMAP;
}

impl SyscallHandler for IommuUnmapHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let dev = args.arg(2) as u32;
        let iova = args.arg(3) as u64;
        let pages = args.arg(4) as usize;
        svc.unmap_pages(ctrl, dev, iova, pages)
            .map(|_| 0)
            .map_err(SyscallError::from_iommu)
    }
}

/// IOMMU_DETACH (0x84): отвязать устройство.
///
/// ABI: arg1 = контроллер, arg2 = DeviceId.
pub struct IommuDetachHandler;

impl IommuDetachHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_DETACH;
}

impl SyscallHandler for IommuDetachHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let dev = args.arg(2) as u32;
        svc.detach(ctrl, dev)
            .map(|_| 0)
            .map_err(SyscallError::from_iommu)
    }
}

/// IOMMU_IRQ_MAP (0x85): запрограммировать IRTE (v0.8).
///
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = vector,
/// arg4 = APIC-destination, arg5 = флаги (bit0 level, bit1 logical).
/// Возврат: handle (индекс IRTE).
pub struct IommuIrqMapHandler;

impl IommuIrqMapHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_IRQ_MAP;
}

impl SyscallHandler for IommuIrqMapHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let dev = args.arg(2) as u32;
        let vector = (args.arg(3) as u64) as u8;
        let dest = (args.arg(4) as u64) as u8;
        let flags = (args.arg(5) as u64) as u8;
        svc.irq_map(ctrl, dev, vector, dest, flags)
            .map(|h| h as usize)
            .map_err(SyscallError::from_iommu)
    }
}

/// IOMMU_IRQ_UNMAP (0x86): погасить IRTE по handle.
///
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = handle.
pub struct IommuIrqUnmapHandler;

impl IommuIrqUnmapHandler {
    pub const SYSCALL: SyscallNumber = crate::syscall::nums::IOMMU_IRQ_UNMAP;
}

impl SyscallHandler for IommuIrqUnmapHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let Some(svc) = service() else {
            return Err(SyscallError::NotSupported);
        };
        let ctrl = args.arg(1) as u32;
        let dev = args.arg(2) as u32;
        let handle = args.arg(3) as u32;
        svc.irq_unmap(ctrl, dev, handle)
            .map(|_| 0)
            .map_err(SyscallError::from_iommu)
    }
}

// ───────────────────── Тесты (host) ─────────────────────

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicU32, Ordering};

    use crate::capability::CapabilityManager;
    use crate::syscall::types::{SyscallCtx, SyscallNumber};
    use crate::syscall::{SyscallArgs, SyscallError, SyscallHandler, SyscallRegistry};
    use crate::task::{TaskId, TcbManager, ThreadId};

    use super::*;

    /// Подсчитывающий мок-сервис.
    struct MockSvc {
        attached: AtomicU32,
        maps: AtomicU32,
        unmaps: AtomicU32,
        detached: AtomicU32,
        last_detached: AtomicU32,
        irq_mapped: AtomicU32,
        irq_unmapped: AtomicU32,
    }

    impl MockSvc {
        fn is_detached(&self, d: u32) -> bool {
            self.last_detached.load(Ordering::SeqCst) == d && d != 0
        }
    }

    impl IommuService for MockSvc {
        fn controller_count(&self) -> usize {
            1
        }
        fn controller_info(&self, idx: u32) -> Result<IommuInfo, IommuError> {
            if idx != 0 {
                return Err(IommuError::InvalidIndex);
            }
            Ok(IommuInfo {
                version: 0x0105,
                mgaw_bits: 48,
                agaw48: true,
                queued_inval: true,
                pass_through: false,
                include_all: true,
                irq_remap: true,
                large_pages: true,
            })
        }
        fn attach(&self, _c: u32, bus: u8, dev: u8, _f: u8) -> Result<u32, IommuError> {
            if bus == 0 && dev == 0 {
                return Err(IommuError::UnknownDevicePath); // host-мост не для DMA-демо
            }
            let id = self.attached.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(id)
        }
        fn map_pages(
            &self,
            _c: u32,
            d: u32,
            iova: u64,
            _p: u64,
            pages: usize,
            _prot: u8,
        ) -> Result<(), IommuError> {
            if d == 0 {
                return Err(IommuError::DeviceNotBound);
            }
            if iova % 4096 != 0 {
                return Err(IommuError::InvalidConfig);
            }
            if pages > 2 {
                return Err(IommuError::IovaConflict);
            }
            self.maps.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn unmap_pages(
            &self,
            _c: u32,
            d: u32,
            _iova: u64,
            _pages: usize,
        ) -> Result<(), IommuError> {
            if d == 0 || self.is_detached(d) {
                return Err(IommuError::DeviceNotBound);
            }
            self.unmaps.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn detach(&self, _c: u32, d: u32) -> Result<(), IommuError> {
            if d == 0 || self.is_detached(d) {
                return Err(IommuError::DeviceNotBound);
            }
            self.last_detached.store(d, Ordering::SeqCst);
            self.detached.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn irq_map(
            &self,
            _c: u32,
            d: u32,
            vector: u8,
            _dest: u8,
            _flags: u8,
        ) -> Result<u32, IommuError> {
            if d == 0 {
                return Err(IommuError::DeviceNotBound);
            }
            if !(0x10..=0xFE).contains(&vector) {
                return Err(IommuError::InvalidConfig);
            }
            let n = self.irq_mapped.fetch_add(1, Ordering::Relaxed);
            Ok(n + 1) // handle 1, 2, ... — 0 = «нет»
        }
        fn irq_unmap(&self, _c: u32, d: u32, handle: u32) -> Result<(), IommuError> {
            if d == 0 || self.is_detached(d) {
                return Err(IommuError::DeviceNotBound);
            }
            if handle == 0 {
                return Err(IommuError::InvalidConfig);
            }
            self.irq_unmapped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    // Глобальный Once не сбрасывается между тестами — мок ставится один
    // раз; тесты ниже НЕ полагаются на порядок (счётчики монотонны).
    static MOCK: MockSvc = MockSvc {
        attached: AtomicU32::new(0),
        maps: AtomicU32::new(0),
        unmaps: AtomicU32::new(0),
        detached: AtomicU32::new(0),
        last_detached: AtomicU32::new(0),
        irq_mapped: AtomicU32::new(0),
        irq_unmapped: AtomicU32::new(0),
    };

    fn ensure_svc() {
        let _ = install_iommu_service(&MOCK);
    }

    fn registry_with_iommu() -> SyscallRegistry {
        let r = SyscallRegistry::new();
        r.install_default_table();
        r
    }

    fn ctx_of<'a>(
        tasks: &'a TcbManager,
        caps: &'a CapabilityManager,
        task: TaskId,
        thread: ThreadId,
    ) -> SyscallCtx<'a> {
        SyscallCtx::core(5, task, tasks, caps).with_thread(thread)
    }

    #[test]
    fn enum_words() {
        ensure_svc();
        let r = registry_with_iommu();
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let id = TaskId::from_u128(0x9001);
        let mut ctx = ctx_of(&tasks, &caps, id, id);
        assert_eq!(
            r.dispatch_number(
                IommuEnumHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0xFFFF_FFFF, 0, 0, 0, 0])
            ),
            Ok(1)
        );
        // Флаги: agaw48(1) | qi(2) | include_all(8) | irq_remap(0x10)
        // | large_pages(0x20) | mgaw<<8 = 0x303B.
        assert_eq!(
            r.dispatch_number(
                IommuEnumHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 0, 0, 0, 0])
            ),
            Ok(0x303B)
        );
        assert_eq!(
            r.dispatch_number(
                IommuEnumHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 1, 0, 0, 0])
            ),
            Ok(0x0105)
        );
        assert_eq!(
            r.dispatch_number(
                IommuEnumHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 1, 0, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument) // InvalidIndex -> InvalidArgument
        );
    }

    #[test]
    fn attach_map_unmap_detach_cycle() {
        ensure_svc();
        let r = registry_with_iommu();
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let id = TaskId::from_u128(0x9002);
        let mut ctx = ctx_of(&tasks, &caps, id, id);
        let dev = r
            .dispatch_number(
                IommuAttachHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 2, 0, 1, 0]),
            )
            .expect("attach");
        assert!(dev > 0);
        // Мост 00:00.0 — не устройство DMA-демо.
        assert_eq!(
            r.dispatch_number(
                IommuAttachHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 0, 0, 0, 0])
            ),
            Err(SyscallError::NotFound)
        );
        // Map: 2 страницы RW по iova 0x10000.
        let prot_rw = 0b011u64;
        let packed = 2 | (prot_rw << 32);
        assert_eq!(
            r.dispatch_number(
                IommuMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x1_0000, 0x20_0000, packed as usize])
            ),
            Ok(0)
        );
        // Незакруглённый IOVA — InvalidConfig.
        assert_eq!(
            r.dispatch_number(
                IommuMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x1_0001, 0x20_0000, packed as usize])
            ),
            Err(SyscallError::InvalidArgument)
        );
        // 3 страницы — IovaConflict (мок-лимит).
        let packed3 = 3 | (prot_rw << 32);
        assert_eq!(
            r.dispatch_number(
                IommuMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x2_0000, 0x20_0000, packed3 as usize])
            ),
            Err(SyscallError::AlreadyExists)
        );
        assert_eq!(
            r.dispatch_number(
                IommuUnmapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x1_0000, 2, 0])
            ),
            Ok(0)
        );
        assert_eq!(
            r.dispatch_number(
                IommuDetachHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0, 0, 0])
            ),
            Ok(0)
        );
        assert_eq!(
            r.dispatch_number(
                IommuUnmapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x1_0000, 1, 0])
            ),
            Err(SyscallError::NotFound)
        );
    }

    #[test]
    fn irq_map_unmap_cycle() {
        ensure_svc();
        let r = registry_with_iommu();
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let id = TaskId::from_u128(0x9004);
        let mut ctx = ctx_of(&tasks, &caps, id, id);
        let dev = r
            .dispatch_number(
                IommuAttachHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 3, 0, 0, 0]),
            )
            .expect("attach");
        // IRQ_MAP: vector 0x41 -> handle > 0 (0 = «нет»).
        let handle = r
            .dispatch_number(
                IommuIrqMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x41, 0, 0]),
            )
            .expect("irq_map");
        assert!(handle > 0);
        // Вектор вне 0x10..0xFE — InvalidConfig.
        assert_eq!(
            r.dispatch_number(
                IommuIrqMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0x05, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
        // Незакреплённое устройство — DeviceNotBound.
        assert_eq!(
            r.dispatch_number(
                IommuIrqMapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 0, 0x41, 0, 0])
            ),
            Err(SyscallError::NotFound)
        );
        assert_eq!(
            r.dispatch_number(
                IommuIrqUnmapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, handle, 0, 0])
            ),
            Ok(0)
        );
        // handle = 0 — InvalidConfig.
        assert_eq!(
            r.dispatch_number(
                IommuIrqUnmapHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, dev, 0, 0, 0])
            ),
            Err(SyscallError::InvalidArgument)
        );
    }

    #[test]
    fn default_table_contains_iommu() {
        ensure_svc();
        let r = registry_with_iommu();
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let id = TaskId::from_u128(0x9003);
        let mut ctx = ctx_of(&tasks, &caps, id, id);
        // Дефолтная таблица диспетчеризует IOMMU-группу (без сервиса —
        // NotSupported, но НЕ «нет хендлера»: различаем через мок выше —
        // сервис уже стоит в ensure_svc).
        let ret = r.dispatch_number(
            IommuEnumHandler::SYSCALL,
            &mut ctx,
            &SyscallArgs::new([0, 0xFFFF_FFFF, 0, 0, 0, 0]),
        );
        assert_eq!(ret, Ok(1));
        // Номера — плотная группа 0x80..0x86.
        assert_eq!(IommuEnumHandler::SYSCALL, SyscallNumber(0x80));
        assert_eq!(IommuAttachHandler::SYSCALL, SyscallNumber(0x81));
        assert_eq!(IommuMapHandler::SYSCALL, SyscallNumber(0x82));
        assert_eq!(IommuUnmapHandler::SYSCALL, SyscallNumber(0x83));
        assert_eq!(IommuDetachHandler::SYSCALL, SyscallNumber(0x84));
        assert_eq!(IommuIrqMapHandler::SYSCALL, SyscallNumber(0x85));
        assert_eq!(IommuIrqUnmapHandler::SYSCALL, SyscallNumber(0x86));
    }
}
