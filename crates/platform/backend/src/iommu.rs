// ==== IOMMU: общие хелперы драйверов + агрегатор сервисов (Intel VT-d | AMD-Vi) ====
//
// Общее для обоих драйверов (vtd/amd):
//   * `Mmio` — блок MMIO-регистров контроллера через physmap (volatile);
//   * `zero_page`/`free_page` — кадры из ядрового LLFree-пула (как v0.6);
//   * `zero_huge` — contiguous 2 МиБ (порядок 9, Class(1)): Device Table
//     AMD-Vi (65536 DTE × 32 байта).
//
// Инвариант v0.6 (унаследован): база ядрового пула = 0 → fid ≡ физика/4K
// (см. pools.rs: free_range с fid_base 0 у доступного low-mem). Все
// структуры IOMMU живут в физике < 4 GiB (physmap; QEMU-масштаб).
//
// `IommuAgg` — объектно-безопасный сервис сисколов IOMMU_* поверх готовых
// контроллеров: сперва ВСЕ единицы Intel (в порядке DMAR), затем ВСЕ
// единицы AMD (в порядке IVRS; QEMU кладёт 10h/11h одной единицы —
// дедуп по базе в драйверах). Индексация ENUM — сквозная и стабильна.

use kernel_hal::traits::iommu::IommuError;
use pkg_generic_interface::syscall::iommu::{IommuInfo, IommuService};

use crate::amd::AMD0;
use crate::memory::phys_ptr;
use crate::vtd::VTD0;

// ───────────────────── MMIO (physmap, volatile) ─────────────────────

/// Блок MMIO-регистров контроллера IOMMU.
#[derive(Clone, Copy)]
pub(crate) struct Mmio {
    base: u64,
}

impl Mmio {
    pub(crate) const fn new(base: u64) -> Self {
        Self { base }
    }

    pub(crate) fn read32(&self, off: u64) -> u32 {
        // SAFETY: physmap покрывает MMIO (< 4 GiB), выравнивание 4.
        unsafe { phys_ptr::<u32>(self.base + off).read_volatile() }
    }

    pub(crate) fn read64(&self, off: u64) -> u64 {
        // SAFETY: как read32, выравнивание 8.
        unsafe { phys_ptr::<u64>(self.base + off).read_volatile() }
    }

    pub(crate) fn write32(&self, off: u64, v: u32) {
        // SAFETY: как read32.
        unsafe { phys_ptr::<u32>(self.base + off).write_volatile(v) };
    }

    pub(crate) fn write64(&self, off: u64, v: u64) {
        // SAFETY: как read64.
        unsafe { phys_ptr::<u64>(self.base + off).write_volatile(v) };
    }
}

// ───────────────────── Кадры (ядровый LLFree) ─────────────────────

/// Выделить обнулённую страницу (физика). None — пул не поднят/кончился.
pub(crate) fn zero_page() -> Option<u64> {
    let frames = pkg_generic_interface::mem::gallocator::frames()?;
    let (_, fid) = frames.alloc(0, llfree::Class(0), None).ok()?;
    let phys = fid.0 as u64 * 4096;
    // SAFETY: кадр наш, physmap покрывает.
    unsafe { core::ptr::write_bytes(phys_ptr::<u8>(phys), 0, 4096) };
    Some(phys)
}

/// Вернуть страницу в пул.
pub(crate) fn free_page(phys: u64) {
    if let Some(frames) = pkg_generic_interface::mem::gallocator::frames() {
        let fid = llfree::FrameId((phys / 4096) as usize);
        frames.free(fid, 0, llfree::Class(0), None);
    }
}

/// Выделить обнулённые 2 МиБ (512 contiguous кадров, порядок 9, «большие»
/// куски пула Class(1)). None — пул не поднят/нет свободного huge.
pub(crate) fn zero_huge() -> Option<u64> {
    let frames = pkg_generic_interface::mem::gallocator::frames()?;
    let (_, fid) = frames.alloc(9, llfree::Class(1), None).ok()?;
    let phys = fid.0 as u64 * 4096;
    // SAFETY: 512 наших кадров подряд (huge-выравнивание LLFree), physmap
    // покрывает (физика < 4 GiB).
    unsafe { core::ptr::write_bytes(phys_ptr::<u8>(phys), 0, 512 * 4096) };
    Some(phys)
}

// ───────────────────── Агрегатор сервисов ─────────────────────

/// Готовые контроллеры: сперва все Intel (в порядке DMAR), затем все
/// AMD (в порядке IVRS). Возвращает (драйвер, локальный индекс внутри
/// драйвера) для сквозного индекса сискола.
fn pick(idx: u32) -> Result<(&'static dyn IommuService, u32), IommuError> {
    let nv = VTD0.controller_count() as u32;
    let na = AMD0.controller_count() as u32;
    if idx < nv {
        return Ok((&VTD0, idx));
    }
    let amd_idx = idx - nv;
    if amd_idx < na {
        return Ok((&AMD0, amd_idx));
    }
    if nv + na == 0 {
        Err(IommuError::IommuNotPresent)
    } else {
        Err(IommuError::InvalidIndex)
    }
}

/// Сервис-агрегатор: единственная установка в syscall::iommu::SERVICE.
/// Сквозной индекс контроллера транслируется в (драйвер, локальный).
pub struct IommuAgg;

static AGG: IommuAgg = IommuAgg;

impl IommuService for IommuAgg {
    fn controller_count(&self) -> usize {
        VTD0.controller_count() + AMD0.controller_count()
    }

    fn controller_info(&self, idx: u32) -> Result<IommuInfo, IommuError> {
        let (d, local) = pick(idx)?;
        d.controller_info(local)
    }

    fn attach(&self, ctrl: u32, bus: u8, device: u8, function: u8) -> Result<u32, IommuError> {
        let (d, local) = pick(ctrl)?;
        d.attach(local, bus, device, function)
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
        let (d, local) = pick(ctrl)?;
        d.map_pages(local, device, iova, phys, pages, prot)
    }

    fn unmap_pages(
        &self,
        ctrl: u32,
        device: u32,
        iova: u64,
        pages: usize,
    ) -> Result<(), IommuError> {
        let (d, local) = pick(ctrl)?;
        d.unmap_pages(local, device, iova, pages)
    }

    fn detach(&self, ctrl: u32, device: u32) -> Result<(), IommuError> {
        let (d, local) = pick(ctrl)?;
        d.detach(local, device)
    }

    fn irq_map(
        &self,
        ctrl: u32,
        device: u32,
        vector: u8,
        dest: u8,
        flags: u8,
    ) -> Result<u32, IommuError> {
        let (d, local) = pick(ctrl)?;
        d.irq_map(local, device, vector, dest, flags)
    }

    fn irq_unmap(&self, ctrl: u32, device: u32, handle: u32) -> Result<(), IommuError> {
        let (d, local) = pick(ctrl)?;
        d.irq_unmap(local, device, handle)
    }
}

// ───────────────────── Запуск (X86Platform::run) ─────────────────────

/// Запуск IOMMU-подсистемы: DMAR (Intel VT-d) и IVRS (AMD-Vi) по очереди;
/// сервис сисколов ставится агрегатором, если поднялся хоть один
/// контроллер. Вызывается ПОСЛЕ kinit (пулы/куча подняты), ДО release_aps
/// (конкуренции ещё нет — APы припаркованы).
pub fn init_and_install() {
    // Пул не поднят (ранний fatal-путь run()) — тихо уходим: сисколы
    // ответят ENOSYS.
    if pkg_generic_interface::mem::gallocator::frames().is_none() {
        return;
    }
    let vtd = crate::vtd::try_init();
    let amd = crate::amd::try_init();
    if !vtd && !amd {
        crate::kprintln!("iommu: no controllers (QEMU: -device intel-iommu | -device amd-iommu)");
        return;
    }
    // Связка с syscall-слоем: без SERVICE Once все IOMMU_* отвечают ENOSYS
    // (баг v0.6.1 — см. vtd.rs); агрегатор покрывает оба вендора.
    pkg_generic_interface::syscall::iommu::install_iommu_service(&AGG);
    crate::kprintln!(
        "iommu: IommuService installed ({} controller(s), IOMMU_* syscalls live)",
        AGG.controller_count()
    );
}
