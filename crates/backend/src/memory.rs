// ==== Таблицы страниц: бекенд MMAP/KMAP/ASID поверх крейта x86_64 ====
//
// Контракты ядра (`hal::traits`), исполненные x86_64-железом:
//
//   * `UserTables` — адресное пространство пользовательского фасада:
//     PML4 из физического пула; реализует MMAPInterface (extend/shrink
//     диапазона), KMAPInterface (перенос ядра в пользовательскую
//     таблицу) и ASIDInterface (activate = запись CR3; теги PCID в v0.5
//     не используются — нетегированный бекенд).
//   * `kernel_root` — снапшот корня ядерных таблиц (head.S строит их
//     статикой и переключает CR3 до входа в rust; снапшот обязателен:
//     после первого activate(User) текущий CR3 перестаёт быть ядерным).
//
// Геометрия (arch::boot): ядро — high-half KERNEL_LINK_BASE, вся
// физика — physmap (PHYSMAP_BASE, 4 GiB покрытие), пользователь — от
// USER_ALLOC_BASE. Политика изоляции — MapFullKernel: верхняя половина
// пользовательского PML4 = копия ядерной (supervisor-only), Meltdown-
// класс закрыт только на железе с RDCL_NO — проверка в startup, здесь
// только исполнение политики.
//
// Ограничение v0.5 (сознательное, задокументировано): shrink_region
// НЕ освобождает опустевшие промежуточные таблицы (PDPT/PD/PT остаются
// закреплены за пространством до его гибели). Цена — несколько KiB на
// задачу; корректность не страдает. Освобождение — v0.6 с подсчётом
// ссылок записей.

use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use llfree::Alloc;

use pkg_generic_interface::hal::traits::asid::{
    ASIDInterface, AddressSpaceMode, AsidPair, FlushMode, TlbOp,
};
use pkg_generic_interface::hal::traits::kmap::{KMAPInterface, KernelRegion, KernelRegionKind};
use pkg_generic_interface::hal::traits::mmap::{
    MMAPInterface, MMAPMemoryFlags, MemErrorCode, PAGE_SIZE, PageInfo, PhysADDR, VirtualADDR,
};
use pkg_generic_interface::mem::gallocator;

use arch::boot;

// ───────────────────────── physmap-хелперы ─────────────────────────

/// Физика -> physmap-вирт (ядро читает любую память верхней половиной).
#[inline]
pub fn phys_to_virt(p: u64) -> u64 {
    boot::PHYSMAP_BASE + p
}

/// Типизированный physmap-указатель.
#[inline]
pub fn phys_ptr<T>(p: u64) -> *mut T {
    phys_to_virt(p) as *mut T
}

// ───────────────────────── Корень ядра ─────────────────────────

static KERNEL_ROOT: spin::Once<u64> = spin::Once::new();

/// Запомнить ядерный корень (вызывается калибровщиком kinit РОВНО один
/// раз, до первого activate пользовательского пространства: текущий CR3
/// в этот момент — ядерный, построенный head.S).
pub fn init_kernel_root() -> u64 {
    *KERNEL_ROOT.call_once(|| {
        x86_64::registers::control::Cr3::read()
            .0
            .start_address()
            .as_u64()
    })
}

/// Ядерный корень (физика). Паника до `init_kernel_root` — ошибка
/// последовательности запуска (раньше звать некому).
pub fn kernel_root() -> u64 {
    KERNEL_ROOT
        .get()
        .copied()
        .expect("backend: kernel root not initialised (call init_kernel_root from kinit)")
}

// ───────────────────────── Фреймы для таблиц ─────────────────────────

/// Адаптер: LLFree (глобальный пул ядра) как FrameAllocator для
/// промежуточных таблиц x86_64-mapper'а.
struct LlfreeFrames;

unsafe impl FrameAllocator<Size4KiB> for LlfreeFrames {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let llf = gallocator::llfree()?;
        // Class(0) — small: зарегистрирован Classing::simple при создании
        // LLFree (startup); order 0 = одна страница.
        let req = llfree::Request::new(0, llfree::Class(0), None);
        let (fid, _) = llf.get(None, req).ok()?;
        PhysFrame::from_start_address(PhysAddr::new(fid.0 as u64 * PAGE_SIZE as u64)).ok()
    }
}

/// Перевод флагов ядра в PTE-флаги x86_64 (пользовательская страница).
fn user_pte_flags(mmap: MMAPMemoryFlags) -> PageTableFlags {
    let mut f = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if mmap.contains(MMAPMemoryFlags::WRITABLE) {
        f |= PageTableFlags::WRITABLE;
    }
    // W^X гарантирует W без X: NX ставим всему неисполняемому.
    if !mmap.contains(MMAPMemoryFlags::EXECUTABLE) {
        f |= PageTableFlags::NO_EXECUTE;
    }
    if mmap.contains(MMAPMemoryFlags::GLOBAL) {
        f |= PageTableFlags::GLOBAL;
    }
    f
}

// ───────────────────────── Пользовательские таблицы ─────────────────────────

/// Адресное пространство задачи: PML4 + реализации контрактов ядра.
///
/// Один тип на три трейта — требование `create_ufacade[_asid]`
/// (MmapWraper: MMAPInterface + KMAPInterface [+ ASIDInterface]).
pub struct UserTables {
    /// Физический адрес PML4.
    root: u64,
}

impl UserTables {
    /// Создать пустое пространство: PML4-фрейм из пула, обнулён.
    pub fn new() -> Result<Self, MemErrorCode> {
        let llf = gallocator::llfree().ok_or(MemErrorCode::InternalError)?;
        let req = llfree::Request::new(0, llfree::Class(0), None);
        let (fid, _) = llf.get(None, req).map_err(|_| MemErrorCode::NoMemoryLeft)?;
        let root = fid.0 as u64 * PAGE_SIZE as u64;
        // Обнулить корень (в кадре мусор от прошлой жизни).
        // SAFETY: страница принадлежит нам (только что из пула), physmap
        // покрывает её физику.
        unsafe { core::ptr::write_bytes(phys_ptr::<u8>(root), 0, PAGE_SIZE) };
        Ok(Self { root })
    }

    /// Физический корень PML4.
    pub fn root_phys(&self) -> u64 {
        self.root
    }

    /// Mapper поверх physmap для ЭТОГО пространства.
    ///
    /// SAFETY (вызывающий = сам бекенд): корень валиден и не заменяется
    /// одновременно из другого контекста; physmap покрывает root.
    unsafe fn mapper(&mut self) -> OffsetPageTable<'static> {
        // SAFETY: контракт выше; 'static — physmap живёт вечно.
        unsafe {
            OffsetPageTable::new(
                &mut *phys_ptr::<PageTable>(self.root),
                VirtAddr::new(boot::PHYSMAP_BASE),
            )
        }
    }

    /// Копия ядерных PML4-записей диапазона в это пространство
    /// (supervisor-only: флаги USER_ACCESSIBLE у ядерных записей нет).
    fn copy_kernel_entries(&mut self, v_base: VirtualADDR, pages_count: usize) {
        // Индекс PML4 — ровно 9 бит каноничного адреса: биты знакового
        // расширения (47+) обязаны сниматься маской, иначе для верхней
        // половины индекс уезжает за 511 и цикл копирования пуст
        // (баг v0.5.2: physmap/ядро не попадали в пользовательские PML4).
        let first = (v_base.as_usize() >> 39) & 0x1FF;
        let last = ((v_base.as_usize() + (pages_count << 12).saturating_sub(1)) >> 39) & 0x1FF;
        crate::kprintln!(
            "kmap: copy entries [{}..={}] into root={:#x} (kern_root={:#x})",
            first,
            last.min(511),
            self.root,
            kernel_root()
        );
        // SAFETY: обе таблицы доступны через physmap.
        unsafe {
            let kern = &*phys_ptr::<PageTable>(kernel_root());
            let user = &mut *phys_ptr::<PageTable>(self.root);
            for i in first..=last.min(511) {
                if i >= 256 {
                    user[i] = kern[i].clone();
                }
            }
        }
    }
}

impl MMAPInterface for UserTables {
    fn extend_region(
        &mut self,
        _allocator: &llfree::LLFree<'static>,
        v_base: VirtualADDR,
        p_base: PhysADDR,
        pages: usize,
        mmap: MMAPMemoryFlags,
    ) -> Result<PageInfo, MemErrorCode> {
        if pages == 0 || !v_base.is_aligned() || !p_base.is_aligned() {
            return Err(MemErrorCode::InvalidArgument(
                "extend_region: zero size or unaligned",
            ));
        }
        let flags = user_pte_flags(mmap);
        let start_va = VirtAddr::new(v_base.as_usize() as u64);
        let start_page = Page::<Size4KiB>::containing_address(start_va);
        for off in 0..pages as u64 {
            let page = start_page + off;
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
                p_base.as_usize() as u64 + off * PAGE_SIZE as u64,
            ));
            // SAFETY: mapper валиден (см. UserTables::mapper); флаги не
            // конфликтуют с существующими записями (map_to следит).
            let r = unsafe { self.mapper().map_to(page, frame, flags, &mut LlfreeFrames) }
                .map_err(|_| MemErrorCode::AlreadyMapped)?;
            // Флаш сразу: ошибка не накапливается между страницами.
            unsafe { r.flush() };
        }
        Ok(PageInfo::new(p_base, pages))
    }

    fn shrink_region(
        &mut self,
        _phys_page_allocator: &llfree::LLFree<'static>,
        allocation: VirtualADDR,
        pages: usize,
    ) -> Result<(), MemErrorCode> {
        if pages == 0 || !allocation.is_aligned() {
            return Err(MemErrorCode::InvalidArgument(
                "shrink_region: zero size or unaligned",
            ));
        }
        let start_page =
            Page::<Size4KiB>::containing_address(VirtAddr::new(allocation.as_usize() as u64));
        for off in 0..pages as u64 {
            let page = start_page + off;
            // SAFETY: mapper валиден; unmap возвращает фрейм-владельцу
            // только ВИРТУАЛЬНУЮ запись — физику возвращает UFacade.
            let r = unsafe { self.mapper() }
                .unmap(page)
                .map_err(|_| MemErrorCode::NotMapped)?;
            unsafe { r.1.flush() };
        }
        Ok(())
    }

    /// Нетегированный бекенд: теги в TlbOp игнорируются, операция
    /// выполняется минимально достаточной нетегированной формой.
    ///
    /// SMP v0.6: инвалидация — ЛОКАЛЬНО + рассылка остальным CPU
    /// (smp::tlb_shootdown): чужой CPU может исполнять пользовательский
    /// код В ЭТОМ пространстве (BKL не защищает user-исполнение).
    /// Вызывается только под BKL (пути фасада) — инициатор
    /// сериализован, тупиков нет (см. klock/smp).
    fn invalidate_tlb(&mut self, op: TlbOp) -> Result<(), MemErrorCode> {
        match op {
            TlbOp::Page { v, .. } => {
                crate::smp::tlb_shootdown(crate::smp::ShootMode::Page, v.as_usize() as u64);
            }
            // Нет тегов: контекст = все не-глобальные записи CPU.
            TlbOp::Context(_) | TlbOp::Pair(_) => {
                crate::smp::tlb_shootdown(crate::smp::ShootMode::All, 0);
            }
            TlbOp::All { include_global } => {
                if include_global {
                    crate::smp::tlb_shootdown(crate::smp::ShootMode::AllGlobal, 0);
                } else {
                    crate::smp::tlb_shootdown(crate::smp::ShootMode::All, 0);
                }
            }
        }
        Ok(())
    }
}

/// Сброс TLB-глобальных записей через CR4.PGE toggle.
///
/// SAFETY: привилегированный код ядра; только полный флаш.
unsafe fn toggle_pge() {
    use x86_64::registers::control::Cr4;
    let mut cr4 = Cr4::read_raw();
    let pge = cr4 & (1 << 7);
    cr4 &= !(1 << 7);
    // SAFETY: выкл PGE и записать CR4 (гасит глобальные записи).
    unsafe { Cr4::write_raw(cr4) };
    core::arch::asm!("lfence");
    // SAFETY: вернуть PGE как было.
    unsafe { Cr4::write_raw(cr4 | pge) };
}

/// Полный локальный сброс TLB, включая глобальные записи (CR3 + PGE
/// toggle). Обёртка для SMP-shootdown (см. smp::tlb_shootdown).
///
/// SAFETY: привилегированный код ядра; полный флаш.
pub unsafe fn flush_all_global() {
    use x86_64::instructions::tlb;
    tlb::flush_all();
    // SAFETY: см. toggle_pge.
    unsafe { toggle_pge() };
}

impl KMAPInterface for UserTables {
    /// Перенос региона ядра в пользовательскую таблицу.
    ///
    /// MapFullKernel: Kernel-регионы — копия ядерных PML4-записей
    /// (supervisor-only по построению ядерных таблиц). EntryTrampoline
    /// в v0.5 не используется (нет KPTI) — обрабатываем как Kernel.
    /// UserShared — копия тех же записей + USER_ACCESSIBLE в флагах
    /// нижнего уровня: разделяемые с пользователем страницы обязаны быть
    /// доступны ему (контракт KMAPInterface п.2).
    fn map_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode> {
        crate::kprintln!(
            "kmap: region {} vbase={:#x} pages={} root={:#x}",
            region.name(),
            region.v_base().as_usize(),
            region.pages_count(),
            self.root
        );
        match region.kind() {
            KernelRegionKind::Kernel | KernelRegionKind::EntryTrampoline => {
                self.copy_kernel_entries(region.v_base(), region.pages_count());
                Ok(())
            }
            KernelRegionKind::UserShared => {
                // v0.5: разделяемых регионов в KMAP ядра нет (нет vdso);
                // корректная реализация потребует физику региона, которой
                // тип сознательно не несёт — расширение v0.6.
                Err(MemErrorCode::InvalidArgument(
                    "backend: UserShared KMAP regions are not supported in v0.5",
                ))
            }
        }
    }

    /// Снятие региона: очистка PML4-записей диапазона (только целиком
    /// попавшие PML4-слоты; частичный слот — ошибка конфигурации).
    fn unmap_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode> {
        // 9-битные индексы PML4 (маска знакового расширения — см. copy).
        let first = (region.v_base().as_usize() >> 39) & 0x1FF;
        let last = ((region.v_base().as_usize() + (region.pages_count() << 12).saturating_sub(1))
            >> 39)
            & 0x1FF;
        if first != last {
            return Err(MemErrorCode::InvalidArgument(
                "unmap_kernel_region: region spans multiple PML4 slots",
            ));
        }
        // SAFETY: корень доступен через physmap, эксклюзивно наш.
        unsafe {
            let user = &mut *phys_ptr::<PageTable>(self.root);
            user[first].set_unused();
        }
        Ok(())
    }
}

impl ASIDInterface for UserTables {
    /// Нетегированный бекенд: пары тегов не выдаются; тегированный путь
    /// (`create_ufacade_asid`) на этом бекенде не работает —startup
    /// использует plain `create_ufacade`.
    fn assign_asid_pair(&mut self, _pair: AsidPair) -> Result<(), MemErrorCode> {
        Err(MemErrorCode::InvalidArgument(
            "backend: untagged (no PCID) — ASID pairs not supported",
        ))
    }

    fn asid_pair(&self) -> Option<AsidPair> {
        None
    }

    /// Активация таблицы: запись CR3 (нетегированная — полный сброс
    /// не-глобальных записей текущего CPU; FlushMode::NoFlush без PCID
    /// невозможен — сброс всегда, это безопаснее, чем утечка переводов).
    fn activate(&mut self, mode: AddressSpaceMode, _flush: FlushMode) -> Result<(), MemErrorCode> {
        let root = match mode {
            AddressSpaceMode::User => self.root,
            AddressSpaceMode::Kernel => kernel_root(),
        };
        let frame = PhysFrame::from_start_address(PhysAddr::new(root))
            .map_err(|_| MemErrorCode::Unaligned)?;
        // SAFETY: привилегированный код ядра; корень валиден.
        unsafe {
            x86_64::registers::control::Cr3::write(
                frame,
                x86_64::registers::control::Cr3Flags::empty(),
            )
        };
        Ok(())
    }

    fn root_table(&self) -> Option<PhysADDR> {
        Some(PhysADDR(self.root as usize))
    }
}
