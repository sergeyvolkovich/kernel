//! Связка talc (куча ядра) и llfree (аллокатор фреймов).
//!
//! Архитектура:
//!   1. FRAMES (llfree) — общий backend для фреймов
//!   2. Глобальный аллокатор (talc) — использует FRAMES для роста кучи
//!   3. Slab-пул — использует FRAMES напрямую, независимо от глобального аллокатора
//!
//! Все три компонента могут инициализироваться и работать независимо.

use core::{alloc::Layout, ptr::NonNull};

use attachable_slab_allocator::{Result, SlabError, define_allocation_hooks};
use llfree::{Alloc, Class, FRAME_SIZE, FrameId, HUGE_ORDER, LLFree, Request, TREE_ORDER};
use spin::{Mutex, Once};
use talc::{
    DefaultBinning,
    base::{Talc, binning::Binning},
    min_first_heap_size,
    source::Source,
    sync::TalcLock,
};

const MIN_CHUNK_ORDER: usize = HUGE_ORDER;

// ===========================================================================
// Фреймовый слой — общий backend для обоих аллокаторов
// ===========================================================================

pub struct Frames {
    llf: LLFree<'static>,
    mem_base: usize,
    /// Виртуальная база ядерной кучи (physmap платформы): указатели
    /// кучи/слэба = физика + virt_base. Куча ОБЯЗАНА жить в диапазоне,
    /// переносимом в пользовательские таблицы (physmap копируется в
    /// PML4[256..512] задач): сырые физические адреса ядру как указатели
    /// запрещены — под пользовательским CR3 они не отображены.
    virt_base: usize,
}

static FRAMES: Once<Frames> = Once::new();

/// Инициализация фреймового слоя. Должна быть вызвана первой.
/// `virt_base` — виртуальная база direct-map (x86_64: PHYSMAP_BASE).
pub fn init_frames(llf: LLFree<'static>, mem_base: usize, virt_base: usize) {
    debug_assert_eq!(
        mem_base % (FRAME_SIZE << MIN_CHUNK_ORDER),
        0,
        "mem_base не выровнен на 2 МиБ"
    );
    FRAMES.call_once(move || Frames {
        llf,
        mem_base,
        virt_base,
    });
}

#[inline(always)]
pub fn frames() -> Option<&'static Frames> {
    FRAMES.get()
}

#[inline(always)]
pub fn llfree() -> Option<&'static LLFree<'static>> {
    FRAMES.get().map(|f| &f.llf)
}

impl Frames {
    #[inline(always)]
    pub fn alloc(
        &self,
        order: usize,
        class: Class,
        cpu: Option<usize>,
    ) -> core::result::Result<(usize, FrameId), ()> {
        let req = Request::new(order, class, cpu);
        let (frame, _class) = self.llf.get(None, req).map_err(|_| ())?;
        Ok((self.mem_base + frame.0 * FRAME_SIZE, frame))
    }

    #[inline(always)]
    pub fn free(&self, frame: FrameId, order: usize, class: Class, cpu: Option<usize>) {
        let _ = self.llf.put(frame, Request::new(order, class, cpu));
    }

    #[inline(always)]
    pub fn tree_stats(&self) -> llfree::TreeStats {
        self.llf.tree_stats()
    }

    #[inline(always)]
    pub fn drain_locals(&self) {
        self.llf.drain();
    }
}

#[inline(always)]
fn local_cpu() -> Option<usize> {
    // Some(crate::percpu::cpu_id())
    None
}

// ===========================================================================
// Slab-пул — независимый аллокатор для attachable_slab_allocator
// ===========================================================================

/// Пул для slab-аллокатора. Получает фреймы напрямую из llfree,
/// минуя глобальный аллокатор.
pub struct SlabPool {
    frames: &'static Frames,
    slab_order: usize, // размер slab в фреймах (степень двойки)
    slab_class: Class,
}

static SLAB_POOL: Once<SlabPool> = Once::new();

/// Инициализация slab-пула. Может быть вызвана независимо от глобального аллокатора.
///
/// # Arguments
/// * `slab_size` — размер одного slab в байтах. Должен быть степенью двойки.
///   Будет округлен вверх до кратного FRAME_SIZE.
pub fn init_slab_pool(slab_size: usize) {
    let frames = FRAMES
        .get()
        .expect("FRAMES must be initialized before SLAB_POOL");

    // Вычисляем order: сколько фреймов нужно для одного slab
    let frames_per_slab = slab_size.div_ceil(FRAME_SIZE);
    let slab_order = frames_per_slab.next_power_of_two().trailing_zeros() as usize;

    SLAB_POOL.call_once(move || SlabPool {
        frames,
        slab_order,
        slab_class: Class(1), // huge class для больших блоков
    });
}

impl SlabPool {
    /// Выделить память для slab. Возвращает указатель на выровненный блок.
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
        // Проверяем, что запрашиваемый размер не превышает размер slab
        let slab_size = FRAME_SIZE << self.slab_order;
        if layout.size() > slab_size {
            return None;
        }

        // Выделяем фреймы из llfree напрямую
        let (phys, _frame_id) = self
            .frames
            .alloc(self.slab_order, self.slab_class, local_cpu())
            .ok()?;

        // Указатель слэба — ВИРТУАЛЬНЫЙ (physmap): см. Frames::virt_base.
        let addr = self.frames.virt_base + phys;

        // Проверяем выравнивание виртуального указателя (его и вернём).
        if addr % layout.align() != 0 {
            // Если выравнивание не подходит, освобождаем и возвращаем None
            // (в реальности slab-аллокатор должен запрашивать правильно выровненную память)
            let frame = FrameId((phys - self.frames.mem_base) / FRAME_SIZE);
            self.frames
                .free(frame, self.slab_order, self.slab_class, local_cpu());
            return None;
        }

        NonNull::new(addr as *mut u8)
    }

    /// Освободить память slab.
    #[inline(always)]
    unsafe fn free(&self, ptr: NonNull<u8>, _layout: Layout) {
        let addr = ptr.as_ptr() as usize;

        // Указатель виртуальный (physmap): снять virt_base, затем FrameId.
        let phys = addr - self.frames.virt_base;
        let frame = FrameId((phys - self.frames.mem_base) / FRAME_SIZE);

        // Возвращаем фреймы в llfree
        self.frames
            .free(frame, self.slab_order, self.slab_class, local_cpu());
    }
}

// ===========================================================================
// Хуки для attachable_slab_allocator — используют SlabPool напрямую
// ===========================================================================

unsafe fn slab_alloc(layout: Layout) -> Option<NonNull<u8>> {
    // SAFETY: контракт хука — layout валиден; пул инициализирован
    // (None -> отказ без разыменования).
    unsafe { SLAB_POOL.get()?.alloc(layout) }
}

unsafe fn slab_free(ptr: NonNull<u8>, layout: Layout) -> Result<()> {
    let pool = SLAB_POOL.get().ok_or(SlabError::FatalError)?;
    unsafe { pool.free(ptr, layout) };
    Ok(())
}

#[cfg(not(test))]
define_allocation_hooks!(slab_alloc, slab_free);

// ===========================================================================
// Глобальный аллокатор — talc поверх llfree (независимый от slab)
// ===========================================================================

#[derive(Debug)]
pub struct GAlocatorInterface;

impl GAlocatorInterface {
    pub const fn new() -> Self {
        Self
    }
}

unsafe impl Source for GAlocatorInterface {
    fn acquire<B: Binning>(
        talc: &mut Talc<Self, B>,
        layout: Layout,
    ) -> core::result::Result<(), ()> {
        let mut need = layout.size() + layout.align() * 2;
        if !talc.is_metadata_established() {
            need += min_first_heap_size::<B>();
        }

        let order = need
            .div_ceil(FRAME_SIZE)
            .next_power_of_two()
            .trailing_zeros() as usize;
        let order = order.max(MIN_CHUNK_ORDER);
        if order > TREE_ORDER {
            return Err(());
        }

        let frames = FRAMES.get().ok_or(())?;
        let class = Class(1);
        let req = Request::new(order, class, local_cpu());

        let (frame, _cls) = frames.llf.get(None, req).map_err(|_| ())?;
        let phys = frames.mem_base + frame.0 * FRAME_SIZE;
        let len = FRAME_SIZE << order;

        // Куча — ВИРТУАЛЬНЫЙ диапазон поверх physmap: talc получает
        // указатели, валидные и под пользовательским CR3 (physmap
        // копируется в PML4 задач; сырую физику ядро как указатели
        // не использует).
        let base = frames.virt_base + phys;
        if unsafe { talc.claim(base as *mut u8, len) }.is_none() {
            let _ = frames.llf.put(frame, req);
            return Err(());
        }
        Ok(())
    }
}

// Тип боевого аллокатора (talc поверх llfree). САМ #[global_allocator]
// объявляет БЕКЕНД (crates/backend): это связывающий символ образа, а
// не generic-интерфейса ядра. Host-тесты (наши и зависимых крейтов)
// без него линкуются аллокатором std — llfree там не поднят (v0.11:
// до этого cfg(test) не действует на зависимости, и backend-тесты
// падали на первом же выделении тест-рантайма).
pub type KernelAllocator = TalcLock<Mutex<()>, GAlocatorInterface, DefaultBinning>;

/// Конструктор боевого аллокатора (const): статик объявляет бекенд.
pub const fn kernel_allocator() -> KernelAllocator {
    TalcLock::new(GAlocatorInterface::new())
}

// ===========================================================================
// Вспомогательные функции
// ===========================================================================

/// Проверка инициализации компонентов
pub fn is_frames_initialized() -> bool {
    FRAMES.get().is_some()
}

pub fn is_slab_pool_initialized() -> bool {
    SLAB_POOL.get().is_some()
}
