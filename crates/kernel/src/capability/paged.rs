// ==== Страничные таблицы слотов ядра ====
//
// Замена RB-дерева на горячем пути (шаги 1–2 из плана):
//
// ```text
//   PagedTable<T>
//   ├─ dir: [Option<NonNull<Page<T, N>>>; DIR_LEN]   фиксированный каталог
//   ├─ pages: SlabCacheOf<Page<T, N>>                страницы из slab (frame-политика)
//   └─ free_head: u32                                интрузивный freelist
//
//   Page<T, N>  = { live_mask: u32, slots: [MaybeUninit<T>; N] }
//   Слот        = { ObjHeader (generation, смещение 0), payload T }
// ```
//
// Ключевые свойства:
// * страницы **никогда не двигаются** — адреса слотов стабильны, поэтому
//   `TargetRef` (указатель на заголовок + поколение) честен до освобождения
//   самой таблицы;
// * рост O(1) без копирования: новая страница пришивается к каталогу,
//   старые слоты остаются на местах;
// * lookup по (idx, generation) — два обращения в память (каталог → страница)
//   плюс одно сравнение generation-слова по смещению 0;
// * freelist **интрузивный**: ссылка «следующий свободный» лежит в мёртвой
//   памяти слота сразу за generation-словом — никакой Vec/Box на структуру;
// * переполнение поколения: слот **выводится из оборота** (retire),
//   а не оборачивается.
//
// Поколение: 0 — «свежая страница, слот никогда не выдавался» (не валидно
// в хендлах и TargetRef), 1..=u32::MAX-1 — поколения живых объектов,
// u32::MAX — выведенный из оборота слот. Освобождение хранит generation+1 в
// памяти слота, поэтому повторное использование продолжает счёт, а старые
// хендлы честно гаснут (ABA-защита).
//
// Синхронизация: без внутреннего лока — сериализуется RefCell владельца
// (ядро однопоточное, тот же контракт, что у менеджеров).

use core::fmt;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{NonNull, drop_in_place};
use core::sync::atomic::{AtomicU32, Ordering};

use intrusive_collections::UnsafeRef;

use crate::capability::mem::{SLAB_SIZE, SlabCacheOf, alloc_slot, free_slot};

/// Слотов на страницу. Обязано быть ≤ 32 (live_mask — u32).
pub const PAGE_SLOTS_MAX: usize = 32;

/// Смещение интрузивной freelist-ссылки в СВОБОДНОМ слоте: сразу за
/// generation-словом. Пишется только в мёртвый слот (после drop T), читается
/// только при переиспользовании.
const FREE_LINK_OFFSET: usize = 4;

/// Пометка «свободного конца» freelist.
const NO_FREE: u32 = u32::MAX;
/// Поколение выведенного из оборота слота.
const GEN_RETIRED: u32 = u32::MAX;

// ==== Заголовок объекта ====

/// Заголовок объекта ядра: поколение для ABA-защиты хендлов и TargetRef.
///
/// По контракту [`KernelObj`] лежит первым полем объекта, поэтому адрес
/// заголовка == адрес объекта, а generation-слово — по смещению 0 (именно его
/// читает горячий путь, ещё до инициализации остальной памяти).
#[repr(C)]
pub struct ObjHeader {
    generation: AtomicU32,
}

impl ObjHeader {
    pub const fn new(generation: u32) -> Self {
        Self {
            generation: AtomicU32::new(generation),
        }
    }

    /// Текущее поколение (Acquire — синхронизируется с Release при смерти).
    #[inline]
    pub fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    /// Смерть объекта: сначала бьём поколение (Release), потом освобождаем
    /// ресурсы. Все хендлы и TargetRef с прежним поколением честно гаснут.
    #[inline]
    pub fn kill(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }
}

/// Объект, живущий в [`PagedTable`] и адресуемый через [`TargetRef`].
///
/// # Safety (для реализующего типа)
/// * `hdr` обязан быть **первым полем** структуры (`repr(C)`, offset 0) —
///   по этому адресу горячий путь читает generation-слово сырым чтением;
/// * `Drop` типа не должен трогать `hdr` (таблица пишет туда generation+1 до/после
///   дропа и не ожидает помех);
/// * объект не должен быть `Unpin`-зависимым: после записи в слот он
///   никогда не двигается.
pub unsafe trait KernelObj {
    fn hdr(&self) -> &ObjHeader;
}

// ==== TargetRef ====

/// Ссылка на объект ядра: указатель на заголовок (стабильный адрес) +
/// поколение. Кэшируется прямо в capability — горячий путь не спускается
/// ни по каким деревьям (шаг 2 из плана).
///
/// `generation == 0` — «бессмертная» цель (`TargetRef::immortal`): устройства
/// по `DevicePath` живут вне этого крейта, их живость контролирует
/// `DeviceManager`, а отзыв выполняется через revoke самой capability.
pub struct TargetRef {
    hdr: NonNull<ObjHeader>,
    generation: u32,
}

impl TargetRef {
    /// Бессмертная цель: `alive()` всегда true, память не разыменовывается.
    pub const fn immortal() -> Self {
        Self {
            hdr: NonNull::dangling(),
            generation: 0,
        }
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) const fn hdr_ptr(&self) -> NonNull<ObjHeader> {
        self.hdr
    }

    /// Жив ли объект? Одно (атомарное) чтение generation-слова по стабильному адресу.
    ///
    /// Для мёртвого объекта разыменование безопасно: память под заголовком
    /// type-stable (страницы не двигаются и не меняют тип), а generation-слово
    /// честно скажет «мёртв».
    #[inline]
    pub fn alive(&self) -> bool {
        if self.generation == 0 {
            return true;
        }
        // SAFETY: ссылки выдаются только на живые страницы таблиц, страницы
        // не двигаются и не возвращаются в аллокатор до дропа таблицы.
        unsafe { self.hdr.as_ref() }
            .generation
            .load(Ordering::Acquire)
            == self.generation
    }

    /// Объект по ссылке (None — мёртв).
    ///
    /// # Safety
    /// Ссылка обязана быть создана для объекта типа `T` (одна таблица —
    /// один тип) и указывать на страницу живой таблицы.
    #[inline]
    pub(crate) unsafe fn obj<T: KernelObj>(&self) -> Option<&T> {
        if !self.alive() {
            return None;
        }
        // SAFETY: контракт вызова — hdr по смещению 0, тот же адрес.
        Some(unsafe { &*(self.hdr.as_ptr() as *const T) })
    }

    /// Ссылка на живой объект (generation ≥ 1 у всех выданных слотов).
    pub(crate) fn from_obj<T: KernelObj>(t: &T) -> Self {
        Self {
            hdr: NonNull::from(t.hdr()),
            generation: t.hdr().generation(),
        }
    }
}

impl Clone for TargetRef {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for TargetRef {}

impl PartialEq for TargetRef {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && (self.generation == 0 || self.hdr.as_ptr() == other.hdr.as_ptr())
    }
}
impl Eq for TargetRef {}

impl fmt::Debug for TargetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("TargetRef");
        s.field("generation", &self.generation);
        if self.generation != 0 {
            s.field("alive", &self.alive());
        } else {
            s.field("immortal", &true);
        }
        s.finish()
    }
}

// ==== Слот-ссылка ====

/// Ссылка на слот таблицы: (idx, generation). Сырьё для пользовательских хендлов
/// (`CapHandle`) и для стабильной ссылки задачи на саму себя (`self_slot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotRef {
    pub idx: u32,
    pub generation: u32,
}

// ==== Ошибка ====

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagedError {
    /// Квота каталога исчерпана (DIR_LEN * N слотов).
    NoSpace,
    /// Slab не смог выделить страницу.
    Oom,
}

impl fmt::Display for PagedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PagedError::NoSpace => f.write_str("paged table directory exhausted"),
            PagedError::Oom => f.write_str("paged table: page allocation failed"),
        }
    }
}

// ==== Страница ====

/// Страница слотов: выделяется из slab-кэша, никогда не двигается и не
/// возвращается в аллокатор, пока жива таблица (grace period — забота
/// будущего владельца таблицы; сейчас страницы живут до дропа таблицы).
///
/// `live_mask` — бит на слот (N ≤ 32): авторитет живости для перечисления
/// и дропа. Логика хендлов при этом опирается только на generation-слово —
/// маска дублирует её дёшево и не нужна в горячем пути.
#[repr(C)]
struct Page<T, const N: usize> {
    live_mask: u32,
    slots: [MaybeUninit<T>; N],
}

impl<T, const N: usize> Page<T, N> {
    /// Нулевая страница: все generation-слова = 0 («слот никогда не выдавался»),
    /// live_mask = 0.
    fn zeroed() -> Self {
        // SAFETY: все-нулевое битовое представление валидно и для u32,
        // и для [MaybeUninit<T>; N] (MaybeUninit допускает любой узор).
        unsafe { MaybeUninit::<Self>::zeroed().assume_init() }
    }
}

// ==== Таблица ====

/// Страничная таблица слотов типа `T: KernelObj`.
///
/// Константы задают квоту: `DIR_LEN * N` слотов. Память страниц берёт из
/// slab-кэшей (`crate::mem`), свободные слоты перезваниваются интрузивным
/// freelist'ом. Таблица рассчитана на жизнь по стабильному адресу
/// (RefCell/Box менеджера) — как и остальные slab-владельцы крейта.
pub struct PagedTable<T: KernelObj, const N: usize, const DIR_LEN: usize> {
    dir: [Option<NonNull<Page<T, N>>>; DIR_LEN],
    pages: SlabCacheOf<Page<T, N>>,
    free_head: u32,
    high: u32,
    live: usize,
    _pd: PhantomData<fn() -> T>,
}

impl<T: KernelObj, const N: usize, const DIR_LEN: usize> PagedTable<T, N, DIR_LEN> {
    /// Пустая таблица. Память под страницы не выделяется (лениво, при
    /// первом alloc).
    pub fn new() -> Result<Self, PagedError> {
        const {
            assert!(N <= PAGE_SLOTS_MAX, "N слотов не влезает в u32 live_mask");
        }
        debug_assert!(
            size_of::<Page<T, N>>() <= SLAB_SIZE,
            "страница PagedTable не помещается в slab"
        );
        Ok(Self {
            dir: [None; DIR_LEN],
            pages: SlabCacheOf::new().map_err(|_| PagedError::Oom)?,
            free_head: NO_FREE,
            high: 0,
            live: 0,
            _pd: PhantomData,
        })
    }

    // -- служебные --

    #[inline]
    fn page_of(&self, idx: u32) -> Option<NonNull<Page<T, N>>> {
        *self.dir.get(idx as usize / N)?
    }

    #[inline]
    fn slot_ptr(page: NonNull<Page<T, N>>, slot_i: usize) -> *mut T {
        // SAFETY: страница жива (в каталоге), slot_i < N.
        unsafe { core::ptr::addr_of_mut!((*page.as_ptr()).slots[slot_i]) as *mut T }
    }

    /// Чтение generation-слова по смещению 0. Память там всегда инициализирована:
    /// свежая страница занулена, дальше пишутся только валидные поколения.
    #[inline]
    fn raw_gen(slot: *mut T) -> u32 {
        // SAFETY: KernelObj гарантирует hdr первым полем; чтение атомарное.
        unsafe {
            (*slot.cast::<ObjHeader>())
                .generation
                .load(Ordering::Acquire)
        }
    }

    // -- аллокация --

    /// Выделяет слот и строит объект `make(idx, generation)`.
    ///
    /// Переиспользованный слот продолжает поколение (generation+1 сохранён при
    /// free), свежий — получает generation = 1.
    pub fn alloc(&mut self, make: impl FnOnce(u32, u32) -> T) -> Result<SlotRef, PagedError> {
        let idx = match self.free_head {
            NO_FREE => {
                if self.high as usize == DIR_LEN * N {
                    return Err(PagedError::NoSpace);
                }
                let idx = self.high;
                let di = idx as usize / N;
                if self.dir[di].is_none() {
                    // Новая страница из slab-кэша: занулена, ничего не
                    // копируется, старые слоты остаются на местах.
                    let page =
                        alloc_slot(&mut self.pages, Page::zeroed()).map_err(|_| PagedError::Oom)?;
                    let raw = UnsafeRef::into_raw(page);
                    // SAFETY: raw происходит из slab и не нулевой.
                    self.dir[di] = Some(unsafe { NonNull::new_unchecked(raw) });
                }
                self.high += 1;
                idx
            }
            head => {
                // Снимаем голову freelist: ссылка «next» лежит в мёртвой
                // памяти слота за generation-словом.
                let page = self.page_of(head).expect("freelist-слот без страницы");
                let slot = Self::slot_ptr(page, head as usize % N);
                // SAFETY: слот мёртв, ячейка freelist инициализирована при free.
                let next = unsafe {
                    core::ptr::read_unaligned(slot.byte_add(FREE_LINK_OFFSET) as *const u32)
                };
                self.free_head = next;
                head
            }
        };

        let page = self.page_of(idx).expect("слот без страницы");
        let slot = Self::slot_ptr(page, idx as usize % N);
        let prev_gen = Self::raw_gen(slot);
        debug_assert!(
            prev_gen != GEN_RETIRED,
            "выведенный из оборота слот не должен попадать в freelist"
        );
        let generation = if prev_gen == 0 { 1 } else { prev_gen };

        // SAFETY: слот неинициализирован (либо мёртв), пишем объект целиком.
        unsafe { slot.write(make(idx, generation)) };
        // SAFETY: страница жива.
        unsafe { (*page.as_ptr()).live_mask |= 1 << (idx as usize % N) };
        self.live += 1;
        Ok(SlotRef { idx, generation })
    }

    // -- горячий путь --

    /// Валидация (idx, generation) и доступ к объекту: каталог → страница →
    /// сравнение generation. Никаких деревьев, O(1), 2–3 обращения в память.
    #[inline]
    pub fn get(&self, idx: u32, generation: u32) -> Option<&T> {
        if generation == 0 || generation == GEN_RETIRED {
            return None;
        }
        let page = self.page_of(idx)?;
        let slot = Self::slot_ptr(page, idx as usize % N);
        // Свободный слот хранит «последний+1», свежий — 0, выведенный —
        // MAX: ни одно из этих значений не совпадёт с живым хендлом.
        if Self::raw_gen(slot) != generation {
            return None;
        }
        // SAFETY: generation совпал — слот занят живым объектом.
        Some(unsafe { &*slot })
    }

    /// То же с эксклюзивным доступом.
    #[inline]
    pub fn get_mut(&mut self, idx: u32, generation: u32) -> Option<&mut T> {
        if generation == 0 || generation == GEN_RETIRED {
            return None;
        }
        let page = self.page_of(idx)?;
        let slot = Self::slot_ptr(page, idx as usize % N);
        if Self::raw_gen(slot) != generation {
            return None;
        }
        // SAFETY: generation совпал — слот занят живым объектом; доступ
        // эксклюзивен по контракту однопоточности (&mut self).
        Some(unsafe { &mut *slot })
    }

    /// TargetRef на живой объект слота.
    pub fn target(&self, r: SlotRef) -> Option<TargetRef> {
        self.get(r.idx, r.generation).map(TargetRef::from_obj)
    }

    // -- освобождение --

    /// Освобождает слот: **сначала** инкремент поколения (Release), **потом**
    /// drop объекта (порядок из плана). Слот с исчерпанным поколением
    /// выводится из оборота, а не оборачивается.
    ///
    /// Возвращает false, если слот и так был свободен/не существует.
    pub fn free(&mut self, idx: u32) -> bool {
        let Some(page) = self.page_of(idx) else {
            return false;
        };
        let slot_i = idx as usize % N;
        let mask = 1u32 << slot_i;
        // SAFETY: страница жива (в каталоге).
        let page_ref = unsafe { &mut *page.as_ptr() };
        if page_ref.live_mask & mask == 0 {
            return false;
        }

        let slot = Self::slot_ptr(page, slot_i);
        // 1. Поколение вверх: все хендлы/TargetRef на объект гаснут сразу.
        let generation = Self::raw_gen(slot);
        debug_assert!(
            generation != 0 && generation != GEN_RETIRED,
            "слот обязан быть живым"
        );
        let next = generation + 1; // без переполнения: generation живых ≤ MAX-1, см. retire
        // SAFETY: слот жив, hdr по смещению 0.
        unsafe {
            (*slot.cast::<ObjHeader>())
                .generation
                .store(next, Ordering::Release)
        };

        // 2. Drop объекта (его Drop не трогает hdr — контракт KernelObj).
        // SAFETY: слот жив и снят со всех контейнеров — контракт вызывающего.
        unsafe { drop_in_place(slot) };

        // 3. Слот мёртв: пришиваем к интрузивному freelist.
        page_ref.live_mask &= !mask;
        self.live -= 1;
        if next == GEN_RETIRED {
            // Исчерпание поколения: слот навсегда выведен из оборота —
            // в freelist не возвращается, generation-слово остаётся MAX.
        } else {
            // SAFETY: слот мёртв, ячейка freelist никем не занята.
            unsafe {
                core::ptr::write_unaligned(
                    slot.byte_add(FREE_LINK_OFFSET) as *mut u32,
                    self.free_head,
                )
            };
            self.free_head = idx;
        }
        true
    }

    // -- перечисление (редкий путь) --

    pub fn live_count(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Первый живой слот (для дренажа revoke_all).
    pub fn first_live(&self) -> Option<SlotRef> {
        for (di, entry) in self.dir.iter().enumerate() {
            let Some(page) = *entry else { continue };
            // SAFETY: страница жива.
            let mask = unsafe { page.as_ref() }.live_mask;
            if mask != 0 {
                let s = mask.trailing_zeros() as usize;
                let idx = (di * N + s) as u32;
                return Some(SlotRef {
                    idx,
                    generation: Self::raw_gen(Self::slot_ptr(page, s)),
                });
            }
        }
        None
    }

    /// Обход живых слотов (аудит, revoke_all). Callback не должен вызывать
    /// методы таблицы (контракт однопоточности, как у RefCell-менеджеров).
    pub fn for_each_live(&self, mut f: impl FnMut(SlotRef, &T)) {
        for (di, entry) in self.dir.iter().enumerate() {
            let Some(page) = *entry else { continue };
            // SAFETY: страница жива.
            let p = unsafe { page.as_ref() };
            let mut mask = p.live_mask;
            while mask != 0 {
                let s = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                let idx = (di * N + s) as u32;
                let slot = Self::slot_ptr(page, s);
                let r = SlotRef {
                    idx,
                    generation: Self::raw_gen(slot),
                };
                // SAFETY: бит live_mask установлен — объект жив.
                f(r, unsafe { &*slot });
            }
        }
    }

    /// Debug-хук тестов: принудительно выставить поколение слота
    /// (для проверки retire без цикла из 2^32 итераций).
    #[cfg(test)]
    pub fn debug_set_gen(&mut self, idx: u32, generation: u32) {
        let page = self.page_of(idx).expect("нет страницы");
        let slot = Self::slot_ptr(page, idx as usize % N);
        // SAFETY: слот жив (используется тестами только на живых слотах).
        unsafe {
            (*slot.cast::<ObjHeader>())
                .generation
                .store(generation, Ordering::Release)
        };
    }
}

impl<T: KernelObj, const N: usize, const DIR_LEN: usize> Drop for PagedTable<T, N, DIR_LEN> {
    /// Гасит живые объекты и возвращает страницы в slab. Страницы не
    /// двигались и тип не меняли — слоты возвращаются в свой кэш.
    fn drop(&mut self) {
        for entry in &mut self.dir {
            let Some(page) = *entry else { continue };
            // SAFETY: страница жива и заведена нами через alloc_slot.
            let p = unsafe { &mut *page.as_ptr() };
            for i in 0..N {
                if p.live_mask & (1 << i) != 0 {
                    // SAFETY: бит установлен — объект жив.
                    unsafe { drop_in_place(Self::slot_ptr(page, i)) };
                }
            }
            p.live_mask = 0;
            // SAFETY: страница выделена alloc_slot того же типа и размера
            // и больше ни в каких контейнерах не состоит.
            unsafe { free_slot(UnsafeRef::from_raw(page.as_ptr())) };
        }
        // self.pages (SlabCache) дропается сам и вернёт пустые slab-ы.
    }
}

// ==== Тесты ====

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    #[repr(C)]
    struct TestObj {
        hdr: ObjHeader,
        val: u64,
        /// Общий счётчик дропов (Arc — чтобы не гонять глобальный static
        /// между параллельными тестами).
        drops: Option<alloc::sync::Arc<AtomicUsize>>,
    }

    unsafe impl KernelObj for TestObj {
        fn hdr(&self) -> &ObjHeader {
            &self.hdr
        }
    }
    const _: () = assert!(core::mem::offset_of!(TestObj, hdr) == 0);

    impl TestObj {
        fn new(idx: u32, generation: u32, val: u64) -> Self {
            let _ = idx;
            Self {
                hdr: ObjHeader::new(generation),
                val,
                drops: None,
            }
        }

        fn counted(
            idx: u32,
            generation: u32,
            val: u64,
            drops: alloc::sync::Arc<AtomicUsize>,
        ) -> Self {
            Self {
                hdr: ObjHeader::new(generation),
                val,
                drops: Some(drops),
            }
        }
    }

    impl Drop for TestObj {
        fn drop(&mut self) {
            if let Some(c) = &self.drops {
                c.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    type Table = PagedTable<TestObj, 4, 8>;

    fn table() -> Table {
        Table::new().expect("Table::new")
    }

    fn put(t: &mut Table, val: u64) -> SlotRef {
        t.alloc(|idx, generation| TestObj::new(idx, generation, val))
            .unwrap()
    }

    #[test]
    fn alloc_get_free_cycle() {
        let mut t = table();
        let r = put(&mut t, 42);
        assert_eq!(r.generation, 1, "первое поколение — единица");
        assert_eq!(t.get(r.idx, r.generation).unwrap().val, 42);
        assert_eq!(t.live_count(), 1);

        assert!(t.free(r.idx));
        assert!(
            t.get(r.idx, r.generation).is_none(),
            "после free слот мёртв"
        );
        assert!(!t.free(r.idx), "повторный free — не жив");
        assert_eq!(t.live_count(), 0);
    }

    #[test]
    fn gen_grows_on_reuse_and_old_handles_die() {
        let mut t = table();
        let r1 = put(&mut t, 1);
        let old = r1;
        t.free(r1.idx);
        let r2 = t
            .alloc(|idx, generation| TestObj::new(idx, generation, 2))
            .unwrap();
        assert_eq!(r2.idx, old.idx, "слот переиспользован из freelist");
        assert_eq!(
            r2.generation,
            old.generation + 1,
            "поколение продолжилось, не обернулось"
        );

        // Старый хендл честно мёртв, новый жив.
        assert!(t.get(old.idx, old.generation).is_none());
        assert_eq!(t.get(r2.idx, r2.generation).unwrap().val, 2);
    }

    #[test]
    fn freelist_is_lifo() {
        let mut t = table();
        let a = put(&mut t, 1);
        let b = put(&mut t, 2);
        let _c = put(&mut t, 3);
        t.free(a.idx);
        t.free(b.idx);
        let d = put(&mut t, 4);
        assert_eq!(d.idx, b.idx, "LIFO: последним освобождён — первым выдан");
    }

    #[test]
    fn retire_on_gen_exhaustion() {
        let mut t = table();
        let r = put(&mut t, 7);
        // Выставляем почти исчерпанное поколение.
        t.debug_set_gen(r.idx, u32::MAX - 1);
        t.free(r.idx);

        // Слот выведен из оборота: следующий alloc берёт свежий индекс.
        let r2 = put(&mut t, 8);
        assert_ne!(r2.idx, r.idx, "retired-слот не возвращается в оборот");
        assert!(t.get(r.idx, u32::MAX - 1).is_none());
        assert!(
            t.get(r.idx, u32::MAX).is_none(),
            "MAX не выдаётся в хендлах"
        );
        assert_eq!(t.get(r2.idx, r2.generation).unwrap().val, 8);
    }

    #[test]
    fn directory_exhaustion_is_no_space() {
        // 2 страницы × 4 слота = 8 слотов.
        let mut t: PagedTable<TestObj, 4, 2> = PagedTable::new().unwrap();
        for i in 0..8u64 {
            let _ = t
                .alloc(|idx, generation| TestObj::new(idx, generation, i))
                .unwrap();
        }
        match t.alloc(|idx, generation| TestObj::new(idx, generation, 9)) {
            Err(PagedError::NoSpace) => {}
            other => panic!("ожидался NoSpace, получено {other:?}"),
        }
    }

    #[test]
    fn pages_grow_without_moving() {
        let mut t = table();
        let mut refs = alloc::vec::Vec::new();
        for i in 0..8u64 {
            refs.push(put(&mut t, i));
        }
        // Адреса первых слотов не изменились после роста каталога.
        for (i, r) in refs.iter().enumerate() {
            assert_eq!(t.get(r.idx, r.generation).unwrap().val, i as u64);
        }
        assert_eq!(t.first_live().unwrap().idx, refs[0].idx);
    }

    #[test]
    fn for_each_live_walks_live_slots_only() {
        let mut t = table();
        let a = put(&mut t, 1);
        let _b = put(&mut t, 2);
        let _c = put(&mut t, 3);
        t.free(a.idx);

        let mut seen = alloc::vec::Vec::new();
        t.for_each_live(|r, o| seen.push((r.idx, o.val)));
        assert_eq!(seen.len(), 2);
        assert!(
            seen.iter().all(|(_, v)| *v != 1),
            "мёртвый слот не обходится"
        );
    }

    #[test]
    fn drop_runs_obj_dtors_and_returns_pages() {
        let counter = alloc::sync::Arc::new(AtomicUsize::new(0));
        {
            let mut t = table();
            for i in 0..6u64 {
                let _ = t
                    .alloc(|idx, generation| TestObj::counted(idx, generation, i, counter.clone()))
                    .unwrap();
            }
            assert_eq!(counter.load(Ordering::SeqCst), 0);
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            6,
            "все живые объекты погашены"
        );
    }

    #[test]
    fn target_ref_tracks_liveness() {
        let mut t = table();
        let r = put(&mut t, 5);
        let target = t.target(r).unwrap();
        assert!(target.alive());

        // Объект по ссылке читается.
        // SAFETY: target создан для TestObj этой таблицы.
        assert_eq!(unsafe { target.obj::<TestObj>() }.unwrap().val, 5);

        t.free(r.idx);
        assert!(!target.alive(), "после смерти generation не совпадает");
        // SAFETY: разыменование мёртвой цели — None (память type-stable).
        assert!(unsafe { target.obj::<TestObj>() }.is_none());
    }

    #[test]
    fn immortal_target_is_always_alive() {
        let t = TargetRef::immortal();
        assert!(t.alive());
        assert_eq!(t.generation(), 0);
    }

    #[test]
    fn gen_zero_handles_are_never_valid() {
        let mut t = table();
        let _r = put(&mut t, 1);
        // Свежая (не занятая) ячейка хранит generation 0 — хендл с generation 0 не валиден.
        assert!(t.get(3, 0).is_none());
    }
}
