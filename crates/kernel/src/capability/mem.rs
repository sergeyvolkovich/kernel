// ==== Мост к attachable-slab-allocator ====
//
// Боевой крейт — no_std, поэтому «сырая» память для slab-ов берётся не из
// std, а из аллокатора платформы. Крейт `attachable-slab-allocator` намеренно
// не знает, откуда брать память: он требует, чтобы финальный бинарник
// определил пару хуков через макрос `define_allocation_hooks!` (линкер
// упадёт с «undefined reference», пока хуки не определены — это защита от
// случайного выбора источника памяти).
//
// Контракт хуков:
//   unsafe fn alloc(Layout) -> Option<NonNull<u8>>
//   unsafe fn free(NonNull<u8>, Layout) -> Result<(), SlabError>
//
// Требование к `alloc`: возвращённый блок обязан быть выровнен по
// `layout.align()`. Крейт использует трюк «выравнивание == размер»:
// `SLAB_SIZE` — степень двойки, а заголовок slab-а находится по адресу
// `ptr & !(SLAB_SIZE - 1)`. Невыровненная память приведёт к порче списка.
//
// Ядро определяет хуки само (один раз на бинарник), например поверх
// страничного аллокатора, который по построению отдаёт SLAB_SIZE-выровненные
// страницы:
//
// ```ignore
// use attachable_slab_allocator::{define_allocation_hooks, Result};
// use core::{alloc::Layout, ptr::NonNull};
//
// unsafe fn kernel_slab_alloc(layout: Layout) -> Option<NonNull<u8>> {
//     // Страницы у нас SLAB_SIZE-выровнены, поэтому layout.align()
//     // выполняется автоматически.
//     Some(kernel_pages::alloc_pages(layout.size()))
// }
//
// unsafe fn kernel_slab_free(ptr: NonNull<u8>, layout: Layout) -> Result<()> {
//     kernel_pages::free_pages(ptr, layout.size());
//     Ok(())
// }
//
// define_allocation_hooks!(kernel_slab_alloc, kernel_slab_free);
// ```
//
// Для host-сборок (тесты, инструменты) включён фича-флаг `host-hooks`:
// хуки строятся поверх `alloc::alloc` с ручным довыравниванием, т.к.
// системный аллокатор гарантирует только 16-байтное выравнивание.

use core::ptr::NonNull;

use attachable_slab_allocator::{SlabBox, SlabCache, SlabError};
use intrusive_collections::UnsafeRef;

/// Конфигурация slab-ов, единая для всех менеджеров крейта.
///
/// `NoLock` — однопоточное ядро (синхронизация менеджеров — RefCell,
/// см. `capability` и `task`): slab-у внутренний лок не нужен, всё
/// сериализуется заимствованиями RefCell менеджера.
pub type SlabLock = attachable_slab_allocator::locks::NoLock;

/// Размер одного slab-а (страница). Степень двойки — обязательное
/// требование аллокатора (трюк «выравнивание == размер»).
pub const SLAB_SIZE: usize = 4096;

/// Slab-кэш, общий тип для всех менеджеров крейта.
pub type SlabCacheOf<T> = SlabCache<T, SlabLock, SLAB_SIZE>;

// ==== Host-хуки поверх системного аллокатора ====
//
// Глобальный аллокатор гарантирует выравнивание не больше 16 байт, а slab
// обязан лежать на SLAB_SIZE-границе. Поэтому выделяем с запасом
// (size + align + 8), вырезаем выровненный кусок, а исходный базовый
// указатель прячем в 8 байтах непосредственно перед ним.

#[cfg(any(test, feature = "host-hooks"))]
mod host_hooks {
    use super::*;
    use core::alloc::Layout;

    // NB: макрос `define_allocation_hooks!` негигиеничен: сгенерированные
    // функции используют неполное имя `Result`, поэтому алиас крейта обязан
    // быть в области видимости места разворота макроса.
    use attachable_slab_allocator::Result; // noqa: конфликт имён не возникает

    const STASH: usize = core::mem::size_of::<usize>();

    unsafe fn host_slab_alloc(layout: Layout) -> Option<NonNull<u8>> {
        // SAFETY: layout с ненулевым размером; общий размер складываем
        // вручную, чтобы не полагаться на Layout::extend.
        let total = layout.size() + layout.align() + STASH;
        let raw_layout = Layout::from_size_align(total, STASH).ok()?;
        // SAFETY: raw_layout валиден (ненулевой размер, выравнивание 8).
        let raw = unsafe { alloc::alloc::alloc(raw_layout) };
        let raw = NonNull::new(raw)?;
        let base = raw.as_ptr() as usize;

        // Выровненный старт: гарантированно >= base + STASH, поэтому окно
        // [aligned - STASH, aligned) лежит внутри выделенного блока.
        let aligned = (base + STASH + layout.align() - 1) & !(layout.align() - 1);
        // SAFETY: aligned >= base + 8; в окне никто не живёт.
        unsafe { core::ptr::write_unaligned((aligned - STASH) as *mut usize, base) };

        NonNull::new(aligned as *mut u8)
    }

    unsafe fn host_slab_free(
        ptr: NonNull<u8>,
        layout: Layout,
    ) -> attachable_slab_allocator::Result<()> {
        let aligned = ptr.as_ptr() as usize;
        // SAFETY: базовый указатель записан хуком alloc в (aligned - 8).
        let base =
            unsafe { core::ptr::read_unaligned((aligned - STASH) as *const usize) } as *mut u8;
        let total = layout.size() + layout.align() + STASH;
        // SAFETY: base получен из alloc с тем же raw_layout.
        let raw_layout =
            Layout::from_size_align(total, STASH).map_err(|_| SlabError::FatalError)?;
        unsafe { alloc::alloc::dealloc(base, raw_layout) };
        Ok(())
    }

    attachable_slab_allocator::define_allocation_hooks!(host_slab_alloc, host_slab_free);
}

// ==== Перевод SlabBox <-> UnsafeRef ====
//
// Интрузивные контейнеры хранят объекты через `UnsafeRef<T>` (невладеющие
// ссылки: линк-поля лежат внутри самих объектов). Владение памятью при этом
// остаётся у менеджера: узел аллоцируется из slab-а, забывается
// (`mem::forget`), а при освобождении `SlabBox` восстанавливается из
// сырого указателя и дропается — это возвращает слот в slab.

/// Выделяет слот под `value` и возвращает невладеющую ссылку на него.
///
/// Слот инициализируется через `ptr::write` до любого разыменования:
/// `SlabCache::alloc` отдаёт неинициализированную память.
///
/// # Safety (для вызывающего)
/// Узел, полученный из `alloc_slot`, обязан быть освобождён ровно один раз
/// через [`free_slot`] — но только после того, как он снят со всех
/// интрузивных контейнеров, в которые был вставлен.
pub(crate) fn alloc_slot<T>(
    cache: &mut SlabCacheOf<T>,
    value: T,
) -> Result<UnsafeRef<T>, SlabError> {
    let slot: SlabBox<T, SlabLock, SLAB_SIZE> = cache.alloc()?;
    // SAFETY: слот неинициализирован; инициализируем записью по указателю.
    unsafe { core::ptr::write(slot.as_ptr(), value) };
    let ptr = slot.as_ptr();
    core::mem::forget(slot);
    // SAFETY: указатель происходит из slab-а и будет освобождён менеджером
    // через `free_slot` (контракт задокументирован выше).
    Ok(unsafe { UnsafeRef::from_raw(ptr) })
}

/// Возвращает слот узла в slab.
///
/// Восстанавливает `SlabBox` из сырого указателя и дропает его:
/// `SlabBox::drop` выполняет `drop_in_place(T)` и возвращает слот в slab.
///
/// # Safety (для вызывающего)
/// `slot` обязан указывать на живой узел, выделенный через [`alloc_slot`],
/// и на момент вызова не состоять ни в одном интрузивном контейнере.
pub(crate) fn free_slot<T>(slot: UnsafeRef<T>) {
    let raw = UnsafeRef::into_raw(slot);
    // SAFETY: узел выделен `alloc_slot` (тот же SLAB_SIZE) и уже ни в одном
    // контейнере — контракт вызывающего.
    unsafe {
        let ptr = NonNull::new_unchecked(raw);
        drop(SlabBox::<T, SlabLock, SLAB_SIZE>::new(ptr));
    }
}
