use alloc::vec::Vec;
use core::{mem::forget, ptr::NonNull, slice};

use crate::{
    hal::traits::asid::{
        ASIDInterface, AddressSpaceMode, AsidAllocator, AsidPair, FlushMode, TlbOp,
    },
    hal::traits::kmap::{KMAPInterface, KernelRegion},
    hal::traits::mmap::{
        MMAPInterface, MMAPMemoryFlags, MemErrorCode, PageInfo, PhysADDR, VirtualADDR,
    },
    mem::UnnamedUPage,
    mem::kmap::KMap,
};

use aligned_box::AlignedBox;
use attachable_slab_allocator::{SlabBox, SlabCache, locks::SpinLock};
use heapless::pool::arc::{Arc, ArcPool};
use intrusive_collections::{Bound, KeyAdapter, RBTree, RBTreeLink, UnsafeRef, intrusive_adapter};
use llfree::{Alloc, Class, Classing, FRAME_SIZE, LLFree, MetaData, Request};

/// Slab size used for the record cache. Must be a power of two.
pub const RECORD_SLAB_SIZE: usize = 4096;

/// Alignment of the LLFree metadata buffers.
/// 64 (cache line) is a safe lower bound; check the requirement of the
/// pinned `llfree` revision and raise it if needed.
const META_ALIGN: usize = 64;

pub type RecordSlab = SlabCache<RecordData, SpinLock, RECORD_SLAB_SIZE>;
type RecordBox = SlabBox<RecordData, SpinLock, RECORD_SLAB_SIZE>;

/// Учётная запись отображения: одна аллокация фасада.
///
/// ДВА интрузивных членства (см. `intrusive-collections`):
///   * `p_link` — индекс по физической базе (адаптер `RDPAdapter`): разрыв
///     «физика -> запись» при отложенном возврате фреймов, аудит;
///   * `v_link` — индекс по виртуальной базе (адаптер `RDVAdapter`): ГОРЯЧИЙ путь
///     `shrink_memory_wiev` — поиск региона по адресу пользователя.
///
/// Двойной индекс — основная оптимизация реестра: раньше поиск по виртуальному
/// адресу линейно сканировал записи (O(n) по числу регионов процесса);
/// теперь — O(log n) по дереву с ключом `v_addr`. Оба дерева шарят одну
/// и ту же память слота (интрузивность: ссылки лежат внутри объекта,
/// ни одной дополнительной аллокации на индекс).
pub struct RecordData {
    p_addr: PageInfo,
    p_class: Class,

    v_addr: VirtualADDR,
    v_class: Class,

    /// Кадры ВНЕШНИЕ (SHM-регион, устройство, grant от другой задачи):
    /// при снятии отображения физика НЕ возвращается пулу — владеет ею
    /// источник (ShmRegion / исходный фасад при grant).
    external: bool,

    /// ФИКСИРОВАННОЕ отображение (ELF-сегменты загрузчика, стек старта,
    /// argv-страница): адрес выбран НЕ фасадным аллокатором диапазона,
    /// поэтому при снятии виртуальный диапазон НЕ возвращается в
    /// `generic_vmap_allocator` (он ему не принадлежал). Физика — по флагу
    /// `external`.
    fixed: bool,

    /// Членство в индексе по физической базе.
    p_link: RBTreeLink,
    /// Членство в индексе по виртуальной базе.
    v_link: RBTreeLink,
}

intrusive_adapter!(RDPAdapter = UnsafeRef<RecordData> : RecordData {p_link => RBTreeLink});

impl<'a> KeyAdapter<'a> for RDPAdapter {
    /// v0.14: ключ — ПАРА (физическая база, виртуальная база). Одна и та
    /// же физика МОЖЕТ быть отображена несколько раз (acpid/acpi-крейт
    /// мапит заголовок таблицы и затем полную таблицу по одному адресу;
    /// AML-менеджер держит перекрывающиеся снапшоты). Уникальность
    /// гарантируется уникальным vaddr (аллокатор фасадного окна), а не
    /// физикой — как в seL4 (frame может стоять в нескольких мапингах).
    type Key = (usize, usize);

    fn get_key(&self, value: &'a RecordData) -> Self::Key {
        (value.p_addr.p.0, value.v_addr.0)
    }
}

intrusive_adapter!(RDVAdapter = UnsafeRef<RecordData> : RecordData {v_link => RBTreeLink});

impl<'a> KeyAdapter<'a> for RDVAdapter {
    type Key = VirtualADDR;

    fn get_key(&self, value: &'a RecordData) -> Self::Key {
        value.v_addr
    }
}

/// Backing memory of the `LLFree` metadata. Only held for ownership.
#[allow(dead_code)]
struct DataBundles {
    trees: AlignedBox<[u8]>,
    locals: AlignedBox<[u8]>,
    lower: AlignedBox<[u8]>,
}

pub struct UFacade<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> {
    static_allocator: Arc<AP>,
    mmap_interface: MmapWraper,

    // NOTE: field order matters. Fields are dropped top to bottom, so the
    // allocator must come BEFORE the buffers it points into.
    generic_vmap_allocator: LLFree<'static>,
    /// Only held for ownership: keeps the `LLFree` metadata buffers alive
    /// and ensures they are dropped after the allocator.
    #[allow(dead_code)]
    data_bundles: DataBundles,

    allocation_class: Class,
    allocation_base: VirtualADDR,

    /// Реестр отображений: двойной интрузивный индекс (см. [`RecordData`]).
    /// Порядок полей важен для дропа: деревья гасятся раньше slab-кэша.
    records_by_paddr: RBTree<RDPAdapter>,
    records_by_vaddr: RBTree<RDVAdapter>,

    /// Собственный slab-кэш записей фасада.
    ///
    /// Раньше кэш передавался вызывающим в каждый `extend_memory_wiev`
    /// (&mut RecordSlab): общий кэш — общая блокировка и общая локальность;
    /// записи фасада — внутренность фасада, поэтому кэш переехал внутрь:
    /// изоляция аллокаций по адресному пространству, меньше параметров на
    /// горячем пути, слоты автоматически возвращаются в свой кэш при дропе.
    record_cache: RecordSlab,

    /// Регионы ядра, отображённые в ЭТО адресное пространство при создании
    /// через [`UFacade::new_with_kernel`] (пусто для фасадов без ядра).
    ///
    /// Хранится для аудита ([`UFacade::kernel_regions`]) и явного разбора
    /// ([`UFacade::unmap_kernel_regions`]). Дроп фасада, как и раньше, НЕ
    /// снимает отображений: таблицы страниц адресного пространства
    /// уничтожаются владельцем целиком (см. контракт `Drop`).
    kernel_mappings: Vec<KernelRegion>,

    /// Пара тегов ASID/PCID этого адресного пространства.
    ///
    /// `Some` — только если фасад создан тегированным путём
    /// ([`UFacade::new_with_kernel_asid`], бекенд реализует
    /// [`ASIDInterface`]). Живость тегов — контракт владельца: до дропа
    /// вызвать [`UFacade::release_asid`] (гасит TLB и возвращает пару пулу).
    asid_pair: Option<AsidPair>,
}

/// Owned copy of the record data to avoid borrow conflicts.
#[derive(Debug, Clone)]
struct RecordSnapshot {
    p_addr: PhysADDR,
    p_pages_count: usize,
    p_class: Class,
    v_addr: VirtualADDR,
    v_class: Class,
    /// Кадры внешние — физика не возвращается пулу при shrink.
    external: bool,
    /// Фиксированный регион — виртуальный диапазон не возвращается.
    fixed: bool,
}

/// LLFree order (log2 of the frame count) for a mapping of `pages` pages.
/// Used identically in `extend` and `shrink`, so both always agree.
fn order_of(pages: usize) -> Option<usize> {
    pages
        .checked_next_power_of_two()
        .map(|n| n.ilog2() as usize)
}

impl<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> UFacade<MmapWraper, AP> {
    pub fn new(
        static_allocator: Arc<AP>,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
    ) -> Result<Self, MemErrorCode> {
        let (cl, _) = Classing::simple(cpu_count);

        let metadata_sizes = LLFree::metadata_size(&cl, pages_count);

        let mut locals = AlignedBox::slice_from_value(META_ALIGN, metadata_sizes.local, 0u8)
            .map_err(MemErrorCode::AlignBoxError)?;
        let mut trees = AlignedBox::slice_from_value(META_ALIGN, metadata_sizes.trees, 0u8)
            .map_err(MemErrorCode::AlignBoxError)?;
        let mut lower = AlignedBox::slice_from_value(META_ALIGN, metadata_sizes.lower, 0u8)
            .map_err(MemErrorCode::AlignBoxError)?;

        // SAFETY: the buffers live on the heap, so moving the `AlignedBox`
        // handles into `DataBundles` does not move the memory. They are stored
        // in the same struct as the allocator and, thanks to the field order,
        // are dropped after it. Nothing else touches them after this point.
        let meta = unsafe {
            MetaData {
                local: slice::from_raw_parts_mut(locals.as_mut_ptr(), locals.len()),
                trees: slice::from_raw_parts_mut(trees.as_mut_ptr(), trees.len()),
                lower: slice::from_raw_parts_mut(lower.as_mut_ptr(), lower.len()),
            }
        };

        // The virtual range starts out completely free.
        let allocator = LLFree::new(pages_count, llfree::Init::FreeAll, &cl, meta)
            .map_err(MemErrorCode::PageAllocator)?;

        // Собственный slab-кэш записей: слоты из глобальных slab-хуков
        // (host: capability::mem::host_hooks; ядро: gallocator::SlabPool).
        let record_cache = RecordSlab::new().map_err(MemErrorCode::SlabError)?;

        Ok(Self {
            static_allocator,
            mmap_interface,
            generic_vmap_allocator: allocator,
            data_bundles: DataBundles {
                trees,
                locals,
                lower,
            },
            // Класс запросов для обоих аллокаторов: дефолтный класс classing-а
            // (`Classing::simple` регистрирует классы 0/small и 1/huge, деревья
            // стартуют с default). Фактические классы выдачи `get` сохраняются
            // в записи (v_class/p_class), поэтому `put` всегда согласован —
            // фиксированный класс запроса не ломает возврат фреймов.
            allocation_class: cl.default,
            allocation_base,
            records_by_paddr: RBTree::new(RDPAdapter::new()),
            records_by_vaddr: RBTree::new(RDVAdapter::new()),
            record_cache,
            kernel_mappings: Vec::new(),
            asid_pair: None,
        })
    }

    /// Create an owned snapshot of the record found by virtual address.
    ///
    /// O(log n): спуск по дереву с ключом `v_addr` — первый элемент с базой
    /// не выше адреса (lower_bound), затем шаг назад, если точного совпадения
    /// базы нет. Раньше — линейный скан реестра.
    fn snapshot_by_vaddr(&self, v_addr: VirtualADDR) -> Option<RecordSnapshot> {
        let mut cursor = self.records_by_vaddr.lower_bound(Bound::Included(&v_addr));
        // Точное совпадение с базой региона?
        if let Some(record) = cursor.get()
            && record.v_addr == v_addr
        {
            return Some(RecordSnapshot {
                p_addr: record.p_addr.p,
                p_pages_count: record.p_addr.pages_count,
                p_class: record.p_class,
                v_addr: record.v_addr,
                v_class: record.v_class,
                external: record.external,
                fixed: record.fixed,
            });
        }
        // Иначе кандидат — запись с наибольшей базой ниже адреса: только она
        // может содержать адрес (записи не пересекаются по построению).
        cursor.move_prev();
        cursor.get().and_then(|record| {
            let size = record.p_addr.pages_count * FRAME_SIZE;
            (record.v_addr.0 <= v_addr.0 && v_addr.0 - record.v_addr.0 < size).then_some(
                RecordSnapshot {
                    p_addr: record.p_addr.p,
                    p_pages_count: record.p_addr.pages_count,
                    p_class: record.p_class,
                    v_addr: record.v_addr,
                    v_class: record.v_class,
                    external: record.external,
                    fixed: record.fixed,
                },
            )
        })
    }

    /// Create an owned snapshot of the record found by physical address.
    ///
    /// O(log n) по индексу физической базы (редкий путь: аудит/диагностика).
    #[allow(dead_code)]
    fn snapshot_by_paddr(&self, p_addr: PhysADDR) -> Option<RecordSnapshot> {
        // v0.14: ключ дерева — пара (p, vaddr) (физика может стоять в
        // нескольких мапингах) — частичный поиск по физике линейный;
        // путь только аудит/диагностика, не горячий.
        self.records_by_paddr
            .iter()
            .find(|r| r.p_addr.p == p_addr)
            .map(|record| RecordSnapshot {
                p_addr: record.p_addr.p,
                p_pages_count: record.p_addr.pages_count,
                p_class: record.p_class,
                v_addr: record.v_addr,
                v_class: record.v_class,
                external: record.external,
                fixed: record.fixed,
            })
    }

    /// Unlink a record from BOTH intrusive indices without freeing its
    /// memory. The returned `UnsafeRef` still points into a live slab slot.
    ///
    /// Ключи обоих деревьев берутся из снимка: записи иммутабельны, пока
    /// живы, поэтому физическая и виртуальная базы снимка — те же ключи,
    /// под которыми запись вставлялась.
    fn detach_record(
        &mut self,
        snapshot: &RecordSnapshot,
    ) -> Result<UnsafeRef<RecordData>, MemErrorCode> {
        let paddr = self
            .records_by_paddr
            .find_mut(&(snapshot.p_addr.0, snapshot.v_addr.0))
            .remove()
            .ok_or(MemErrorCode::InvalADDR)?;
        let vaddr = self
            .records_by_vaddr
            .find_mut(&snapshot.v_addr)
            .remove()
            .ok_or(MemErrorCode::InternalError)?;
        debug_assert!(
            core::ptr::eq(
                UnsafeRef::into_raw(paddr.clone()) as *const u8,
                UnsafeRef::into_raw(vaddr) as *const u8,
            ),
            "оба индекса обязаны ссылаться на одну и ту же запись"
        );
        Ok(paddr)
    }

    /// Re-insert a detached record into both indices (откат неудачного
    /// `shrink_memory_wiev`: отображение живо, учёт обязан вернуться).
    fn attach_record(&mut self, record: UnsafeRef<RecordData>) {
        let raw = UnsafeRef::into_raw(record);
        // SAFETY: запись только что снята с обоих индексов и жива в своём слоте.
        self.records_by_paddr
            .insert(unsafe { UnsafeRef::from_raw(raw) });
        // SAFETY: то же самое — второе невладеющее представление того же слота.
        self.records_by_vaddr
            .insert(unsafe { UnsafeRef::from_raw(raw) });
    }

    /// Return a detached record's slot to the slab.
    ///
    /// `SlabBox::drop` runs `drop_in_place::<RecordData>` and then frees the slot;
    /// the box finds its home slab by address alignment, so no `SlabCache` handle
    /// is needed. The record must already be unlinked from the tree.
    fn free_record(record: UnsafeRef<RecordData>) {
        let ptr: *mut RecordData = UnsafeRef::into_raw(record);
        // SAFETY: `ptr` was obtained from a `SlabBox` allocation in `store_record`
        // (ownership was transferred to the tree via `forget`), and it is non-null.
        let handle = RecordBox::new(unsafe { NonNull::new_unchecked(ptr) });
        drop(handle);
    }

    /// Store a record in both RBTree indices using the facade-owned slab cache.
    fn store_record(&mut self, state: RecordData) -> Result<(), MemErrorCode> {
        // `RBTree::insert` does not check for duplicate keys, so do it up front.
        // v0.14: проверки дубликата по ФИЗИКЕ больше НЕТ: одна и та же
        // физика может быть отображена многократно (acpid/acpi-крейт:
        // заголовок таблицы + полная таблица по одному адресу; ключ
        // paddr-индекса — пара (p, vaddr), уникальность даёт vaddr).
        if self.records_by_vaddr.find(&state.v_addr).get().is_some() {
            return Err(MemErrorCode::InternalError);
        }

        let alloc = self.record_cache.alloc()?; // SlabBox<RecordData, ..>
        let ptr = alloc.as_ptr();

        // SAFETY: слот неинициализирован (в нём индекс freelist), поэтому
        // пишем значение целиком до любого разыменования.
        unsafe { core::ptr::write(ptr, state) };

        // `insert` возвращает CursorMut и не падает (паника возможна только
        // при повторной вставке уже связанного линка — невозможно для только
        // что записанной записи). Два SafeRef на один слот — легальны:
        // UnsafeRef невладеющий, а членства в разных деревьях дают разные
        // линк-поля одной записи.
        // SAFETY: ptr происходит из живой slab-аллокации этого же вызова.
        let for_p = unsafe { UnsafeRef::from_raw(ptr) };
        // SAFETY: тот же ptr, второе невладеющее представление.
        let for_v = unsafe { UnsafeRef::from_raw(ptr) };
        self.records_by_paddr.insert(for_p);
        self.records_by_vaddr.insert(for_v);

        // The trees now own the slot; don't let SlabBox free it on drop.
        forget(alloc);
        Ok(())
    }
}

// ==== KMAP: ядро ОС в адресном пространстве UMAP-фасада ====
//
// Отдельный impl-блок с усиленным баундом: базовый UFacade остаётся
// доступным бекендам без поддержки KMAP, а ядро отображается только там,
// где arch-код умеет это делать.
//
// Как учитывается Meltdown/Spectre. Состав отображения определяет политика
// изоляции, заданная в KMap платформенным кодом (он и только он знает,
// уязвим ли CPU):
//   - `UserTableIsolation` (KPTI, безопасный дефолт): в пользовательскую
//     таблицу попадают только EntryTrampoline и UserShared регионы —
//     остальное ядро при спекуляции из user-режима недостижимо;
//   - `MapFullKernel` (здоровое железо, RDCL_NO): ядро переносится целиком
//     supervisor-only — без переключения таблиц на границе режимов.
// Само переключение таблиц (CR3/TTBR) и расстановка supervisor-only бит —
// контракт arch-бекенда (см. hal::traits::kmap::KMAPInterface), здесь их
// сознательно нет.
impl<MmapWraper: MMAPInterface + KMAPInterface, AP: ArcPool<Data = LLFree<'static>>>
    UFacade<MmapWraper, AP>
{
    /// Создаёт UMAP-фасад и отображает в него ядро ОС согласно KMAP.
    ///
    /// Порядок операций (каждая с откатом, в стиле крейта):
    /// 1. базовая инициализация ([`UFacade::new`]);
    /// 2. проверка, что пользовательский диапазон не задевает регионы ядра;
    /// 3. отображение всех user-visible регионов KMAP по политике изоляции;
    /// 4. отказ на любом шаге п.3 — полный откат уже поставленных регионов.
    ///
    /// Контракт дропа прежний: `Drop` НЕ снимает отображений (таблицы
    /// страниц адресного пространства уничтожает владелец целиком). Для
    /// разбора с явным снятием — [`UFacade::unmap_kernel_regions`] до дропа.
    pub fn new_with_kernel(
        static_allocator: Arc<AP>,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
        kmap: &KMap,
    ) -> Result<Self, MemErrorCode> {
        // Пользовательский диапазон фасада не имеет права пересекаться
        // с ядром: иначе extend/shrink фасада смог бы управлять ядерными
        // адресами. Переполнение конца диапазона `overlaps` трактует как
        // пересечение — консервативный отказ.
        if kmap.overlaps(allocation_base, pages_count) {
            return Err(MemErrorCode::AlreadyMapped);
        }

        let mut facade = Self::new(
            static_allocator,
            mmap_interface,
            pages_count,
            cpu_count,
            allocation_base,
        )?;

        facade.apply_kmap(kmap)?;
        Ok(facade)
    }

    /// Тегированный аналог [`UFacade::new_with_kernel`]: то же самое + пара
    /// тегов ASID/PCID (KPTI без сброса TLB).
    ///
    /// Порядок операций (каждая с откатом, в стиле крейта):
    /// 1. проверка пересечения пользовательского диапазона с ядром;
    /// 2. базовая инициализация ([`UFacade::new`]);
    /// 3. назначение пары тегов бекенду ([`ASIDInterface::assign_asid_pair`])
    ///    — ДО отображения ядерных регионов, чтобы бекенд ставил строки
    ///    таблиц с учётом тегов и глобальности;
    /// 4. отображение user-visible регионов KMAP по политике изоляции;
    ///    отказ — откат отображений (пара при этом остаётся назначенной
    ///    бекенду до его смерти — возврат пары в пул — ОБЯЗАННОСТЬ
    ///    ВЫЗЫВАЮЩЕГО, см. `MemoryManager::create_ufacade_asid`).
    ///
    /// При [`crate::hal::traits::kmap::IsolationPolicy::MapFullKernel`] пара не нужна семантически
    /// (переключения таблиц нет) — используйте [`Self::new_with_kernel`].
    pub fn new_with_kernel_asid(
        static_allocator: Arc<AP>,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
        kmap: &KMap,
        asid_pair: AsidPair,
    ) -> Result<Self, MemErrorCode>
    where
        MmapWraper: ASIDInterface,
    {
        if kmap.overlaps(allocation_base, pages_count) {
            return Err(MemErrorCode::AlreadyMapped);
        }

        let mut facade = Self::new(
            static_allocator,
            mmap_interface,
            pages_count,
            cpu_count,
            allocation_base,
        )?;

        facade.mmap_interface.assign_asid_pair(asid_pair)?;
        facade.asid_pair = Some(asid_pair);

        // Отказ apply_kmap: отображения откатил сам apply_kmap; бекенд
        // умрёт вместе с фасадом, а пара — на совести вызывающего
        // (контракт в доке метода).
        facade.apply_kmap(kmap)?;
        Ok(facade)
    }

    /// Отображает все user-visible регионы KMAP (фильтр политики изоляции).
    ///
    /// При отказе бекенда на любом регионе снимает уже поставленные (в
    /// обратном порядке) и очищает реестр: частично отображённое ядро
    /// наружу не выходит.
    fn apply_kmap(&mut self, kmap: &KMap) -> Result<(), MemErrorCode> {
        debug_assert!(
            self.kernel_mappings.is_empty(),
            "apply_kmap не рассчитан на повторный вызов"
        );
        for region in kmap.user_visible() {
            match self.mmap_interface.map_kernel_region(region) {
                Ok(()) => self.kernel_mappings.push(*region),
                Err(e) => {
                    // Откат: снимаем то, что уже успели поставить.
                    for mapped in self.kernel_mappings.drain(..).rev() {
                        let _ = self.mmap_interface.unmap_kernel_region(&mapped);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Явно снимает отображение ядра из этого адресного пространства.
    ///
    /// Вызывается при разборе адресного пространства ДО дропа фасада.
    /// Снимаются ВСЕ регионы, даже если часть снятий отказала (маппинг уже
    /// не восстановить), возвращается первая ошибка или `Ok(())`. После
    /// вызова реестр пуст — повторный вызов корректен и дёшев.
    ///
    /// Тегированные фасады: после снятия всех регионов гасится TLB ОБЕИХ
    /// тегов пары ([`TlbOp::Pair`]) — минимально достаточная для корректности
    /// инвалидация (строки таблиц уже сняты, переводы протухли). Отказ
    /// инвалидации НЕ отменяет снятия: он возвращается наравне с отказами
    /// бекенда (первая ошибка). Нетегированный фасад — прежнее поведение:
    /// сброс TLB выполняет сам бекенд внутри `unmap_kernel_region`.
    pub fn unmap_kernel_regions(&mut self) -> Result<(), MemErrorCode> {
        let mut first_err = None;
        for region in self.kernel_mappings.drain(..).rev() {
            if let Err(e) = self.mmap_interface.unmap_kernel_region(&region) {
                first_err = first_err.or(Some(e));
            }
        }
        if let Some(pair) = self.asid_pair
            && let Err(e) = self.mmap_interface.invalidate_tlb(TlbOp::Pair(pair))
        {
            first_err = first_err.or(Some(e));
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Регионы ядра, отображённые в это адресное пространство (аудит).
    pub fn kernel_regions(&self) -> &[KernelRegion] {
        &self.kernel_mappings
    }
}

// ==== ASID/PCID: тегированное адресное пространство (KPTI без сброса TLB) ====
//
// Третий impl-блок с усиленным баундом (паттерн крейта — как KMAP-блок
// выше): базовый UFacade работает с любым MMAP-бекендом, ядро — с
// KMAP-бекендом, теги — с бекендом, реализующим [`ASIDInterface`].
// Методы — тонкие делегаты к бекенду + учёт пары в самом фасаде;
// переключение CR3/TTBR и INVPCID — арх-код ВНЕ крейта.
impl<MmapWraper: MMAPInterface + ASIDInterface, AP: ArcPool<Data = LLFree<'static>>>
    UFacade<MmapWraper, AP>
{
    /// Пара тегов этого адресного пространства (`None` — нетегированный
    /// фасад).
    #[inline]
    pub fn asid_pair(&self) -> Option<AsidPair> {
        self.asid_pair
    }

    /// Назначить пару тегов ПОСЛЕ создания (например, нетегированный фасад
    /// повышается до тегированного после горячей замены CPU/таблиц).
    ///
    /// Повторная назначение другой пары живому фасаду — отказ
    /// (предыдущая пара потерялась бы без возврата в пул).
    pub fn assign_asid_pair(&mut self, pair: AsidPair) -> Result<(), MemErrorCode> {
        if self.asid_pair.is_some() {
            return Err(MemErrorCode::InvalidArgument(
                "facade: ASID pair already assigned",
            ));
        }
        self.mmap_interface.assign_asid_pair(pair)?;
        self.asid_pair = Some(pair);
        Ok(())
    }

    /// Активировать таблицу заданного режима (KPTI-переключение).
    ///
    /// Точка входа для syscall-гейта и планировщика: `Kernel` — на входе в
    /// ядро, `User` — на выходе. С парой тегов и [`FlushMode::NoFlush`]
    /// переключение не вымывает TLB — в этом и есть выигрыш PCID.
    pub fn activate(
        &mut self,
        mode: AddressSpaceMode,
        flush: FlushMode,
    ) -> Result<(), MemErrorCode> {
        self.mmap_interface.activate(mode, flush)
    }

    /// Точечная инвалидация TLB (см. [`TlbOp`]).
    pub fn invalidate_tlb(&mut self, op: TlbOp) -> Result<(), MemErrorCode> {
        self.mmap_interface.invalidate_tlb(op)
    }

    /// Физический корень таблиц страниц этого пространства (для трекинга
    /// гейтом сисколов/планировщиком).
    pub fn root_table(&self) -> Option<PhysADDR> {
        self.mmap_interface.root_table()
    }

    /// Освободить пару тегов: гасит TLB обоих тегов и возвращает пару пулу.
    ///
    /// Вызывать при разборе адресного пространства ДО дропа фасада
    /// (контракт, аналогичный [`Self::unmap_kernel_regions`]): дроп фасада
    /// пару НЕ возвращает — бекенд умирает вместе с ним, а пул тегов живёт
    /// дольше. Порядок разрыва тегированного пространства:
    ///   1. [`Self::unmap_kernel_regions`] — снять ядерные регионы;
    ///   2. [`Self::release_asid`] — погасить TLB пары и вернуть теги пулу;
    ///   3. дроп фасада (дроп бекенда уничтожает таблицы страниц целиком).
    ///
    /// Инвалидация ДО free — анти-ASID-reuse: повторная выдача тех же
    /// тегов другому процессу не наследует чужие переводы адресов.
    /// Повторный вызов — no-op (`Ok(())`).
    pub fn release_asid(&mut self, asid_allocator: &dyn AsidAllocator) -> Result<(), MemErrorCode> {
        let Some(pair) = self.asid_pair else {
            return Ok(());
        };
        // Гасим TLB пары; отказ — реальная ошибка бекенда, не глотаем.
        self.mmap_interface.invalidate_tlb(TlbOp::Pair(pair))?;
        asid_allocator.free_pair(pair);
        self.asid_pair = None;
        Ok(())
    }
}

/// Releases the bookkeeping records (slab slots) that the trees point to.
///
/// This does NOT unmap regions or return frames to the allocators; call
/// `shrink_memory_wiev` for every region beforehand if that is required.
/// The same applies to kernel mappings made by `new_with_kernel`: page
/// tables of the address space are destroyed wholesale by its owner; for
/// an explicit teardown call `unmap_kernel_regions` before dropping.
///
/// Тегированные фасады: дроп НЕ возвращает пару тегов пулу — только
/// [`UFacade::release_asid`] (контракт выше). Слоты записей возвращаются
/// в СОБСТВЕННЫЙ slab-кэш фасада (поле `record_cache`), который дропается
/// следом и возвращает страницы slab-аллокатору.
impl<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> Drop
    for UFacade<MmapWraper, AP>
{
    fn drop(&mut self) {
        // Дреинаж ОБЕИХ индексов: линк интрузивного контейнера паникует при
        // дропе связанным, поэтому каждая запись обязана быть снята с обоих
        // деревьев до free_record. После `remove()` курсор указывает на
        // следующий элемент; `None` — дерево пусто.
        while let Some(record) = self.records_by_paddr.front_mut().remove() {
            // Снимаем со второго индекса (ключ читаем до снятия — запись
            // иммутабельна, пока жива).
            // SAFETY: запись жива в своём слоте (только что снята с первого
            // индекса, слот не освобождён).
            let v: &RecordData = unsafe { &*UnsafeRef::into_raw(record.clone()) };
            let v_key = v.v_addr;
            let removed = self.records_by_vaddr.find_mut(&v_key).remove();
            debug_assert!(
                removed.is_some(),
                "запись обязана состоять в обоих индексах"
            );
            Self::free_record(record);
        }
        debug_assert!(
            self.records_by_vaddr.iter().next().is_none(),
            "второй индекс обязан опустеть синхронно с первым"
        );
    }
}

impl<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> UnnamedUPage
    for UFacade<MmapWraper, AP>
{
    /// Order of operations:
    /// 1. detach the record from the tree (so it can be re-inserted on failure),
    /// 2. unmap the region (fallible; on error the record is put back),
    /// 3. return virtual and physical frames (both are attempted even if one fails,
    ///    because the mapping is already gone and cannot be restored),
    /// 4. free the record slot.
    fn shrink_memory_wiev(&mut self, v_addr: VirtualADDR) -> Result<(), MemErrorCode> {
        // Owned snapshot: no borrow of `self` survives this line.
        // Адрес корректен, но записи с таким диапазоном нет — `NotFound`
        // (контракт варианта, см. `MemErrorCode::NotFound`).
        let snapshot = self
            .snapshot_by_vaddr(v_addr)
            .ok_or(MemErrorCode::NotFound)?;

        // Derived values, computed before any mutable use of `self`.
        let order = order_of(snapshot.p_pages_count).ok_or(MemErrorCode::InternalError)?;
        let make_req = |class: Class| Request::new(order, class, None);
        let v_req = make_req(snapshot.v_class);
        let p_req = make_req(snapshot.p_class);

        let v_frame = llfree::FrameId((snapshot.v_addr.0 - self.allocation_base.0) / FRAME_SIZE);
        let p_frame = llfree::FrameId(snapshot.p_addr.0 / FRAME_SIZE);

        // 1. Detach the record (оба индекса). It stays alive in its slab slot.
        let detached = self.detach_record(&snapshot)?;

        // 2. Unmap. If this fails nothing has changed, so restore the record.
        if let Err(e) = self.mmap_interface.shrink_region(
            self.static_allocator.as_ref(),
            snapshot.v_addr,
            snapshot.p_pages_count,
        ) {
            self.attach_record(detached);
            return Err(e);
        }

        // 3. The mapping is gone: always try to return both frame ranges.
        //    Внешние кадры (SHM/устройство/grant) пулу НЕ принадлежат —
        //    возврат только виртуального диапазона. Фиксированные регионы
        //    не принадлежат фасадному аллокатору диапазона — возврата
        //    виртуального тоже нет.
        let v_res = if snapshot.fixed {
            Ok(())
        } else {
            self.generic_vmap_allocator
                .put(v_frame, v_req)
                .map_err(MemErrorCode::PageAllocator)
        };
        let p_res = if snapshot.external {
            Ok(())
        } else {
            self.static_allocator
                .as_ref()
                .put(p_frame, p_req)
                .map_err(MemErrorCode::PageAllocator)
        };

        // 4. The record is stale in any case, release its slot.
        Self::free_record(detached);

        // 5. TLB: переводы снятого региона обязаны умереть. Тегированный
        // фасад — точечно, по user-тегу (страницы пользователя при KPTI
        // живут только в пользовательской таблице); нетегированный — уже
        // сброшено самим бекендом внутри shrink_region.
        let tlb_res = match self.asid_pair {
            Some(pair) => self
                .mmap_interface
                .invalidate_tlb(TlbOp::Context(pair.user()))
                .map(|_| ()),
            None => Ok(()),
        };

        v_res?;
        p_res?;
        tlb_res?;
        Ok(())
    }

    /// Extend the memory view.
    fn extend_memory_wiev(
        &mut self,
        size_count: usize,
        mp: MMAPMemoryFlags,
    ) -> Result<(), MemErrorCode> {
        // Делегирует полному выделению (адрес интересует только вызывающего
        // сискола mem_alloc — `alloc_region`).
        self.alloc_region(size_count, mp).map(|_| ())
    }
}

// ==== Публичное API регионов: аллокация/карта внешних кадров/grant ====
//
// Используется сисколами памяти (`syscall::mem`) и IPC map/grant-элементами
// через `crate::mem::MemRouter`: фасад — единственный владелец отображений
// задачи, всё движение кадров идёт через него.
impl<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> UFacade<MmapWraper, AP> {
    /// Выделить регион (физика из пула + отображение) и вернуть его
    /// виртуальный адрес — «получение расширяемой памяти» для сисколов.
    ///
    /// Тело прежнего `extend_memory_wiev`, вынесенное ради возвращаемого
    /// адреса: адрес выбирает фасадный аллокатор виртуального диапазона.
    pub fn alloc_region(
        &mut self,
        size_count: usize,
        mp: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode> {
        if size_count == 0 {
            return Err(MemErrorCode::InvalidArgument("size_count must be > 0"));
        }

        let order =
            order_of(size_count).ok_or(MemErrorCode::InvalidArgument("size_count is too large"))?;
        // A fresh request per call, so we do not rely on `Request: Copy`.
        let make_req = |class: Class| Request::new(order, class, None);

        // Allocate virtual address range.
        let (v_frame, v_class) = self
            .generic_vmap_allocator
            .get(None, make_req(self.allocation_class))
            .map_err(MemErrorCode::PageAllocator)?;
        let v_req = make_req(v_class);

        let v_addr = VirtualADDR(self.allocation_base.0 + v_frame.0 * FRAME_SIZE);

        // Allocate physical frames.
        let (p_frame, p_class) = match self
            .static_allocator
            .as_ref()
            .get(None, make_req(self.allocation_class))
        {
            Ok(r) => r,
            Err(e) => {
                let _ = self.generic_vmap_allocator.put(v_frame, v_req);
                return Err(MemErrorCode::PageAllocator(e));
            }
        };
        let p_req = make_req(p_class);

        let p_addr = PhysADDR(p_frame.0 * FRAME_SIZE);

        // Create the mapping.
        if let Err(e) = self.mmap_interface.extend_region(
            self.static_allocator.as_ref(),
            v_addr,
            p_addr,
            size_count,
            mp,
        ) {
            let _ = self.static_allocator.as_ref().put(p_frame, p_req);
            let _ = self.generic_vmap_allocator.put(v_frame, v_req);
            return Err(e);
        }

        // Store the record; roll everything back if that fails.
        if let Err(e) = self.store_record(RecordData {
            p_addr: PageInfo {
                p: p_addr,
                pages_count: size_count,
            },
            p_class,
            v_addr,
            v_class,
            external: false,
            fixed: false,
            p_link: RBTreeLink::new(),
            v_link: RBTreeLink::new(),
        }) {
            let _ = self.mmap_interface.shrink_region(
                self.static_allocator.as_ref(),
                v_addr,
                size_count,
            );
            let _ = self.static_allocator.as_ref().put(p_frame, p_req);
            let _ = self.generic_vmap_allocator.put(v_frame, v_req);
            return Err(e);
        }

        Ok(v_addr)
    }

    /// (База физики, страниц) региона, содержащего `vaddr`
    /// (O(log n) по индексу виртуальных баз). `None` — адрес не отображён.
    pub fn region_at(&self, vaddr: VirtualADDR) -> Option<(PhysADDR, usize)> {
        self.snapshot_by_vaddr(vaddr)
            .map(|s| (s.p_addr, s.p_pages_count))
    }

    /// Полное окно региона, содержащего `vaddr`:
    /// (виртуальная база, база физики, страниц). Для flexpage-переносов
    /// (`MemRouter::transfer`): окно может начинаться внутри региона.
    pub fn region_window(&self, vaddr: VirtualADDR) -> Option<(VirtualADDR, PhysADDR, usize)> {
        // Спуск по дереву: наибольшая база <= vaddr — единственный кандидат.
        let mut cursor = self.records_by_vaddr.lower_bound(Bound::Included(&vaddr));
        let mut record = cursor.get();
        if record.is_none() {
            cursor.move_prev();
            record = cursor.get();
        }
        let record = record?;
        let size = record.p_addr.pages_count * FRAME_SIZE;
        if record.v_addr.0 <= vaddr.0 && vaddr.0 - record.v_addr.0 < size {
            Some((record.v_addr, record.p_addr.p, record.p_addr.pages_count))
        } else {
            None
        }
    }

    /// Отобразить ВНЕШНИЕ физические кадры (SHM-регион, BAR устройства,
    /// grant от другой задачи): физика не из пула фасада и не возвращается
    /// ему при снятии — владелец источник (запись `external = true`).
    ///
    /// Возвращает виртуальный адрес, выбранный фасадным аллокатором
    /// диапазона (адрес назначения — право фасада, L4 flexpage-окно
    /// получателя здесь — подсказка верхнего уровня).
    pub fn map_external(
        &mut self,
        paddr: PhysADDR,
        pages: usize,
        mp: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode> {
        if pages == 0 {
            return Err(MemErrorCode::InvalidArgument("pages must be > 0"));
        }
        let order = order_of(pages).ok_or(MemErrorCode::InvalidArgument("pages is too large"))?;
        let make_req = |class: Class| Request::new(order, class, None);

        // Виртуальный диапазон — из фасадного аллокатора.
        let (v_frame, v_class) = self
            .generic_vmap_allocator
            .get(None, make_req(self.allocation_class))
            .map_err(MemErrorCode::PageAllocator)?;
        let v_req = make_req(v_class);
        let v_addr = VirtualADDR(self.allocation_base.0 + v_frame.0 * FRAME_SIZE);

        // Отображение заданных кадров.
        if let Err(e) = self.mmap_interface.extend_region(
            self.static_allocator.as_ref(),
            v_addr,
            paddr,
            pages,
            mp,
        ) {
            let _ = self.generic_vmap_allocator.put(v_frame, v_req);
            return Err(e);
        }

        // Запись external: физика НЕ возвращается пулу при снятии.
        // p_class не участвует в возврате (внешние кадры) — дефолтный класс.
        if let Err(e) = self.store_record(RecordData {
            p_addr: PageInfo {
                p: paddr,
                pages_count: pages,
            },
            p_class: self.allocation_class,
            v_addr,
            v_class,
            external: true,
            fixed: false,
            p_link: RBTreeLink::new(),
            v_link: RBTreeLink::new(),
        }) {
            let _ =
                self.mmap_interface
                    .shrink_region(self.static_allocator.as_ref(), v_addr, pages);
            let _ = self.generic_vmap_allocator.put(v_frame, v_req);
            return Err(e);
        }
        Ok(v_addr)
    }

    /// Отобразить кадры по ФИКСИРОВАННОМУ виртуальному адресу (ELF-сегменты
    /// загрузчика, стек старта, argv-страница протокола запуска).
    ///
    /// Отличия от [`Self::map_external`]: адрес назначения задаёт ВЫЗЫВАЮЩИЙ
    /// (ELF несёт линк-адреса сегментов — окно получателя не подсказка, а
    /// требование); виртуальный диапазон не берётся из фасадного аллокатора
    /// и не возвращается ему при снятии (запись `fixed = true`). Физика —
    /// по флагу `external`: кадры либо из пула владельца (`false`, при
    /// снятии вернутся пулу фасада), либо внешние (`true`).
    ///
    /// Отказы: адрес/физика не выровнены, нулевой размер, пересечение с
    /// существующим регионом ([`MemErrorCode::AlreadyMapped`]).
    pub fn map_fixed(
        &mut self,
        v_base: VirtualADDR,
        p_base: PhysADDR,
        pages: usize,
        mp: MMAPMemoryFlags,
        external: bool,
    ) -> Result<(), MemErrorCode> {
        if pages == 0 || v_base.0 % FRAME_SIZE != 0 || p_base.0 % FRAME_SIZE != 0 {
            return Err(MemErrorCode::InvalidArgument(
                "map_fixed: zero size or unaligned base",
            ));
        }
        // Пересечение по виртуальному диапазону — полная проверка:
        // (a) существующий регион содержит первый/последний адрес нового;
        // (b) существующий регион начинается внутри нового диапазона.
        let last = VirtualADDR(v_base.0 + (pages - 1) * FRAME_SIZE);
        if self.snapshot_by_vaddr(v_base).is_some() {
            return Err(MemErrorCode::AlreadyMapped);
        }
        let mut cursor = self.records_by_vaddr.lower_bound(Bound::Included(&v_base));
        if let Some(rec) = cursor.get()
            && rec.v_addr.0 <= last.0
        {
            return Err(MemErrorCode::AlreadyMapped);
        }

        self.mmap_interface.extend_region(
            self.static_allocator.as_ref(),
            v_base,
            p_base,
            pages,
            mp,
        )?;

        // Запись: fixed = true; v_class/p_class фиктивны (возврата нет ни
        // по виртуальному, ни — для external — по физике).
        self.store_record(RecordData {
            p_addr: PageInfo {
                p: p_base,
                pages_count: pages,
            },
            p_class: self.allocation_class,
            v_addr: v_base,
            v_class: self.allocation_class,
            external,
            fixed: true,
            p_link: RBTreeLink::new(),
            v_link: RBTreeLink::new(),
        })?;
        Ok(())
    }

    /// Снять регион, НЕ возвращая кадры пулу (grant: владение кадрами
    /// передано получателю, у источника окно умирает). Виртуальный
    /// диапазон возвращается фасадному аллокатору, физика остаётся у
    /// нового владельца.
    pub fn detach_region(&mut self, vaddr: VirtualADDR) -> Result<(), MemErrorCode> {
        let snapshot = self
            .snapshot_by_vaddr(vaddr)
            .ok_or(MemErrorCode::NotFound)?;
        let order = order_of(snapshot.p_pages_count).ok_or(MemErrorCode::InternalError)?;
        let v_req = Request::new(order, snapshot.v_class, None);
        let v_frame = llfree::FrameId((snapshot.v_addr.0 - self.allocation_base.0) / FRAME_SIZE);

        // 1. Снятие записи с индексов (живёт в слоте до решения).
        let detached = self.detach_record(&snapshot)?;

        // 2. Unmap; отказ — запись на место, ничего не менялось.
        if let Err(e) = self.mmap_interface.shrink_region(
            self.static_allocator.as_ref(),
            snapshot.v_addr,
            snapshot.p_pages_count,
        ) {
            self.attach_record(detached);
            return Err(e);
        }

        // 3. Виртуальный диапазон назад (кроме фиксированных регионов —
        //    они аллокатору не принадлежали); физика НЕ возвращается (grant).
        let v_res = if snapshot.fixed {
            Ok(())
        } else {
            self.generic_vmap_allocator
                .put(v_frame, v_req)
                .map_err(MemErrorCode::PageAllocator)
        };

        // 4. Запись мертва в любом случае.
        Self::free_record(detached);

        // 5. TLB: переводы снятого региона обязаны умереть (как в shrink).
        let tlb_res = match self.asid_pair {
            Some(pair) => self
                .mmap_interface
                .invalidate_tlb(TlbOp::Context(pair.user()))
                .map(|_| ()),
            None => Ok(()),
        };

        v_res?;
        tlb_res?;
        Ok(())
    }
}
// ==== Тесты (host) ====
//
// Гоняются на хосте (`cargo test`): slab-хуки берутся из `mem.rs`
// (cfg(test) -> host_hooks), глобальный аллокатор — std. Физический и
// виртуальный аллокаторы — настоящие `LLFree`, mmap — мок с журналом
// вызовов и управляемыми отказами (для проверки откатов).
//
// Мок принадлежит фасаду, поэтому тесты читают журнал и переключают
// отказы через приватное поле `facade.mmap_interface` (модуль тестов —
// потомок `ufacade`, приватные поля ему видны).

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;
    use alloc::{boxed::Box, rc::Rc, vec::Vec};
    use core::cell::RefCell;

    use heapless::{arc_pool, pool::arc::ArcBlock};
    use llfree::Init;

    use super::*;
    use crate::hal::traits::asid::{ASIDError, AddressSpaceId};
    use crate::hal::traits::kmap::{IsolationPolicy, KernelRegionKind};
    use crate::hal::traits::mmap::PAGE_SIZE;
    use crate::mem::MemoryManager;

    /// Одно дерево LLFree: TREE_HUGE(4) * 2^HUGE_ORDER(9) = 2048 страниц.
    const FRAMES: usize = 2048;
    /// База виртуального диапазона фасада в тестах.
    const BASE: usize = 0x1_0000_0000;

    // ---- Канонические регионы ядра для KMAP-тестов ----

    /// Трамплин входа (в высокой половине, далеко от BASE).
    const TRAMPOLINE: usize = 0xFFFF_C000_0000_0000;
    /// Образ ядра (Kernel — при KPTI в user-таблицы не попадает).
    const KIMAGE: usize = 0xFFFF_8000_0000_0000;
    /// Разделяемые пользовательские данные (vdso-аналог).
    const VDSO: usize = 0x0000_7000_0000_0000;

    fn test_kmap(policy: IsolationPolicy) -> KMap {
        let mut kmap = KMap::new(policy);
        kmap.add_all([
            KernelRegion::kernel("kimage", VirtualADDR(KIMAGE), 64, MMAPMemoryFlags::RX).unwrap(),
            KernelRegion::entry_trampoline(
                "trampoline",
                VirtualADDR(TRAMPOLINE),
                1,
                MMAPMemoryFlags::RX,
            )
            .unwrap(),
            KernelRegion::user_shared("vdso", VirtualADDR(VDSO), 4, MMAPMemoryFlags::RO).unwrap(),
        ])
        .unwrap();
        kmap
    }

    // ---- Мок MMAPInterface ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Extend {
            v: VirtualADDR,
            p: PhysADDR,
            pages: usize,
        },
        Shrink {
            v: VirtualADDR,
            pages: usize,
        },
        MapKernel {
            name: &'static str,
            v: VirtualADDR,
            pages: usize,
            kind: KernelRegionKind,
        },
        UnmapKernel {
            name: &'static str,
            v: VirtualADDR,
            pages: usize,
            kind: KernelRegionKind,
        },
    }

    /// Мок mmap-бэкенда: журнал вызовов + управляемые отказы.
    ///
    /// Реализует и [`ASIDInterface`] (теги PCID): назначенная пара,
    /// журнал activate/инвалидаций, корень таблиц — чтобы тесты проверяли
    /// тегированные пути фасада тем же моком.
    pub(crate) struct MockMmap {
        log: Vec<Op>,
        fail_extend: bool,
        fail_shrink: bool,
        /// Частичный отказ map_kernel_region: только для региона с этим
        /// именем (остальные ставятся штатно — для проверки откатов).
        fail_map_kernel_name: Option<&'static str>,
        fail_unmap_kernel: bool,
        /// Живые kernel-отображения (контроль симметрии map/unmap).
        mapped_kernel: Vec<KernelRegion>,
        /// Разделяемый тап журнала kernel-операций: когда мок умирает вместе
        /// с фасадом (откат при неудачном `new_with_kernel`), тап продолжает
        /// жить и показывает, ЧТО делал бекенд перед смертью.
        kernel_log_tap: Option<Rc<RefCell<Vec<Op>>>>,
        // ---- PCID-состояние (ASIDInterface) ----
        /// Назначенная пара тегов (assign_asid_pair).
        assigned_asid: Option<AsidPair>,
        /// Журнал активаций (mode, flush).
        activate_log: Vec<(AddressSpaceMode, FlushMode)>,
        /// Журнал TLB-инвалидаций.
        invalidate_log: Vec<TlbOp>,
        /// Управляемый отказ инвалидации TLB.
        fail_invalidate: bool,
        /// Фиктивный корень таблиц.
        root: Option<PhysADDR>,
    }

    impl MockMmap {
        pub(crate) fn new() -> Self {
            Self {
                log: Vec::new(),
                fail_extend: false,
                fail_shrink: false,
                fail_map_kernel_name: None,
                fail_unmap_kernel: false,
                mapped_kernel: Vec::new(),
                kernel_log_tap: None,
                assigned_asid: None,
                activate_log: Vec::new(),
                invalidate_log: Vec::new(),
                fail_invalidate: false,
                root: Some(PhysADDR(0xCAFE_0000)),
            }
        }

        fn last(&self) -> &Op {
            self.log.last().expect("журнал пуст")
        }
    }

    impl ASIDInterface for MockMmap {
        fn assign_asid_pair(&mut self, pair: AsidPair) -> Result<(), MemErrorCode> {
            if self.assigned_asid.is_some() {
                return Err(MemErrorCode::InvalidArgument(
                    "mock: повторное назначение пары",
                ));
            }
            self.assigned_asid = Some(pair);
            Ok(())
        }

        fn asid_pair(&self) -> Option<AsidPair> {
            self.assigned_asid
        }

        fn activate(
            &mut self,
            mode: AddressSpaceMode,
            flush: FlushMode,
        ) -> Result<(), MemErrorCode> {
            self.activate_log.push((mode, flush));
            Ok(())
        }

        fn root_table(&self) -> Option<PhysADDR> {
            self.root
        }
    }

    impl MMAPInterface for MockMmap {
        fn extend_region(
            &mut self,
            _allocator: &LLFree<'static>,
            v_base: VirtualADDR,
            p_base: PhysADDR,
            pages: usize,
            _mmap: MMAPMemoryFlags,
        ) -> Result<PageInfo, MemErrorCode> {
            if self.fail_extend {
                return Err(MemErrorCode::InternalError);
            }
            self.log.push(Op::Extend {
                v: v_base,
                p: p_base,
                pages,
            });
            Ok(PageInfo {
                p: p_base,
                pages_count: pages,
            })
        }

        fn shrink_region(
            &mut self,
            _phys_page_allocator: &LLFree<'static>,
            allocation: VirtualADDR,
            pages: usize,
        ) -> Result<(), MemErrorCode> {
            if self.fail_shrink {
                return Err(MemErrorCode::InternalError);
            }
            self.log.push(Op::Shrink {
                v: allocation,
                pages,
            });
            Ok(())
        }

        /// PCID-мок: журнал + управляемый отказ (дефолт трейта — громкий
        /// Err, мок переопределяет, как настоящий тегированный бекенд).
        fn invalidate_tlb(&mut self, op: TlbOp) -> Result<(), MemErrorCode> {
            if self.fail_invalidate {
                return Err(MemErrorCode::InternalError);
            }
            self.invalidate_log.push(op);
            Ok(())
        }
    }

    impl KMAPInterface for MockMmap {
        fn map_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode> {
            if Some(region.name()) == self.fail_map_kernel_name {
                return Err(MemErrorCode::InternalError);
            }
            let op = Op::MapKernel {
                name: region.name(),
                v: region.v_base(),
                pages: region.pages_count(),
                kind: region.kind(),
            };
            if let Some(tap) = &self.kernel_log_tap {
                tap.borrow_mut().push(op.clone());
            }
            self.log.push(op);
            self.mapped_kernel.push(*region);
            Ok(())
        }

        fn unmap_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode> {
            if self.fail_unmap_kernel {
                return Err(MemErrorCode::InternalError);
            }
            let op = Op::UnmapKernel {
                name: region.name(),
                v: region.v_base(),
                pages: region.pages_count(),
                kind: region.kind(),
            };
            if let Some(tap) = &self.kernel_log_tap {
                tap.borrow_mut().push(op.clone());
            }
            self.log.push(op);
            self.mapped_kernel.retain(|r| r != region);
            Ok(())
        }
    }

    // ---- Настоящие LLFree-аллокаторы для тестов ----

    /// Владение метаданными LLFree: буферы лежат в куче (AlignedBox), а
    /// владеющий их хэндл утекает (`Box::leak`) — это даёт честный
    /// `LLFree<'static>` для тестов (буферы живут до конца процесса).
    struct MetaHolder {
        local: AlignedBox<[u8]>,
        trees: AlignedBox<[u8]>,
        lower: AlignedBox<[u8]>,
    }

    fn make_llfree(frames: usize) -> LLFree<'static> {
        let (cl, _) = Classing::simple(1);
        let sizes = LLFree::metadata_size(&cl, frames);
        let holder = Box::leak(Box::new(MetaHolder {
            local: AlignedBox::slice_from_value(64, sizes.local, 0u8).unwrap(),
            trees: AlignedBox::slice_from_value(64, sizes.trees, 0u8).unwrap(),
            lower: AlignedBox::slice_from_value(64, sizes.lower, 0u8).unwrap(),
        }));
        // SAFETY: буферы — кучевые аллокации, на которые ссылаются утёкшие
        // AlignedBox-хэндлы: они не двигаются и не освобождаются, другого
        // доступа к ним нет, поэтому срезы 'static корректны.
        let meta = unsafe {
            MetaData {
                local: core::slice::from_raw_parts_mut(
                    holder.local.as_mut_ptr(),
                    holder.local.len(),
                ),
                trees: core::slice::from_raw_parts_mut(
                    holder.trees.as_mut_ptr(),
                    holder.trees.len(),
                ),
                lower: core::slice::from_raw_parts_mut(
                    holder.lower.as_mut_ptr(),
                    holder.lower.len(),
                ),
            }
        };
        LLFree::new(frames, Init::FreeAll, &cl, meta).unwrap()
    }

    arc_pool!(TestPool: LLFree<'static>);

    /// Выдаёт статический ArcBlock под физический аллокатор.
    ///
    /// Блоки берутся из статического массива строго по одному (индекс под
    /// мьютексом), поэтому параллельные тесты не конфликтуют: каждый блок
    /// передаётся пулу ровно один раз.
    fn take_block() -> &'static mut ArcBlock<LLFree<'static>> {
        static NEXT: spin::Mutex<usize> = spin::Mutex::new(0);
        static mut BLOCKS: [ArcBlock<LLFree<'static>>; 64] = [const { ArcBlock::new() }; 64];

        let mut next = NEXT.lock();
        assert!(*next < 64, "тесты исчерпали блоки пула");
        let idx = *next;
        *next += 1;
        // SAFETY: блок живёт в статике и выдаётся ровно один раз (индекс
        // под мьютексом, повторных обращений по индексу нет); после manage
        // владение переходит пулу. `addr_of_mut!` не создаёт ссылку и не
        // копирует значение (ArcBlock не Copy) — берётся только адрес.
        unsafe { core::ptr::addr_of_mut!(BLOCKS[idx]).as_mut().unwrap() }
    }

    /// Свежий пул с одним физическим аллокатором на `FRAMES` страниц.
    fn make_p_allocator() -> Arc<TestPool> {
        TestPool.manage(take_block());
        TestPool.alloc(make_llfree(FRAMES)).unwrap()
    }

    /// Полное число свободных страниц физического аллокатора.
    fn p_free(p_alloc: &Arc<TestPool>) -> usize {
        p_alloc.as_ref().stats().free_frames
    }

    /// Ссылки указывают на один и тот же аллокатор (heapless `Arc` не имеет
    /// `Arc::ptr_eq`, поэтому сравниваются указатели на данные).
    fn same_alloc<P: ArcPool<Data = LLFree<'static>>>(a: &Arc<P>, b: &Arc<P>) -> bool {
        core::ptr::eq(
            a.as_ref() as *const LLFree<'static>,
            b.as_ref() as *const LLFree<'static>,
        )
    }

    // ---- Хелперы над журналом мока ----

    impl Op {
        fn pages(&self) -> usize {
            match self {
                Op::Extend { pages, .. }
                | Op::Shrink { pages, .. }
                | Op::MapKernel { pages, .. }
                | Op::UnmapKernel { pages, .. } => *pages,
            }
        }

        fn v_addr(&self) -> VirtualADDR {
            match self {
                Op::Extend { v, .. }
                | Op::Shrink { v, .. }
                | Op::MapKernel { v, .. }
                | Op::UnmapKernel { v, .. } => *v,
            }
        }
    }

    // ---- UFacade ----

    #[test]
    fn extend_shrink_roundtrip() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Расширение: 4 страницы по базовому адресу диапазона.
        facade.extend_memory_wiev(4, MMAPMemoryFlags::RW).unwrap();
        assert_eq!(
            facade.mmap_interface.last(),
            &Op::Extend {
                v: VirtualADDR(BASE),
                p: PhysADDR(0),
                pages: 4,
            }
        );

        // Сжатие по любому адресу внутри региона снимает весь регион.
        facade
            .shrink_memory_wiev(VirtualADDR(BASE + 2 * FRAME_SIZE))
            .unwrap();
        assert_eq!(
            facade.mmap_interface.last(),
            &Op::Shrink {
                v: VirtualADDR(BASE),
                pages: 4,
            }
        );

        // Физические и виртуальные фреймы вернулись: весь объём снова
        // доступен одним запросом (order = TREE_ORDER).
        facade
            .extend_memory_wiev(FRAMES, MMAPMemoryFlags::RW)
            .unwrap();
        assert_eq!(facade.mmap_interface.last().pages(), FRAMES);
        facade.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        assert_eq!(p_free(&p_alloc), FRAMES);
    }

    #[test]
    fn several_regions_and_record_audit() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Три региона: запросы 1 / 3 / 8 страниц -> ордера 0 / 2 / 3, т.е.
        // vmap выдаёт фреймы 0 / 4 / 8 (выравнивание по ордеру).
        for (i, (pages, frame)) in [(1usize, 0usize), (3, 4), (8, 8)].into_iter().enumerate() {
            facade
                .extend_memory_wiev(pages, MMAPMemoryFlags::RX)
                .unwrap();
            let op = facade.mmap_interface.last();
            assert_eq!(op.pages(), pages, "регион {i}: размер в mock");
            assert_eq!(
                op.v_addr(),
                VirtualADDR(BASE + frame * FRAME_SIZE),
                "регион {i}: фрейм vmap с учётом выравнивания ордера"
            );
        }

        // Внутренний реестр: ровно три записи.
        assert_eq!(facade.records_by_vaddr.iter().count(), 3);
        // Физический аллокатор отдал 1 + 4 (округление 3) + 8 = 13 фреймов.
        assert_eq!(p_free(&p_alloc), FRAMES - 13);

        // Снимаем средний регион (запрос 3 страницы -> округление до 4).
        facade
            .shrink_memory_wiev(VirtualADDR(BASE + 4 * FRAME_SIZE))
            .unwrap();
        assert_eq!(facade.records_by_vaddr.iter().count(), 2);
        assert_eq!(p_free(&p_alloc), FRAMES - 9);

        // Освобождённые фреймы переиспользуются: следующий одностраничный
        // extend получает первый свободный фрейм (1).
        facade.extend_memory_wiev(1, MMAPMemoryFlags::RO).unwrap();
        assert_eq!(
            facade.mmap_interface.last().v_addr(),
            VirtualADDR(BASE + FRAME_SIZE),
            "vmap переиспользовал освобождённые фреймы"
        );
    }

    #[test]
    fn shrink_unknown_address_is_not_found() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Ничего не отображено — любой адрес неизвестен.
        match facade.shrink_memory_wiev(VirtualADDR(BASE)) {
            Err(MemErrorCode::NotFound) => {}
            other => panic!("ожидался NotFound, получено {other:?}"),
        }

        // И адрес вне отображённого региона тоже.
        facade.extend_memory_wiev(1, MMAPMemoryFlags::RW).unwrap();
        match facade.shrink_memory_wiev(VirtualADDR(BASE + 64 * FRAME_SIZE)) {
            Err(MemErrorCode::NotFound) => {}
            other => panic!("ожидался NotFound, получено {other:?}"),
        }
        // Регион не пострадал.
        assert_eq!(facade.records_by_vaddr.iter().count(), 1);
    }

    #[test]
    fn extend_zero_rejected() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        match facade.extend_memory_wiev(0, MMAPMemoryFlags::RW) {
            Err(MemErrorCode::InvalidArgument(_)) => {}
            other => panic!("ожидался InvalidArgument, получено {other:?}"),
        }
        assert!(
            facade.mmap_interface.log.is_empty(),
            "мок не должен вызываться"
        );
        assert_eq!(p_free(&p_alloc), FRAMES, "фреймы не должны тратиться");
    }

    #[test]
    fn extend_out_of_memory() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Запрос больше всего диапазона: ордер 4096 страниц (12) больше
        // TREE_ORDER (11) — отказ LLFree::get, мок не вызван.
        match facade.extend_memory_wiev(FRAMES * 2, MMAPMemoryFlags::RW) {
            Err(MemErrorCode::PageAllocator(_)) => {}
            other => panic!("ожидался PageAllocator, получено {other:?}"),
        }
        assert!(facade.mmap_interface.log.is_empty());

        // Исчерпание: весь диапазон одним запросом.
        facade
            .extend_memory_wiev(FRAMES, MMAPMemoryFlags::RW)
            .unwrap();
        // Следующий запрос любого размера невозможен.
        assert!(facade.extend_memory_wiev(1, MMAPMemoryFlags::RW).is_err());
        assert_eq!(p_free(&p_alloc), 0);
    }

    #[test]
    fn extend_rollback_on_mmap_failure() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Отказ extend_region: фасад обязан вернуть фреймы обоим аллокаторам.
        facade.mmap_interface.fail_extend = true;
        assert!(facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).is_err());
        assert_eq!(p_free(&p_alloc), FRAMES, "физические фреймы не возвращены");
        assert!(
            facade.records_by_vaddr.iter().next().is_none(),
            "запись не должна создаться"
        );

        // После снятия отказа повторное расширение получает ТЕ ЖЕ адреса:
        // доказательство полного отката (фреймы вернулись).
        facade.mmap_interface.fail_extend = false;
        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();
        assert_eq!(
            facade.mmap_interface.last(),
            &Op::Extend {
                v: VirtualADDR(BASE),
                p: PhysADDR(0),
                pages: 2,
            }
        );
    }

    #[test]
    fn shrink_rollback_on_mmap_failure() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();

        // Отказ shrink_region: запись обязана вернуться в реестр, фреймы —
        // остаться занятыми (регион всё ещё отображён).
        facade.mmap_interface.fail_shrink = true;
        assert!(facade.shrink_memory_wiev(VirtualADDR(BASE)).is_err());
        assert_eq!(facade.records_by_vaddr.iter().count(), 1, "запись потеряна");
        assert_eq!(
            p_free(&p_alloc),
            FRAMES - 2,
            "фреймы возвращены при живом отображении"
        );

        // Повторное сжатие после снятия отказа проходит штатно.
        facade.mmap_interface.fail_shrink = false;
        facade.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        assert_eq!(facade.records_by_vaddr.iter().count(), 0);
        assert_eq!(p_free(&p_alloc), FRAMES);
    }

    #[test]
    fn drop_with_live_records_is_safe() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        for pages in [1usize, 2, 4, 8] {
            facade
                .extend_memory_wiev(pages, MMAPMemoryFlags::RW)
                .unwrap();
        }
        assert_eq!(facade.records_by_vaddr.iter().count(), 4);

        // Дроп фасада с живыми записями: освобождение слотов записей без
        // паники и double-free (SlabBox находит свой slab по выравниванию).
        // Физические фреймы при этом остаются занятыми (дроп фасада не
        // откатывает отображения — контракт задокументирован в Drop).
        drop(facade);
        // Заняты фреймы 0 и 2..15 (15 фреймов); фрейм 1 остался свободен
        // после выравнивания ордера 1 (аллокация 2 страниц взяла 2..3).
        assert_eq!(p_free(&p_alloc), FRAMES - 15);

        // Slab-слоты записей пригодны для переиспользования новым фасадом;
        // vmap у нового фасада свой (полностью свободный), физический
        // аллокатор общий — новый регион ложится на свободный фрейм 1.
        let mut facade2 = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();
        facade2.extend_memory_wiev(1, MMAPMemoryFlags::RW).unwrap();
        assert_eq!(
            facade2.mmap_interface.last(),
            &Op::Extend {
                v: VirtualADDR(BASE),
                p: PhysADDR(FRAME_SIZE),
                pages: 1,
            }
        );
    }

    // ---- MemoryManager ----

    #[test]
    fn manager_facade_lifecycle() {
        let p_alloc = make_p_allocator();
        let mut mgr = MemoryManager::new(p_alloc.clone()).unwrap();
        assert!(
            same_alloc(mgr.p_allocator(), &p_alloc),
            "менеджер хранит переданный Arc"
        );

        // Создание фасада и работа через UnnamedUPage.
        let mut facade = mgr
            .create_facade(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();
        facade.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();

        // Дроп бокса уничтожает фасад; слот возвращается в кэш и пригоден
        // для нового фасада.
        drop(facade);
        let mut facade2 = mgr
            .create_facade(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        facade2.extend_memory_wiev(1, MMAPMemoryFlags::RW).unwrap();
        // Штатное завершение жизненного цикла: сжатие до дропа бокса.
        facade2.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        drop(facade2);

        // Физический аллокатор разделяемый: все фреймы вернулись.
        assert_eq!(p_free(&p_alloc), FRAMES);
    }

    #[test]
    fn manager_facades_share_p_allocator() {
        let p_alloc = make_p_allocator();
        let mut mgr = MemoryManager::new(p_alloc.clone()).unwrap();

        // Два фасада с независимыми vmap-диапазонами, но общим физическим
        // аллокатором: вместе исчерпывают его полностью.
        let mut f1 = mgr
            .create_facade(MockMmap::new(), FRAMES / 2, 1, VirtualADDR(BASE))
            .unwrap();
        let mut f2 = mgr
            .create_facade(
                MockMmap::new(),
                FRAMES / 2,
                1,
                VirtualADDR(BASE + 0x1000_0000),
            )
            .unwrap();

        f1.extend_memory_wiev(FRAMES / 2, MMAPMemoryFlags::RW)
            .unwrap();
        f2.extend_memory_wiev(FRAMES / 2, MMAPMemoryFlags::RW)
            .unwrap();
        assert_eq!(p_free(&p_alloc), 0, "оба фасада исчерпали общий пул");

        // Независимое сжатие каждым фасадом.
        f1.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        assert_eq!(p_free(&p_alloc), FRAMES / 2);
        f2.shrink_memory_wiev(VirtualADDR(BASE + 0x1000_0000))
            .unwrap();
        assert_eq!(p_free(&p_alloc), FRAMES);
    }

    // ---- KMAP: ядро в UMAP-фасаде ----

    /// Имена MapKernel-операций журнала (для компактных ассертов).
    fn kernel_ops(log: &[Op]) -> Vec<(&'static str, bool)> {
        log.iter()
            .filter_map(|op| match op {
                Op::MapKernel { name, .. } => Some((*name, true)),
                Op::UnmapKernel { name, .. } => Some((*name, false)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn ufacade_kpti_maps_only_trampoline_and_shared() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::UserTableIsolation);

        let mut facade = UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        )
        .unwrap();

        // KPTI: kimage (Kernel) в user-таблице отсутствует, трамплин и
        // vdso — присутствуют.
        assert_eq!(
            kernel_ops(&facade.mmap_interface.log),
            vec![("vdso", true), ("trampoline", true)],
            "KPTI обязан скрыть Kernel-регионы"
        );
        assert_eq!(facade.mmap_interface.mapped_kernel.len(), 2);
        assert_eq!(facade.kernel_regions().len(), 2);
        assert!(
            facade.kernel_regions().iter().all(|r| r.name() != "kimage"),
            "kimage не должен быть в реестре фасада"
        );

        // Пользовательская работа фасада не нарушена.
        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();
        assert_eq!(
            facade.mmap_interface.last(),
            &Op::Extend {
                v: VirtualADDR(BASE),
                p: PhysADDR(0),
                pages: 2,
            }
        );
    }

    #[test]
    fn ufacade_full_policy_maps_everything() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::MapFullKernel);

        let facade = UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        )
        .unwrap();

        // Здоровое железо: ядро переносится целиком (supervisor-only —
        // обязательство бекенда).
        assert_eq!(
            kernel_ops(&facade.mmap_interface.log),
            vec![("vdso", true), ("kimage", true), ("trampoline", true)]
        );
        assert_eq!(facade.kernel_regions().len(), 3);
    }

    #[test]
    fn ufacade_kernel_map_rolls_back_on_partial_failure() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::UserTableIsolation);

        // Порядок user-visible при KPTI: vdso, затем trampoline. Отказ на
        // трамплине: vdso обязан быть поставлен и СНЯТ откатом.
        let tap = Rc::new(RefCell::new(Vec::new()));
        let mut mmap = MockMmap::new();
        mmap.fail_map_kernel_name = Some("trampoline");
        mmap.kernel_log_tap = Some(tap.clone());

        let err = match UFacade::new_with_kernel(
            p_alloc.clone(),
            mmap,
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        ) {
            Err(e) => e,
            Ok(_) => panic!("создание фасада обязано упасть на отказе бекенда"),
        };
        assert!(matches!(err, MemErrorCode::InternalError));

        // Фасад и мок погибли вместе, но тап жив: откат снял vdso.
        assert_eq!(
            kernel_ops(&tap.borrow()),
            vec![("vdso", true), ("vdso", false)],
            "частичное отображение ядра обязано откатиться полностью"
        );
    }

    #[test]
    fn ufacade_user_range_overlapping_kernel_rejected() {
        let p_alloc = make_p_allocator();
        // vdso при 0x7000_0000_0000 занимает 4 страницы; кладём диапазон
        // фасада прямо на него.
        let kmap = test_kmap(IsolationPolicy::UserTableIsolation);
        let vdso = kmap.find_by_vaddr(VirtualADDR(VDSO)).unwrap();

        let err = match UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            vdso.pages_count(),
            1,
            vdso.v_base(),
            &kmap,
        ) {
            Err(e) => e,
            Ok(_) => panic!("пересечение с ядром обязано отвергаться"),
        };
        assert!(
            matches!(err, MemErrorCode::AlreadyMapped),
            "пересечение с ядром обязано отвергаться до любых отображений"
        );

        // Частичное пересечение (первая страница фасада — последняя vdso).
        let partial_base = vdso.end().unwrap().as_usize() - PAGE_SIZE;
        let err = match UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            4,
            1,
            VirtualADDR(partial_base),
            &kmap,
        ) {
            Err(e) => e,
            Ok(_) => panic!("частичное пересечение обязано отвергаться"),
        };
        assert!(matches!(err, MemErrorCode::AlreadyMapped));
    }

    #[test]
    fn ufacade_kernel_addr_operations_are_not_found() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::UserTableIsolation);

        let mut facade = UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        )
        .unwrap();

        // shrink по ядерному адресу: регион ядра — не запись фасада,
        // пользовательская операция обязана отказаться (NotFound).
        match facade.shrink_memory_wiev(VirtualADDR(TRAMPOLINE)) {
            Err(MemErrorCode::NotFound) => {}
            other => panic!("ожидался NotFound, получено {other:?}"),
        }
        // vmap-аллокатор фасада не тратился, физика тоже.
        assert_eq!(p_free(&p_alloc), FRAMES);
    }

    #[test]
    fn unmap_kernel_regions_explicit_teardown() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::MapFullKernel);

        let mut facade = UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        )
        .unwrap();
        assert_eq!(facade.kernel_regions().len(), 3);
        assert_eq!(facade.mmap_interface.mapped_kernel.len(), 3);

        // Явный разбор: всё снимается, реестр пуст.
        facade.unmap_kernel_regions().unwrap();
        assert!(facade.kernel_regions().is_empty());
        assert!(
            facade.mmap_interface.mapped_kernel.is_empty(),
            "после teardown мок обязан быть симметричным"
        );

        // Повторный вызов корректен (пустой реестр — пустая работа).
        facade.unmap_kernel_regions().unwrap();
        assert_eq!(kernel_ops(&facade.mmap_interface.log).len(), 6); // 3 map + 3 unmap
    }

    #[test]
    fn unmap_kernel_regions_reports_error_but_unmaps_all() {
        let p_alloc = make_p_allocator();
        let kmap = test_kmap(IsolationPolicy::MapFullKernel);

        let mut facade = UFacade::new_with_kernel(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &kmap,
        )
        .unwrap();

        // Отказ снятия: метод обязан снять ВСЁ и вернуть первую ошибку.
        facade.mmap_interface.fail_unmap_kernel = true;
        assert!(matches!(
            facade.unmap_kernel_regions(),
            Err(MemErrorCode::InternalError)
        ));
        assert!(
            facade.kernel_regions().is_empty(),
            "реестр очищается при любом исходе"
        );
    }

    #[test]
    fn manager_default_kmap_empty_and_conservative() {
        let p_alloc = make_p_allocator();
        let mgr = MemoryManager::<MockMmap, TestPool>::new(p_alloc).unwrap();

        assert!(mgr.kmap().is_empty(), "дефолтная KMAP пуста");
        assert_eq!(
            mgr.kmap().policy(),
            IsolationPolicy::UserTableIsolation,
            "дефолтная политика — безопасная (KPTI)"
        );
    }

    #[test]
    fn manager_create_ufacade_full_cycle() {
        let p_alloc = make_p_allocator();
        let mut mgr = MemoryManager::new(p_alloc.clone()).unwrap();

        // Платформа заполняет KMAP и задаёт политику по данным CPU.
        let mut kmap = test_kmap(IsolationPolicy::UserTableIsolation);
        kmap.set_policy(IsolationPolicy::MapFullKernel);
        mgr.install_kmap(kmap);
        assert_eq!(mgr.kmap().len(), 3);

        // UMAP-фасад с отображённым ядром + штатная пользовательская работа.
        let mut facade = mgr
            .create_ufacade(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        assert_eq!(facade.kernel_regions().len(), 3, "политика full: всё ядро");

        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();
        facade.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();

        // Разбор адресного пространства: сначала ядро, потом дроп фасада.
        facade.unmap_kernel_regions().unwrap();
        drop(facade);

        // create_facade (без KMAP) остаётся доступен на том же менеджере.
        let mut plain = mgr
            .create_facade(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        assert!(
            plain.kernel_regions().is_empty(),
            "фасад без KMAP ядерных отображений не имеет"
        );
        plain.unmap_kernel_regions().unwrap(); // no-op
        plain.extend_memory_wiev(1, MMAPMemoryFlags::RW).unwrap();
        plain.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        drop(plain);

        assert_eq!(p_free(&p_alloc), FRAMES, "фреймы вернулись полностью");
    }

    #[test]
    fn manager_kpti_via_create_ufacade_hides_kernel() {
        let p_alloc = make_p_allocator();
        let mut mgr = MemoryManager::new(p_alloc).unwrap();
        mgr.install_kmap(test_kmap(IsolationPolicy::UserTableIsolation));

        let facade = mgr
            .create_ufacade(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();

        assert_eq!(
            kernel_ops(&facade.mmap_interface.log),
            vec![("vdso", true), ("trampoline", true)],
            "KPTI-политика менеджера обязана дойти до фасада"
        );
        assert_eq!(facade.kernel_regions().len(), 2);
    }

    // ---- install_p_allocator (глобальная одноразовая установка) ----

    #[test]
    fn install_p_allocator_is_one_shot() {
        let arc = crate::mem::install_p_allocator(make_llfree(FRAMES));
        // Повторный вызов возвращает кешированный Arc (аргумент отбрасывается):
        // повторная выдача того же статического блока пулу недопустима.
        let arc2 = crate::mem::install_p_allocator(make_llfree(FRAMES));
        assert!(
            same_alloc(&arc, &arc2),
            "повторная установка обязана вернуть кешированный Arc"
        );

        // Аллокатор из Arc работоспособен: фрейм выделяется и возвращается.
        let (frame, class) = arc
            .as_ref()
            .get(None, Request::new(0, Class(0), None))
            .unwrap();
        arc.as_ref()
            .put(frame, Request::new(0, class, None))
            .unwrap();
    }

    // ---- ASID/PCID: тегированные фасады ----

    /// Считающий пул тегов: пары с парным битом (x86-стиль), подсчёт
    /// live/free для проверки откатов и разрыва.
    struct CountingAsidPool {
        next: core::cell::Cell<u16>,
        live: core::cell::Cell<usize>,
        freed: core::cell::Cell<usize>,
    }

    impl CountingAsidPool {
        fn new() -> Self {
            Self {
                next: core::cell::Cell::new(1), // 0 — UNTAGGED, не выдаём
                live: core::cell::Cell::new(0),
                freed: core::cell::Cell::new(0),
            }
        }

        fn live(&self) -> usize {
            self.live.get()
        }

        fn freed(&self) -> usize {
            self.freed.get()
        }
    }

    impl AsidAllocator for CountingAsidPool {
        fn alloc_pair(&self) -> Result<AsidPair, ASIDError> {
            let user = self.next.get();
            if user >= 0x800 {
                return Err(ASIDError::Exhausted);
            }
            self.next.set(user + 1);
            self.live.set(self.live.get() + 1);
            // Парный бит 0x800: ядровый тег = user | 0x800.
            Ok(AsidPair::with_kernel_bit(AddressSpaceId(user), 0x800))
        }

        fn free_pair(&self, _pair: AsidPair) {
            self.live.set(self.live.get() - 1);
            self.freed.set(self.freed.get() + 1);
        }

        fn capacity(&self) -> usize {
            0x800 - 1
        }

        fn tag_bits(&self) -> u32 {
            12
        }
    }

    fn static_pool() -> &'static CountingAsidPool {
        Box::leak(Box::new(CountingAsidPool::new()))
    }

    /// Фасад обязан влезать в свой slab (4096): иначе SlabCache::alloc
    /// откажет в рантайме. Страховка от разрастания структуры.
    #[test]
    fn facade_fits_slab() {
        assert!(
            core::mem::size_of::<UFacade<MockMmap, TestPool>>() <= crate::mem::FACADE_SLAB_SIZE,
            "UFacade вырос за пределы slab-а: {}",
            core::mem::size_of::<UFacade<MockMmap, TestPool>>()
        );
    }

    #[test]
    fn pcid_facade_lifecycle() {
        let p_alloc = make_p_allocator();
        let pool = static_pool();
        let mut mgr = MemoryManager::new(p_alloc.clone()).unwrap();
        mgr.install_kmap(test_kmap(IsolationPolicy::UserTableIsolation));
        mgr.install_asid_allocator(pool);

        // Тегированный фасад: пара из пула, ядро по KPTI-политике.
        let mut facade = mgr
            .create_ufacade_asid(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        assert_eq!(pool.live(), 1, "пара выдана пулом");
        let pair = facade.asid_pair().expect("пара назначена фасаду");
        assert_eq!(facade.mmap_interface.assigned_asid, Some(pair));
        assert_eq!(pair.kernel().as_u16(), pair.user().as_u16() | 0x800);

        // KPTI: только трамплин и vdso (пара тегов не расширяет доступность).
        assert_eq!(
            kernel_ops(&facade.mmap_interface.log),
            vec![("vdso", true), ("trampoline", true)]
        );

        // KPTI-переключение через фасад: активации журналируются бекендом.
        facade
            .activate(AddressSpaceMode::Kernel, FlushMode::NoFlush)
            .unwrap();
        facade
            .activate(AddressSpaceMode::User, FlushMode::NoFlush)
            .unwrap();
        assert_eq!(
            facade.mmap_interface.activate_log,
            vec![
                (AddressSpaceMode::Kernel, FlushMode::NoFlush),
                (AddressSpaceMode::User, FlushMode::NoFlush),
            ],
            "гейт/планировщик переключают таблицы через фасад"
        );

        // Корень таблиц доступен гейту.
        assert_eq!(facade.root_table(), Some(PhysADDR(0xCAFE_0000)));

        // Пользовательская работа + точечная инвалидация по user-тегу.
        facade.extend_memory_wiev(2, MMAPMemoryFlags::RW).unwrap();
        facade.shrink_memory_wiev(VirtualADDR(BASE)).unwrap();
        assert_eq!(
            facade.mmap_interface.invalidate_log,
            vec![TlbOp::Context(pair.user())],
            "unmap региона гасит только user-тег"
        );

        // Разбор тегированного пространства: ядро -> теги -> дроп.
        facade.unmap_kernel_regions().unwrap();
        assert_eq!(
            facade.mmap_interface.invalidate_log,
            vec![TlbOp::Context(pair.user()), TlbOp::Pair(pair),],
            "разбор ядра гасит оба тега пары"
        );
        facade.release_asid(pool).unwrap();
        assert_eq!(facade.asid_pair(), None, "пара возвращена пулу");
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.freed(), 1);

        // Повторный release_asid — no-op.
        facade.release_asid(pool).unwrap();
        assert_eq!(pool.freed(), 1);

        drop(facade);
        assert_eq!(p_free(&p_alloc), FRAMES, "фреймы вернулись полностью");
    }

    #[test]
    fn pcid_create_without_pool_rejects() {
        let p_alloc = make_p_allocator();
        let mut mgr = MemoryManager::<MockMmap, TestPool>::new(p_alloc).unwrap();
        mgr.install_kmap(test_kmap(IsolationPolicy::UserTableIsolation));
        // Пул НЕ зарегистрирован.

        // unwrap_err требует Debug у Ok-типа (SlabBox его не имеет) — match.
        let err = match mgr.create_ufacade_asid(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE)) {
            Err(e) => e,
            Ok(_) => panic!("без зарегистрированного пула создание обязано отказать"),
        };
        assert!(
            matches!(err, MemErrorCode::Asid(ASIDError::NotSupported)),
            "ожидался Asid(NotSupported), получено {err:?}"
        );
    }

    #[test]
    fn pcid_failure_rolls_back_pair_to_pool() {
        let p_alloc = make_p_allocator();
        let pool = static_pool();
        let mut mgr = MemoryManager::new(p_alloc.clone()).unwrap();
        mgr.install_kmap(test_kmap(IsolationPolicy::UserTableIsolation));
        mgr.install_asid_allocator(pool);

        // Отказ бекенда на трамплине: apply_kmap откатывает отображения,
        // менеджер возвращает пару пулу.
        let mut mmap = MockMmap::new();
        mmap.fail_map_kernel_name = Some("trampoline");
        mmap.kernel_log_tap = Some(Rc::new(RefCell::new(Vec::new())));

        // unwrap_err требует Debug у Ok-типа (SlabBox его не имеет) — match.
        let err = match mgr.create_ufacade_asid(mmap, FRAMES, 1, VirtualADDR(BASE)) {
            Err(e) => e,
            Ok(_) => panic!("отказ бекенда на трамплине обязан провалить создание"),
        };
        assert!(matches!(err, MemErrorCode::InternalError));

        // Пара НЕ утекла: пул вернулся к нулю live, free зафиксирован.
        assert_eq!(pool.live(), 0, "пара обязана вернуться пулу при отказе");
        assert_eq!(pool.freed(), 1);

        // Слоты фасадного slab-кэша не заняты (создание не состоялось).
        // Повторное создание succeeds: пул выдаёт новую пару.
        let facade = mgr
            .create_ufacade_asid(MockMmap::new(), FRAMES, 1, VirtualADDR(BASE))
            .unwrap();
        assert!(facade.asid_pair().is_some());
        assert_eq!(pool.live(), 1);
        assert_eq!(pool.freed(), 1, "новая пара, а не переиспользование");
    }

    #[test]
    fn pcid_assign_twice_rejected_and_release_error_propagates() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new_with_kernel_asid(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
            &test_kmap(IsolationPolicy::UserTableIsolation),
            AsidPair::new(AddressSpaceId(1), AddressSpaceId(2)),
        )
        .unwrap();

        // Повторное назначение пары живому фасаду — отказ (мок и фасад).
        let second = AsidPair::new(AddressSpaceId(3), AddressSpaceId(4));
        assert!(matches!(
            facade.assign_asid_pair(second),
            Err(MemErrorCode::InvalidArgument(_))
        ));

        // Отказ инвалидации TLB в release_asid — реальная ошибка, пара
        // НЕ возвращается пулу (инвалидация не выполнена).
        facade.mmap_interface.fail_invalidate = true;
        let pool = static_pool();
        let err = facade.release_asid(pool).unwrap_err();
        assert!(matches!(err, MemErrorCode::InternalError));
        assert!(facade.asid_pair().is_some(), "пара осталась за фасадом");
        assert_eq!(pool.freed(), 0, "free не вызван после отказа инвалидации");
    }

    /// v0.14: большие MEM_ALLOC (куча acpid) — запрос order 11 (2048 стр)
    /// через дефолтный класс фасада обязан проходить (класс запроса
    /// выбирается по ордеру, как в eval-хелперах llfree).
    #[test]
    fn alloc_large_order_class_selection() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            16384,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();
        let v = facade.alloc_region(2048, MMAPMemoryFlags::RW);
        assert!(v.is_ok(), "MEM_ALLOC(2048) отклонён: {v:?}");
        let v = v.unwrap();
        facade.shrink_memory_wiev(v).unwrap();

        // И обычные мелкие аллокации после большой — тоже работают.
        let small = facade.alloc_region(1, MMAPMemoryFlags::RW).unwrap();
        facade.shrink_memory_wiev(small).unwrap();
    }

    /// v0.14 (MMIO_MAP): цикл external map -> free -> map — путь acpid
    /// (acpi::Handler мапит таблицы поверх MMIO_MAP и снимает их при
    /// дропе PhysicalMapping; тысячи итераций за один перечисление).
    #[test]
    fn external_map_free_map_cycle() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Паттерн acpi-крейта (from_rsdt): заголовок таблицы И затем
        // ПОЛНАЯ таблица по ОДНОМУ адресу — обе живы ОДНОВРЕМЕННО
        // (перекрывающиеся мапинги одной физики — легальны, v0.14).
        let hdr = facade
            .map_external(PhysADDR(0x1FB7_D000), 1, MMAPMemoryFlags::RW)
            .unwrap();
        let full = facade
            .map_external(PhysADDR(0x1FB7_D000), 1, MMAPMemoryFlags::RW)
            .expect("повторный map той же физики обязан работать");
        assert_ne!(hdr.0, full.0, "разные записи — разные vaddr");
        facade.shrink_memory_wiev(full).unwrap();
        facade.shrink_memory_wiev(hdr).unwrap();

        // Первая таблица (RSDP-страница): map -> byte-точный доступ.
        let v1 = facade
            .map_external(PhysADDR(0x1FB7_E000), 1, MMAPMemoryFlags::RW)
            .unwrap();
        // Снятие (как MEM_FREE: shrink по адресу региона).
        facade.shrink_memory_wiev(v1).unwrap();
        // Вторая таблица (XSDT-страница) — обязана мапиться после снятия.
        let v2 = facade.map_external(PhysADDR(0x1FB7_D000), 1, MMAPMemoryFlags::RW);
        assert!(v2.is_ok(), "map после free отклонён: {v2:?}");
        facade.shrink_memory_wiev(v2.unwrap()).unwrap();

        // Стресс-цикл: 100 итераций map/free (AML-обход дропает mappings
        // пакетами; переиспользование дыры vaddr — обязательное свойство).
        for i in 0..100usize {
            let v = facade
                .map_external(PhysADDR(0x1000 * (i + 1)), 1, MMAPMemoryFlags::RW)
                .expect("map в цикле");
            facade.shrink_memory_wiev(v).unwrap();
        }
        assert_eq!(facade.records_by_vaddr.iter().count(), 0);
    }

    /// Двойной индекс: устойчивость вставки/снятия записей в обоих деревьях
    /// после циклов extend/shrink (порядок ключей физики и виртуалки может
    /// расходиться — индексы обязаны оставаться согласованными).
    #[test]
    fn dual_index_stays_consistent_across_cycles() {
        let p_alloc = make_p_allocator();
        let mut facade = UFacade::new(
            p_alloc.clone(),
            MockMmap::new(),
            FRAMES,
            1,
            VirtualADDR(BASE),
        )
        .unwrap();

        // Три региона разных ордеров: 1, 3, 8 страниц (фреймы 0 / 4 / 8).
        for pages in [1usize, 3, 8] {
            facade
                .extend_memory_wiev(pages, MMAPMemoryFlags::RW)
                .unwrap();
        }

        // Снятие среднего региона по внутреннему адресу (не база!):
        // проверка lower_bound + move_prev пути vaddr-индекса.
        facade
            .shrink_memory_wiev(VirtualADDR(BASE + 5 * FRAME_SIZE))
            .unwrap();
        assert_eq!(facade.records_by_vaddr.iter().count(), 2);
        assert_eq!(
            facade.records_by_paddr.iter().count(),
            2,
            "индексы синхронны"
        );

        // Повторное расширение тем же размером: vaddr переиспользует дыру,
        // физика может быть другой — оба индекса обязаны сойтись.
        facade.extend_memory_wiev(3, MMAPMemoryFlags::RW).unwrap();
        assert_eq!(facade.records_by_vaddr.iter().count(), 3);
        assert_eq!(facade.records_by_paddr.iter().count(), 3);

        // Поиск по базе и по внутренним адресам всех регионов. Внутренний
        // адрес проверяем только у мультистраничных: одностраничный регион
        // выравниванием ордера окружён дырами (3 стр -> ордер 2 -> 4 фрейма).
        let spans: Vec<(usize, usize)> = facade
            .records_by_vaddr
            .iter()
            .map(|r| (r.v_addr.0, r.p_addr.pages_count))
            .collect();
        for (base, pages) in &spans {
            assert!(
                facade.snapshot_by_vaddr(VirtualADDR(*base)).is_some(),
                "поиск по базе {base:#x}"
            );
            if *pages > 1 {
                assert!(
                    facade
                        .snapshot_by_vaddr(VirtualADDR(base + FRAME_SIZE))
                        .is_some(),
                    "поиск по внутреннему адресу {base:#x}+1p (страниц {})",
                    pages
                );
            }
        }

        // Промах: адрес до всех регионов (дыра выравнивания ордера у
        // первого одностраничного региона — фреймы 1..3 свободны).
        assert!(
            facade
                .snapshot_by_vaddr(VirtualADDR(BASE + FRAME_SIZE))
                .is_none()
        );

        // Полное сжатие всех регионов: оба индекса пусты, дроп чист.
        for (base, _) in &spans {
            facade.shrink_memory_wiev(VirtualADDR(*base)).unwrap();
        }
        assert_eq!(facade.records_by_vaddr.iter().count(), 0);
        assert_eq!(facade.records_by_paddr.iter().count(), 0);
        assert_eq!(p_free(&p_alloc), FRAMES);
    }
}
