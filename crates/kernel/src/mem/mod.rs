use alloc::collections::BTreeMap;
use attachable_slab_allocator::{SlabBox, SlabCache, locks::SpinLock};
use core::cell::{RefCell, UnsafeCell};
use heapless::{arc_pool, pool::arc::ArcPool};
use llfree::LLFree;
use spin::{LazyLock, Once};

/// Владеющий `Arc` и `ArcBlock` из heapless-пула (общие типы физического
/// аллокатора у всех фасадов крейта; ре-экспорт, чтобы внешнему коду
/// не тянуть heapless напрямую).
pub use heapless::pool::arc::{Arc, ArcBlock};

use crate::{
    hal::traits::asid::{ASIDInterface, AsidAllocator},
    hal::traits::kmap::{IsolationPolicy, KMAPInterface},
    hal::traits::mmap::{MMAPInterface, MMAPMemoryFlags, MemErrorCode, PhysADDR, VirtualADDR},
    mem::kmap::KMap,
};

/// Ре-экспорт фасада адресного пространства: стартовая последовательность
/// и платформы работают с фасадами через менеджер и по ссылке.
pub use ufacade::UFacade;

/// Боевая обвязка кучи ядра (talc поверх llfree) и `#[global_allocator]`.
///
/// Компилируется только в no_std-сборке ядра: llfree требует зарезервированную
/// область памяти, инициализируемую платформенным кодом до первой аллокации.
/// На host-сборках (cargo test, фича `host-hooks`) глобальный аллокатор —
/// системный (std), а slab-хуки определяет `capability::mem` — иначе тестовый
/// бинарник падает до входа в тесты («memory allocation failed»: talc не
/// способен выдать память без поднятого llfree).
#[cfg(not(any(test, feature = "host-hooks")))]
pub mod gallocator;
pub mod kmap;
pub mod ufacade;

pub trait UnnamedUPage {
    /// Расширить представление памяти фасада на `size_count` страниц.
    ///
    /// Slab-кэш записей — внутренность фасада (см. [`UFacade`]): вызывающий
    /// больше не поставляет его — записи адресного пространства аллоцируются
    /// в собственном кэше фасада (изоляция + локальность).
    fn extend_memory_wiev(
        &mut self,
        size_count: usize,
        mp: MMAPMemoryFlags,
    ) -> Result<(), MemErrorCode>;

    fn shrink_memory_wiev(&mut self, v_addr: VirtualADDR) -> Result<(), MemErrorCode>;
}

arc_pool!(  ARCPool   : LLFree<'static>);

// ==== Роутер памяти: доступ подсистем к фасадам задач ====

/// Типизированный доступ подсистем (сисколы памяти, IPC map/grant-элементы,
/// SHM) к адресному пространству задачи — type-erased, чтобы syscall-слой
/// (не знающий параметра MMAP платформы) мог работать с памятью.
///
/// Реализуется над [`MemoryManager`] владельцем ядра (GCTL), который знает
/// конкретный `MMAP`; адрес выбирает фасад задачи (аллокатор виртуального
/// диапазона) — окно flexpage получателя — подсказка.
pub trait MemRouter {
    /// Выделить задаче регион (физика из пула + отображение);
    /// возвращает виртуальный адрес (сискол mem_alloc).
    fn alloc_region(
        &self,
        task: crate::task::TaskId,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode>;

    /// Снять регион задачи по адресу (сискол mem_free; внешний/собственный
    /// учёт кадров — на фасаде).
    fn free_region(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Result<(), MemErrorCode>;

    /// Отобразить внешние кадры (SHM/BAR) в пространство задачи.
    fn map_external(
        &self,
        task: crate::task::TaskId,
        paddr: PhysADDR,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode>;

    /// (База виртуальная, база физики, страниц) региона, содержащего адрес
    /// (map-элементы IPC: окно flexpage может начинаться внутри региона).
    fn region_at(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Option<(VirtualADDR, PhysADDR, usize)>;

    /// Flexpage-перенос (IPC map/grant-элемент): окно `src_vaddr` (страниц)
    /// задачи `src` отобразить в задачу `dst`. `grant = true` — с передачей
    /// владения (у источника окно снимается). Возвращает адрес в `dst`.
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self,
        dst: crate::task::TaskId,
        dst_hint: usize,
        src: crate::task::TaskId,
        src_vaddr: usize,
        pages: usize,
        grant: bool,
        flags: MMAPMemoryFlags,
    ) -> Result<usize, MemErrorCode>;
}

struct APXCTL(UnsafeCell<ArcBlock<LLFree<'static>>>);

unsafe impl Send for APXCTL {}
unsafe impl Sync for APXCTL {}

static ALLOCATOR_OBJ: LazyLock<APXCTL> = LazyLock::new(|| APXCTL(UnsafeCell::new(ArcBlock::new())));

/// Кеш одноразовой установки глобального физического аллокатора
/// (см. [`install_p_allocator`]).
static P_ALLOCATOR: Once<Arc<ARCPool>> = Once::new();

/// Размер slab-а под объекты фасадов (`MemoryManager`). Степень двойки —
/// требование attachable-slab-allocator.
pub const FACADE_SLAB_SIZE: usize = 4096;

/// Владеющий указатель на фасад в slab-кэше менеджера.
///
/// Полный аналог `Box<UFacade>`: дроп выполняет `UFacade::drop`
/// (освобождение записей) и возвращает слот в кэш, поэтому отдельного
/// метода `destroy` не нужно.
pub type FacadeBox<MmapWraper, AP> = SlabBox<UFacade<MmapWraper, AP>, SpinLock, FACADE_SLAB_SIZE>;

/// Одноразовая установка глобального физического аллокатора.
///
/// Первый вызов инициализирует статический блок ALLOCATOR_OBJ, передаёт
/// его пулу [`ARCPool`] и помещает в блок `p_allocator`; возвращает владеющий
/// `Arc<ARCPool>` — готовый аргумент для [`MemoryManager::new`].
/// Повторные вызовы игнорируют аргумент и возвращают тот же `Arc`
/// (повторная выдача того же блока пулу недопустима).
pub fn install_p_allocator(p_allocator: LLFree<'static>) -> Arc<ARCPool> {
    P_ALLOCATOR
        .call_once(|| {
            // Инициализируем глобальный блок (первое обращение к LazyLock).
            LazyLock::force(&ALLOCATOR_OBJ);

            // SAFETY: блок инициализирован `force` выше; единственный путь к
            // `ALLOCATOR_OBJ` — эта функция, исполняемая ровно один раз
            // (spin::Once), поэтому живых заимствований внутренности нет и
            // эксклюзивный доступ через UnsafeCell легален. Блок лежит в
            // статике, ссылка корректна `'static`; после `manage` владение
            // переходит пулу и больше никто к блоку не обращается.
            let block: &'static mut ArcBlock<LLFree<'static>> =
                unsafe { &mut *LazyLock::force(&ALLOCATOR_OBJ).0.get() };
            ARCPool.manage(block);

            // Блок только что передан пулу — свободный блок гарантированно
            // есть, аллокация обязана пройти.
            match ARCPool.alloc(p_allocator) {
                Ok(arc) => arc,
                Err(_) => unreachable!("ARCPool: блок только что был передан пулу"),
            }
        })
        .clone()
}

pub struct MemoryManager<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> {
    p_allocator: Arc<AP>,
    allocator: SlabCache<UFacade<MmapWraper, AP>, SpinLock, FACADE_SLAB_SIZE>,
    /// Таблица адресного пространства ядра (KMAP) с политикой изоляции.
    /// Влияет только на фасады, созданные после установки (`create_ufacade`):
    /// каждый новый UMAP получает из неё ядро ОС с учётом Meltdown/Spectre.
    kmap: KMap,
    /// Пул тегов ASID/PCID для тегированных фасадов (KPTI без сброса TLB).
    ///
    /// `None` (дефолт) — платформа не регистрировала пул: тегированные пути
    /// ([`Self::create_ufacade_asid`]) отказывают, нетегированные работают
    /// как раньше. Пул — `&'static dyn` (глобальный сервис, как планировщик
    /// у `TcbManager`): время жизни ≥ времени жизни менеджера.
    asid_allocator: Option<&'static dyn AsidAllocator>,
    /// Привязка задача -> фасад: адрес slab-слота (стабилен, пока жив бокс).
    /// Платформа регистрирует фасад после `create_ufacade*`
    /// ([`Self::bind_facade`]) и снимает ДО дропа бокса
    /// ([`Self::unbind_facade`]) — сисколы памяти и IPC-элементы идут через
    /// [`Self::with_facade`] (интерьерный мутабельный доступ по сырой
    /// ссылке; однопоточный контракт крейта — тот же рефлекс, что
    /// UnsafeRef в интрузивных контейнерах).
    facades: RefCell<BTreeMap<crate::task::TaskId, *mut UFacade<MmapWraper, AP>>>,
}

impl<MmapWraper: MMAPInterface, AP: ArcPool<Data = LLFree<'static>>> MemoryManager<MmapWraper, AP> {
    /// Создаёт менеджер поверх разделяемого физического аллокатора.
    ///
    /// `p_allocator` — владеющий `Arc` на пул-аллоцированный `LLFree`
    /// (например, из [`install_p_allocator`]): один и тот же аллокатор
    /// разделяется всеми созданными фасадами (каждый клонирует `Arc` в
    /// [`UFacade::new`]).
    pub fn new(p_allocator: Arc<AP>) -> Result<Self, MemErrorCode> {
        Ok(Self {
            p_allocator,
            allocator: SlabCache::new().map_err(MemErrorCode::SlabError)?,
            // Безопасный дефолт: KPTI-изоляция включена, таблица пуста.
            // Пока платформа не докажет обратное (см. IsolationPolicy),
            // крейт не доверяет железу.
            kmap: KMap::new(IsolationPolicy::conservative()),
            asid_allocator: None,
            facades: RefCell::new(BTreeMap::new()),
        })
    }

    // ==== Привязка задача -> фасад (сисколы памяти / IPC map-элементы) ====

    /// Зарегистрировать фасад задачи (адрес slab-слота стабилен, пока жив
    /// `FacadeBox`). Повторная привязка задачи перезаписывает прошлую —
    /// платформа отвечает за непересечение времени жизни боксов.
    pub fn bind_facade(&self, task: crate::task::TaskId, facade: &FacadeBox<MmapWraper, AP>) {
        self.facades
            .borrow_mut()
            .insert(task, facade.as_ptr() as *mut UFacade<MmapWraper, AP>);
    }

    /// Снять привязку (ОБЯЗАТЕЛЬНО до дропа фасадного бокса).
    /// Возвращает, была ли привязка.
    pub fn unbind_facade(&self, task: &crate::task::TaskId) -> bool {
        self.facades.borrow_mut().remove(task).is_some()
    }

    /// Фасад привязан? (аудит/тесты).
    pub fn has_facade(&self, task: &crate::task::TaskId) -> bool {
        self.facades.borrow().contains_key(task)
    }

    /// Доступ к фасаду задачи для изменения (сисколы памяти, IPC-элементы).
    /// `None` — задача без фасада (не регистрировала или уже сняла).
    ///
    /// SAFETY-контракт: живость указателя гарантирует парой
    /// `bind_facade`/`unbind_facade` (платформа обязана снять привязку до
    /// дропа бокса); однопоточный контракт крейта делает мутабельный доступ
    /// по сырой ссылке корректным.
    pub fn with_facade<R>(
        &self,
        task: &crate::task::TaskId,
        f: impl FnOnce(&mut UFacade<MmapWraper, AP>) -> R,
    ) -> Option<R> {
        let ptr = *self.facades.borrow().get(task)?;
        // SAFETY: контракт bind/unbind + однопоточность.
        Some(f(unsafe { &mut *ptr }))
    }

    /// Число привязанных фасадов (аудит).
    pub fn bound_facade_count(&self) -> usize {
        self.facades.borrow().len()
    }

    /// Зарегистрировать пул тегов ASID/PCID (только один раз, как
    /// `install_p_allocator`): включает тегированные фасады.
    ///
    /// Повторная регистрация игнорируется (пул — глобальный сервис; менять
    /// его на живую нельзя: выданные пары потеряли бы владельца).
    pub fn install_asid_allocator(&mut self, allocator: &'static dyn AsidAllocator) {
        if self.asid_allocator.is_none() {
            self.asid_allocator = Some(allocator);
        }
    }

    /// Зарегистрированный пул тегов (аудит/тесты).
    pub fn asid_allocator(&self) -> Option<&'static dyn AsidAllocator> {
        self.asid_allocator
    }

    /// Разделяемый физический аллокатор (для собственных отображений ядра).
    pub fn p_allocator(&self) -> &Arc<AP> {
        &self.p_allocator
    }

    /// Таблица адресного пространства ядра (KMAP) — только чтение.
    /// Наполнение — платформенным кодом до/независимо от создания фасадов.
    pub fn kmap(&self) -> &KMap {
        &self.kmap
    }

    /// Установить KMAP (таблицу ядра) для последующих `create_ufacade`.
    ///
    /// Заменяет и таблицу, и политику изоляции целиком. Уже созданные
    /// фасады не пересматриваются (их отображения ядра — их собственные);
    /// см. [`UFacade::unmap_kernel_regions`] для явного разбора.
    pub fn install_kmap(&mut self, kmap: KMap) {
        self.kmap = kmap;
    }

    /// Создаёт UMAP-фасад с отображённым ядром ОС (учёт Meltdown/Spectre).
    ///
    /// Отличие от [`MemoryManager::create_facade`]: в пользовательскую
    /// таблицу страниц фасада переносится ядро — по KMAP менеджера и его
    /// политике изоляции: при KPTI — только трамплин входа и
    /// пользовательские разделяемые страницы, на здоровом железе — полное
    /// supervisor-only ядро. Пользовательский диапазон фасада обязан не
    /// пересекаться с регионами ядра (`Err(AlreadyMapped)`).
    ///
    /// Требует от бекенда поддержки [`KMAPInterface`] (arch-реализация);
    /// обычный `create_facade` остаётся доступен бекендам без KMAP.
    pub fn create_ufacade(
        &mut self,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
    ) -> Result<FacadeBox<MmapWraper, AP>, MemErrorCode>
    where
        MmapWraper: KMAPInterface,
    {
        let facade = UFacade::new_with_kernel(
            self.p_allocator.clone(),
            mmap_interface,
            pages_count,
            cpu_count,
            allocation_base,
            &self.kmap,
        )?;
        self.write_facade_slot(facade)
    }

    /// Создаёт тегированный UMAP-фасад: ядро по KMAP + пара тегов ASID/PCID
    /// из зарегистрированного пула (см. [`Self::install_asid_allocator`]).
    ///
    /// Отличие от [`MemoryManager::create_ufacade`]: адресное пространство
    /// получает пару тегов ДО отображения ядерных регионов, и переключение
    /// таблиц на границе режимов (syscall entry/exit, диспетчеризация)
    /// выполняется тегированно — без сброса TLB
    /// (`crate::hal::traits::asid::FlushMode::NoFlush`).
    /// Требует от бекенда [`ASIDInterface`] поверх [`KMAPInterface`].
    ///
    /// Разбор тегированного фасада (контракт `UFacade::release_asid`):
    /// `unmap_kernel_regions` -> `release_asid` -> дроп бокса.
    ///
    /// Отказы: пул не зарегистрирован / исчерпан — [`MemErrorCode::Asid`];
    /// пересечение с ядром и отказы бекенда — как у `create_ufacade`;
    /// при любом отказе пара тегов возвращается пулу (откат).
    pub fn create_ufacade_asid(
        &mut self,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
    ) -> Result<FacadeBox<MmapWraper, AP>, MemErrorCode>
    where
        MmapWraper: KMAPInterface + ASIDInterface,
    {
        let asid_allocator = self.asid_allocator.ok_or(MemErrorCode::Asid(
            crate::hal::traits::asid::ASIDError::NotSupported,
        ))?;
        // Пара тегов: при любом отказе ниже возвращается пулу (владение
        // парой ещё не передано фасаду — это обязанность вызывающего).
        let pair = asid_allocator.alloc_pair()?;

        match UFacade::new_with_kernel_asid(
            self.p_allocator.clone(),
            mmap_interface,
            pages_count,
            cpu_count,
            allocation_base,
            &self.kmap,
            pair,
        ) {
            Ok(facade) => self.write_facade_slot(facade),
            Err(e) => {
                // Откат: пара не у дел — вернуть пулу. TLB пары чист
                // (отображения откатил apply_kmap внутри конструктора).
                asid_allocator.free_pair(pair);
                Err(e)
            }
        }
    }

    /// Создаёт новый фасад в slab-кэше менеджера и возвращает владеющий
    /// бокс на него.
    ///
    /// Владение передаётся вызывающему: дроп [`FacadeBox`] уничтожает фасад
    /// (освобождая его записи) и возвращает слот в кэш — отдельного
    /// `destroy` не предусмотрено.
    ///
    /// Параметры `pages_count` / `cpu_count` / `allocation_base` описывают
    /// виртуальный диапазон, которым управляет фасад (см. [`UFacade::new`]).
    pub fn create_facade(
        &mut self,
        mmap_interface: MmapWraper,
        pages_count: usize,
        cpu_count: usize,
        allocation_base: VirtualADDR,
    ) -> Result<FacadeBox<MmapWraper, AP>, MemErrorCode> {
        let facade = UFacade::new(
            self.p_allocator.clone(),
            mmap_interface,
            pages_count,
            cpu_count,
            allocation_base,
        )?;
        self.write_facade_slot(facade)
    }

    /// Пишет фасад в слот slab-кэша менеджера (общий хвост `create_*`).
    fn write_facade_slot(
        &mut self,
        facade: UFacade<MmapWraper, AP>,
    ) -> Result<FacadeBox<MmapWraper, AP>, MemErrorCode> {
        // Слот из кэша неинициализирован: инициализируем записью значения,
        // после чего бокс становится его единственным владельцем (дроп бокса
        // выполнит `drop_in_place::<UFacade>` и вернёт слот в кэш).
        let slot = self.allocator.alloc()?; // SlabError -> MemErrorCode (#[from])
        // SAFETY: `SlabCache::alloc` отдаёт неинициализированную память;
        // значение записывается здесь же, до любого разыменования бокса.
        unsafe { core::ptr::write(slot.as_ptr(), facade) };
        Ok(slot)
    }
}

// ==== Реализация роутера над менеджером (GCTL отдаёт её сискол-слою) ====

/// `MemRouter` поверх [`MemoryManager`]: все операции — через привязку
/// задача -> фасад ([`MemoryManager::bind_facade`]).
pub struct MemRouterImpl<'a, MMAP: MMAPInterface> {
    mm: &'a MemoryManager<MMAP, ARCPool>,
}

impl<'a, MMAP: MMAPInterface> MemRouterImpl<'a, MMAP> {
    pub fn new(mm: &'a MemoryManager<MMAP, ARCPool>) -> Self {
        Self { mm }
    }

    /// (v_base, p_base, pages) региона, содержащего адрес (приватный
    /// помощник transfer: фасад отдаёт полное окно региона).
    fn region_info(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Option<(VirtualADDR, PhysADDR, usize)> {
        self.mm
            .with_facade(&task, |f| f.region_window(vaddr))
            .flatten()
    }
}

impl<MMAP: MMAPInterface> MemRouter for MemRouterImpl<'_, MMAP> {
    fn alloc_region(
        &self,
        task: crate::task::TaskId,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode> {
        self.mm
            .with_facade(&task, |f| f.alloc_region(pages, flags))
            .unwrap_or(Err(MemErrorCode::NotFound))
    }

    fn free_region(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Result<(), MemErrorCode> {
        self.mm
            .with_facade(&task, |f| UnnamedUPage::shrink_memory_wiev(f, vaddr))
            .unwrap_or(Err(MemErrorCode::NotFound))
    }

    fn map_external(
        &self,
        task: crate::task::TaskId,
        paddr: PhysADDR,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<VirtualADDR, MemErrorCode> {
        self.mm
            .with_facade(&task, |f| f.map_external(paddr, pages, flags))
            .unwrap_or(Err(MemErrorCode::NotFound))
    }

    fn region_at(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Option<(VirtualADDR, PhysADDR, usize)> {
        self.region_info(task, vaddr)
    }

    fn transfer(
        &self,
        dst: crate::task::TaskId,
        _dst_hint: usize,
        src: crate::task::TaskId,
        src_vaddr: usize,
        pages: usize,
        grant: bool,
        flags: MMAPMemoryFlags,
    ) -> Result<usize, MemErrorCode> {
        if pages == 0 {
            return Err(MemErrorCode::InvalidArgument("pages must be > 0"));
        }
        // 1. Регион источника: (v_base, p_base, region_pages).
        let (v_base, p_base, region_pages) = self
            .region_info(src, VirtualADDR(src_vaddr))
            .ok_or(MemErrorCode::NotFound)?;
        let page_off = (src_vaddr - v_base.0) / crate::hal::traits::mmap::PAGE_SIZE;
        if src_vaddr < v_base.0 || page_off + pages > region_pages {
            return Err(MemErrorCode::InvalidArgument(
                "flexpage window exceeds source region",
            ));
        }
        let window_paddr = PhysADDR(p_base.0 + page_off * crate::hal::traits::mmap::PAGE_SIZE);

        // 2. Grant — только целым регионом (владение кадрами неделимо).
        if grant && (page_off != 0 || pages != region_pages) {
            return Err(MemErrorCode::InvalidArgument(
                "grant requires the whole source region",
            ));
        }

        // 3. Отображение у получателя (внешние кадры; у источника остаются).
        let dst_vaddr = self.map_external(dst, window_paddr, pages, flags)?;

        // 4. Grant: окно у источника снимается без возврата кадров пулу.
        if grant {
            self.mm
                .with_facade(&src, |f| f.detach_region(v_base))
                .unwrap_or(Err(MemErrorCode::NotFound))?;
        }
        Ok(dst_vaddr.0)
    }
}
