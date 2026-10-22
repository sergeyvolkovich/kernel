use alloc::collections::BTreeMap;
use attachable_slab_allocator::{SlabBox, SlabCache, locks::SpinLock};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::sync::KSpin;
use heapless::{arc_pool, pool::arc::ArcPool};
use llfree::LLFree;
use spin::{LazyLock, Mutex, Once};

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

    /// Сменить права доступа отображённых страниц задачи (v0.17,
    /// MEM_PROTECT): окно [vaddr, vaddr+pages*4K) в ОДНОМ регионе
    /// (правило flexpage-окон); затрагивается только пространство
    /// САМОЙ задачи (SHM-кадры у других задач — их право).
    fn protect_region(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<(), MemErrorCode>;

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

    /// Отобразить внешние кадры (окно региона задачи `src`) в пространство
    /// задачи `dst` по ФИКСИРОВАННОМУ адресу (spawn-протокол v0.9:
    /// MEM_MAP_AT — родитель кладёт ELF-сегменты/стек/argv ребёнка).
    /// Кадры остаются собственностью источника (запись `external = true`
    /// у получателя: смерть цели их НЕ возвращает пулу).
    /// Возврат: `dst_vaddr` (тот же, что запросили).
    fn map_external_at(
        &self,
        dst: crate::task::TaskId,
        src: crate::task::TaskId,
        src_vaddr: usize,
        dst_vaddr: usize,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<usize, MemErrorCode>;
}

// ==== Фабрика адресных пространств (v0.9) ====

/// Создание/разрушение пользовательских адресных пространств в рантайме
/// (TASK_CREATE порождает домен СО пространством; смерть домена —
/// разрушение пространства).
///
/// Тип-стёртый сервисный контракт (как [`MemRouter`]): syscall-слой не
/// знает параметр MMAP платформы. Реализует startup-обёртка над GCTL
/// (геометрия окна/стек — политика платформы). Отсутствие фабрики —
/// TASK_CREATE создаёт «голый» домен без пространства (совместимость).
pub trait SpaceFactory {
    /// Создать и привязать пространство задачи. Идемпотентность НЕ
    /// гарантируется: повторный вызов для живой задачи — ошибка
    /// `AlreadyMapped`-класса на усмотрение реализации.
    fn create_space(&self, task: crate::task::TaskId) -> Result<(), MemErrorCode>;

    /// Разрушить пространство задачи (unbind + дроп фасада; записи с
    /// `external = false` возвращают кадры пулу). Кос TASK_CREATE не
    /// вызывает. Инициализационные пространства (kinit) могут быть
    /// «вечными» — их разрушение возвращает ошибку.
    fn destroy_space(&self, task: crate::task::TaskId) -> Result<(), MemErrorCode>;
}

// ==== Чтение памяти задач из ядра (v0.9) ====

/// Канал «ядро читает память задачи» (copyin-примитив без промотирования
/// страниц ядра): физика региона — через [`MemRouter`], байты — через
/// direct-map платформы. Единственный на сегодня пользователь —
/// TASK_SPAWN_IMAGE (чтение спавн-дескриптора из памяти родителя);
/// будущие протоколы (серверы конфигурации, copyout) — тот же контракт.
///
/// Отсутствие сервиса — сисколы, требующие чтения памяти пользователя,
/// отвечают ENOSYS (платформа без direct-map — совместимость).
pub trait UserCopy {
    /// Прочитать `out.len()` байт задачи `task` по адресу `vaddr`.
    /// Отказ — адрес вне регионов задачи ИЛИ окно выходит за регион
    /// (дескриптор не может «читать за» отведённую страницу).
    fn read_task_bytes(
        &self,
        task: crate::task::TaskId,
        vaddr: usize,
        out: &mut [u8],
    ) -> Result<(), MemErrorCode>;
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
    /// Слот-кэш фасадов. Mutex — интерьерная мутабельность: РАНТАЙМ-пути
    /// (v0.9 `create_task_space` из syscall-контекста через &self)
    /// берут lock; пути с &mut self (kinit/тесты) — `get_mut` без лока.
    allocator: spin::Mutex<SlabCache<UFacade<MmapWraper, AP>, SpinLock, FACADE_SLAB_SIZE>>,
    /// Таблица адресного пространства ядра (KMAP) с политикой изоляции.
    /// Влияет только на фасады, созданные после установки (`create_ufacade`):
    /// каждый новый UMAP получает из неё ядро ОС с учётом Meltdown/Spectre.
    kmap: KMap,
    /// Пул тегов ASID/PCID для тегированных фасадов (KPTI без сброса TLB).
    ///
    /// `None` (дефолт) — платформа не регистрировала пул: тегированные фасады
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
    facades: KSpin<BTreeMap<crate::task::TaskId, *mut UFacade<MmapWraper, AP>>>,
    /// Рантайм-фасады v0.9 (владение менеджером): TASK_CREATE-порождённые
    /// пространства. Фасад инициализации (kinit/платформа) здесь НЕ лежит
    /// — он «вечный» (leak), разрушение — платформенная ответственность.
    owned: KSpin<BTreeMap<crate::task::TaskId, FacadeBox<MmapWraper, AP>>>,
    /// SMP v0.12: лок операций фасадов (ранг KMEM — лист; см. `sync`).
    /// Сериализует [`Self::with_facade`] и все изменения таблиц привязок:
    /// два потока одного домена не получают параллельный `&mut UFacade`,
    /// многошаговые операции роутера (`transfer`/`map_external_at`) держат
    /// его ОТ начала до конца (TOCTOU физики региона закрыт). Единственный
    /// ядровый лок, под которым ядро ждёт cross-CPU (TLB shootdown ACK):
    /// его ожидатели всегда на «глубине 0» — ACK доставляется в спине.
    ops: KSpin<()>,
    /// Геометрия рантайм-пространств (копится с первого `configure_spaces`):
    /// окно фасада (страниц) + базы. Политика платформы, устанавливается
    /// startup-кодом ДО первого TASK_CREATE (SMP v0.12: атомики).
    runtime_window_pages: AtomicUsize,
    runtime_cpu_count: AtomicUsize,
    runtime_base: AtomicUsize,
    runtime_geometry_set: AtomicBool,
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
            allocator: Mutex::new(SlabCache::new().map_err(MemErrorCode::SlabError)?),
            // Безопасный дефолт: KPTI-изоляция включена, таблица пуста.
            // Пока платформа не докажет обратное (см. IsolationPolicy),
            // крейт не доверяет железу.
            kmap: KMap::new(IsolationPolicy::conservative()),
            asid_allocator: None,
            facades: KSpin::new(BTreeMap::new()),
            owned: KSpin::new(BTreeMap::new()),
            ops: KSpin::new(()),
            runtime_window_pages: AtomicUsize::new(0),
            runtime_cpu_count: AtomicUsize::new(1),
            runtime_base: AtomicUsize::new(0),
            runtime_geometry_set: AtomicBool::new(false),
        })
    }

    // ==== Привязка задача -> фасад (сисколы памяти / IPC map-элементы) ====

    /// Зарегистрировать фасад задачи (адрес slab-слота стабилен, пока жив
    /// `FacadeBox`). Повторная привязка задачи перезаписывает прошлую —
    /// платформа отвечает за непересечение времени жизни боксов.
    pub fn bind_facade(&self, task: crate::task::TaskId, facade: &FacadeBox<MmapWraper, AP>) {
        let _ops = self.ops.lock();
        self.facades
            .lock()
            .insert(task, facade.as_ptr() as *mut UFacade<MmapWraper, AP>);
    }

    /// Снять привязку (ОБЯЗАТЕЛЬНО до дропа фасадного бокса).
    /// Возвращает, была ли привязка.
    pub fn unbind_facade(&self, task: &crate::task::TaskId) -> bool {
        let _ops = self.ops.lock();
        self.facades.lock().remove(task).is_some()
    }

    /// Фасад привязан? (аудит/тесты).
    pub fn has_facade(&self, task: &crate::task::TaskId) -> bool {
        self.facades.lock().contains_key(task)
    }

    /// Доступ к фасаду задачи для изменения (сисколы памяти, IPC-элементы).
    /// `None` — задача без фасада (не регистрировала или уже сняла).
    ///
    /// SMP v0.12: операция исполняется под [`Self::ops`] (ранг KMEM —
    /// лист): параллельные `&mut UFacade` исключены, TLB shootdown
    /// внутри операции доставляет ACK ожидающим (глубина 0).
    ///
    /// SAFETY-контракт: живость указателя гарантирует парой
    /// `bind_facade`/`unbind_facade` (платформа обязана снять привязку до
    /// дропа бокса); эксклюзивность — лок `ops`.
    pub fn with_facade<R>(
        &self,
        task: &crate::task::TaskId,
        f: impl FnOnce(&mut UFacade<MmapWraper, AP>) -> R,
    ) -> Option<R> {
        let ops = self.ops.lock();
        self.with_facade_under(&ops, task, f)
    }

    /// То же под УЖЕ взятым ops-гардом (многошаговые операции роутера:
    /// `transfer`/`map_external_at` держат сериализацию от чтения физики
    /// региона до завершения отображения — TOCTOU кадров закрыт).
    pub(crate) fn with_facade_under<R>(
        &self,
        _ops: &crate::sync::KSpinGuard<'_, ()>,
        task: &crate::task::TaskId,
        f: impl FnOnce(&mut UFacade<MmapWraper, AP>) -> R,
    ) -> Option<R> {
        let ptr = *self.facades.lock().get(task)?;
        // SAFETY: контракт bind/unbind + ops-лок.
        Some(f(unsafe { &mut *ptr }))
    }

    /// Гард операций подсистемы памяти (транзакции роутера/спавна).
    /// Ранг KMEM — лист: под этим гардом ДРУГИЕ ядровые локи не берутся
    /// (кроме внутренних атомиков аллокаторов).
    pub(crate) fn ops_guard(&self) -> crate::sync::KSpinGuard<'_, ()> {
        self.ops.lock()
    }

    /// Число привязанных фасадов (аудит).
    pub fn bound_facade_count(&self) -> usize {
        self.facades.lock().len()
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
        // Mutex::get_mut: путь &mut self — без блокировки.
        let slot = self.allocator.get_mut().alloc()?; // SlabError -> MemErrorCode (#[from])
        // SAFETY: `SlabCache::alloc` отдаёт неинициализированную память;
        // значение записывается здесь же, до любого разыменования бокса.
        unsafe { core::ptr::write(slot.as_ptr(), facade) };
        Ok(slot)
    }

    // ==== Рантайм-пространства v0.9 (TASK_CREATE/смерть домена) ====

    /// Задать геометрию рантайм-пространств (политика платформы:
    /// окно фасада/число CPU/база — те же константы, что у фасада init).
    /// Вызывается startup-кодом один раз, ДО первого TASK_CREATE.
    pub fn configure_runtime_spaces(
        &self,
        window_pages: usize,
        cpu_count: usize,
        base: VirtualADDR,
    ) {
        self.runtime_window_pages
            .store(window_pages, Ordering::Relaxed);
        self.runtime_cpu_count.store(cpu_count, Ordering::Relaxed);
        self.runtime_base.store(base.0, Ordering::Relaxed);
        self.runtime_geometry_set.store(true, Ordering::Relaxed);
    }

    /// Создать адресное пространство задачи в РАНТАЙМЕ (через &self —
    /// интерьерная мутабельность: slab-кэш под Mutex, привязки под
    /// RefCell; однопоточный контракт крейта сохраняется).
    ///
    /// Владение фасадом переходит менеджеру (`owned`): при смерти домена
    /// [`Self::destroy_task_space`] дропает бокс — записи фасада с
    /// `external = false` возвращают кадры пулу, `external = true`
    /// (map_at-окна родителя) остаются за источником (L4 pager-модель).
    pub fn create_task_space(
        &self,
        task: crate::task::TaskId,
        mmap_interface: MmapWraper,
    ) -> Result<(), MemErrorCode>
    where
        MmapWraper: KMAPInterface,
    {
        if !self.runtime_geometry_set.load(Ordering::Relaxed) {
            return Err(MemErrorCode::InvalidArgument(
                "runtime space geometry is not configured",
            ));
        }
        if self.has_facade(&task) {
            return Err(MemErrorCode::AlreadyMapped);
        }
        let ops = self.ops.lock();
        let facade = UFacade::new_with_kernel(
            self.p_allocator.clone(),
            mmap_interface,
            self.runtime_window_pages.load(Ordering::Relaxed),
            self.runtime_cpu_count.load(Ordering::Relaxed),
            VirtualADDR(self.runtime_base.load(Ordering::Relaxed)),
            &self.kmap,
        )?;
        // Слот под Mutex (рантайм-путь): alloc() возвращает ВЛАДЕЮЩИЙ бокс
        // неинициализированного слота — та же схема, что write_facade_slot.
        let slot = self.allocator.lock().alloc()?;
        // SAFETY: слот неинициализирован; значение записывается здесь же,
        // до любого разыменования — контракт `SlabCache::alloc`.
        unsafe { core::ptr::write(slot.as_ptr(), facade) };
        // Привязка ДО помещения во владение: с этой точки сисколы
        // памяти задачи находят фасад; ошибка ниже откатит привязку.
        // Вся пара «привязка + владение» — под ops-гардом: параллельного
        // окна «фасад виден, но ещё не owned» не существует.
        let ptr = slot.as_ptr() as *mut UFacade<MmapWraper, AP>;
        self.facades.lock().insert(task, ptr);
        self.owned.lock().insert(task, slot);
        drop(ops);
        Ok(())
    }

    /// Разрушить рантайм-пространство задачи (unbind + дроп фасада;
    /// кадры owned-записей фасада вернутся пулу). Отказ — пространства
    /// нет ИЛИ оно не рантайм-ное (kinit-фасад «вечный»: владение не у
    /// менеджера).
    pub fn destroy_task_space(&self, task: &crate::task::TaskId) -> Result<(), MemErrorCode> {
        // ops держится ДО дропа бокса: пока фасад разрушается, никакой
        // параллельный with_facade не держит его по сырой ссылке.
        let ops = self.ops.lock();
        let removed = self.owned.lock().remove(task);
        match removed {
            Some(_box) => {
                // Сначала снятие привязки (контракт bind/unbind), затем
                // дроп бокса-владельца (порядок: пользователь уже мёртв,
                // сисколы этого фасада больше не приходят).
                self.facades.lock().remove(task);
                drop(_box);
                drop(ops);
                Ok(())
            }
            None => {
                drop(ops);
                Err(MemErrorCode::NotFound)
            }
        }
    }

    /// Число рантайм-пространств под владением менеджера (аудит).
    pub fn owned_space_count(&self) -> usize {
        self.owned.lock().len()
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

    /// Вариант `region_info` под УЖЕ взятым ops-гардом (многошаговые
    /// операции `transfer`/`map_external_at`: физика региона и её
    /// отображение — одна критсекция KMEM, TOCTOU кадров исключён).
    fn region_info_under(
        &self,
        ops: &crate::sync::KSpinGuard<'_, ()>,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
    ) -> Option<(VirtualADDR, PhysADDR, usize)> {
        self.mm
            .with_facade_under(ops, &task, |f| f.region_window(vaddr))
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

    fn protect_region(
        &self,
        task: crate::task::TaskId,
        vaddr: VirtualADDR,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<(), MemErrorCode> {
        self.mm
            .with_facade(&task, |f| f.protect_region(vaddr, pages, flags))
            .unwrap_or(Err(MemErrorCode::NotFound))
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
        // SMP v0.12: вся операция — под ОДНИМ ops-гардом (физика региона
        // не может уйти в пул между чтением и отображением).
        let ops = self.mm.ops_guard();
        // 1. Регион источника: (v_base, p_base, region_pages).
        let (v_base, p_base, region_pages) = self
            .region_info_under(&ops, src, VirtualADDR(src_vaddr))
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
        let dst_vaddr = self
            .mm
            .with_facade_under(&ops, &dst, |f| f.map_external(window_paddr, pages, flags))
            .unwrap_or(Err(MemErrorCode::NotFound))?;

        // 4. Grant: окно у источника снимается без возврата кадров пулу.
        if grant {
            self.mm
                .with_facade_under(&ops, &src, |f| f.detach_region(v_base))
                .unwrap_or(Err(MemErrorCode::NotFound))?;
        }
        Ok(dst_vaddr.0)
    }

    fn map_external_at(
        &self,
        dst: crate::task::TaskId,
        src: crate::task::TaskId,
        src_vaddr: usize,
        dst_vaddr: usize,
        pages: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<usize, MemErrorCode> {
        if pages == 0 {
            return Err(MemErrorCode::InvalidArgument("pages must be > 0"));
        }
        // SMP v0.12: физика региона и отображение — одна критсекция.
        let ops = self.mm.ops_guard();
        // 1. Физика источника: окно региона, содержащего src_vaddr
        //    (выравнивание вниз до база региона — как transfer).
        let (v_base, p_base, region_pages) = self
            .region_info_under(&ops, src, VirtualADDR(src_vaddr))
            .ok_or(MemErrorCode::NotFound)?;
        let page_off = (src_vaddr - v_base.0) / crate::hal::traits::mmap::PAGE_SIZE;
        if src_vaddr < v_base.0
            || page_off + pages > region_pages
            || (src_vaddr - v_base.0) % crate::hal::traits::mmap::PAGE_SIZE != 0
        {
            return Err(MemErrorCode::InvalidArgument(
                "map_at window exceeds source region",
            ));
        }
        let window_paddr = PhysADDR(p_base.0 + page_off * crate::hal::traits::mmap::PAGE_SIZE);
        // 2. Фиксированное отображение у получателя (external = true:
        //    кадры — собственность источника, смерть цели их не тронет).
        self.mm
            .with_facade_under(&ops, &dst, |f| {
                f.map_fixed(VirtualADDR(dst_vaddr), window_paddr, pages, flags, true)
            })
            .unwrap_or(Err(MemErrorCode::NotFound))?;
        Ok(dst_vaddr)
    }
}
