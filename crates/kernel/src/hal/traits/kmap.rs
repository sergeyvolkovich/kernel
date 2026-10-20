// ==== KMAP: словарь отображения ядра в пользовательские таблицы страниц ====
//
// Модуль содержит ТОЛЬКО словарь и контракт. Ни один тип здесь не знает о
// формате таблиц страниц, CR3/TTBR, битах PTE или порядке переключения
// адресных пространств — всё это архитектурный код ВНЕ крейта, реализующий
// [`KMAPInterface`] (по образцу `MMAPInterface` из `hal::traits::mmap`).
//
// Зачем это нужно. Meltdown (Rogue Data Cache Load) позволяет непривилегиро-
// ванному коду спекулятивно читать ядровые страницы, ЕСЛИ те отображены в
// пользовательскую таблицу страниц: при спекуляции arch-бэкенды исторически
// не проверяли привилегии на пути загрузки. Классический ответ — KPTI
// (Kernel Page Table Isolation): пользовательские таблицы почти не содержат
// ядра (только трамплин входа), полное отображение живёт в таблицах ядра,
// а на каждом входе/выходе происходит переключение таблиц. Если CPU не
// уязвим (например, выверен по RDCL_NO) или уязвимость закрыта иначе,
// KPTI можно не включать: полное supervisor-only ядро в каждой пользователь-
// ской таблице дешевле — нет перезагрузки TLB на границе режимов.
//
// Обе стратегии выражаются одной таблицей регионов ядра
// ([`crate::mem::kmap::KMap`]) и политикой [`IsolationPolicy`]:
//   - таблица описывает, ЧТО вообще существует в адресном пространстве ядра;
//   - политика решает, какая часть таблицы обязана попасть в каждую
//     пользовательскую таблицу страниц.
//
// Выбор конкретной политики — решение платформенного кода (проверка CPUID/
// MSR/спецификации CPU), крейт только исполняет её. Сознательно: эвристика
// «уязвим/не уязвим» — архитектурное знание, а здесь его место не в крейте.

use core::fmt;

use crate::hal::traits::mmap::{MMAPMemoryFlags, MemErrorCode, VirtualADDR};

// ───────────────────────────── Вид региона ─────────────────────────────

/// Роль региона ядра при отображении в пользовательские таблицы страниц.
///
/// Тип определяет судьбу региона при изоляции: `Kernel`-регионы при KPTI
/// наружу не выходят, `EntryTrampoline` и `UserShared` присутствуют в
/// пользовательских таблицах при любой политике.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelRegionKind {
    /// Обычные регионы ядра: .text/.rodata/.data, куча, physmap, MMIO.
    ///
    /// При [`IsolationPolicy::UserTableIsolation`] в пользовательские таблицы
    /// НЕ переносятся — только в таблицы ядра (бекенду они либо уже
    /// отображены, либо это не забота крейта).
    Kernel,

    /// Трамплин входа в ядро: arch-аналог syscall entry, векторов,
    /// cpu entry area — единственный код ядра, достижимый в user-таблице
    /// при KPTI (иначе после переключения на пользовательскую таблицу
    /// вход в ядро невозможен).
    ///
    /// Политика крейта запрещает WRITABLE у таких регионов: записываемый
    /// трамплин в пользовательской таблице обесценивает изоляцию (его
    /// содержимое — часть поверхности атаки Spectre-класса на входе в ядро).
    EntryTrampoline,

    /// Легитимно разделяемые с пользователем данные (vdso/vvar-аналоги).
    ///
    /// Отображаются при любой политике; права ПОЛЬЗОВАТЕЛЯ на эти страницы
    /// задаются флагами региона — это единственные user-доступные страницы
    /// из KMAP. Бекенд обязан ставить их без supervisor-only.
    UserShared,
}

impl fmt::Display for KernelRegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Kernel => "kernel",
            Self::EntryTrampoline => "entry-trampoline",
            Self::UserShared => "user-shared",
        };
        f.write_str(s)
    }
}

// ───────────────────────────── Политика изоляции ─────────────────────────────

/// Политика отображения ядра в пользовательские таблицы страниц.
///
/// Реакция на Meltdown/Spectre-класс уязвимостей на уровне компоновки
/// адресных пространств. Выбор политики делает платформенный код (он знает,
/// уязвим ли CPU); крейт гарантирует лишь соответствие содержимого
/// пользовательских таблиц выбранной стратегии.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IsolationPolicy {
    /// Полное ядро в каждой пользовательской таблице (supervisor-only).
    ///
    /// КОРРЕКТНО ТОЛЬКО если платформа гарантирует отсутствие
    /// Meltdown-класса уязвимостей (arch: RDCL_NO и родственные биты) либо
    /// они закрыты иными средствами — иначе это прямая дыра. Выигрыш: нет
    /// переключения таблиц и перезагрузки TLB на границе режимов.
    MapFullKernel,

    /// KPTI (Kernel Page Table Isolation): в пользовательских таблицах
    /// только [`KernelRegionKind::EntryTrampoline`] и
    /// [`KernelRegionKind::UserShared`]; полное ядро — только в таблицах
    /// ядра. Безопасный по умолчанию выбор.
    UserTableIsolation,
}

impl IsolationPolicy {
    /// Виден ли регион данного типа в пользовательской таблице при политике.
    #[inline]
    pub const fn visible_in_user_tables(self, kind: KernelRegionKind) -> bool {
        match self {
            Self::MapFullKernel => true,
            // KPTI: обычное ядро в пользовательских таблицах не живёт.
            Self::UserTableIsolation => !matches!(kind, KernelRegionKind::Kernel),
        }
    }

    /// Требует ли политика переключения таблиц на границе режимов.
    ///
    /// KPTI (`UserTableIsolation`) — да: ядро и пользователь живут в
    /// разных таблицах, вход/выход syscall и переключение контекста
    /// обязаны переключать таблицы (`ASIDInterface::activate`); при
    /// наличии PCID/ASID — тегированно, без сброса TLB
    /// (`FlushMode::NoFlush`, пара [`crate::hal::traits::asid::AsidPair`]). `MapFullKernel` — нет:
    /// одна таблица на всё, переключение не нужно (и теги не нужны).
    #[inline]
    pub const fn requires_table_switch(self) -> bool {
        matches!(self, Self::UserTableIsolation)
    }

    /// Нужна ли паре «ядро/пользователь» пара тегов при этой политике.
    ///
    /// Тавтология `requires_table_switch` с точки зрения семантики, но
    /// разная аудитория: первое читает код гейта/планировщика (когда
    /// переключать), второе — код памяти (чем метить). См.
    /// [`crate::hal::traits::asid`].
    #[inline]
    pub const fn requires_asid_pair(self) -> bool {
        self.requires_table_switch()
    }

    /// Безопасный по умолчанию выбор: изоляция включена.
    ///
    /// Платформа может ослабить до [`Self::MapFullKernel`], только проверив
    /// CPU — крейт по умолчанию не доверяет железу.
    #[inline]
    pub const fn conservative() -> Self {
        Self::UserTableIsolation
    }
}

impl fmt::Display for IsolationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MapFullKernel => "map-full-kernel (supervisor-only in user tables)",
            Self::UserTableIsolation => "user-table-isolation (KPTI)",
        };
        f.write_str(s)
    }
}

// ───────────────────────────── Регион ядра ─────────────────────────────

/// Запись KMAP: непрерывный виртуальный диапазон ядра.
///
/// Сознательно БЕЗ физического адреса: связь «высокая половина ↔ physmap»
/// и способ получения физики (копирование готовых PTE ядра, смещение на
/// physmap-базу, отдельные страницы-трамплины) — свойства архитектуры.
/// Бекенд разрешает физику сам; крейт ведёт учёт только виртуальной геометрии.
///
/// Создание — только через [`KernelRegion::kernel`]/
/// [`KernelRegion::entry_trampoline`]/[`KernelRegion::user_shared`]: конструкторы валидируют геометрию и флаги (W^X, запрет
/// записи в трамплин), поэтому live-запись таблицы всегда корректна.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KernelRegion {
    /// Уникальное в таблице имя (аудит/логи; горячий путь его не читает).
    name: &'static str,
    /// База диапазона (страница-выровнена — проверяется при создании).
    v_base: VirtualADDR,
    /// Размер в страницах (> 0).
    pages_count: usize,
    /// Права региона (ядерная сторона; для `UserShared` — и пользователя).
    flags: MMAPMemoryFlags,
    kind: KernelRegionKind,
}

impl KernelRegion {
    /// Общая валидация геометрии и флагов.
    fn build(
        name: &'static str,
        v_base: VirtualADDR,
        pages_count: usize,
        flags: MMAPMemoryFlags,
        kind: KernelRegionKind,
    ) -> Result<Self, MemErrorCode> {
        if pages_count == 0 {
            return Err(MemErrorCode::InvalidArgument(
                "kernel region: pages_count must be > 0",
            ));
        }
        if !v_base.is_aligned() {
            return Err(MemErrorCode::Unaligned);
        }
        // Единая политика прав: хотя бы одно право R/W/X, W^X запрещён.
        flags.validate()?;
        Ok(Self {
            name,
            v_base,
            pages_count,
            flags,
            kind,
        })
    }

    /// Регион обычного ядра ([`KernelRegionKind::Kernel`]).
    pub fn kernel(
        name: &'static str,
        v_base: VirtualADDR,
        pages_count: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<Self, MemErrorCode> {
        Self::build(name, v_base, pages_count, flags, KernelRegionKind::Kernel)
    }

    /// Трамплин входа в ядро ([`KernelRegionKind::EntryTrampoline`]).
    ///
    /// WRITABLE запрещён: трамплин живёт в пользовательских таблицах и при
    /// KPTI, записываемый трамплин делает изоляцию фикцией (см. документацию
    /// [`KernelRegionKind::EntryTrampoline`]).
    pub fn entry_trampoline(
        name: &'static str,
        v_base: VirtualADDR,
        pages_count: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<Self, MemErrorCode> {
        if flags.contains(MMAPMemoryFlags::WRITABLE) {
            return Err(MemErrorCode::InvalidArgument(
                "kernel region: EntryTrampoline must not be WRITABLE (KPTI)",
            ));
        }
        Self::build(
            name,
            v_base,
            pages_count,
            flags,
            KernelRegionKind::EntryTrampoline,
        )
    }

    /// Разделяемые с пользователем данные ([`KernelRegionKind::UserShared`]).
    ///
    /// Флаги здесь — права пользователя (регион обязан быть читаемым,
    /// что и проверяет общая валидация).
    ///
    /// [`MMAPMemoryFlags::GLOBAL`] (TLB-глобальность) запрещена: глобальные
    /// записи переживают любые теги и сбросы, а права user-страниц —
    /// пространство-зависимое свойство (разные процессы могут иметь разные
    /// копии/права разделяемых страниц). Ставить глобальность на user-доступные
    /// страницы — открывать окно к чужим переводам после смены пространства.
    pub fn user_shared(
        name: &'static str,
        v_base: VirtualADDR,
        pages_count: usize,
        flags: MMAPMemoryFlags,
    ) -> Result<Self, MemErrorCode> {
        if flags.contains(MMAPMemoryFlags::GLOBAL) {
            return Err(MemErrorCode::InvalidArgument(
                "kernel region: UserShared must not be TLB-global (per-ASID pages)",
            ));
        }
        Self::build(
            name,
            v_base,
            pages_count,
            flags,
            KernelRegionKind::UserShared,
        )
    }

    // ── Доступ (только чтение: записи иммутабельны по построению) ──

    #[inline]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    #[inline]
    pub const fn v_base(&self) -> VirtualADDR {
        self.v_base
    }

    #[inline]
    pub const fn pages_count(&self) -> usize {
        self.pages_count
    }

    #[inline]
    pub const fn flags(&self) -> MMAPMemoryFlags {
        self.flags
    }

    #[inline]
    pub const fn kind(&self) -> KernelRegionKind {
        self.kind
    }

    /// Размер региона в байтах; `None` при переполнении.
    #[inline]
    pub const fn size_bytes(&self) -> Option<usize> {
        self.pages_count
            .checked_mul(crate::hal::traits::mmap::PAGE_SIZE)
    }

    /// Первый адрес за регионом; `None` при переполнении.
    #[inline]
    pub const fn end(&self) -> Option<VirtualADDR> {
        match self.size_bytes() {
            Some(size) => match self.v_base.0.checked_add(size) {
                Some(end) => Some(VirtualADDR(end)),
                None => None,
            },
            None => None,
        }
    }

    /// Принадлежит ли адрес диапазону региона.
    #[inline]
    pub const fn contains(&self, v: VirtualADDR) -> bool {
        match self.end() {
            Some(end) => self.v_base.0 <= v.0 && v.0 < end.0,
            None => false,
        }
    }
}

impl fmt::Display for KernelRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] {} +{}p {:?}",
            self.name, self.kind, self.v_base, self.pages_count, self.flags
        )
    }
}

// ───────────────────────────── Трейт бекенда ─────────────────────────────

/// Архитектурный бекенд: выполняет отображение регионов ядра в конкретную
/// пользовательскую таблицу страниц.
///
/// Реализуется платформенным кодом ВНЕ крейта (тот же исполнитель, что у
/// [`crate::hal::traits::mmap::MMAPInterface`]). Контракт реализации:
///
/// 1. Страницы [`KernelRegionKind::Kernel`] и [`KernelRegionKind::EntryTrampoline`]
///    ставятся supervisor-only: пользователь не имеет к ним доступа при
///    любом наборе флагов (флаги региона описывают ядровую сторону —
///    исполняемость и т.п.).
/// 2. Страницы [`KernelRegionKind::UserShared`] отображаются с правами
///    ПОЛЬЗОВАТЕЛЯ из флагов региона (это единственные user-доступные
///    страницы KMAP).
/// 3. `EntryTrampoline` обязан оставаться достижимым после переключения
///    на пользовательскую таблицу — в этом его смысл.
/// 4. Повторное отображение уже отображённого региона — `Err(AlreadyMapped)`;
///    снятие неотображённого — `Err(NotMapped)`.
/// 5. Реализация НЕ обязана выделять/освобождать физическую память: регион
///    уже существует в ядре, речь только о строках таблиц страниц.
/// 6. Тегированные бекенды (реализуют [`crate::hal::traits::asid::ASIDInterface`])
///    ставят строки с учётом назначенной пары тегов (вызов
///    `ASIDInterface::assign_asid_pair` фасадом гарантированно ПРОИСХОДИТ
///    РАНЬШЕ первого `map_kernel_region` этого фасада) и бита
///    [`MMAPMemoryFlags::GLOBAL`] региона; нетегированные — сбрасывают
///    затронутые TLB-записи внутри самих map/unmap.
pub trait KMAPInterface {
    /// Отобразить регион ядра в пользовательскую таблицу страниц.
    fn map_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode>;

    /// Снять отображение региона ядра.
    fn unmap_kernel_region(&mut self, region: &KernelRegion) -> Result<(), MemErrorCode>;
}
