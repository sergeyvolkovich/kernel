// ==== ASID/PCID: теги адресных пространств и KPTI-переключение таблиц ====
//
// Зачем теги. Политика KPTI (`IsolationPolicy::UserTableIsolation`,
// см. `hal::traits::kmap`) закрывает Meltdown (Rogue Data Cache Load)
// разносом ядра и пользователя по разным таблицам страниц — но каждое
// переключение таблиц на границе режимов (вход/выход syscall, переключение
// контекста) без тегов сбрасывает не-глобальные записи TLB ЦЕЛИКОМ.
// На syscall-тяжёлой нагрузке это главная цена KPTI.
//
// Тег адресного пространства (x86: PCID, ARM: ASID) решает проблему:
// записи TLB помечаются тегом и переживают переключение CR3/TTBR, а
// неактуальные записи гасятся точечно (INVPCID / TLBI ASID) при unmap.
// Пара тегов KPTI — по одному на пользовательскую и ядровую таблицы
// одного процесса — даёт переключение «без сброса»: ядро активирует
// таблицу с её тегом, TLB обоих таблиц остаётся тёплым.
//
// Схема (без тегов -> с тегами):
// ```text
//   без PCID:  user CR3 <──flush──> kernel CR3      (полный сброс TLB)
//   с PCID:    user CR3 | tag U <──switch──> kernel CR3 | tag K
//              TLB: [ U: user-страницы | K: kernel-страницы ]  (без сброса)
// ```
//
// Что здесь есть, а чего СОЗНАТЕЛЬНО нет:
//   * типы-значения: [`AddressSpaceId`], [`AsidPair`], [`TlbOp`],
//     [`FlushMode`], [`AddressSpaceMode`] — словарь, общий для x86/ARM;
//   * контракт арх-бекенда: [`ASIDInterface`] (переключение/инвалидация
//     поверх [`MMAPInterface`]) и [`AsidAllocator`] (пул тегов);
//   * НЕТ: форматов CR3/TTBR, кодирования тегов в регистрах, самого
//     алгоритма аллокации — это архитектурный код ВНЕ крейта. Крейт
//     ведёт учёт (какой фасад какой парой владеет), бекенд исполняет.
//
// Meltdown/Spectre-гигиена, закреплённая этим модулем:
//   1. KPTI остаётся политикой компоновки таблиц (`IsolationPolicy`),
//      теги её не ослабляют: пользовательская таблица по-прежнему не
//      содержит ядра, кроме EntryTrampoline/UserShared.
//   2. Инвалидация при unmap — по тегам [`TlbOp`], а не «сбросить всё»:
//      и быстрее, и обязательна для корректности (нетегированный бекенд
//      выполняет полный сброс внутри своих shrink/unmap — контракт
//      `MMAPInterface::invalidate_tlb`).
//   3. Освобождение пары тегов (`UFacade::release_asid`) гасит её TLB
//      ДО возврата в пул: повторная выдача тега другому процессу не
//      наследует чужие переводы адресов (anti-ASID-reuse).
//   4. [`MMAPMemoryFlags::GLOBAL`] (TLB-глобальные страницы) разрешён
//      только отображениям, идентичным во всех пространствах, и под
//      KPTI живёт лишь в таблицах ядра — глобальные записи переживают
//      даже сброс тегов, поэтому разделяемые с пользователем страницы
//      ими не маркируются (см. `KernelRegion::user_shared`).
//   5. Spectre-класс (v1/v2/retbleed) — уязвимости предсказателя ветвлений,
//      НЕ таблиц страниц; на этом слое они закрыты запретом записываемого
//      трамплина (W^X входа в ядро) и контрактом планировщика
//      (`SchedulerInterface::switch_context`). STIBP/IBRS/eIBRS — уровень
//      CPU-конфигурации платформенного кода, вне компетенции крейта.

use core::fmt;

use thiserror::Error;

use crate::traits::mmap::{MMAPInterface, MemErrorCode, PhysADDR, VirtualADDR};

// ───────────────────────────── Тег адресного пространства ─────────────────────────────

/// Тег адресного пространства: x86 PCID / ARM ASID.
///
/// Голое число без семантики выдачи: как теги назначаются (аппаратный пул,
/// статическое разбиение, поколенческий аллокатор с отложенным переисполь-
/// зованием) — знание платформы, см. [`AsidAllocator`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct AddressSpaceId(pub u16);

impl AddressSpaceId {
    /// Нулевой тег зарезервирован «нет тега» во многих реализациях
    /// (x86: PCID 0 используется нетегированным CR3) — удобный маркер
    /// для тестов и заглушек.
    pub const UNTAGGED: Self = Self(0);

    #[inline]
    pub const fn new(tag: u16) -> Self {
        Self(tag)
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Старший бит, доступный тегу при ширине `bits` (маска «ядро/пользователь»
    /// для схем `with_kernel_bit`). `None`, если бит не помещается.
    #[inline]
    pub const fn high_bit(bits: u32) -> Option<u16> {
        if bits == 0 || bits > 16 {
            None
        } else {
            Some(1u16 << (bits - 1))
        }
    }
}

impl fmt::Display for AddressSpaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "asid({:#06x})", self.0)
    }
}

// ───────────────────────────── Пара тегов KPTI ─────────────────────────────

/// Пара тегов одного адресного пространства при KPTI: пользовательская
/// и ядровая таблицы процесса.
///
/// Два тега вместо одного — прямое следствие изоляции: пользовательская
/// таблица (без ядра) и ядровая таблица (со всем ядром) одного процесса
/// НЕсовместимы по содержанию, обязаны иметь разные TLB-теги, иначе записи
/// из пользовательской таблицы будут «протекать» в ядровый контекст и
/// наоборот.
///
/// Схемы кодирования:
///
///   * два независимых тега из пула ([`Self::new`]);
///   * парный бит: ядровый = пользовательский | `bit` ([`Self::with_kernel_bit`]) —
///     x86-стиль: одна половина пространства PCID уходит парам K/U, чтение
///     тега текущей таблицы по биту однозначно определяет режим. Бит обязан
///     влезать в ширину тега (см. [`AddressSpaceId::high_bit`]).
///
/// На железе без Meltdown-уязвимостей (`MapFullKernel`) пара не нужна:
/// одно пространство — один тег (или вовсе без тегов).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AsidPair {
    user: AddressSpaceId,
    kernel: AddressSpaceId,
}

impl AsidPair {
    /// Пара из двух независимых тегов.
    #[inline]
    pub const fn new(user: AddressSpaceId, kernel: AddressSpaceId) -> Self {
        Self { user, kernel }
    }

    /// Пара с парным битом: `kernel = user | bit`.
    ///
    /// Требование: `bit` — степень двойки, влезающая в ширину тега;
    /// иначе пары могут конфликтовать с чужими пользовательскими тегами.
    /// Ширину знает платформа (см. [`AsidAllocator::tag_bits`]).
    #[inline]
    pub const fn with_kernel_bit(user: AddressSpaceId, bit: u16) -> Self {
        Self {
            user,
            kernel: AddressSpaceId(user.0 | bit),
        }
    }

    /// Тег пользовательской таблицы (в ней — только EntryTrampoline/UserShared
    /// и собственные страницы процесса).
    #[inline]
    pub const fn user(&self) -> AddressSpaceId {
        self.user
    }

    /// Тег ядровой таблицы процесса (в ней — полное ядро).
    #[inline]
    pub const fn kernel(&self) -> AddressSpaceId {
        self.kernel
    }

    /// Оба тега пары (порядок: пользователь, ядро).
    #[inline]
    pub const fn tags(&self) -> [AddressSpaceId; 2] {
        [self.user, self.kernel]
    }
}

impl fmt::Display for AsidPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "asid-pair(user={}, kernel={})", self.user, self.kernel)
    }
}

// ───────────────────────────── Режимы и политика сброса ─────────────────────────────

/// Какая из таблиц адресного пространства активна (семантика KPTI).
///
/// * `User` — пользовательская таблица: ядро в ней отсутствует (KPTI) или
///   отображено supervisor-only (`MapFullKernel` — режим не используется,
///   переключения нет);
/// * `Kernel` — ядровая таблица: активна на протяжении syscall/IRQ/исключения.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressSpaceMode {
    User,
    Kernel,
}

impl fmt::Display for AddressSpaceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::Kernel => "kernel",
        })
    }
}

/// Политика сброса TLB при активации таблицы ([`ASIDInterface::activate`]).
///
/// * `NoFlush` — тегированное переключение: записи TLB под обоими тегами
///   пары остаются тёплыми (требует PCID/ASID);
/// * `FlushAll` — нетегированное переключение: полный локальный сброс
///   не-глобальных записей (x86: запись CR3 без PCID).
///
/// Глобальные записи (бит [`crate::traits::mmap::MMAPMemoryFlags::GLOBAL`])
/// не сбрасываются ни одной из политик — гасятся только
/// [`TlbOp::All`] с `include_global = true`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlushMode {
    NoFlush,
    FlushAll,
}

// ───────────────────────────── TLB-операции ─────────────────────────────

/// Точечная инвалидация TLB (контракт `MMAPInterface::invalidate_tlb`).
///
/// Выбор операции — минимальная достаточная: инвалидируя меньше, чем
/// нужно, получаем устаревшие переводы (корректность/безопасность);
/// инвалидируя больше — платим производительностью (это уже только
/// скорость). Фасады крейта выдают минимально достаточную операцию:
///
/// | событие                                | операция                        |
/// |----------------------------------------|---------------------------------|
/// | unmap пользовательского региона        | [`TlbOp::Context`] (user-тег)   |
/// | разбор ядерных отображений фасада      | [`TlbOp::Pair`]                 |
/// | гибель адресного пространства          | [`TlbOp::Pair`] до free пары    |
/// | правка собственных отображений ядра    | [`TlbOp::All`] с глобальными    |
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlbOp {
    /// Одна страница в заданном теге (x86: INVPCID, тип individual-address;
    /// ARM: TLBI VAAE1IS + ASID).
    Page {
        v: VirtualADDR,
        asid: AddressSpaceId,
    },
    /// Все записи одного тега (x86: INVPCID single-context).
    Context(AddressSpaceId),
    /// Оба тега пары KPTI (два single-context; разбор/гибель пространства).
    Pair(AsidPair),
    /// Все записи всех тегов текущего CPU.
    ///
    /// `include_global` — гасить и TLB-глобальные страницы (x86: PCID-all +
    /// отдельный INVLPG с включённым PCID для глобальных; проще — перезагрузка
    /// CR4.PGE). Правка ядерных отображений, меняющая их физику/права,
    /// обязана идти с `include_global = true`.
    All { include_global: bool },
}

impl fmt::Display for TlbOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Page { v, asid } => write!(f, "tlb-invlpg({v}, {asid})"),
            Self::Context(asid) => write!(f, "tlb-invalidate-context({asid})"),
            Self::Pair(pair) => write!(f, "tlb-invalidate-pair({pair})"),
            Self::All { include_global } => {
                write!(f, "tlb-invalidate-all(global={include_global})")
            }
        }
    }
}

// ───────────────────────────── Ошибки ─────────────────────────────

/// Отказ пула тегов ASID/PCID.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ASIDError {
    /// Пул исчерпан: живых адресных пространств больше, чем тегов
    /// (12 бит PCID = 4096 тегов без парного бита, 2048 пар с ним).
    /// Лечение — очередь на переиспользование с отложенным free
    /// (контракт [`AsidAllocator`]) либо деградация в нетегированный
    /// режим (`FlushMode::FlushAll`) на части пространств.
    #[error("ASID/PCID pool exhausted")]
    Exhausted,
    /// Платформа не поддерживает теги (нет PCID/ASID или отключены).
    #[error("ASID/PCID not supported by platform")]
    NotSupported,
    /// Пара не принадлежит выдавшему её пулу (ошибка интеграции).
    #[error("ASID/PCID pair does not belong to this pool")]
    ForeignPair,
}

// ───────────────────────────── Пул тегов (арх-бекенд) ─────────────────────────────

/// Пул тегов ASID/PCID: выдаёт и возвращает пары тегов для адресных
/// пространств с KPTI.
///
/// Реализуется платформенным кодом ВНЕ крейта (как [`MMAPInterface`]).
/// Все методы — `&self`: пул глобальный сервис ядра, синхронизация —
/// внутренняя забота реализации (крейт вызывает его из однопоточного
/// контекста менеджера памяти).
///
/// Контракт переиспользования (анти-ASID-reuse, критично для корректности):
/// возвращённый через `free_pair` тег НЕ выдаётся повторно, пока в TLB
/// любого CPU могут оставаться его записи.
///
/// Стандартные стратегии:
///   1. поколенческая (generation-счётчик, отложенный возврат);
///   2. full-TLB-flush при исчерпании к поколению 0 (как Linux x86
///      `flush_tlb_all` при rollover PCID);
///   3. справочный счётчик TLB-записей (ARM ASID allocator).
///
/// Крейт помогает контракту: фасад пользовательских адресных пространств ядра
/// гасит TLB пары ДО возврата тегов в пул.
///
/// Парный бит (если схема `with_kernel_bit`) обязан резервироваться пулом:
/// тег с этим битом не выдаётся как пользовательский.
pub trait AsidAllocator {
    /// Выделить пару тегов под новое адресное пространство с KPTI.
    fn alloc_pair(&self) -> Result<AsidPair, ASIDError>;

    /// Вернуть пару тегов. Вызывающий обязан погасить её TLB ДО вызова
    /// (контракт выше); пул вправе debug_assert'ить сказанное.
    fn free_pair(&self, pair: AsidPair);

    /// Число тегов, которое может выдать пул (ёмкость пользовательских
    /// тегов; при парном бите — половина адресного пространства тегов).
    fn capacity(&self) -> usize;

    /// Ширина тега в битах (x86 PCID: 12; ARM ASID: 8 или 16).
    /// Информационное: фасады не кодируют теги, ширину использует
    /// платформа для `AsidPair::with_kernel_bit`.
    fn tag_bits(&self) -> u32;
}

// ───────────────────────────── Трейт тегированного бекенда ─────────────────────────────

/// Архитектурный бекенд с тегами ASID/PCID: переключение таблиц KPTI и
/// точечные инвалидации TLB поверх базового [`MMAPInterface`].
///
/// Реализуется платформенным кодом ВНЕ крейта для бекендов, чьё железо
/// умеет PCID/ASID. Бекенду БЕЗ тегов реализовывать не нужно: фасады
/// просто не выдают ему пар (проверка — через реализацию этого трейта;
/// см. `MemoryManager::create_ufacade_asid`).
///
/// Контракт реализации (по методам):
///
/// 1. `assign_asid_pair` — запомнить пару как теги ЭТОГО адресного
///    пространства. Вызывается фасадом ДО отображения ядерных регионов
///    (`KMAPInterface::map_kernel_region`): бекенд обязан уметь ставить
///    PTE с учётом тегов/глобальности уже на этом шаге. Повторное
///    назначение другой пары — `Err(InvalidArgument)`.
/// 2. `activate` — переключить активную таблицу (`User`/`Kernel`) с
///    политикой сброса. При `NoFlush` записи TLB под обоими тегами
///    обязаны сохраниться: это и есть смысл PCID. Выход в `User` при
///    KPTI гарантирует, что активная таблица не содержит ядра сверх
///    EntryTrampoline/UserShared — полноту проверки выполняет компоновка
///    (KMAP ядра), здесь — только исполнение переключения.
/// 3. `root_table` — физический корень таблиц страниц пространства
///    (для трекинга гейтом сисколов / планировщиком). `None` допустимо,
///    если бекенд не раскрывает корень.
///
/// Инвалидация TLB — НЕ здесь: единственная точка определения —
/// [`MMAPInterface::invalidate_tlb`] (дефолт — громкий отказ); бекенд,
/// реализующий этот трейт, ОБЯЗАН также переопределить её (INVPCID/TLBI
/// по [`TlbOp`]) — теги без точечных инвалидаций бессмысленны.
///
/// Инвариант KPTI-пары: тег `kernel` активен ТОЛЬКО в ядровом режиме;
/// пользовательский код, исполняющийся с активным kernel-тегом, — ошибка
/// интеграции платформы (крейт таких переключений не заказывает).
pub trait ASIDInterface: MMAPInterface {
    /// Назначить пары тегов этому адресному пространству (до отображений).
    fn assign_asid_pair(&mut self, pair: AsidPair) -> Result<(), MemErrorCode>;

    /// Текущая пара тегов (`None` — не назначена / бекенд без тегов).
    fn asid_pair(&self) -> Option<AsidPair>;

    /// Активировать таблицу заданного режима с политикой сброса TLB.
    fn activate(&mut self, mode: AddressSpaceMode, flush: FlushMode) -> Result<(), MemErrorCode>;

    /// Физический корень таблиц страниц этого пространства.
    fn root_table(&self) -> Option<PhysADDR>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asid_pair_kernel_bit_math() {
        let bit = AddressSpaceId::high_bit(12).unwrap();
        assert_eq!(bit, 0x800);

        let pair = AsidPair::with_kernel_bit(AddressSpaceId(0x123), bit);
        assert_eq!(pair.user(), AddressSpaceId(0x123));
        assert_eq!(pair.kernel(), AddressSpaceId(0x923));
        // Бит уже стоит в user — ядровый тег не меняется (idempotent).
        let pair2 = AsidPair::with_kernel_bit(pair.kernel(), bit);
        assert_eq!(pair2.kernel(), pair.kernel());

        // Независимые теги.
        let pair3 = AsidPair::new(AddressSpaceId(1), AddressSpaceId(2));
        assert_eq!(pair3.tags(), [AddressSpaceId(1), AddressSpaceId(2)]);
        assert_eq!(
            pair3.to_string(),
            "asid-pair(user=asid(0x0001), kernel=asid(0x0002))"
        );
    }

    #[test]
    fn high_bit_bounds() {
        assert_eq!(AddressSpaceId::high_bit(0), None);
        assert_eq!(AddressSpaceId::high_bit(1), Some(1));
        assert_eq!(AddressSpaceId::high_bit(16), Some(0x8000));
        assert_eq!(AddressSpaceId::high_bit(17), None);
        assert_eq!(AddressSpaceId::high_bit(u32::MAX), None);
    }
}
