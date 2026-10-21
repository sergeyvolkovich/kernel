// ==== Типы capability-модели (двухуровневая схема) ====
//
// Уровень 1 — глобальные объекты ядра в страничных таблицах:
//   * TaskObj  (таблица в TcbManager)          — цель `TaskTCB`;
//   * GateObj  (таблица в CapabilityManager)   — цель `Gate` (IPC-гейт);
//   * IrqObj   (таблица в CapabilityManager)   — цель `Irq` (линия прерываний);
//   * сырые ресурсы — БЕЗ объекта: `IoResource` (v0.14) адресует ДИАПАЗОН
//     (физика / порты / GSI) без знания об устройствах — ядро не знает
//     НИ ОДНОГО устройства (перечисление и драйверы — юзерспейс), цель
//     «бессмертна» (TargetRef::immortal), отзыв — revoke самой capability.
//
// Уровень 2 — локальная таблица хендлов задачи (`HandleTable` из CTE).
// Пользовательский хендл — не Uuid, а `CapHandle = u64 (idx, generation)`, как fd
// с поколением. Хендл валиден только в cspace задачи-владельца: чужой
// хендл неотличим от несуществующего (нет side channel).
//
// Дерево деривации — интрузивные списки детей на CTE; ссылки на родителя
// generation-защищены (слоты страничных таблиц стабильны, при reuse поколение
// продолжается).
//
// Горячий путь (`resolve_slot`): хендл → CTE (2 обращения, страницы) →
// generation слота → perms → alive(цель) [+ alive(владелец) для Gate/Irq] —
// деревья не трогаются. Ленивые две проверки generation — по плану.

use thiserror::Error;

use crate::capability::paged::{PagedError, TargetRef};

use crate::task::TaskId;

bitflags::bitflags! {
    /// Права операции над capability.
    ///
    /// Устойчивое кодирование прежней версии (Send = 1, Mint = 1 << 1) —
    /// значения битов менять нельзя: они попадают в сериализуемые
    /// структуры и ABI.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ActionPermissions: u8 {
        /// Возможность передать слот другой задаче (transfer).
        const Send = 1;
        /// Возможность породить производную capability (derive).
        const Mint = 1 << 1;
    }
}

impl ActionPermissions {
    /// Права, достаточные для передачи хендла (`send`).
    pub const FOR_SEND: Self = Self::Send;
    /// Права, достаточные для порождения производной (`mint`).
    pub const FOR_MINT: Self = Self::Mint;
}

/// Битовая маска badge capability: «какие подресурсы объекта доступны».
///
/// Семантика битов определяется подсистемой, выдавшей capability (для
/// устройства — номера BAR, для IRQ — векторы); ядро модели гарантирует
/// монотонное сужение при mint: `child.badge == parent.badge & mask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapabilityBadge(pub u64);

impl CapabilityBadge {
    /// Полный доступ ко всем подресурсам (для корневых grant-ов).
    pub const FULL: Self = Self(u64::MAX);
    /// Пустой доступ: capability-заглушка без подресурсов.
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Пересечение масок (сужение доступа).
    pub const fn narrow(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }

    /// Содержит ли все биты `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Есть ли общие биты с `other`.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

// ==== Хендлы ====

/// Пользовательский хендл capability: `u64 = (idx: u32, generation: u32)`, как fd
/// с поколением. Локален задаче-владельцу; генерация защищает от ABA при
/// переиспользовании слота хендл-таблицы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapHandle(pub u64);

impl CapHandle {
    pub const fn new(idx: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | idx as u64)
    }

    pub const fn idx(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for CapHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cap(idx={},generation={})",
            self.idx(),
            self.generation()
        )
    }
}

/// Ссылка на объект ядра в глобальной таблице: `(idx, generation)`. Для аудита и
/// отладки; capability адресует объект через кэшированный `TargetRef`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjId(pub u64);

impl ObjId {
    pub const fn new(idx: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | idx as u64)
    }

    pub const fn idx(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for ObjId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "obj(idx={},generation={})",
            self.idx(),
            self.generation()
        )
    }
}

/// Линия прерываний (GSI / контроллерно-зависимый номер). Стабильное имя
/// для персистентности и отладки — в горячем пути не участвует.
/// MSI-источники (`MsiSource`, IRTE) остаются уровнем HAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IrqId(pub u32);

impl core::fmt::Display for IrqId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "irq({})", self.0)
    }
}

// ==== Объекты capability ====

/// Сырой аппаратный ресурс за capability (v0.14: «устройств в ядре нет»).
///
/// Право — ДИАПАЗОН адресов/портов/линий, а не идентификатор устройства:
/// кто такой «COM1» или «LPC-мост» — знает только юзерспейс. Корневой
/// сервер (init) получает гранты на всё адресное пространство ресурсов
/// от kinit и распределяет их ПОСЛЕ собственного перечисления (ACPI
/// manager / драйверы — уже юзерспейс-код, включая AML). Ядро проверяет
/// только принадлежность адреса диапазону capability (гейты сисколов
/// MMIO_MAP / IOP_IN / IOP_OUT / IRQ_ATTACH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoResourceKind {
    /// Физический диапазон: MMIO-баре устройств, таблицы прошивки
    /// (ACPI),APIC-регионов и т.д. `base..base+len` по физике.
    Mmio { base: u64, len: u64 },
    /// Диапазон I/O-портов (x86: 0..=65535), `base..base+len`.
    IoPort { base: u16, len: u16 },
    /// Диапазон внешних линий прерываний (GSI): `base..base+count`.
    Irq { base: u32, count: u32 },
}

impl IoResourceKind {
    /// Слово-вид разновидности для CAP_INFO (аудит/диагностика):
    /// 1 = Mmio, 2 = IoPort, 3 = Irq.
    pub fn flavor_word(&self) -> u64 {
        match self {
            IoResourceKind::Mmio { .. } => 1,
            IoResourceKind::IoPort { .. } => 2,
            IoResourceKind::Irq { .. } => 3,
        }
    }

    /// Слова-идентификаторы для CAP_INFO: [base, len|count].
    pub fn ident_words(&self) -> [u64; 2] {
        match self {
            IoResourceKind::Mmio { base, len } => [*base, *len],
            IoResourceKind::IoPort { base, len } => [*base as u64, *len as u64],
            IoResourceKind::Irq { base, count } => [*base as u64, *count as u64],
        }
    }

    /// Сужение поддиапазона (v0.15): производная IoResource обязана
    /// лежать ВНУТРИ родительского диапазона той же разновидности —
    /// решёточный инвариант деривации (производная никогда не шире
    /// родителя, как у прав и badge).
    ///
    /// Инварианты (нарушение любого — `None`, отказ без побочных
    /// эффектов):
    /// 1. вложение: `new_base >= base` и `new_base + new_len <= base + len`
    ///    (арифметика без переполнения — checked_add);
    /// 2. позитивность: `new_len > 0` (пустой диапазон — не право);
    /// 3. совпадение вида: пары слов интерпретируются по разновидности
    ///    РОДИТЕЛЯ (Mmio: 64/64 бита, IoPort: граница u16, Irq: граница u32);
    /// 4. транзитивность обеспечена самим вложением: сужать можно только
    ///    от уже суженного и только внутрь его.
    pub fn narrow(&self, new_base: u64, new_len: u64) -> Option<IoResourceKind> {
        if new_len == 0 {
            return None;
        }
        match *self {
            IoResourceKind::Mmio { base, len } => {
                // Вложение без переполнения: сравниваем через checked_add.
                let new_end = new_base.checked_add(new_len)?;
                let end = base.checked_add(len)?;
                if new_base >= base && new_end <= end {
                    Some(IoResourceKind::Mmio {
                        base: new_base,
                        len: new_len,
                    })
                } else {
                    None
                }
            }
            IoResourceKind::IoPort { base, len } => {
                let new_end = new_base.checked_add(new_len)?;
                let end = base as u64 + len as u64;
                if new_base >= base as u64 && new_end <= end {
                    Some(IoResourceKind::IoPort {
                        base: new_base as u16,
                        len: new_len as u16,
                    })
                } else {
                    None
                }
            }
            IoResourceKind::Irq { base, count } => {
                let new_end = new_base.checked_add(new_len)?;
                let end = base as u64 + count as u64;
                if new_base >= base as u64 && new_end <= end {
                    Some(IoResourceKind::Irq {
                        base: new_base as u32,
                        count: new_len as u32,
                    })
                } else {
                    None
                }
            }
        }
    }
}

/// Объект, на который ссылается capability. Сохранён из прежней версии
/// (внешний формат расширяется новыми вариантами), поля открыты для
/// сопоставления с образцом.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContainerACCCapability {
    /// Ссылка на TCB задачи: цель — generation-защищённый объект задачи.
    TaskTCB { task_id: TaskId },
    /// IPC-гейт (объект ядра): очередь, ожидающий поток и т.д.
    Gate { gate_id: ObjId },
    /// Линия прерываний: стабильное имя `irq` + ссылка на объект ядра.
    Irq { irq: IrqId, obj_id: ObjId },
    /// Сырой аппаратный ресурс (v0.14): диапазон физики / портов / GSI.
    /// Цель «бессмертна» (право на диапазон, не на объект ядра); выдаёт
    /// kinit корневому серверу (init), производные — CAP_MINT в
    /// юзерспейс-менеджеры и драйверы. Ядро НЕ знает, какому «устройству»
    /// соответствует диапазон — это политика юзерспейса.
    IoResource { kind: IoResourceKind },
    /// Мастер-право подсистемы IOMMU/DMA-ремаппинга (v0.9): гейт всей
    /// группы сисколов 0x80. Цель «бессмертна» (глобальный сервис —
    /// как IoResource): право выдаёт ядро доверенным задачам
    /// (init — менеджер устройств), отзыв — revoke производной.
    /// Ядро НЕ гарантирует уникальность держателя: политика выдачи —
    /// у стартового кода платформы.
    IommuAdmin,
}

impl ContainerACCCapability {
    /// Слово-вид для аудита дерева деривации (no_std без fmt::Debug в
    /// консоли): 2=TaskTCB, 3=Gate, 4=Irq, 5=IommuAdmin,
    /// 6=IoResource(Mmio), 7=IoResource(IoPort), 8=IoResource(Irq)
    /// (v0.14; 1 — DeviceReference — удалён вместе с реестром устройств).
    pub fn kind_word(&self) -> u64 {
        match self {
            ContainerACCCapability::TaskTCB { .. } => 2,
            ContainerACCCapability::Gate { .. } => 3,
            ContainerACCCapability::Irq { .. } => 4,
            ContainerACCCapability::IommuAdmin => 5,
            ContainerACCCapability::IoResource {
                kind: IoResourceKind::Mmio { .. },
            } => 6,
            ContainerACCCapability::IoResource {
                kind: IoResourceKind::IoPort { .. },
            } => 7,
            ContainerACCCapability::IoResource {
                kind: IoResourceKind::Irq { .. },
            } => 8,
        }
    }
}

/// Состояние IPC-endpoint'а: буфер сообщений + очереди блокировки.
///
/// Живёт в `GateObj` (таблица гейтов [`crate::capability::CapabilityManager`]);
/// определено в IPC-подсистеме ([`crate::ipc`]) — см. документацию там.
/// Placeholder-версия заменена реальным состоянием вместе с IPC-подсистемой.
pub use crate::ipc::EndpointState;

/// Capability-«гейт»: ссылка на объект + права + badge.
///
/// Инварианты (поддерживаются менеджером, недоступны для мутации снаружи):
/// * у корневой capability права назначает грантодатель (ядро);
/// * у производной: `perms ⊆ parent.perms`, `badge ⊆ parent.badge`.
pub struct CapabilityGate {
    cap_ref: ContainerACCCapability,
    perms: ActionPermissions,
    badge: CapabilityBadge,
}

impl CapabilityGate {
    /// Создаёт гейт (обычно для корневого grant-а).
    pub fn new(
        cap_ref: ContainerACCCapability,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Self {
        Self {
            cap_ref,
            perms,
            badge,
        }
    }

    /// Ссылка на объект capability.
    pub fn cap_ref(&self) -> &ContainerACCCapability {
        &self.cap_ref
    }

    /// Права операции.
    pub fn perms(&self) -> ActionPermissions {
        self.perms
    }

    /// Маска подресурсов.
    pub fn badge(&self) -> CapabilityBadge {
        self.badge
    }

    /// Порождает гейт производной capability: права и badge сужаются
    /// пересечением с `spec`, диапазон IoResource — вложенным
    /// поддиапазоном `spec.range` (v0.15). Метод — «чистая» функция над
    /// значениями; дерево деривации и счётчики ведёт менеджер.
    ///
    /// `Err(RangeNotSubset)` — поддиапазон не вложен в родительский либо
    /// диапазон запрошен у не-IoResource источника; отказ чистый: ни CTE,
    /// ни узла деривации не создаётся (гарантирует менеджер).
    pub(crate) fn derive(&self, spec: &MintSpec) -> Result<Self, CapabilityError> {
        let cap_ref = match (&self.cap_ref, spec.range) {
            (ContainerACCCapability::IoResource { kind }, Some((base, len))) => {
                let narrowed = kind
                    .narrow(base, len)
                    .ok_or(CapabilityError::RangeNotSubset)?;
                ContainerACCCapability::IoResource { kind: narrowed }
            }
            // Диапазон имеет смысл только у сырых ресурсов: у гейтов/TCB
            // сужением служит badge, у IoResource — поддиапазон.
            (_, Some(_)) => return Err(CapabilityError::RangeNotSubset),
            _ => self.cap_ref.clone(),
        };
        Ok(Self {
            cap_ref,
            perms: self.perms & spec.perms,
            badge: self.badge.narrow(spec.badge),
        })
    }
}

impl core::fmt::Debug for CapabilityGate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CapabilityGate")
            .field("cap_ref", &self.cap_ref)
            .field("perms", &self.perms)
            .field("badge", &self.badge)
            .finish()
    }
}

/// Запрошенное сужение при mint: какие права, какие подресурсы (badge) и
/// какой ПОДДИАПАЗОН просит производная capability. Менеджер отвечает
/// пересечением с родителем (права/badge) и проверкой вложенности
/// (диапазон: только ⊆ родителя).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintSpec {
    pub perms: ActionPermissions,
    pub badge: CapabilityBadge,
    /// Сужение поддиапазона IoResource (v0.15): `Some((base, len))` —
    /// только для источников-`IoResource` (иначе отказ
    /// [`CapabilityError::RangeNotSubset`]); `None` — прежняя семантика
    /// (диапазон клонируется целиком, как права/badge без сужения).
    pub range: Option<(u64, u64)>,
}

impl MintSpec {
    /// Без сужения: производная получает те же права/badge/диапазон, что
    /// родитель (диапазон IoResource клонируется целиком).
    pub const UNCHANGED: Self = Self {
        perms: ActionPermissions::all(),
        badge: CapabilityBadge::FULL,
        range: None,
    };

    /// Сужение поддиапазона IoResource: `base..base+len` обязано лежать
    /// внутри родительского диапазона (проверяет менеджер через
    /// [`IoResourceKind::narrow`]).
    pub const fn subrange(perms: ActionPermissions, base: u64, len: u64) -> Self {
        Self {
            perms,
            badge: CapabilityBadge::FULL,
            range: Some((base, len)),
        }
    }
}

// ==== Снимки для аудита и горячего пути ====

/// Родитель по деривации: хендл родительского CTE в cspace его владельца.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentRef {
    /// Задача, в cspace которой лежит родительский CTE.
    pub task: TaskId,
    /// Хендл родителя в таблице этой задачи.
    pub handle: CapHandle,
}

/// Снимок слота для аудита (копия; объекты — внутренности менеджеров).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityView {
    /// Хендл в cspace владельца.
    pub id: CapHandle,
    /// Текущий владелец слота.
    pub owner: TaskId,
    /// Слот, из которого порождена эта capability (`None` — корневая).
    pub parent: Option<ParentRef>,
    pub perms: ActionPermissions,
    pub badge: CapabilityBadge,
    /// Стабильное имя цели (клон; для ACPI-путей клонируется строка).
    pub cap_ref: ContainerACCCapability,
}

/// Результат горячего пути (`resolve` / `resolve_cached`): всё, что нужно
/// для проверки прав и доставки, скопировано наружу (ссылки не утекают из
/// под RefCell).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapResolved {
    pub perms: ActionPermissions,
    pub badge: CapabilityBadge,
    /// Цель: generation-защищённая ссылка (для Gate/Irq после её живости можно
    /// дойти до объекта через менеджер).
    pub target: TargetRef,
}

impl CapResolved {
    /// Жива ли цель (для повторных проверок вне менеджера).
    pub fn alive(&self) -> bool {
        self.target.alive()
    }
}

/// Отчёт об отзыве: сколько слотов погашено (сам слот + всё дерево
/// производных, включая слоты, принадлежавшие другим задачам).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevokeReport {
    pub revoked_slots: usize,
}

/// Ошибка операции над capability.
///
/// Политика ошибок (анти-side-channel): «нет такого хендла» и «хендл
/// протух» — один и тот же [`CapabilityError::InvalidHandle`]; существование
/// чужих capability по хендлу не различимо (хендл локален cspace). Отдельные
/// ошибки (`MissingRight`, `TaskNotFound`) выдаются только после того, как
/// хендл нашёлся в таблице вызывающего.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityError {
    #[error("task {0} not found")]
    TaskNotFound(TaskId),
    /// Хендл не найден в cspace ИЛИ указывает на погашенный слот/цель —
    /// намеренно неразличимые случаи (side channel на жизнь объектов).
    #[error("invalid capability handle {0}")]
    InvalidHandle(CapHandle),
    /// У capability нет нужного права (Send/Mint).
    #[error("capability {id} lacks {required:?}")]
    MissingRight {
        id: CapHandle,
        required: ActionPermissions,
    },
    /// TaskTCB-грант на незарегистрированную (или мёртвую) задачу.
    #[error("capability references unknown task {0}")]
    UnknownTaskTarget(TaskId),
    /// Нарушение внутреннего инварианта (не должно происходить).
    #[error("internal capability manager error")]
    Internal,
    /// Сбой slab/страничной таблицы (память под CTE, гейт или IRQ-объект).
    #[error("out of memory")]
    OutOfMemory,
    /// Запрошенный поддиапазон IoResource не вложен в родительский
    /// (v0.15): вне диапазона, нулевая длина, переполнение конца,
    /// несовпадение разновидности либо диапазон запрошен у не-IoResource
    /// источника. Отказ чистый: ни CTE, ни узла деривации не создано.
    #[error("requested subrange is not within the parent IoResource")]
    RangeNotSubset,
}

impl From<PagedError> for CapabilityError {
    fn from(_: PagedError) -> Self {
        CapabilityError::OutOfMemory
    }
}
