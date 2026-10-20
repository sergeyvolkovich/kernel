// ==== Типы capability-модели (двухуровневая схема) ====
//
// Уровень 1 — глобальные объекты ядра в страничных таблицах:
//   * TaskObj  (таблица в TcbManager)          — цель `TaskTCB`;
//   * GateObj  (таблица в CapabilityManager)   — цель `Gate` (IPC-гейт);
//   * IrqObj   (таблица в CapabilityManager)   — цель `Irq` (линия прерываний);
//   * устройства — БЕЗ объекта: `DeviceReference` адресует DeviceManager
//     по `DevicePath` (вне крейта), цель «бессмертна» (TargetRef::immortal),
//     отзыв выполняется через revoke самой capability.
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
use crate::hal::types::DevicePath;

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

/// Объект, на который ссылается capability. Сохранён из прежней версии
/// (внешний формат расширяется новыми вариантами), поля открыты для
/// сопоставления с образцом.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContainerACCCapability {
    /// Ссылка на устройство: ключ — типизированный `DevicePath`, тот же,
    /// что в реестре `DeviceManager`. Цель «бессмертна» на этом слое:
    /// живость устройства контролирует DeviceManager вне крейта, отзыв —
    /// через revoke capability.
    DeviceReference { dev_path: DevicePath },
    /// Ссылка на TCB задачи: цель — generation-защищённый объект задачи.
    TaskTCB { task_id: TaskId },
    /// IPC-гейт (объект ядра): очередь, ожидающий поток и т.д.
    Gate { gate_id: ObjId },
    /// Линия прерываний: стабильное имя `irq` + ссылка на объект ядра.
    Irq { irq: IrqId, obj_id: ObjId },
    /// Мастер-право подсистемы IOMMU/DMA-ремаппинга (v0.9): гейт всей
    /// группы сисколов 0x80. Цель «бессмертна» (глобальный сервис —
    /// как DeviceReference): право выдаёт ядро доверенным задачам
    /// (init — менеджер устройств), отзыв — revoke производной.
    /// Ядро НЕ гарантирует уникальность держателя: политика выдачи —
    /// у стартового кода платформы.
    IommuAdmin,
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
    /// пересечением с `spec`. Метод — «чистая» функция над значениями;
    /// дерево деривации и счётчики ведёт менеджер.
    pub(crate) fn derive(&self, spec: &MintSpec) -> Self {
        Self {
            cap_ref: self.cap_ref.clone(),
            perms: self.perms & spec.perms,
            badge: self.badge.narrow(spec.badge),
        }
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

/// Запрошенное сужение при mint: какие права и какие подресурсы просит
/// производная capability. Менеджер отвечает пересечением с родителем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintSpec {
    pub perms: ActionPermissions,
    pub badge: CapabilityBadge,
}

impl MintSpec {
    /// Без сужения: производная получает те же права/badge, что родитель.
    pub const UNCHANGED: Self = Self {
        perms: ActionPermissions::all(),
        badge: CapabilityBadge::FULL,
    };
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
#[derive(Debug, Error)]
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
}

impl From<PagedError> for CapabilityError {
    fn from(_: PagedError) -> Self {
        CapabilityError::OutOfMemory
    }
}
