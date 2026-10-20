// ==== RAII-гард capability-хендла на время исполнения сискола ====
//
// Зачем гарду. Сискол — единственный вход в ядро от пользователя, и работа
// с его хендлами имеет две классические ошибки:
//   1. утечка транзитных прав: сискол заминтил производную capability
//      (сужение badge для доступа к подресурсу) и вышел по раннему
//      `return Err(..)` без отзыва — право осталось жить в cspace;
//   2. гонка живости: проверили `alive()` в начале, полстраницы кода
//      работали с целью, цель умерла (revoke в другом месте).
//
// Гард закрывает обе:
//   * [`HandleGuard::resolve`] — снимок разрешения (`CapResolved`:
//     perms/badge/TargetRef) с живостью, проверяемой в любой момент
//     одной атомарной читалкой (`alive()`); держатель не хранит ссылок
//     под RefCell менеджера;
//   * [`HandleGuard::mint_transient`] — транзитная capability, чьё
//     поддерево отзывается в `Drop` автоматически: ранние выходы и `?`
//     безопасны по построению.
//
// Гард ничего не делает сам (кроме отзыва транзита в дропе): это обвязка
// времени жизни, НЕ логика операций — семантика остаётся в менеджерах.

use core::fmt;
use core::mem::ManuallyDrop;

use crate::capability::{
    ActionPermissions, CapHandle, CapResolved, CapabilityBadge, CapabilityManager, MintSpec,
};
use crate::task::{TaskId, TcbManager};

use super::types::SyscallError;

// ───────────────────────────── Гард ─────────────────────────────

/// RAII-гард хендла вызывающей задачи: снимок разрешения + авто-отзыв
/// транзитной capability при дропе.
///
/// Два способа рождения (оба проверяют хендл в cspace владельца):
///   * [`Self::resolve`] — чистое чтение: дроп ничего не отзывает;
///   * [`Self::mint_transient`] — производная capability: дроп отзывает
///     её поддерево (`CapabilityManager::revoke`) — даже при раннем
///     выходе через `?`/панику unwind (host-сборки).
///
/// Живость цели проверяется по требованию (`alive`): между проверками
/// цель может умереть — гард честно скажет `false` (поколение TargetRef).
pub struct HandleGuard<'a> {
    /// Менеджер capability (для отзыва транзита).
    mgr: &'a CapabilityManager,
    /// Реестр задач (revoke ходит по cspace задач).
    tasks: &'a TcbManager,
    /// Владелец capability (вызывающая задача).
    owner: TaskId,
    /// Хендл транзитной capability (`Some` — только у mint_transient;
    /// дроп отзывает поддерево).
    transient: Option<CapHandle>,
    /// Снимок разрешения (права/badge/цель).
    resolved: CapResolved,
}

impl<'a> HandleGuard<'a> {
    /// Снять показания с хендла: снимок прав без права владения.
    ///
    /// Ошибки — переведённые ошибки менеджера (обычно `InvalidHandle`:
    /// «нет» и «протух» неразличимы — анти-side-channel политика крейта).
    pub fn resolve(
        mgr: &'a CapabilityManager,
        tasks: &'a TcbManager,
        owner: TaskId,
        handle: CapHandle,
    ) -> Result<Self, SyscallError> {
        let resolved = mgr
            .resolve(tasks, owner, handle)
            .map_err(SyscallError::from)?;
        Ok(Self {
            mgr,
            tasks,
            owner,
            transient: None,
            resolved,
        })
    }

    /// Породить транзитную производную от `source` и завернуть в гард:
    /// дроп гарда отзывает её поддерево.
    ///
    /// Сужение задают `spec.perms`/`spec.badge` (пересечение с родителем —
    /// инвариант менеджера). Хендл производной доступен через [`Self::handle`]
    /// (например, чтобы передать его в менеджер памяти как источник права).
    pub fn mint_transient(
        mgr: &'a CapabilityManager,
        tasks: &'a TcbManager,
        owner: TaskId,
        source: CapHandle,
        spec: &MintSpec,
    ) -> Result<Self, SyscallError> {
        let handle = mgr
            .mint(tasks, owner, source, owner, spec)
            .map_err(SyscallError::from)?;
        // Снимок ПЕРЕД возвратом: хендл только что создан, жив.
        let resolved = mgr
            .resolve(tasks, owner, handle)
            .map_err(SyscallError::from)?;
        Ok(Self {
            mgr,
            tasks,
            owner,
            transient: Some(handle),
            resolved,
        })
    }

    /// Права capability (снимок на момент создания гарда).
    #[inline]
    pub fn perms(&self) -> ActionPermissions {
        self.resolved.perms
    }

    /// Маска подресурсов (badge).
    #[inline]
    pub fn badge(&self) -> CapabilityBadge {
        self.resolved.badge
    }

    /// Жива ли цель (проверка по требованию — см. документацию типа).
    #[inline]
    pub fn alive(&self) -> bool {
        self.resolved.alive()
    }

    /// Хендл транзитной capability (`None` у resolve-гарда). Значение —
    /// для передачи в менеджеры; отзыв — только дропом гарда.
    #[inline]
    pub fn handle(&self) -> Option<CapHandle> {
        self.transient
    }

    /// Задача-владелец cspace (для аудита).
    #[inline]
    pub fn owner(&self) -> TaskId {
        self.owner
    }

    /// Забрать снимок разрешения, ОТМЕНИВ авто-отзыв транзита.
    ///
    /// Единственный легальный способ оставить транзитную capability
    /// жить дольше гарда (например, сискол решил выдать её пользователю
    /// как результат): владение правом переходит вызывающему, отзыв —
    /// его забота (хендл у него, см. [`Self::handle`] до забора).
    pub fn into_resolved(self) -> (CapResolved, Option<CapHandle>) {
        // ManuallyDrop: забираем поля до дропа обёртки — Drop гарда
        // (авто-отзыв) не выполняется.
        let this = ManuallyDrop::new(self);
        // SAFETY: this больше не дропнется (ManuallyDrop), поля читаются
        // один раз по живому адресу.
        unsafe {
            (
                core::ptr::read(&this.resolved),
                core::ptr::read(&this.transient),
            )
        }
    }
}

impl Drop for HandleGuard<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.transient.take() {
            // Транзитная capability: отзываем ПОДДЕРЕВО (revoke гасит и
            // производные, если сискол успел наминтить их от транзита).
            // Отказ ретраить некому (дроп) — съедаем: потерянный транзит
            // виден аудиту cspace и чистится revoke_all при гибели задачи.
            let _ = self.mgr.revoke(self.tasks, self.owner, handle);
        }
    }
}

impl fmt::Debug for HandleGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleGuard")
            .field("owner", &self.owner)
            .field("transient", &self.transient)
            .field("perms", &self.resolved.perms)
            .field("badge", &self.resolved.badge)
            .field("alive", &self.resolved.alive())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::capability::{
        ActionPermissions, CapabilityBadge, CapabilityGate, ContainerACCCapability, MintSpec,
    };
    use crate::task::{TaskPriority, TcbManager};

    use super::*;
    /// Детерминированно-уникальный TaskId для тестов: uuid без фичи v4 —
    /// генератора нет, счётчик процесса даёт достаточную уникальность.
    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    /// Менеджеры утекают в статике: дроп TcbManager с живыми capability
    /// честно паникует debug-ассертом (контракт разрыва ядра) — тестам
    /// полный tear-down не нужен, enough утечь.
    fn setup() -> (
        &'static TcbManager,
        &'static CapabilityManager,
        TaskId,
        CapHandle,
    ) {
        use alloc::boxed::Box;
        let tasks = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps = Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();

        // Корневой grant на сам TCB задачи.
        let gate = CapabilityGate::new(
            ContainerACCCapability::TaskTCB { task_id: task },
            ActionPermissions::all(),
            CapabilityBadge::FULL,
        );
        let handle = caps.grant(tasks, task, gate).unwrap();
        (tasks, caps, task, handle)
    }

    #[test]
    fn resolve_guard_reads_without_side_effects() {
        let (tasks, caps, task, handle) = setup();

        let guard = HandleGuard::resolve(caps, tasks, task, handle).unwrap();
        assert_eq!(guard.perms(), ActionPermissions::all());
        assert_eq!(guard.badge(), CapabilityBadge::FULL);
        assert!(guard.alive());
        assert_eq!(guard.handle(), None, "resolve-гард не транзитен");
        assert_eq!(guard.owner(), task);

        // Дроп чистого чтения не меняет cspace.
        let before = caps.task_cap_count(tasks, task).unwrap();
        drop(guard);
        assert_eq!(caps.task_cap_count(tasks, task), Some(before));
    }

    #[test]
    fn resolve_rejects_foreign_and_stale_handles() {
        let (tasks, caps, task, handle) = setup();

        // Чужая задача: её cspace пуст — хендл неотличим от битого.
        let stranger = uuid_next();
        tasks.create(stranger, TaskPriority::DEFAULT).unwrap();
        let err = HandleGuard::resolve(caps, tasks, stranger, handle).unwrap_err();
        assert_eq!(err, SyscallError::InvalidHandle);

        // Протухший хендл: поколение слота побито.
        let stale = CapHandle::new(handle.idx(), handle.generation().wrapping_add(1));
        let err = HandleGuard::resolve(caps, tasks, task, stale).unwrap_err();
        assert_eq!(err, SyscallError::InvalidHandle);
    }

    #[test]
    fn transient_guard_revokes_on_drop() {
        let (tasks, caps, task, handle) = setup();

        let spec = MintSpec {
            perms: ActionPermissions::Send,
            badge: CapabilityBadge::from_bits(0xFF),
        };

        let guard = HandleGuard::mint_transient(caps, tasks, task, handle, &spec).unwrap();
        assert_eq!(guard.handle(), Some(guard.handle().unwrap()));
        assert_eq!(guard.perms(), ActionPermissions::Send, "сужение прав");
        assert!(guard.badge().contains(CapabilityBadge::from_bits(0xFF)));

        // Транзит жив, пока жив гард: два слота в cspace.
        assert_eq!(caps.task_cap_count(tasks, task), Some(2));

        // Ранний выход по `?`-стилю (макет): дроп отзывает транзит.
        let result: Result<(), SyscallError> = (|| {
            let _g = HandleGuard::mint_transient(caps, tasks, task, handle, &spec)?;
            Err(SyscallError::NotFound) // имитация отказа после транзита
        })();
        assert_eq!(result, Err(SyscallError::NotFound));
        assert_eq!(caps.task_cap_count(tasks, task), Some(2));

        // Дроп основного гарда — только 1 слот (корневой).
        drop(guard);
        assert_eq!(caps.task_cap_count(tasks, task), Some(1));
    }

    #[test]
    fn into_resolved_disarms_auto_revoke() {
        let (tasks, caps, task, handle) = setup();

        let spec = MintSpec {
            perms: ActionPermissions::Send,
            badge: CapabilityBadge::FULL,
        };
        let guard = HandleGuard::mint_transient(caps, tasks, task, handle, &spec).unwrap();
        let transient = guard.handle().unwrap();

        // Забираем снимок + отменяем авто-отзыв: транзит остаётся жить.
        let (resolved, kept) = guard.into_resolved();
        assert_eq!(kept, Some(transient));
        assert_eq!(resolved.perms, ActionPermissions::Send);

        // Транзит не отозван — в cspace два слота.
        assert_eq!(caps.task_cap_count(tasks, task), Some(2));
        // Явная уборка (обязанность забравшего).
        caps.revoke(tasks, task, transient).unwrap();
        assert_eq!(caps.task_cap_count(tasks, task), Some(1));
    }
}
