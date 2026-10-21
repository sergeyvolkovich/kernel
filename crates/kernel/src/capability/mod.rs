// ==== Менеджер capability (двухуровневая схема) ====
//
// Замена схемы «RB-дерево + Uuid на горячем пути» (по плану из обсуждения):
//
// ```text
//   Уровень 1 — глобальные объекты ядра (страничные таблицы, type-stable):
//     TcbManager::tasks: PagedTable<TaskObj>     цель TaskTCB
//     CapabilityManager::gates: PagedTable<GateObj>   цель Gate (IPC)
//     CapabilityManager::irqs:  PagedTable<IrqObj>    цель Irq
//     устройства — без объекта: DeviceReference адресует DeviceManager
//     по DevicePath (вне крейта), цель «бессмертна» на этом слое.
//
//   Уровень 2 — cspace задачи: HandleTable = PagedTable<Cte> в TaskObj,
//     хендл = CapHandle (idx, generation), локален задаче, как fd с поколением.
// ```
//
// CTE (capability-table entry) — один объект, два членства (всё через
// собственные линк-поля):
// ```text
//   Cte
//   ├─ (лежит в слоте HandleTable владельца)   хендл = (self_idx, hdr.generation)
//   └─ child_link ∈ parent.children            дерево деривации (mint)
// ```
//
// Инварианты (проверки — debug_assert в горячих путях):
// 1. Живой CTE ровно один раз занимает слот своей HandleTable; generation-слово
//    слота — авторитет живости (переиспользование продолжает счёт).
// 2. Слот с родителем P состоит в P.children; родитель жив, пока есть
//    дети (delete/revoke перепривязывают/гасят детей до освобождения).
// 3. Права/badge ребёнка ⊆ родителя (монотонное сужение).
// 4. Память слота возвращается в страницу только после снятия со всех
//    членств; порядок уничтожения: generation вверх → drop (порядок из плана).
//
// Синхронизация: RefCell (ядро однопоточное). Мутации хендл-таблиц идут
// через `TcbManager::with_caps_mut`, объектов гейтов/IRQ — через RefCell
// менеджера; узлы Cte правятся по сырым указателям под эксклюзивностью
// borrow_mut (тот же контракт, что в прежней версии).
//
// Горячий путь (`resolve_slot`, O(1), без деревьев):
// ```text
//   task SlotRef → TaskObj (2 обращения, страницы)
//     → caps.get(idx, generation) → generation слота CTE → perms
//     → alive(target) (одно чтение generation) [+ alive(owner) для Gate/Irq]
// ```

pub mod mem;
pub mod paged;
pub mod types;

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::sync::{KSpin, RawGate};
use core::ptr::NonNull;

use intrusive_collections::{LinkedList, LinkedListLink, UnsafeRef, intrusive_adapter};

use crate::capability::paged::{KernelObj, ObjHeader, PagedTable, SlotRef, TargetRef};
use crate::task::{TaskId, TcbManager};

pub use types::{
    ActionPermissions, CapHandle, CapResolved, CapabilityBadge, CapabilityError, CapabilityGate,
    CapabilityView, ContainerACCCapability, EndpointState, IrqId, MintSpec, ObjId, ParentRef,
    RevokeReport,
};

/// Слотов на страницу хендл-таблицы. Страница = 4 + 8 * sizeof(Cte) ≈ 1.2 КБ:
/// slab требует ≥ 2 слотов размера страницы в slab-е 4 КБ.
const CTE_PAGE_SLOTS: usize = 8;
/// Страниц в каталоге: квота — 256 хендлов на задачу (подгони под квоту).
const CTE_DIR_LEN: usize = 32;

/// Слотов/страниц для гейтов: квота 256 гейтов на систему.
const GATE_PAGE_SLOTS: usize = 16;
const GATE_DIR_LEN: usize = 16;
/// Слотов/страниц для линий прерываний: квота 256.
const IRQ_PAGE_SLOTS: usize = 16;
const IRQ_DIR_LEN: usize = 16;

// ==== CTE: слот хендл-таблицы ====

/// Capability-table entry: слот локальной таблицы хендлов задачи.
/// Первый объект, чей адрес никогда не меняется, пока слот жив.
#[repr(C)]
pub(crate) struct Cte {
    /// Поколение слота (первое поле — контракт [`KernelObj`]; входит в
    /// пользовательский хендл).
    hdr: ObjHeader,
    /// Собственный индекс в таблице владельца (free без обратного маппинга).
    self_idx: u32,
    /// Владелец (куда включён этот CTE). Меняется при send.
    owner: TaskId,
    /// Цель: указатель на ObjHeader + поколение (кэш разрешения, шаг 2).
    target: TargetRef,
    /// Стабильное имя цели (аудит/отладка; горячий путь не читает).
    cap_ref: ContainerACCCapability,
    perms: ActionPermissions,
    badge: CapabilityBadge,
    /// Родитель по деривации: generation-защищённая ссылка на чужой CTE
    /// (+ индекс родителя для реконструкции его хендла).
    parent: Option<CteRef>,
    /// Якорь списка детей этого слота.
    children: LinkedList<CteChildrenAdapter>,
    /// Членство в списке детей родителя.
    child_link: LinkedListLink,
}

/// Ссылка на CTE: как `TargetRef`, плюс индекс слота — чтобы восстановить
/// хендл родителя в аудите (`CapabilityView.parent`).
#[derive(Clone, Copy)]
pub(crate) struct CteRef {
    target: TargetRef,
    idx: u32,
}

impl CteRef {
    /// Хендл родительского CTE в cspace его владельца.
    fn handle(&self) -> CapHandle {
        CapHandle::new(self.idx, self.target.generation())
    }
}

unsafe impl KernelObj for Cte {
    fn hdr(&self) -> &ObjHeader {
        &self.hdr
    }
}
const _: () = assert!(core::mem::offset_of!(Cte, hdr) == 0);

intrusive_adapter!(pub(crate) CteChildrenAdapter = UnsafeRef<Cte>: Cte { child_link => LinkedListLink });

/// Локальная таблица хендлов задачи (уровень 2).
pub(crate) type HandleTable = PagedTable<Cte, CTE_PAGE_SLOTS, CTE_DIR_LEN>;

impl Cte {
    /// Корневой CTE (без родителя). Права/badge назначает грантодатель.
    fn root(
        idx: u32,
        generation: u32,
        owner: TaskId,
        target: TargetRef,
        gate: &CapabilityGate,
    ) -> Self {
        Self {
            hdr: ObjHeader::new(generation),
            self_idx: idx,
            owner,
            target,
            cap_ref: gate.cap_ref().clone(),
            perms: gate.perms(),
            badge: gate.badge(),
            parent: None,
            children: LinkedList::new(CteChildrenAdapter::new()),
            child_link: LinkedListLink::new(),
        }
    }

    fn view(&self) -> CapabilityView {
        CapabilityView {
            id: CapHandle::new(self.self_idx, self.hdr.generation()),
            owner: self.owner,
            parent: self.parent.map(|p| {
                // SAFETY: родитель жив, пока есть дети (инвариант 2),
                // и состоит в чьей-то таблице — чтение owner безопасно.
                let pc: &Cte = unsafe { &*(p.target.hdr_ptr().as_ptr() as *const Cte) };
                ParentRef {
                    task: pc.owner,
                    handle: p.handle(),
                }
            }),
            perms: self.perms,
            badge: self.badge,
            cap_ref: self.cap_ref.clone(),
        }
    }
}

// ==== Объекты ядра: гейт и линия прерываний ====

/// IPC-гейт как самостоятельный объект (шаг 3 из плана): всё нужное для
/// отправки лежит в одном месте, проверка «жив ли владелец» не требует
/// спуска — ленивые две проверки generation (гейт + владелец).
#[repr(C)]
pub(crate) struct GateObj {
    /// Поколение объекта (первое поле — контракт [`KernelObj`]).
    hdr: ObjHeader,
    /// Владелец-задача: generation-защищённая ссылка на TaskObj (ленивая
    /// проверка №2 в горячем пути).
    owner: TargetRef,
    /// Состояние endpoint'а. Плейсхолдер до появления IPC-подсистемы.
    endpoint: EndpointState,
}

unsafe impl KernelObj for GateObj {
    fn hdr(&self) -> &ObjHeader {
        &self.hdr
    }
}
const _: () = assert!(core::mem::offset_of!(GateObj, hdr) == 0);

type GateTable = PagedTable<GateObj, GATE_PAGE_SLOTS, GATE_DIR_LEN>;

// ───────────────────── Пер-gate локи IPC-rendezvous (SMP v0.12) ─────────────────────

/// Статическая таблица локов критсекций rendezvous: ключ — СЛОТ таблицы
/// гейтов (16×16 = 256). Стабильность ключа снимает проблему времени
/// жизни лока: destroy_gate и переиспользование слота не инвалидируют
/// лок (переиспользованный слот — тот же лок, сериализация корректна);
/// держатели не хранят указателей на объект гейта.
static GATE_LOCKS: [RawGate; GATE_PAGE_SLOTS * GATE_DIR_LEN] =
    [const { RawGate::new() }; GATE_PAGE_SLOTS * GATE_DIR_LEN];

/// Лок endpoint'а по идентификатору гейта — для критсекций `crate::ipc`
/// (ранг GATE — см. `crate::sync`). `debug_assert` вместо паники:
/// ObjId гейтов рождаются только из таблицы этой ёмкости (битые —
/// отсеивает generation-проверка `with_endpoint`).
pub(crate) fn gate_lock(gate: ObjId) -> &'static RawGate {
    let idx = gate.idx() as usize;
    debug_assert!(
        idx < GATE_LOCKS.len(),
        "gate idx вне таблицы локов (битый ObjId?)"
    );
    // Выход за границы невозможен по построению ёмкости; безопасный
    // кламп вместо паники в release.
    &GATE_LOCKS[idx.min(GATE_LOCKS.len() - 1)]
}

struct GateSpace {
    gates: GateTable,
}

/// Объект линии прерываний. Плейсхолдер отцепления обработчика живёт
/// в revocation-семантике: generation вверх — все capability на линию гаснут.
#[repr(C)]
pub(crate) struct IrqObj {
    hdr: ObjHeader,
    owner: TargetRef,
    /// Стабильное имя линии (GSI).
    irq: IrqId,
}

unsafe impl KernelObj for IrqObj {
    fn hdr(&self) -> &ObjHeader {
        &self.hdr
    }
}
const _: () = assert!(core::mem::offset_of!(IrqObj, hdr) == 0);

type IrqTable = PagedTable<IrqObj, IRQ_PAGE_SLOTS, IRQ_DIR_LEN>;

struct IrqSpace {
    irqs: IrqTable,
}

// ==== Менеджер ====

/// Менеджер capability: локальные cspace (в объектах задач) + глобальные
/// таблицы гейтов и линий прерываний + дерево деривации с рекурсивным
/// revoke и badge-сужением.
///
/// Менеджер заимствует реестр задач: хендл-таблица каждой задачи лежит
/// в её TaskObj, операции идут через `TcbManager::with_caps_mut`.
pub struct CapabilityManager {
    gates: KSpin<GateSpace>,
    irqs: KSpin<IrqSpace>,
    /// Эпоха отзывов для inline-cache (SMP v0.12: AtomicU64).
    epoch: AtomicU64,
    /// Суммарное число живых CTE во всех cspace (SMP v0.12: атомик).
    live: AtomicUsize,
}

impl CapabilityManager {
    /// Пустой менеджер над реестром задач `tasks`.
    pub fn new() -> Result<Self, CapabilityError> {
        Ok(Self {
            gates: KSpin::new(GateSpace {
                gates: PagedTable::new()?,
            }),
            irqs: KSpin::new(IrqSpace {
                irqs: PagedTable::new()?,
            }),
            epoch: AtomicU64::new(0),
            live: AtomicUsize::new(0),
        })
    }

    // ==== Гранты ====

    /// Выдаёт задаче корневую capability (без родителя). Права и badge
    /// назначает грантодатель — этот метод и есть точка входа доверия.
    ///
    /// Для `TaskTCB`-гейта задача `task_id` обязана быть зарегистрирована
    /// и жива (иначе [`CapabilityError::UnknownTaskTarget`]). Гейты и линии
    /// прерываний грантами не выдаются: их объекты создаются
    /// [`Self::create_gate`] / [`Self::create_irq`].
    pub fn grant(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        gate: CapabilityGate,
    ) -> Result<CapHandle, CapabilityError> {
        let target = match gate.cap_ref() {
            ContainerACCCapability::DeviceReference { .. } => {
                // Устройство адресуется по пути; живость контролирует
                // DeviceManager вне крейта. Цель «бессмертна», отзыв —
                // через revoke capability.
                TargetRef::immortal()
            }
            ContainerACCCapability::TaskTCB { task_id } => tasks
                .target_ref(task_id)
                .ok_or(CapabilityError::UnknownTaskTarget(*task_id))?,
            // Мастер-право IOMMU (v0.9): глобальный сервис ядра — цель
            // «бессмертна», как у устройств; право живёт, пока не отозвано.
            ContainerACCCapability::IommuAdmin => TargetRef::immortal(),
            ContainerACCCapability::Gate { .. } | ContainerACCCapability::Irq { .. } => {
                return Err(CapabilityError::Internal);
            }
        };

        match tasks.with_caps_mut(&task, |t| {
            t.alloc(|idx, generation| Cte::root(idx, generation, task, target, &gate))
                .map_err(CapabilityError::from)
        }) {
            Some(Ok(sr)) => {
                self.live.fetch_add(1, Ordering::Relaxed);
                Ok(CapHandle::new(sr.idx, sr.generation))
            }
            Some(Err(e)) => Err(e),
            None => Err(CapabilityError::TaskNotFound(task)),
        }
    }

    // ==== Деривация и передача ====

    /// Порождает производную capability от хендла `src` (в cspace
    /// `src_task`) в cspace задачи `dst_task`.
    ///
    /// Требует права `Mint` у источника. Права и badge производной —
    /// пересечение с запрошенными (`MintSpec`): производная никогда не
    /// шире родителя. Производная сразу получает `TargetRef` на цель —
    /// без дополнительного поиска (шаг 3 из плана).
    pub fn mint(
        &self,
        tasks: &TcbManager,
        src_task: TaskId,
        src: CapHandle,
        dst_task: TaskId,
        spec: &MintSpec,
    ) -> Result<CapHandle, CapabilityError> {
        // 1. Снимок источника: валидация, сужение, ссылки. Shared borrow
        //    отпускаем до мутаций.
        let (child_gate, child_target, parent_ref) = {
            let got = tasks.with_caps(&src_task, |t| {
                let cte = t
                    .get(src.idx(), src.generation())
                    .ok_or(CapabilityError::InvalidHandle(src))?;
                if !cte.perms.contains(ActionPermissions::Mint) {
                    return Err(CapabilityError::MissingRight {
                        id: src,
                        required: ActionPermissions::FOR_MINT,
                    });
                }
                let parent = CapabilityGate::new(cte.cap_ref.clone(), cte.perms, cte.badge);
                Ok((
                    parent.derive(spec),
                    cte.target,
                    CteRef {
                        target: TargetRef::from_obj(cte),
                        idx: src.idx(),
                    },
                ))
            });
            match got {
                None => return Err(CapabilityError::TaskNotFound(src_task)),
                Some(Err(e)) => return Err(e),
                Some(Ok(v)) => v,
            }
        };

        // 2. Новый CTE в таблице получателя (сбой — чистый откат: ничего
        //    не привязано).
        let (child_sr, child_ptr) = match tasks.with_caps_mut(&dst_task, |t| {
            let sr = t
                .alloc(|idx, generation| {
                    Cte::root(idx, generation, dst_task, child_target, &child_gate)
                })
                .map_err(CapabilityError::from)?;
            // Обратная ссылка на родителя — часть дерева деривации
            // (инвариант 2: узел с родителем состоит и в его children).
            let node = t
                .get_mut(sr.idx, sr.generation)
                .expect("слот только что выделен");
            node.parent = Some(parent_ref);
            Ok((sr, NonNull::from(node)))
        }) {
            Some(Ok(v)) => v,
            Some(Err(e)) => return Err(e),
            None => return Err(CapabilityError::TaskNotFound(dst_task)),
        };

        // 3. Привязка к дереву деривации: push в children родителя.
        //    Родитель жив (шаг 1, однопоточно — между шагами никто не
        //    исполнялся).
        let pushed = tasks.with_caps_mut(&src_task, |_t| {
            // SAFETY: parent_ref — живой CTE источника; hdr по смещению 0,
            // эксклюзивность обеспечена borrow_mut менеджера задач.
            let parent: &mut Cte =
                unsafe { &mut *(parent_ref.target.hdr_ptr().as_ptr() as *mut Cte) };
            // SAFETY: ребёнок только что создан, ни в одном контейнере.
            parent
                .children
                .push_back(unsafe { UnsafeRef::from_raw(child_ptr.as_ptr()) });
        });
        debug_assert!(pushed.is_some(), "источник существовал на шаге 1");

        self.live.fetch_add(1, Ordering::Relaxed);
        Ok(CapHandle::new(child_sr.idx, child_sr.generation))
    }

    /// Передаёт хендл `src` (владелец `src_task`) в cspace задачи
    /// `dst_task` (transfer, без деривации): цель, права, badge и место в
    /// дереве деривации сохраняются, меняется владелец.
    ///
    /// Требует права `Send`. Передача «себе» допустима. Возвращает НОВЫЙ
    /// хендл у получателя — хендлы локальны cspace и не переносятся 1:1;
    /// старый хендл гасится (generation слота вверх).
    pub fn send(
        &self,
        tasks: &TcbManager,
        src_task: TaskId,
        src: CapHandle,
        dst_task: TaskId,
    ) -> Result<CapHandle, CapabilityError> {
        // 1. Валидация источника: право Send + снимок данных.
        let (old_ptr, target, cap_ref, perms, badge) = {
            let got = tasks.with_caps_mut(&src_task, |t| {
                let cte = t
                    .get_mut(src.idx(), src.generation())
                    .ok_or(CapabilityError::InvalidHandle(src))?;
                if !cte.perms.contains(ActionPermissions::Send) {
                    return Err(CapabilityError::MissingRight {
                        id: src,
                        required: ActionPermissions::FOR_SEND,
                    });
                }
                let (target, cap_ref, perms, badge) =
                    (cte.target, cte.cap_ref.clone(), cte.perms, cte.badge);
                let ptr = NonNull::from(cte);
                Ok((ptr, target, cap_ref, perms, badge))
            });
            match got {
                None => return Err(CapabilityError::TaskNotFound(src_task)),
                Some(Err(e)) => return Err(e),
                Some(Ok(v)) => v,
            }
        };

        // 2. Получатель существует?
        if tasks.with_caps_mut(&dst_task, |_| ()).is_none() {
            return Err(CapabilityError::TaskNotFound(dst_task));
        }

        // 3. Новый CTE у получателя (сбой — чистый откат).
        let (new_sr, new_ptr) = match tasks.with_caps_mut(&dst_task, |t| {
            let gate = CapabilityGate::new(cap_ref.clone(), perms, badge);
            let sr = t
                .alloc(|idx, generation| Cte::root(idx, generation, dst_task, target, &gate))
                .map_err(CapabilityError::from)?;
            let ptr = {
                let node = t
                    .get_mut(sr.idx, sr.generation)
                    .expect("слот только что выделен");
                core::ptr::from_mut(node)
            };
            Ok((sr, ptr))
        }) {
            Some(Ok(v)) => v,
            Some(Err(e)) => return Err(e),
            None => return Err(CapabilityError::TaskNotFound(dst_task)),
        };

        // 4. Перенос деривации: дети переезжают от old к new, new занимает
        //    место old в родителе (id/место сохраняются семантически).
        tasks.with_caps_mut(&src_task, |_t| {
            // SAFETY: old — живой CTE источника (шаг 1), new — только что
            // созданный; однопоточная эксклюзивность под borrow_mut.
            let old: &mut Cte = unsafe { &mut *old_ptr.as_ptr() };
            let new: &mut Cte = unsafe { &mut *new_ptr };
            let new_ref = CteRef {
                target: TargetRef::from_obj(new),
                idx: new_sr.idx,
            };

            // 4а. Дети переезжают к new.
            while let Some(child) = old.children.pop_front() {
                // SAFETY: ребёнок — живой узел дерева деривации.
                unsafe { (*UnsafeRef::into_raw(child.clone())).parent = Some(new_ref) };
                new.children.push_back(child);
            }

            // 4б. new занимает место old.
            new.parent = old.parent;
            if let Some(p) = old.parent {
                // SAFETY: родитель жив, пока есть дети (инвариант 2).
                let pm: &mut Cte = unsafe { &mut *(p.target.hdr_ptr().as_ptr() as *mut Cte) };
                // Отвязка ОБЯЗАНА исполняться и в release: v0.11-баг
                // «debug_assert!(remove_from_children(..))» — в release
                // debug_assert не вычисляет выражение, узел оставался в
                // списке родителя «призраком» (freed-слот в чужой
                // children-голове) — на повторном использовании адреса
                // слота это даёт KERNEL FAULT в intrusive-unlink.
                if !remove_from_children(&mut pm.children, old_ptr) {
                    Self::audit_inconsistent_tree(
                        "send: old not in parent list",
                        p.target.hdr_ptr().cast::<Cte>(),
                        old_ptr,
                    );
                }
                pm.children
                    .push_back(unsafe { UnsafeRef::from_raw(new_ptr) });
            }
            old.parent = None;
        });

        // 5. Старый CTE гасим: generation слота вверх → старый хендл умирает.
        let freed = tasks.with_caps_mut(&src_task, |t| t.free(src.idx()));
        debug_assert!(freed == Some(true), "старый слот обязан быть живым");

        self.epoch.fetch_add(1, Ordering::AcqRel); // любой отзыв прав — эпоха
        Ok(CapHandle::new(new_sr.idx, new_sr.generation))
    }

    // ==== Удаление и отзыв ====

    /// Удаляет один хендл. Дети НЕ отзываются: они перепривязываются к
    /// родителю удаляемого (инвариант монотонности сохраняется). Полное
    /// гашение поддерева — [`Self::revoke`].
    pub fn delete(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        id: CapHandle,
    ) -> Result<(), CapabilityError> {
        // 1. Находим узел (эксклюзивно).
        let old_ptr = match tasks.with_caps_mut(&task, |t| {
            let cte = t
                .get_mut(id.idx(), id.generation())
                .ok_or(CapabilityError::InvalidHandle(id))?;
            Ok(NonNull::from(cte))
        }) {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(e),
            None => return Err(CapabilityError::TaskNotFound(task)),
        };

        // 2. Дети вверх (к родителю удаляемого либо в корни), unlink из
        //    родителя.
        tasks.with_caps_mut(&task, |_t| {
            // SAFETY: old жив (шаг 1), эксклюзивно под borrow_mut.
            let old: &mut Cte = unsafe { &mut *old_ptr.as_ptr() };
            let parent = old.parent;
            while let Some(child) = old.children.pop_front() {
                // SAFETY: ребёнок — живой узел.
                unsafe { (*UnsafeRef::into_raw(child.clone())).parent = parent };
                if let Some(p) = parent {
                    // SAFETY: родитель жив (инвариант 2).
                    let pm: &mut Cte = unsafe { &mut *(p.target.hdr_ptr().as_ptr() as *mut Cte) };
                    pm.children.push_back(child);
                }
                // У корня без родителя дети становятся корнями.
            }
            if let Some(p) = parent {
                // SAFETY: родитель жив (инвариант 2).
                let pm: &mut Cte = unsafe { &mut *(p.target.hdr_ptr().as_ptr() as *mut Cte) };
                // Отвязка ОБЯЗАНА исполняться и в release (см. send:
                // debug_assert-обёртка не выполняла её — «призрак»).
                if !remove_from_children(&mut pm.children, old_ptr) {
                    Self::audit_inconsistent_tree(
                        "delete: old not in parent list",
                        p.target.hdr_ptr().cast::<Cte>(),
                        old_ptr,
                    );
                }
            }
            old.parent = None;
        });

        // 3. Слот хендл-таблицы освобождаем (generation вверх → хендл умирает).
        let freed = tasks.with_caps_mut(&task, |t| t.free(id.idx()));
        debug_assert!(freed == Some(true), "слот обязан быть живым");
        self.live.fetch_sub(1, Ordering::Relaxed);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Отзывает хендл и ВСЁ его дерево производных (в любых задачах).
    /// Возвращает отчёт с числом погашенных слотов.
    pub fn revoke(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        id: CapHandle,
    ) -> Result<RevokeReport, CapabilityError> {
        let old_ptr = match tasks.with_caps_mut(&task, |t| {
            let cte = t
                .get_mut(id.idx(), id.generation())
                .ok_or(CapabilityError::InvalidHandle(id))?;
            Ok(NonNull::from(cte))
        }) {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(e),
            None => return Err(CapabilityError::TaskNotFound(task)),
        };

        let revoked = self.revoke_node(tasks, old_ptr, true);
        self.live.fetch_sub(revoked, Ordering::Relaxed);
        self.epoch.fetch_add(1, Ordering::AcqRel);

        Ok(RevokeReport {
            revoked_slots: revoked,
        })
    }

    /// Отзывает все capability задачи (её cspace целиком + все производные,
    /// осевшие в других задачах). Стандартный шаг перед
    /// `TcbManager::destroy`.
    pub fn revoke_all(
        &self,
        tasks: &TcbManager,
        task: TaskId,
    ) -> Result<RevokeReport, CapabilityError> {
        if tasks.with_caps(&task, |_| ()).is_none() {
            return Err(CapabilityError::TaskNotFound(task));
        }
        let revoked = self.revoke_all_for(tasks, task);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(RevokeReport {
            revoked_slots: revoked,
        })
    }

    // ==== Гейты (IPC) ====

    /// Создаёт IPC-гейт, принадлежащий `owner`, и выдаёт ему корневую
    /// capability. Владелец гасит гейт через [`Self::destroy_gate`]; все
    /// производные capability гаснут по поколению объекта (лениво).
    pub fn create_gate(
        &self,
        tasks: &TcbManager,
        owner: TaskId,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Result<CapHandle, CapabilityError> {
        let owner_ref = tasks
            .target_ref(&owner)
            .ok_or(CapabilityError::TaskNotFound(owner))?;

        // 1. Объект гейта в глобальной таблице.
        // Легаси-путь: endpoint без буфера и очередей (рендевуз-режим для
        // платформ без планировщика); полный endpoint — `create_endpoint`.
        let gr = self
            .gates
            .lock()
            .gates
            .alloc(|_idx, generation| GateObj {
                hdr: ObjHeader::new(generation),
                owner: owner_ref,
                endpoint: EndpointState::default(),
            })
            .map_err(CapabilityError::from)?;
        let gate_id = ObjId::new(gr.idx, gr.generation);
        let target = self.gate_target(gr);

        // 2. Корневой CTE у владельца; при неудаче откатываем объект.
        let gate = CapabilityGate::new(ContainerACCCapability::Gate { gate_id }, perms, badge);
        let created = tasks.with_caps_mut(&owner, |t| {
            t.alloc(|idx, generation| Cte::root(idx, generation, owner, target, &gate))
                .map_err(CapabilityError::from)
        });
        match created {
            Some(Ok(sr)) => {
                self.live.fetch_add(1, Ordering::Relaxed);
                Ok(CapHandle::new(sr.idx, sr.generation))
            }
            Some(Err(e)) => {
                // Откат: объект гейта больше никому не нужен.
                self.gates.lock().gates.free(gr.idx);
                Err(e)
            }
            None => {
                self.gates.lock().gates.free(gr.idx);
                Err(CapabilityError::TaskNotFound(owner))
            }
        }
    }

    /// Гасит IPC-гейт по хендлу владельца. Объект гасится сразу (generation вверх,
    /// потом drop — порядок из плана): все capability на гейт, включая
    /// производные в других задачах, протухают лениво — их слоты чистят
    /// владельцы через `delete`/`revoke_all` (медленный путь).
    pub fn destroy_gate(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        handle: CapHandle,
    ) -> Result<(), CapabilityError> {
        let gate_id = tasks
            .with_caps(&task, |t| {
                match &t.get(handle.idx(), handle.generation())?.cap_ref {
                    ContainerACCCapability::Gate { gate_id } => Some(*gate_id),
                    _ => None,
                }
            })
            .flatten()
            .ok_or(CapabilityError::InvalidHandle(handle))?;

        let freed = self.gates.lock().gates.free(gate_id.idx());
        debug_assert!(freed, "объект гейта обязан быть живым");
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    // ==== Endpoint'ы (IPC-подсистема) ====

    /// Создать IPC-endpoint с полным состоянием (вызывается
    /// `crate::ipc::IpcManager::create_endpoint`): буфер ёмкости `capacity`
    /// + две очереди блокировки планировщика (send/recv).
    ///
    /// `capacity = 0` — строгий rendezvous (L4 sync IPC), `> 0` —
    /// буферизация (notification-канал). Семантика — в `crate::ipc`.
    pub fn create_endpoint(
        &self,
        tasks: &TcbManager,
        owner: TaskId,
        capacity: usize,
        send_q: crate::task::scheduler::BlockQueueId,
        recv_q: crate::task::scheduler::BlockQueueId,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Result<CapHandle, CapabilityError> {
        let owner_ref = tasks
            .target_ref(&owner)
            .ok_or(CapabilityError::TaskNotFound(owner))?;

        // 1. Объект гейта с реальным состоянием endpoint'а.
        let gr = self
            .gates
            .lock()
            .gates
            .alloc(|_idx, generation| GateObj {
                hdr: ObjHeader::new(generation),
                owner: owner_ref,
                endpoint: EndpointState::new(capacity, send_q, recv_q),
            })
            .map_err(CapabilityError::from)?;
        let gate_id = ObjId::new(gr.idx, gr.generation);
        let target = self.gate_target(gr);

        // 2. Корневой CTE у владельца; при неудаче откатываем объект.
        let gate = CapabilityGate::new(ContainerACCCapability::Gate { gate_id }, perms, badge);
        let created = tasks.with_caps_mut(&owner, |t| {
            t.alloc(|idx, generation| Cte::root(idx, generation, owner, target, &gate))
                .map_err(CapabilityError::from)
        });
        match created {
            Some(Ok(sr)) => {
                self.live.fetch_add(1, Ordering::Relaxed);
                Ok(CapHandle::new(sr.idx, sr.generation))
            }
            Some(Err(e)) => {
                self.gates.lock().gates.free(gr.idx);
                Err(e)
            }
            None => {
                self.gates.lock().gates.free(gr.idx);
                Err(CapabilityError::TaskNotFound(owner))
            }
        }
    }

    /// Доступ к состоянию endpoint'а (буфер/очереди) для IPC-подсистемы.
    /// `None` — гейт не существует/погашен. Реентери в методы менеджера
    /// capability из замыкания — паника заимствования.
    pub(crate) fn with_endpoint<R>(
        &self,
        gate: ObjId,
        f: impl FnOnce(&mut EndpointState) -> R,
    ) -> Option<R> {
        let mut space = self.gates.lock();
        let g = space.gates.get_mut(gate.idx(), gate.generation())?;
        Some(f(&mut g.endpoint))
    }

    /// Пер-gate лок endpoint'а (критсекции rendezvous `crate::ipc`):
    /// делегирует статической таблице `GATE_LOCKS` по слоту гейта.
    pub(crate) fn gate_lock(&self, gate: ObjId) -> &'static RawGate {
        gate_lock(gate)
    }

    /// ObjId гейта по хендлу в cspace задачи (маршрутизация IPC-операций:
    /// capability -> endpoint). `None` — хендл битый или не гейт.
    pub fn endpoint_of(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        handle: CapHandle,
    ) -> Option<ObjId> {
        tasks
            .with_caps(&task, |t| {
                match &t.get(handle.idx(), handle.generation())?.cap_ref {
                    ContainerACCCapability::Gate { gate_id } => Some(*gate_id),
                    _ => None,
                }
            })
            .flatten()
    }

    // ==== Прерывания ====

    /// Создаёт объект линии прерываний `irq` (владелец — `owner`) и выдаёт
    /// корневую capability. Badge маскирует подресурсы линии (например,
    /// векторы MSI). Претенденты получают производные capability; отзыв
    /// владельца гасит линию по поколению объекта.
    pub fn create_irq(
        &self,
        tasks: &TcbManager,
        owner: TaskId,
        irq: IrqId,
        perms: ActionPermissions,
        badge: CapabilityBadge,
    ) -> Result<CapHandle, CapabilityError> {
        let owner_ref = tasks
            .target_ref(&owner)
            .ok_or(CapabilityError::TaskNotFound(owner))?;

        let or = self
            .irqs
            .lock()
            .irqs
            .alloc(|_idx, generation| IrqObj {
                hdr: ObjHeader::new(generation),
                owner: owner_ref,
                irq,
            })
            .map_err(CapabilityError::from)?;
        let obj_id = ObjId::new(or.idx, or.generation);
        let target = self.irq_target(or);

        let gate = CapabilityGate::new(ContainerACCCapability::Irq { irq, obj_id }, perms, badge);
        let created = tasks.with_caps_mut(&owner, |t| {
            t.alloc(|idx, generation| Cte::root(idx, generation, owner, target, &gate))
                .map_err(CapabilityError::from)
        });
        match created {
            Some(Ok(sr)) => {
                self.live.fetch_add(1, Ordering::Relaxed);
                Ok(CapHandle::new(sr.idx, sr.generation))
            }
            Some(Err(e)) => {
                self.irqs.lock().irqs.free(or.idx);
                Err(e)
            }
            None => {
                self.irqs.lock().irqs.free(or.idx);
                Err(CapabilityError::TaskNotFound(owner))
            }
        }
    }

    /// Гасит линию прерываний по хендлу владельца (см. [`Self::destroy_gate`]).
    pub fn destroy_irq(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        handle: CapHandle,
    ) -> Result<(), CapabilityError> {
        let obj_id = tasks
            .with_caps(&task, |t| {
                match &t.get(handle.idx(), handle.generation())?.cap_ref {
                    ContainerACCCapability::Irq { obj_id, .. } => Some(*obj_id),
                    _ => None,
                }
            })
            .flatten()
            .ok_or(CapabilityError::InvalidHandle(handle))?;

        let freed = self.irqs.lock().irqs.free(obj_id.idx());
        debug_assert!(freed, "объект линии обязан быть живым");
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    // ==== Горячий путь ====

    /// Разрешает хендл по стабильной ссылке задачи (`TcbManager::self_slot`,
    /// кэшируется планировщиком) — горячий путь IPC: O(1), без uuid-дерева,
    /// около пяти обращений в память независимо от размера таблиц.
    ///
    /// Проверяет generation слота CTE, права и живость цели (для Gate/Irq —
    /// ленивые ДВЕ проверки generation: объект и владелец). «Нет такого хендла»
    /// и «хендл протух» — один и тот же [`CapabilityError::InvalidHandle`]
    /// (анти-side-channel).
    #[inline]
    pub fn resolve_slot(
        &self,
        tasks: &TcbManager,
        task: SlotRef,
        handle: CapHandle,
    ) -> Result<CapResolved, CapabilityError> {
        self.resolve_inner(tasks, task, handle).map(|(r, _)| r)
    }

    /// Разрешает хендл по TaskId. Удобство для редких путей: сначала
    /// uuid-дерево, потом горячий путь. Ядро в syscall-входе должно
    /// использовать [`Self::resolve_slot`] со ссылкой текущей задачи.
    pub fn resolve(
        &self,
        tasks: &TcbManager,
        owner: TaskId,
        handle: CapHandle,
    ) -> Result<CapResolved, CapabilityError> {
        let Some(task) = tasks.self_slot(&owner) else {
            return Err(CapabilityError::InvalidHandle(handle));
        };
        self.resolve_slot(tasks, task, handle)
    }

    /// Полный результат горячего пути: снимок + ссылка на владельца
    /// (для второй ленивой проверки в inline-cache).
    fn resolve_inner(
        &self,
        tasks: &TcbManager,
        task: SlotRef,
        handle: CapHandle,
    ) -> Result<(CapResolved, Option<TargetRef>), CapabilityError> {
        // O(1): TaskObj по (idx, generation) — два обращения в страницы таблицы.
        tasks
            .with_task_obj(task, |tcb| {
                // O(1): CTE по (idx, generation) — ещё два обращения; generation-слово
                // слота проверяется внутри get.
                let cte = tcb
                    .caps
                    .get(handle.idx(), handle.generation())
                    .ok_or(CapabilityError::InvalidHandle(handle))?;
                let owner_check = Self::check_alive(cte, handle)?;
                Ok((
                    CapResolved {
                        perms: cte.perms,
                        badge: cte.badge,
                        target: cte.target,
                    },
                    owner_check,
                ))
            })
            .unwrap_or(Err(CapabilityError::InvalidHandle(handle)))
    }

    /// Ленивая проверка живости цели по стабильному имени. Для Gate/Irq —
    /// две проверки generation: сам объект и его владелец (вариант «лениво» из
    /// плана). Возвращает TargetRef владельца (для кэша), если он есть.
    fn check_alive(cte: &Cte, handle: CapHandle) -> Result<Option<TargetRef>, CapabilityError> {
        let dead = || CapabilityError::InvalidHandle(handle);
        match &cte.cap_ref {
            ContainerACCCapability::DeviceReference { .. } => {
                // Цель «бессмертна» на этом слое (см. grant).
                Ok(None)
            }
            // Мастер-право IOMMU (v0.9): цель «бессмертна» — отзыв только
            // revoke самой capability (как у устройств).
            ContainerACCCapability::IommuAdmin => Ok(None),
            ContainerACCCapability::TaskTCB { .. } => {
                // Одна проверка: generation задачи и есть живость цели.
                if !cte.target.alive() {
                    return Err(dead());
                }
                Ok(None)
            }
            ContainerACCCapability::Gate { .. } => {
                // SAFETY: target создан для GateObj (cap_ref Gate) и указывает
                // на type-stable страницу таблицы гейтов.
                let g = unsafe { cte.target.obj::<GateObj>() }.ok_or_else(dead)?;
                // Вторая ленивая проверка: жив ли владелец гейта.
                if !g.owner.alive() {
                    return Err(dead());
                }
                Ok(Some(g.owner))
            }
            ContainerACCCapability::Irq { .. } => {
                // SAFETY: target создан для IrqObj (cap_ref Irq).
                let o = unsafe { cte.target.obj::<IrqObj>() }.ok_or_else(dead)?;
                if !o.owner.alive() {
                    return Err(dead());
                }
                Ok(Some(o.owner))
            }
        }
    }

    // ==== Inline-cache (шаг 5 из плана) ====

    /// Разрешает хендл через direct-mapped кэш. Хит = совпадение эпохи и
    /// тега + дешёвая перепроверка живости (1–2 атомарных чтения generation
    /// вместо спуска по таблицам и uuid-карте).
    ///
    /// Инвалидация: менеджер поднимает эпоху на любом отзыве прав
    /// (delete/revoke/revoke_all/send/destroy_gate/destroy_irq); смерть
    /// цели и владельца гейта ловится перепроверкой `alive()` на хите.
    /// При частых отзывах кэш бесполезен — сначала замерьте (`hits`/`misses`).
    pub fn resolve_cached<const LINES: usize>(
        &self,
        tasks: &TcbManager,
        cache: &mut ResolveCache<LINES>,
        task: SlotRef,
        handle: CapHandle,
    ) -> Result<CapResolved, CapabilityError> {
        let tag = Self::cache_tag(task, handle);
        let li = ((tag >> 13) as usize) % cache.lines.len();
        let epoch = self.epoch.load(Ordering::Acquire);

        {
            let line = &cache.lines[li];
            if line.valid && line.epoch == epoch && line.tag == tag {
                let owner_ok = line.owner_check.map_or(true, |t| t.alive());
                if owner_ok && line.res.target.alive() {
                    cache.hits += 1;
                    return Ok(line.res);
                }
                // Цель/владелец умерли: строка больше не годится, медленный
                // путь перепишет её.
            }
        }

        cache.misses += 1;
        let (res, owner_check) = self.resolve_inner(tasks, task, handle)?;
        let line = &mut cache.lines[li];
        line.epoch = self.epoch.load(Ordering::Acquire);
        line.tag = tag;
        line.res = res;
        line.owner_check = owner_check;
        line.valid = true;
        Ok(res)
    }

    fn cache_tag(task: SlotRef, handle: CapHandle) -> u64 {
        let mut h = handle.bits()
            ^ (task.idx as u64).rotate_left(17)
            ^ (task.generation as u64).rotate_left(33);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h
    }

    /// Явно поднимает эпоху кэша: вызывайте после внешних изменений
    /// живости, о которых менеджер не знает (например, после
    /// `TcbManager::set_state(Dead)`, если кэш важнее перепроверки).
    pub fn invalidate_resolve_cache(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    // ==== Аудит ====

    /// Снимок хендла по (задача, хендл).
    pub fn get(&self, tasks: &TcbManager, task: TaskId, id: CapHandle) -> Option<CapabilityView> {
        tasks
            .with_caps(&task, |t| {
                t.get(id.idx(), id.generation()).map(|cte| cte.view())
            })
            .flatten()
    }

    /// Число живых хендлов у задачи (`None` — задачи нет).
    pub fn task_cap_count(&self, tasks: &TcbManager, task: TaskId) -> Option<usize> {
        tasks.cap_count(&task)
    }

    /// Общее число живых CTE во всех cspace.
    pub fn total_count(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Обход всех capability задачи. Callback — копии (`CapabilityView`);
    /// вызов методов менеджера из callback — паника RefCell (контракт
    /// однопоточности).
    pub fn for_each_task_cap(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        mut f: impl FnMut(CapabilityView),
    ) {
        let _ = tasks.with_caps(&task, |t| {
            t.for_each_live(|_r, cte| f(cte.view()));
        });
    }

    // ==== Служебные ====

    /// TargetRef на объект гейта по слот-ссылке.
    fn gate_target(&self, r: SlotRef) -> TargetRef {
        self.gates
            .lock()
            .gates
            .target(r)
            .expect("гейт только что создан")
    }

    /// TargetRef на объект линии по слот-ссылке.
    fn irq_target(&self, r: SlotRef) -> TargetRef {
        self.irqs
            .lock()
            .irqs
            .target(r)
            .expect("объект линии только что создан")
    }

    /// Рекурсивный отзыв поддерева: гасит узел и всех его детей (в любых
    /// задачах). Возвращает число погашенных слотов.
    ///
    /// `detach_from_parent` выставляется только для корня рекурсии:
    /// родительский обход снимает ребёнка со своего children-якоря сам
    /// (`pop_front`), поэтому рекурсивный вызов НЕ должен снимать его
    /// повторно — иначе двойное unlink-ание одного и того же линк-поля.
    fn revoke_node(
        &self,
        tasks: &TcbManager,
        raw: NonNull<Cte>,
        detach_from_parent: bool,
    ) -> usize {
        let mut revoked = 0;
        let (owner, self_idx, parent) = {
            // SAFETY: узел жив (состоит в чьей-то HandleTable),
            // эксклюзивность — однопоточный контракт менеджера.
            let node: &mut Cte = unsafe { &mut *raw.as_ptr() };
            // 1. Дети вперёд: pop снимает ребёнка с нашего children-якоря,
            //    рекурсивный вызов уже НЕ снимает его с родителя повторно.
            while let Some(child) = node.children.pop_front() {
                // SAFETY: ребёнок — живой узел дерева деривации.
                let child_ptr = unsafe { NonNull::new_unchecked(UnsafeRef::into_raw(child)) };
                // Аудит дерева (v0.11): ребёнок, снятый с НАШЕГО якоря,
                // обязан ссылаться на нас как на родителя (инвариант 2).
                // Рассинхрон — баг дерева деривации: без аудита pop
                // «призрака» (уже отвязанного/освобождённого узла) ловит
                // KERNEL FAULT позже (intrusive unlink по мусорным
                // указателям).
                {
                    // SAFETY: ребёнок — живой узел (проверка до рекурсии).
                    let c: &Cte = unsafe { &*child_ptr.as_ptr() };
                    let ok = c
                        .parent
                        .is_some_and(|p| p.target.hdr_ptr().as_ptr() as *mut Cte == raw.as_ptr());
                    if !ok {
                        Self::audit_inconsistent_tree(
                            "pop: child.parent != popping node",
                            raw,
                            child_ptr,
                        );
                    }
                }
                revoked += self.revoke_node(tasks, child_ptr, false);
            }
            // 2. Снимаем узел с children его родителя — только если нас не
            //    снял родительский pop (т.е. мы — корень рекурсии).
            let parent = if detach_from_parent {
                node.parent.take()
            } else {
                None
            };
            (node.owner, node.self_idx, parent)
        };
        if let Some(p) = parent {
            // SAFETY: родитель жив (инвариант 2), эксклюзивно доступен.
            let pm: &mut Cte = unsafe { &mut *(p.target.hdr_ptr().as_ptr() as *mut Cte) };
            if !remove_from_children(&mut pm.children, raw) {
                // Аудит дерева (v0.11): ребёнок уходит из дерева, но в
                // списке родителя его НЕТ — зеркальный рассинхрон
                // (children-якорь родителя будет указывать на freed-слот,
                // KERNEL FAULT при следующем pop). debug_assert в release
                // молчал — аудит обязан попадать в консоль всегда.
                Self::audit_inconsistent_tree(
                    "detach: child not in parent list",
                    p.target.hdr_ptr().cast::<Cte>(),
                    raw,
                );
            }
        }

        // 3. Слот у владельца: generation вверх → drop (порядок из плана).
        let freed = tasks.with_caps_mut(&owner, |t| t.free(self_idx));
        debug_assert!(freed == Some(true), "слот CTE обязан быть живым");
        if freed != Some(true) {
            Self::audit_inconsistent_tree("free: CTE slot already dead", raw, raw);
        }
        revoked + 1
    }

    /// Аудит рассинхронизации дерева деривации (v0.11): единственный
    /// вывод — строка в DebugSink (ядро продолжает работу; аудит-ловушка
    /// для отладки багов дерева, фатальные проверки остаются ассертами
    /// отладочных сборок). Оба указателя — Cte-узлы (a — родитель/узел,
    /// b — ребёнок/дубликат).
    fn audit_inconsistent_tree(what: &str, a: NonNull<Cte>, b: NonNull<Cte>) {
        // SAFETY: чтение идентичности для аудита — память узлов обязана
        // быть доступной (иначе аудит не имеет смысла).
        let (ka, oa) = unsafe {
            let n: &Cte = a.as_ref();
            (n.cap_ref.kind_word(), n.owner)
        };
        let (kb, ob) = unsafe {
            let n: &Cte = b.as_ref();
            (n.cap_ref.kind_word(), n.owner)
        };
        let line = alloc::format!(
            "[kernel: captree] INCONSISTENT: {} a={:#x}(kind={:#x} owner={}) b={:#x}(kind={:#x} owner={})\r\n",
            what,
            a.as_ptr() as usize,
            ka,
            oa,
            b.as_ptr() as usize,
            kb,
            ob,
        );
        if let Some(sink) = crate::syscall::debug::debug_sink() {
            sink.write(line.as_bytes());
        }
    }

    /// Число живых производных у CTE `handle` (длина children-списка).
    /// Тест-хук инварианта 2: после отзыва производных у родителя
    /// не должно оставаться «призраков» (freed-слотов в списке) —
    /// v0.11-баг отвязки в release ловится именно здесь.
    pub fn child_count_of(
        &self,
        tasks: &TcbManager,
        task: TaskId,
        handle: CapHandle,
    ) -> Option<usize> {
        // LinkedList не даёт len (низкоуровневая коллекция) — считаем
        // курсором (тест-хук, редкий путь).
        let mut count = 0usize;
        let got = tasks.with_caps(&task, |t| {
            let cte = t.get(handle.idx(), handle.generation())?;
            let mut cur = cte.children.front();
            while !cur.is_null() {
                count += 1;
                cur.move_next();
            }
            Some(())
        });
        got.flatten().map(|()| count)
    }

    /// Дренаж cspace задачи: revoke всех корней её таблицы (сами корни
    /// могут иметь родителей в других задачах — detach сделает revoke_node).
    fn revoke_all_for(&self, tasks: &TcbManager, task: TaskId) -> usize {
        let mut revoked = 0;
        loop {
            let head = tasks.with_caps(&task, |t| t.first_live());
            // Внешний Option — существование задачи, внутренний — живой слот.
            let Some(Some(h)) = head else { break };
            let raw = match tasks.with_caps_mut(&task, |t| {
                let node = t
                    .get_mut(h.idx, h.generation)
                    .expect("first_live обязан вернуть живой слот");
                Ok::<NonNull<Cte>, CapabilityError>(NonNull::from(node))
            }) {
                Some(Ok(p)) => p,
                _ => break, // задача исчезла под нами — не бывает, но безопасно
            };
            revoked += self.revoke_node(tasks, raw, true);
        }
        self.live.fetch_sub(revoked, Ordering::Relaxed);
        revoked
    }
}

// ==== Служебные функции ====

/// Удаляет из списка детей узел с данным указателем (линейный поиск).
/// Возвращает true, если найден и удалён.
fn remove_from_children(list: &mut LinkedList<CteChildrenAdapter>, target: NonNull<Cte>) -> bool {
    let mut cur = list.front_mut();
    while !cur.is_null() {
        if cur.get_ptr() == Some(target) {
            cur.remove();
            return true;
        }
        cur.move_next();
    }
    false
}

// impl Drop for CapabilityManager<'_> {
//     /// Гасит все CTE корректно: рекурсивно по дереву деривации, снимая
//     /// слоты из хендл-таблиц задач — TCB остаётся с пустыми cspace,
//     /// поэтому последующий drop `TcbManager` безопасен.
//     fn drop(&mut self) {
//         let tasks = tasks;
//         // Курсорный обход задач: без аллокаций и без вложенных borrow.
//         let mut cur = tasks.first_task();
//         while let Some(uuid) = cur {
//             let _ = self.revoke_all_for(uuid);
//             cur = tasks.next_task_after(&uuid);
//         }
//         debug_assert_eq!(self.live.load(Ordering::Relaxed), 0);
//         // Объекты гейтов/линий гасятся дропом их таблиц (RefCell-поля):
//         // TargetRef наружу не утекали, deref'ов после дропа не будет.
//     }
// }

// ==== Inline-cache ====

/// Строка direct-mapped кэша.
#[derive(Clone, Copy)]
struct CacheLine {
    epoch: u64,
    tag: u64,
    res: CapResolved,
    /// Для Gate/Irq: владелец цели — вторая ленивая проверка на хите.
    owner_check: Option<TargetRef>,
    valid: bool,
}

/// Direct-mapped inline-cache `SlotRef+CapHandle → CapResolved`
/// (шаг 5 из плана; в боевом ядре — per-core/per-thread).
///
/// Хит: эпоха совпала, тег совпал, цель (и владелец гейта) живы —
/// 1–2 атомарных чтения generation. Любой отзыв прав поднимает эпоху менеджера,
/// несовпавшие записи идут по медленному пути. Грубость прямого
/// отображения (конфликты строк) — плата за O(1): при частых отзывах
/// смотрите `misses` и выключайте.
pub struct ResolveCache<const LINES: usize = 64> {
    lines: [CacheLine; LINES],
    /// Статистика для замеров.
    pub hits: u64,
    pub misses: u64,
}

impl<const LINES: usize> ResolveCache<LINES> {
    /// Пустой кэш.
    pub const fn new() -> Self {
        const EMPTY: CacheLine = CacheLine {
            epoch: 0,
            tag: 0,
            res: CapResolved {
                perms: ActionPermissions::empty(),
                badge: CapabilityBadge::EMPTY,
                target: TargetRef::immortal(),
            },
            owner_check: None,
            valid: false,
        };
        Self {
            lines: [EMPTY; LINES],
            hits: 0,
            misses: 0,
        }
    }

    /// Полный сброс (например, после миграции потока на другое ядро).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl<const LINES: usize> Default for ResolveCache<LINES> {
    fn default() -> Self {
        Self::new()
    }
}
