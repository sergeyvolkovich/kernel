// ==== IRQ-роутер: внешние линии (GSI) -> endpoint'ы (L4 irq_attach) ====
//
// v0.14: «устройств в ядре нет» — роутер больше не знает, КАКОЕ
// устройство стоит за линией. Право на линию подтверждает capability
// `IoResource(Irq{base..base+count})` (проверяет syscall-хендлер),
// роутер ведёт ТОЛЬКО привязки: GSI -> endpoint + pending-бит.
//
// Протокол (edge-семантика с pending-битом, как уведомления L4):
//   attach:  линия -> endpoint (одна привязка на линию; право на GSI
//            проверено IoResource-cap в хендлеле сискола);
//   событие: pending = true + signal(gsi) в endpoint; пока pending не
//            снят, повторные события копятся ОДНИМ битом (уведомления
//            не теряются и не переполняют буфер — L4-семантика);
//   ack:     драйвер обработал — pending снят, линия снова взведена
//            (EOI платформы — контроллер маскирует до ACK, см.
//            IrqLineOps; крейт ведёт только логику привязок).
//
// Жизненный цикл: смерть задачи-владельца (detach_all_of) снимает
// привязки — GCTL оркестрирует каскад смерти. «Горячее удаление
// устройства» — больше не понятие ядра: менеджер устройств в юзерспейсе
// сам отзывает capability и приказывает драйверу снять привязку.
//
// Хранение — плоский Vec в RefCell: привязок мало, регистрация редкая
// (сетап драйвера), горячий путь (irq_event) — линейный scan по
// нескольким записям кэш-линии.

use crate::sync::KSpin;

use alloc::vec::Vec;
use thiserror::Error;

use crate::capability::CapabilityManager;
use crate::capability::ObjId;
use crate::ipc::IpcManager;
use crate::task::{TaskId, TcbManager};

/// Отказ операции IRQ-роутера.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrqError {
    /// GSI вне диапазона capability вызывающего.
    #[error("gsi {0} is out of the capability range")]
    InvalidGsi(u32),
    /// Линия уже привязана (одна привязка на линию).
    #[error("irq line already bound")]
    AlreadyBound,
    /// Привязки линии нет.
    #[error("irq binding not found")]
    NotFound,
    /// Операцию пытается совершить не владелец привязки.
    #[error("not the binding owner")]
    NotOwner,
}

/// Привязка линии прерывания.
struct IrqBinding {
    /// Линия (GSI / контроллерно-зависимый номер).
    gsi: u32,
    /// Задача-владелец (detached при её смерти).
    owner: TaskId,
    /// Endpoint доставки (notification GateObj).
    gate: ObjId,
    /// Событие, не подтверждённое ACK (уведомления копятся одним битом).
    pending: bool,
}

/// Роутер привязок IRQ -> endpoint.
pub struct IrqRouter {
    bindings: KSpin<Vec<IrqBinding>>,
}

impl Default for IrqRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqRouter {
    /// Пустой роутер (аллокаций нет — Vec растёт при первом attach).
    pub fn new() -> Self {
        Self {
            bindings: KSpin::new(Vec::new()),
        }
    }

    /// Привязать линию к endpoint'у (L4 irq_attach).
    ///
    /// Право на GSI (диапазон IoResource-cap) проверяет syscall-хендлер —
    /// роутер получает уже авторизованные `gsi`/`gate`; контракт: линия
    /// свободна (одна привязка на GSI).
    pub fn attach(&self, owner: TaskId, gsi: u32, gate: ObjId) -> Result<(), IrqError> {
        let mut bindings = self.bindings.lock();
        if bindings.iter().any(|b| b.gsi == gsi) {
            return Err(IrqError::AlreadyBound);
        }
        bindings.push(IrqBinding {
            gsi,
            owner,
            gate,
            pending: false,
        });
        Ok(())
    }

    /// Снять привязку линии (только владелец).
    pub fn detach(&self, gsi: u32, owner: TaskId) -> Result<(), IrqError> {
        let mut bindings = self.bindings.lock();
        let idx = bindings
            .iter()
            .position(|b| b.gsi == gsi)
            .ok_or(IrqError::NotFound)?;
        if bindings[idx].owner != owner {
            return Err(IrqError::NotOwner);
        }
        bindings.swap_remove(idx);
        Ok(())
    }

    /// Подтвердить обработку (EOI): pending снят, линия снова взведена.
    /// Возврат — был ли необработанный pending (ложный ACK — не ошибка:
    /// идемпотентность протокола важнее строгости).
    pub fn ack(&self, gsi: u32, owner: TaskId) -> Result<bool, IrqError> {
        let mut bindings = self.bindings.lock();
        let b = bindings
            .iter_mut()
            .find(|b| b.gsi == gsi)
            .ok_or(IrqError::NotFound)?;
        if b.owner != owner {
            return Err(IrqError::NotOwner);
        }
        let was = b.pending;
        b.pending = false;
        Ok(was)
    }

    /// Событие на линии (вызов платформы из верхнего полуобработчика).
    ///
    /// `Ok(false)` — линия не привязана (платформа решает сама: shared
    /// IRQ, spurious). `Ok(true)` — событие учтено: сигнал положен в
    /// endpoint или склеен с непогашенным pending. Переполнение буфера
    /// НЕ ошибка: pending взведён, драйвер дочитает предыдущее слово —
    /// семантика уведомлений L4 (события сливаются, не теряются).
    pub fn irq_event(
        &self,
        tasks: &TcbManager,
        caps: &CapabilityManager,
        ipc: &IpcManager,
        gsi: u32,
    ) -> Result<bool, IrqError> {
        // Захват привязки-копии ДО отпуска borrow: доставка заходит в
        // менеджеры (RefCell-реентери недопустимы).
        let (gate, was_pending) = {
            let bindings = self.bindings.lock();
            let Some(b) = bindings.iter().find(|b| b.gsi == gsi) else {
                return Ok(false);
            };
            if b.pending {
                // Склейка: слово уже в endpoint (или буфер полон —
                // драйвер дочитает), нового сигнала не нужно.
                return Ok(true);
            }
            (b.gate, false)
        };
        let _ = was_pending;

        // Сначала pending (событие учтено при любом исходе доставки)...
        if let Some(b) = self
            .bindings
            .lock()
            .iter_mut()
            .find(|b| b.gsi == gsi && b.gate == gate)
        {
            b.pending = true;
        }

        // ...затем доставка signal-слова (номер линии).
        let _ = ipc.signal(tasks, caps, gate, gsi as u64);
        Ok(true)
    }

    /// Снять все привязки задачи (TASK_EXIT / TASK_KILL каскад).
    /// Возврат — число снятых.
    pub fn detach_all_of(&self, owner: &TaskId) -> usize {
        let mut bindings = self.bindings.lock();
        let before = bindings.len();
        bindings.retain(|b| &b.owner != owner);
        before - bindings.len()
    }

    /// Число активных привязок (аудит/тесты).
    pub fn len(&self) -> usize {
        self.bindings.lock().len()
    }

    /// Привязок нет.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Снимок привязки для отладки: (gsi, owner, gate, pending).
    pub fn binding_of(&self, gsi: u32) -> Option<(u32, TaskId, ObjId, bool)> {
        self.bindings
            .lock()
            .iter()
            .find(|b| b.gsi == gsi)
            .map(|b| (b.gsi, b.owner, b.gate, b.pending))
    }
}

// ==== Тесты (host) ====

#[cfg(test)]
pub(crate) mod tests_support {
    use alloc::boxed::Box;

    use crate::capability::{
        ActionPermissions, CapHandle, CapabilityBadge, CapabilityManager, ContainerACCCapability,
    };
    use crate::ipc::IpcManager;
    use crate::task::{TaskId, TaskPriority, TcbManager};

    use super::IrqRouter;

    /// Готовый мир: менеджеры + владелец с Irq-cap и endpoint'ом.
    pub(crate) struct IrqTestEnv {
        pub tasks: &'static TcbManager,
        pub caps: &'static CapabilityManager,
        pub ipc: &'static IpcManager,
        pub router: &'static IrqRouter,
        pub owner: TaskId,
        /// ObjId endpoint'а владельца.
        pub gate: crate::capability::ObjId,
        /// Хендл Irq-cap (диапазон 0..=255) в cspace владельца.
        pub irq_cap: CapHandle,
        /// Хендл Gate-cap endpoint'а.
        pub gate_handle: CapHandle,
    }

    pub(crate) fn irq_test_env() -> IrqTestEnv {
        let tasks: &'static TcbManager = Box::leak(Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            Box::leak(Box::new(CapabilityManager::new().unwrap()));
        let ipc: &'static IpcManager = Box::leak(Box::new(IpcManager::new()));
        let router: &'static IrqRouter = Box::leak(Box::new(IrqRouter::new()));

        let owner = {
            use core::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0x9000);
            TaskId::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
        };
        tasks.create(owner, TaskPriority::DEFAULT).unwrap();

        // Irq-cap владельцу: диапазон GSI 0..=255 (корневой грант kinit).
        let irq_cap = caps
            .grant(
                tasks,
                owner,
                crate::capability::CapabilityGate::new(
                    ContainerACCCapability::IoResource {
                        kind: crate::capability::IoResourceKind::Irq {
                            base: 0,
                            count: 256,
                        },
                    },
                    ActionPermissions::all(),
                    CapabilityBadge::FULL,
                ),
            )
            .unwrap();

        // Notification-endpoint (буфер) для доставки IRQ.
        let gate_handle = ipc
            .create_endpoint(
                tasks,
                caps,
                owner,
                8,
                ActionPermissions::all(),
                CapabilityBadge::FULL,
            )
            .unwrap();
        let view = caps.get(tasks, owner, gate_handle).unwrap();
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            panic!("endpoint-cap");
        };

        IrqTestEnv {
            tasks,
            caps,
            ipc,
            router,
            owner,
            gate: gate_id,
            irq_cap,
            gate_handle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IrqError;
    use super::tests_support::{IrqTestEnv, irq_test_env};

    /// attach + ack + detach по свежему миру.
    #[test]
    fn gsi_keyed_lifecycle() {
        let env: &'static IrqTestEnv = Box::leak(Box::new(irq_test_env()));
        let r = &env.router;
        assert!(r.is_empty());

        // Привязка GSI 42 (авторизована cap-диапазоном — здесь просто
        // вызов роутера).
        r.attach(env.owner, 42, env.gate).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.binding_of(42).map(|b| (b.0, b.3)), Some((42, false)));

        // Повторная привязка той же линии — отказ (одна на GSI).
        assert_eq!(
            r.attach(env.owner, 42, env.gate),
            Err(IrqError::AlreadyBound)
        );

        // Не владелец не может снять/ackнуть.
        let alien = crate::task::TaskId::from_u128(0xBEEF);
        assert_eq!(r.detach(42, alien), Err(IrqError::NotOwner));
        assert_eq!(r.ack(42, alien), Err(IrqError::NotOwner));

        // Событие: pending взводится, слово уходит в endpoint.
        r.irq_event(env.tasks, env.caps, env.ipc, 42).unwrap();
        assert_eq!(r.binding_of(42).map(|b| b.3), Some(true));
        // Непривязанная линия — Ok(false).
        assert!(!r.irq_event(env.tasks, env.caps, env.ipc, 7).unwrap());

        // Ack: pending снят, повторный ack — false (идемпотентность).
        assert!(r.ack(42, env.owner).unwrap());
        assert!(!r.ack(42, env.owner).unwrap());

        // Detach владельцем + detach несуществующей — NotFound.
        r.detach(42, env.owner).unwrap();
        assert_eq!(r.detach(42, env.owner), Err(IrqError::NotFound));
        assert!(r.is_empty());
    }

    /// Каскад смерти задачи снимает её привязки.
    #[test]
    fn detach_all_of_owner() {
        let env: &'static IrqTestEnv = Box::leak(Box::new(irq_test_env()));
        let r = &env.router;
        r.attach(env.owner, 4, env.gate).unwrap();
        r.attach(env.owner, 9, env.gate).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.detach_all_of(&env.owner), 2);
        assert!(r.is_empty());
    }
}
