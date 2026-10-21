// ==== Фасад сырых аппаратных ресурсов: IoResource-capability -> доступ ====
//
// Микроядерный контракт v0.14 («устройств в ядре нет»): ядро НЕ ЗНАЕТ
// устройств. Юзерспейс-менеджер (init -> acpid/драйверы) перечисляет
// железо сам (ACPI/AML — теперь тоже юзерспейс), а ядро лишь МЕДИТИРУЕТ
// доступ к сырым диапазонам за capability `IoResource`:
//
//   MMIO_MAP  (0x41): Mmio-cap + off + pages -> vaddr (как DEVICE_MAP_REGION
//             прежде, но ключ — диапазон физики, а не реестр устройств;
//             физика = base+off, отображение байто-точное: возврат
//             указывает на base+off, кадры — внешние, снятие MEM_FREE);
//   IOP_IN/OUT(0x42/0x43): IoPort-cap + off + width(1|2|4) -> in/out —
//             исполнение в ядре через платформенный сервис IoPortOps
//             (прямой in/out из юзерспейса не существует: IOPL=0);
//   IRQ_ATTACH(0x46): Irq-cap + gsi + gate — линия прерываний как
//             L4-уведомление; право на GSI подтверждает диапазон cap.
//
// Никакой логики устройств: что за «PM1a_CNT» или «UART» — знает только
// юзерспейс; ядро видит байты физики, номера портов и номера линий.

use alloc::format;

use crate::capability::{CapHandle, ContainerACCCapability, IoResourceKind};
use crate::hal::irq::IrqError;
use crate::hal::irq::IrqRouter;
use crate::hal::traits::ioport::IoPortOps;
use crate::hal::traits::irq::IrqLineOps;
use crate::syscall::nums;
use crate::syscall::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};

use super::SyscallHandler;

/// Флаги IRQ_ATTACH (подсказка триггера/полярности линии; канонизация
/// MADT-ISO в бекенде IOAPIC сильнее подсказки — см. enable_line).
pub const IRQ_FLAG_LEVEL: usize = 1;
pub const IRQ_FLAG_ACTIVE_LOW: usize = 2;

/// Перевод ошибок IRQ-роутера в errno-словарь сисколов.
impl From<IrqError> for SyscallError {
    fn from(e: IrqError) -> Self {
        match e {
            IrqError::InvalidGsi(_) => Self::InvalidArgument,
            IrqError::AlreadyBound => Self::AlreadyExists,
            IrqError::NotFound => Self::NotFound,
            IrqError::NotOwner => Self::MissingRight,
        }
    }
}

// ───────────────────── Платформенные сервисы ─────────────────────

static IRQ_LINES: spin::Once<&'static dyn IrqLineOps> = spin::Once::new();
static IO_PORTS: spin::Once<&'static dyn IoPortOps> = spin::Once::new();

/// Установка платформенного сервиса внешних линий (x86_64: IOAPIC —
/// backend ставит в ioapic::init; до установки IRQ_ATTACH работает,
/// но линия не возводится — события не придут).
pub fn install_irq_line_service(ops: &'static dyn IrqLineOps) {
    IRQ_LINES.call_once(|| ops);
}

/// Установка платформенного сервиса I/O-портов (x86_64: backend ставит
/// в platform::run; до установки IOP_IN/IOP_OUT — ENOSYS).
pub fn install_io_port_service(ops: &'static dyn IoPortOps) {
    IO_PORTS.call_once(|| ops);
}

fn irq_lines() -> Option<&'static dyn IrqLineOps> {
    IRQ_LINES.get().copied()
}

fn io_ports() -> Option<&'static dyn IoPortOps> {
    IO_PORTS.get().copied()
}

// ───────────────────── Резолв IoResource-cap ─────────────────────

/// Резолв IoResource-capability вызывающего с ожидаемой разновидностью.
///
/// Чужой/протухший хендл — EBADF (анти-side-channel политика capability-
/// слоя); неверная разновидность (Mmio вместо IoPort и т.д.) — EINVAL.
/// Возврат — КОПИЯ (IoResourceKind: Copy) без заимствования cspace.
fn io_resource_kind(
    ctx: &SyscallCtx<'_>,
    handle: CapHandle,
    flavor: fn(&IoResourceKind) -> bool,
) -> Result<IoResourceKind, SyscallError> {
    let view = ctx.resolve(handle)?;
    match &view.cap_ref {
        ContainerACCCapability::IoResource { kind } => {
            if flavor(kind) {
                Ok(*kind)
            } else {
                Err(SyscallError::InvalidArgument)
            }
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

// ───────────────────── MMIO_MAP (0x41) ─────────────────────

/// Отображение физического диапазона (Mmio-cap) в пространство
/// вызывающего.
///
/// ABI: arg1 = хендл IoResource(Mmio), arg2 = байтовый офсет внутри
/// диапазона (база + офсет — физический адрес; НЕ обязан быть выровнен),
/// arg3 = число страниц 4 КиБ, arg4 = биты MMAPMemoryFlags (0 = дефолт
/// RW device-nocache). Возврат: виртуальный адрес БАЙТО-ТОЧНО
/// соответствующий base+off (страницы внешние — снятие MEM_FREE).
///
/// Проверка диапазона: отображаемые кадры [page(base+off),
/// page(base+off)+pages*4K) обязаны лежать внутри [base, base+len) —
/// правая граница capability должна быть выровнена на страницу.
pub struct MmioMapHandler;

impl MmioMapHandler {
    pub const SYSCALL: SyscallNumber = nums::MMIO_MAP;
}

impl SyscallHandler for MmioMapHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let memory = ctx.memory.ok_or(SyscallError::NotSupported)?;

        let handle = CapHandle(args.arg(1) as u64);
        let off = args.arg(2) as u64;
        let pages = args.arg(3);
        if pages == 0 {
            return Err(SyscallError::InvalidArgument);
        }
        let kind = io_resource_kind(ctx, handle, |k| matches!(k, IoResourceKind::Mmio { .. }))?;
        let IoResourceKind::Mmio { base, len } = kind else {
            unreachable!("flavor проверен выше");
        };

        // Геометрия: физика = base+off; кадры [page_phys, page_phys+
        // pages*4K) внутри [base, base+len).
        let phys = base.checked_add(off).ok_or(SyscallError::InvalidArgument)?;
        let page_phys = phys & !0xFFF;
        let map_end = page_phys
            .checked_add((pages as u64) << 12)
            .ok_or(SyscallError::InvalidArgument)?;
        if phys < base || map_end > base.saturating_add(len) {
            return Err(SyscallError::MissingRight);
        }
        let rem = phys & 0xFFF;

        // Флаги: 0 — дефолт device-nocache (RW, без CACHEABLE).
        let flags = match args.arg(4) {
            0 => crate::hal::traits::mmap::MMAPMemoryFlags::RW,
            bits => {
                let f = crate::hal::traits::mmap::MMAPMemoryFlags::from_bits_retain(bits as u8);
                f.validate().map_err(SyscallError::from)?;
                f
            }
        };

        let vaddr = memory
            .map_external(
                ctx.task,
                crate::hal::traits::mmap::PhysADDR(page_phys as usize),
                pages,
                flags,
            )
            .map_err(|e| {
                // Временная диагностика v0.14 (QEMU-отладка): точный код
                // отказа фасада в консоль.
                crate::task::sandbox_audit(&alloc::format!(
                    "mmio_map: phys={page_phys:#x} pages={pages} err={e:?}"
                ));
                SyscallError::from(e)
            })?;
        Ok(vaddr.0 + rem as usize)
    }
}

// ───────────────────── IOP_IN / IOP_OUT (0x42/0x43) ─────────────────────

/// Чтение из I/O-порта (медитированный доступ за IoPort-cap).
///
/// ABI: arg1 = хендл IoResource(IoPort), arg2 = офсет порта от базы cap,
/// arg3 = ширина в байтах (1 | 2 | 4). Возврат: прочитанное значение.
pub struct IopInHandler;

impl IopInHandler {
    pub const SYSCALL: SyscallNumber = nums::IOP_IN;
}

impl SyscallHandler for IopInHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ports = io_ports().ok_or(SyscallError::NotSupported)?;
        let handle = CapHandle(args.arg(1) as u64);
        let off = args.arg(2) as u32;
        let width = args.arg(3) as u8;
        if !matches!(width, 1 | 2 | 4) {
            return Err(SyscallError::InvalidArgument);
        }
        let kind = io_resource_kind(ctx, handle, |k| matches!(k, IoResourceKind::IoPort { .. }))?;
        let IoResourceKind::IoPort { base, len } = kind else {
            unreachable!("flavor проверен выше");
        };

        // Порт внутри диапазона capability: base+off+width <= base+len.
        let end = off
            .checked_add(width as u32)
            .ok_or(SyscallError::InvalidArgument)?;
        if end > len as u32 {
            return Err(SyscallError::MissingRight);
        }
        let port = base
            .checked_add(off as u16)
            .ok_or(SyscallError::InvalidArgument)?;

        Ok(ports.port_in(port, width) as usize)
    }
}

/// Запись в I/O-порт (медитированный доступ за IoPort-cap).
///
/// ABI: arg1 = хендл IoResource(IoPort), arg2 = офсет порта, arg3 = ширина
/// (1 | 2 | 4), arg4 = значение (младшие width байт).
pub struct IopOutHandler;

impl IopOutHandler {
    pub const SYSCALL: SyscallNumber = nums::IOP_OUT;
}

impl SyscallHandler for IopOutHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let ports = io_ports().ok_or(SyscallError::NotSupported)?;
        let handle = CapHandle(args.arg(1) as u64);
        let off = args.arg(2) as u32;
        let width = args.arg(3) as u8;
        let value = args.arg(4) as u32;
        if !matches!(width, 1 | 2 | 4) {
            return Err(SyscallError::InvalidArgument);
        }
        let kind = io_resource_kind(ctx, handle, |k| matches!(k, IoResourceKind::IoPort { .. }))?;
        let IoResourceKind::IoPort { base, len } = kind else {
            unreachable!("flavor проверен выше");
        };

        let end = off
            .checked_add(width as u32)
            .ok_or(SyscallError::InvalidArgument)?;
        if end > len as u32 {
            return Err(SyscallError::MissingRight);
        }
        let port = base
            .checked_add(off as u16)
            .ok_or(SyscallError::InvalidArgument)?;

        ports.port_out(port, width, value);
        Ok(0)
    }
}

// ───────────────────── IRQ: прерывания как сообщения (L4 irq_attach) ─────────────────────

/// Привязка внешней линии (GSI) к notification-endpoint'у.
///
/// ABI: arg1 = хендл IoResource(Irq) — право на диапазон линий,
/// arg2 = gsi (обязан принадлежать диапазону cap), arg3 = хендл Gate
/// (endpoint с буфером), arg4 = флаги подсказки триггера (bit0 = level,
/// bit1 = active_low; канонизация MADT-ISO бекенда сильнее).
///
/// v0.14: авторизация — диапазоном IoResource(Irq)-cap; «устройство,
/// владеющее линией» — больше не понятие ядра (менеджер устройств в
/// юзерспейсе выдаёт/отзывает cap сам). После привязки ядро возводит
/// линию платформой (IOAPIC RTE + IRTE-ремаппинг при включённом IR);
/// отказ возведения откатывает привязку.
pub struct IrqAttachHandler;

impl IrqAttachHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_ATTACH;
}

impl SyscallHandler for IrqAttachHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;

        let handle = CapHandle(args.arg(1) as u64);
        let gsi = args.arg(2) as u32;
        let flags = args.arg(4);

        // Право на линию: gsi внутри диапазона IoResource(Irq).
        let kind = io_resource_kind(ctx, handle, |k| matches!(k, IoResourceKind::Irq { .. }))?;
        let IoResourceKind::Irq { base, count } = kind else {
            unreachable!("flavor проверен выше");
        };
        let last = base
            .checked_add(count)
            .ok_or(SyscallError::InvalidArgument)?;
        if !(base..last).contains(&gsi) {
            return Err(SyscallError::from(IrqError::InvalidGsi(gsi)));
        }

        // Endpoint: хендл Gate вызывающего.
        let gate_handle = CapHandle(args.arg(3) as u64);
        let view = ctx.resolve(gate_handle)?;
        let ContainerACCCapability::Gate { gate_id } = &view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };

        irq.attach(ctx.task, gsi, *gate_id)?;

        // Платформа возводит линию (триггер/полярность — подсказка;
        // MADT-ISO каноничнее — см. enable_line).
        let level = flags & IRQ_FLAG_LEVEL != 0;
        let active_low = flags & IRQ_FLAG_ACTIVE_LOW != 0;
        if let Some(ops) = irq_lines() {
            if let Err(e) = ops.enable_line(gsi, level, active_low) {
                // Линия не встала — привязка бессмысленна (события
                // не придут): откат и честный отказ.
                let _ = irq.detach(gsi, ctx.task);
                return Err(SyscallError::from_iommu(e));
            }
        }
        Ok(0)
    }
}

/// Снятие привязки (владелец). ABI: arg1 = gsi.
///
/// Линия платформы маскируется.
pub struct IrqDetachHandler;

impl IrqDetachHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_DETACH;
}

impl SyscallHandler for IrqDetachHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;
        let gsi = args.arg(1) as u32;
        irq.detach(gsi, ctx.task)?;
        if let Some(ops) = irq_lines() {
            let _ = ops.disable_line(gsi);
        }
        Ok(0)
    }
}

/// Подтверждение обработки (EOI). ABI: arg1 = gsi. Возврат: был ли
/// необработанный pending (0/1).
pub struct IrqAckHandler;

impl IrqAckHandler {
    pub const SYSCALL: SyscallNumber = nums::IRQ_ACK;
}

impl SyscallHandler for IrqAckHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let irq: &IrqRouter = ctx.irq.ok_or(SyscallError::NotSupported)?;
        let gsi = args.arg(1) as u32;
        Ok(irq.ack(gsi, ctx.task)? as usize)
    }
}

// ───────────────────── Тесты (host) ─────────────────────

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use alloc::boxed::Box;

    use crate::capability::{
        ActionPermissions, CapabilityBadge, CapabilityGate, CapabilityManager,
        ContainerACCCapability, IoResourceKind,
    };
    use crate::hal::irq::tests_support::irq_test_env;
    use crate::hal::traits::ioport::IoPortOps;
    use crate::syscall::types::SyscallCtx;

    use super::*;

    /// Мок-сервис портов: пишет прочитанное в статику.
    static MOCK_PORT: AtomicU32 = AtomicU32::new(0);
    static MOCK_LAST_OUT: AtomicU32 = AtomicU32::new(0);

    struct MockPorts;

    impl IoPortOps for MockPorts {
        fn port_in(&self, port: u16, _width: u8) -> u32 {
            MOCK_PORT.store(port as u32, Ordering::SeqCst);
            0xA5A5_1234
        }
        fn port_out(&self, port: u16, _width: u8, value: u32) {
            MOCK_PORT.store(port as u32, Ordering::SeqCst);
            MOCK_LAST_OUT.store(value, Ordering::SeqCst);
        }
    }

    fn ctx_with(env: &crate::hal::irq::tests_support::IrqTestEnv) -> SyscallCtx<'static> {
        SyscallCtx::core(0, env.owner, env.tasks, env.caps).with_irq(env.router)
    }

    fn grant_io(
        env: &crate::hal::irq::tests_support::IrqTestEnv,
        kind: IoResourceKind,
    ) -> CapHandle {
        env.caps
            .grant(
                env.tasks,
                env.owner,
                CapabilityGate::new(
                    ContainerACCCapability::IoResource { kind },
                    ActionPermissions::all(),
                    CapabilityBadge::FULL,
                ),
            )
            .unwrap()
    }

    /// IOP_OUT/IOP_IN: диапазон проверен, исполнение ушло в сервис.
    #[test]
    fn ioport_mediation() {
        let env = Box::leak(Box::new(irq_test_env()));
        install_io_port_service(&MockPorts);

        // Порт 0x3F8..0x400: cap на COM1-окно.
        let cap = grant_io(
            env,
            IoResourceKind::IoPort {
                base: 0x3F8,
                len: 8,
            },
        );
        let mut ctx = ctx_with(env);

        // OUT: офсет 0, ширина 1 — ок.
        let args = SyscallArgs::new([
            IopOutHandler::SYSCALL.as_u64() as usize,
            cap.bits() as usize,
            0,
            1,
            0x55,
            0,
        ]);
        assert_eq!(IopOutHandler.invoke(&mut ctx, &args).unwrap(), 0);
        assert_eq!(MOCK_PORT.load(Ordering::SeqCst), 0x3F8);
        assert_eq!(MOCK_LAST_OUT.load(Ordering::SeqCst), 0x55);

        // IN: ширина 4 — ок, офсет 7+1=8 — уже за границей.
        let args = SyscallArgs::new([
            IopInHandler::SYSCALL.as_u64() as usize,
            cap.bits() as usize,
            0,
            4,
            0,
            0,
        ]);
        assert_eq!(IopInHandler.invoke(&mut ctx, &args).unwrap(), 0xA5A5_1234);
        let args = SyscallArgs::new([
            IopInHandler::SYSCALL.as_u64() as usize,
            cap.bits() as usize,
            7,
            2,
            0,
            0,
        ]);
        assert_eq!(
            IopInHandler.invoke(&mut ctx, &args),
            Err(SyscallError::MissingRight)
        );

        // Не-IoPort-cap — EINVAL.
        let args = SyscallArgs::new([
            IopInHandler::SYSCALL.as_u64() as usize,
            env.gate_handle.bits() as usize,
            0,
            1,
            0,
            0,
        ]);
        assert_eq!(
            IopInHandler.invoke(&mut ctx, &args),
            Err(SyscallError::InvalidArgument)
        );
    }

    /// IRQ_ATTACH: gsi вне диапазона cap — отказ; в диапазоне — привязка.
    #[test]
    fn irq_attach_range_gate() {
        let env = Box::leak(Box::new(irq_test_env()));
        // В env уже есть корневой Irq-cap 0..=255 (irq_test_env).
        let mut ctx = ctx_with(env);

        // GSI 300 — вне 0..=255.
        let args = SyscallArgs::new([
            IrqAttachHandler::SYSCALL.as_u64() as usize,
            env.irq_cap.bits() as usize,
            300,
            env.gate_handle.bits() as usize,
            0,
            0,
        ]);
        assert_eq!(
            IrqAttachHandler.invoke(&mut ctx, &args),
            Err(SyscallError::InvalidArgument)
        );

        // GSI 42 — в диапазоне: привязка + повтор — AlreadyBound.
        let args = SyscallArgs::new([
            IrqAttachHandler::SYSCALL.as_u64() as usize,
            env.irq_cap.bits() as usize,
            42,
            env.gate_handle.bits() as usize,
            0,
            0,
        ]);
        assert_eq!(IrqAttachHandler.invoke(&mut ctx, &args).unwrap(), 0);
        assert_eq!(
            IrqAttachHandler.invoke(&mut ctx, &args),
            Err(SyscallError::AlreadyExists)
        );
        assert_eq!(env.router.len(), 1);

        // Гейт не владельца — привязка осталась у env.owner.
        let ack = SyscallArgs::new([IrqAckHandler::SYSCALL.as_u64() as usize, 42, 0, 0, 0, 0]);
        assert_eq!(IrqAckHandler.invoke(&mut ctx, &ack).unwrap(), 0);
    }
}
