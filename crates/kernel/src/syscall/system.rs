// ==== Системные сисколы: идентификация себя и часы ядра ====
//
// Два примитива, без которых юзерспейс не может начать работу:
//   * SELF_INFO — задача после старта не знает своих идентификаторов
//     (argc/argv приезжают по IPC, но TaskId/ThreadId — нет): слова
//     идентификации читаются из контекста вызова;
//   * SYS_TIME — монотонные часы (аналог KIP clock в L4): источник —
//     платформенный контракт [`TimeSource`], установленный одноразово
//     (тот же паттерн, что DebugSink и GateManager). Платформа вправе
//     подменить весь слот своим хендлером (reregister).
//
// Таймауты IPC и сон — слой ВЫШЕ: таймер-сервер юзерспейса держит
// таймерные очереди и будит клиентов NOTIFY_SIGNAL (классический
// микроядерный путь L4: ядро не хранит таймеры процессов).

use spin::Once;

use crate::syscall::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallRet};

use crate::syscall::nums;
use crate::syscall::types::SyscallNumber;

// ───────────────────────────── Источник времени ─────────────────────────────

/// Платформенный источник монотонного времени (TSC/HPET/CNTVCT/...).
///
/// Устанавливается одноразово на старте (как DebugSink): единственная
/// точка, где ядро узнаёт «который час». Гарантия контракта —
/// МОНОТОННОСТЬ: последовательные вызовы не убывают (скачки назад —
/// баг бекенда; переполнение u64 наносекунд — 584 года, вне скоупа).
pub trait TimeSource {
    /// Наносекунды с произвольной точки отсчёта (boot).
    fn now_ns(&self) -> u64;
}

struct TimeAnchor(&'static dyn TimeSource);

unsafe impl Send for TimeAnchor {}
unsafe impl Sync for TimeAnchor {}

static TIME_SOURCE: Once<TimeAnchor> = Once::new();

/// Число CPU (установка платформой при SMP-bring-up; по умолчанию 1).
static CPU_COUNT: Once<usize> = Once::new();

/// Зафиксировать число CPU (kinit/platform; до первого SELF_INFO).
pub fn install_cpu_count(n: usize) {
    let _ = CPU_COUNT.call_once(|| n.max(1));
}

/// Установленное число CPU (минимум 1).
pub fn cpu_count() -> usize {
    CPU_COUNT.get().copied().unwrap_or(1)
}

/// Установить источник времени (одноразово; повторные вызовы игнорируют
/// аргумент). Вызывается платформой ДО первого SYS_TIME.
pub fn install_time_source(source: &'static dyn TimeSource) -> Option<&'static dyn TimeSource> {
    Some(TIME_SOURCE.call_once(|| TimeAnchor(source)).0)
}

/// Установленный источник (`None` — SYS_TIME вернёт ENOSYS).
pub fn time_source() -> Option<&'static dyn TimeSource> {
    TIME_SOURCE.get().map(|a| a.0)
}

// ───────────────────────────── SELF_INFO ─────────────────────────────

/// Идентификация себя: TaskId/ThreadId/CPU вызывающего.
///
/// Слова по индексу (arg1): 0 = task_id.lo, 1 = task_id.hi,
/// 2 = thread_id.lo, 3 = thread_id.hi, 4 = cpu, 5 = cpu_count (v0.6).
pub struct SelfInfoHandler;

impl SelfInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::SELF_INFO;
}

impl crate::syscall::SyscallHandler for SelfInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let task = ctx.task.as_u128();
        let thread = ctx.thread.as_u128();
        let words = [
            task as u64,
            (task >> 64) as u64,
            thread as u64,
            (thread >> 64) as u64,
            ctx.cpu as u64,
            cpu_count() as u64,
        ];
        let idx = args.arg(1);
        words
            .get(idx)
            .map(|w| Ok(*w as usize))
            .unwrap_or(Err(SyscallError::InvalidArgument))
    }
}

// ───────────────────────────── SYS_TIME ─────────────────────────────

/// Монотонные часы ядра (KIP clock): наносекунды с загрузки.
///
/// Источник — [`install_time_source`]; без него — ENOSYS (ядро честно
/// отвечает «не поддерживаю», а не врёт нулями).
pub struct SysTimeHandler;

impl SysTimeHandler {
    pub const SYSCALL: SyscallNumber = nums::SYS_TIME;
}

impl crate::syscall::SyscallHandler for SysTimeHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, _args: &SyscallArgs) -> SyscallRet {
        match time_source() {
            Some(src) => Ok(src.now_ns() as usize),
            None => Err(SyscallError::NotSupported),
        }
    }
}

// ───────────────────────────── Тесты (host) ─────────────────────────────

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::cell::Cell;

    use crate::capability::CapabilityManager;
    use crate::syscall::{
        SyscallArgs, SyscallError, SyscallHandler, SyscallNumber, SyscallRegistry,
    };
    use crate::task::TcbManager;

    use super::*;

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    struct FakeClock {
        ns: Cell<u64>,
    }

    impl TimeSource for FakeClock {
        fn now_ns(&self) -> u64 {
            self.ns.get()
        }
    }

    fn ctx_of<'a>(
        tasks: &'a TcbManager,
        caps: &'a CapabilityManager,
        task: uuid::Uuid,
        thread: uuid::Uuid,
    ) -> SyscallCtx<'a> {
        SyscallCtx::core(5, task, tasks, caps).with_thread(thread)
    }

    #[test]
    fn self_info_words() {
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let task = uuid_next();
        let thread = uuid_next();
        let mut ctx = ctx_of(&tasks, &caps, task, thread);

        let mut word = |i: usize| {
            SelfInfoHandler
                .invoke(&mut ctx, &SyscallArgs::new([0, i, 0, 0, 0, 0]))
                .unwrap()
        };
        assert_eq!(word(0), task.as_u128() as usize);
        assert_eq!(word(1), (task.as_u128() >> 64) as usize);
        assert_eq!(word(2), thread.as_u128() as usize);
        assert_eq!(word(3), (thread.as_u128() >> 64) as usize);
        assert_eq!(word(4), 5);
        // Слово 5 — cpu_count (без установки платформы: 1; тесты хоста
        // однопроцессорные, Once глобален — фиксируем через вызов ниже).
        assert_eq!(word(5), crate::syscall::system::cpu_count());
        // Вне диапазона — EINVAL, не паника.
        assert_eq!(
            SelfInfoHandler.invoke(&mut ctx, &SyscallArgs::new([0, 6, 0, 0, 0, 0])),
            Err(SyscallError::InvalidArgument)
        );
    }

    #[test]
    fn sys_time_requires_then_reads_source() {
        let mut ctx = {
            let tasks = Box::leak(Box::new(TcbManager::new().unwrap()));
            let caps = Box::leak(Box::new(CapabilityManager::new().unwrap()));
            ctx_of(tasks, caps, uuid_next(), uuid_next())
        };

        // Источника нет (или установлен другим тестом — монотонность
        // установки глобальна, проверяем оба исхода детерминированно).
        if time_source().is_none() {
            assert_eq!(
                SysTimeHandler.invoke(&mut ctx, &SyscallArgs::none()),
                Err(SyscallError::NotSupported)
            );
        }

        // Установка (первая в процессе — сработает; повторная вернёт её же).
        let clock: &'static FakeClock = Box::leak(Box::new(FakeClock { ns: Cell::new(0) }));
        let installed = install_time_source(clock).unwrap();
        installed.now_ns();
        clock.ns.set(1_234_567_890);
        if core::ptr::eq(
            installed as *const dyn TimeSource,
            clock as *const FakeClock as *const dyn TimeSource,
        ) {
            assert_eq!(
                SysTimeHandler.invoke(&mut ctx, &SyscallArgs::none()),
                Ok(1_234_567_890)
            );
        }

        // Повторная установка игнорируется — источник стабилен.
        let other: &'static FakeClock = Box::leak(Box::new(FakeClock { ns: Cell::new(9) }));
        let again = install_time_source(other).unwrap();
        assert!(core::ptr::eq(
            again as *const dyn TimeSource,
            installed as *const dyn TimeSource
        ));
    }

    #[test]
    fn handlers_installed_by_default_table() {
        let reg = SyscallRegistry::new();
        reg.install_default_table();
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let id = uuid_next();
        let mut ctx = ctx_of(&tasks, &caps, id, id);

        // SELF_INFO диспетчеризуется таблицей по умолчанию.
        let ret = reg
            .dispatch_number(
                SelfInfoHandler::SYSCALL,
                &mut ctx,
                &SyscallArgs::new([0, 0, 0, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(ret, id.as_u128() as usize);
        assert_eq!(SelfInfoHandler::SYSCALL, SyscallNumber(0x03));
        assert_eq!(SysTimeHandler::SYSCALL, SyscallNumber(0x04));
    }
}
