// ==== Отладочные сисколы: консоль, дампы, трассировка ====
//
// Консоль — платформенный `DebugSink` (глобальная одноразовая установка,
// как `GateManager`): ядро интерфейсного слоя само не умеет печатать.
// Дампы — слова по индексу (тот же протокол, что у `DeviceInfoHandler`):
// юзерспейс-отладчик читает их циклом, пока не получит ENOENT.
// Трассировка: гейт реестра проверяет флаг перед диспетчеризацией и
// пишет номер+аргументы в консоль (вкл/выкл из юзерспейса).

use core::sync::atomic::{AtomicBool, Ordering};

use spin::Once;

use crate::syscall::nums;
use crate::task::{TaskPriority, TaskState, ThreadId};

use super::SyscallHandler;
use super::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};

/// Платформенный приёмник отладочного вывода (консоль/serial).
pub trait DebugSink: Send + Sync {
    /// Побайтовый вывод (неблокирующий контракт платформы).
    fn write(&self, bytes: &[u8]);
}

static DEBUG_SINK: Once<&'static dyn DebugSink> = Once::new();
static TRACE_FLAG: AtomicBool = AtomicBool::new(false);

/// Установить приёмник отладки (одноразово, как `GateManager::install`).
/// Не установлен — DEBUG_WRITE тихо отбрасывает (отладка не обязана
/// быть подключена: ядро работает и без консоли).
pub fn install_debug_sink(sink: &'static dyn DebugSink) {
    let _ = DEBUG_SINK.call_once(|| sink);
}

/// Установленный приёмник.
pub fn debug_sink() -> Option<&'static dyn DebugSink> {
    DEBUG_SINK.get().copied()
}

/// Трассировка сисколов включена?
pub fn trace_enabled() -> bool {
    TRACE_FLAG.load(Ordering::Relaxed)
}

/// Включить/выключить трассировку; возвращает прежнее состояние.
pub fn set_trace(enabled: bool) -> bool {
    TRACE_FLAG.swap(enabled, Ordering::Relaxed)
}

/// Вывести байты в приёмник отладки (no-op без установленного sink).
pub fn debug_write(bytes: &[u8]) {
    if let Some(sink) = debug_sink() {
        sink.write(bytes);
    }
}

// ==== DEBUG_WRITE ====

/// Вывод до 40 байт за вызов (arg1..5 — машинные слова, little-endian).
pub struct DebugWriteHandler;

impl DebugWriteHandler {
    pub const SYSCALL: SyscallNumber = nums::DEBUG_WRITE;
}

impl SyscallHandler for DebugWriteHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        // arg1..5 — слова с байтами (len может укорачивать последнее).
        let mut buf = [0u8; 5 * 8];
        for i in 0..5 {
            let word = args.arg(1 + i);
            buf[i * 8..(i + 1) * 8].copy_from_slice(&(word as u64).to_le_bytes());
        }
        // Конвенция юзерспейса: строка NUL-терминирована, «лишние байты
        // консоль не покажет» — здесь и реализуем (баг v0.5.2: нули
        // дописывались в порт как есть, serial захламлялся мусором).
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        debug_write(&buf[..end]);
        Ok(0)
    }
}

// ==== DEBUG_DUMP_TASKS ====

/// Дамп задач по индексу слова:
/// `0` — число задач; далее `1 + i*4 + {0,1,2,3}` — id lo/hi, state, prio.
pub struct DebugDumpTasksHandler;

impl DebugDumpTasksHandler {
    pub const SYSCALL: SyscallNumber = nums::DEBUG_DUMP_TASKS;
}

fn task_state_word(state: TaskState) -> u64 {
    match state {
        TaskState::Ready => 1,
        TaskState::Running => 2,
        TaskState::Blocked => 3,
        TaskState::Suspended => 4,
        TaskState::Dead => 5,
    }
}

impl SyscallHandler for DebugDumpTasksHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let index = args.arg(1);
        let mut views: alloc::vec::Vec<_> = alloc::vec::Vec::new();
        ctx.tasks.for_each(|v| views.push(v));
        if index == 0 {
            return Ok(views.len());
        }
        let entry = index - 1;
        let task = entry / 4;
        let field = entry % 4;
        let Some(v) = views.get(task) else {
            return Err(SyscallError::NotFound);
        };
        let v128 = v.task_id.as_u128();
        Ok(match field {
            0 => v128 as u64 as usize,
            1 => (v128 >> 64) as u64 as usize,
            2 => task_state_word(v.state) as usize,
            _ => v.priority.as_u8() as usize,
        })
    }
}

// ==== DEBUG_TRACE ====

pub struct DebugTraceHandler;

impl DebugTraceHandler {
    pub const SYSCALL: SyscallNumber = nums::DEBUG_TRACE;
}

impl SyscallHandler for DebugTraceHandler {
    fn invoke(&self, _ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let enabled = args.arg(1) != 0;
        Ok(set_trace(enabled) as usize)
    }
}

// ==== DEBUG_DUMP_THREADS ====

/// Дамп потоков задачи по индексу слова:
/// `0` — число потоков; далее `1 + i*6 + {0..5}` — id lo/hi, owner lo/hi,
/// state, priority.
pub struct DebugDumpThreadsHandler;

impl DebugDumpThreadsHandler {
    pub const SYSCALL: SyscallNumber = nums::DEBUG_DUMP_THREADS;
}

impl SyscallHandler for DebugDumpThreadsHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let task = id_from(args.arg(1), args.arg(2));
        let index = args.arg(3);
        let views = ctx.tasks.threads_of(&task);
        if index == 0 {
            return Ok(views.len());
        }
        let entry = index - 1;
        let thread = entry / 6;
        let field = entry % 6;
        let Some(v) = views.get(thread) else {
            return Err(SyscallError::NotFound);
        };
        let idv = v.thread_id.as_u128();
        let ov = v.owner.as_u128();
        Ok(match field {
            0 => idv as u64 as usize,
            1 => (idv >> 64) as u64 as usize,
            2 => ov as u64 as usize,
            3 => (ov >> 64) as u64 as usize,
            4 => task_state_word(v.state) as usize,
            _ => v.priority.as_u8() as usize,
        })
    }
}

fn id_from(lo: usize, hi: usize) -> ThreadId {
    let _ = TaskPriority::DEFAULT;
    uuid::Uuid::from_u128(((hi as u128) << 64) | lo as u128)
}

// ==== Трассировка в реестре ====

/// Вызывается реестром перед диспетчеризацией (вкл/выкл — DEBUG_TRACE).
pub(crate) fn trace_dispatch(number: SyscallNumber, args: &SyscallArgs) {
    if !trace_enabled() {
        return;
    }
    let Some(sink) = debug_sink() else {
        return;
    };
    // Компактный формат: "syscall(0xNNNN) a0..a5\n".
    use core::fmt::Write;
    let mut line = alloc::string::String::new();
    let _ = write!(line, "syscall({:#06x})", number.as_u64());
    for i in 0..crate::syscall::SYSCALL_ARG_COUNT {
        let _ = write!(line, " {:#x}", args.arg(i));
    }
    line.push('\n');
    sink.write(line.as_bytes());
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityManager;
    use crate::syscall::SyscallRegistry;
    use crate::task::{TaskPriority, TcbManager};

    struct CaptureSink;

    impl DebugSink for CaptureSink {
        fn write(&self, bytes: &[u8]) {
            // Глобальный захват: параллельные тесты читают одинаково.
            CAPTURE.lock().extend_from_slice(bytes);
        }
    }

    /// Глобальный захват всех debug-тестов (один sink на процесс —
    /// установка одноразовая, тесты параллельны).
    static CAPTURE: spin::Mutex<alloc::vec::Vec<u8>> = spin::Mutex::new(alloc::vec::Vec::new());

    #[test]
    fn debug_write_goes_to_sink() {
        static SINK: CaptureSink = CaptureSink;
        install_debug_sink(&SINK);
        set_trace(false);

        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let mut ctx = crate::syscall::SyscallCtx::core(0, uuid::Uuid::nil(), &tasks, &caps);

        // Слова "hello" + нули.
        let hello = (u64::from_le_bytes(*b"hello\0\0\0")) as usize;
        let args = SyscallArgs::new([
            DebugWriteHandler::SYSCALL.as_u64() as usize,
            hello,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(DebugWriteHandler.invoke(&mut ctx, &args), Ok(0));
        let written = CAPTURE.lock();
        assert!(written.windows(5).any(|w| w == b"hello"));
    }

    #[test]
    fn trace_toggle_roundtrip() {
        static SINK: CaptureSink = CaptureSink;
        install_debug_sink(&SINK);

        set_trace(true);
        assert!(trace_enabled());
        CAPTURE.lock().clear();
        let args = SyscallArgs::new([0x1234, 1, 2, 3, 4, 5]);
        trace_dispatch(SyscallNumber(0x1234), &args);
        let lines = CAPTURE.lock().clone();
        // Трасса могла быть перекрыта параллельным тестом — ищем строку.
        assert!(lines.windows(15).any(|w| w == b"syscall(0x1234)"));
        // Выключение возвращает прежнее состояние.
        assert_eq!(set_trace(false), true);
        assert!(!trace_enabled());
    }

    #[test]
    fn dump_tasks_and_threads_words() {
        let tasks = TcbManager::new().unwrap();
        let caps = CapabilityManager::new().unwrap();
        let reg = SyscallRegistry::new();
        reg.register(DebugDumpTasksHandler::SYSCALL, &DebugDumpTasksHandler)
            .unwrap();
        reg.register(DebugDumpThreadsHandler::SYSCALL, &DebugDumpThreadsHandler)
            .unwrap();

        let task = uuid::Uuid::from_u128(0xAA);
        tasks.create(task, TaskPriority(77)).unwrap();
        let th = uuid::Uuid::from_u128(0xBB);
        tasks
            .create_thread(th, task, TaskPriority(88), 0x1000, 0x2000)
            .unwrap();

        let mut ctx = crate::syscall::SyscallCtx::core(0, task, &tasks, &caps);
        // Слово 0 — число задач.
        let n = DebugDumpTasksHandler
            .invoke(&mut ctx, &SyscallArgs::new([0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(n, 1);
        // Слова 1..4 — id lo/hi, state, priority.
        let state = DebugDumpTasksHandler
            .invoke(&mut ctx, &SyscallArgs::new([0, 3, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(state, 1); // Ready
        let prio = DebugDumpTasksHandler
            .invoke(&mut ctx, &SyscallArgs::new([0, 4, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(prio, 77);

        // Потоки: слово 0 — число; слово 5 — state потока; 6 — приоритет.
        let ta = task.as_u128();
        let tn = DebugDumpThreadsHandler
            .invoke(
                &mut ctx,
                &SyscallArgs::new([0, ta as usize, (ta >> 64) as usize, 0, 0, 0]),
            )
            .unwrap();
        assert_eq!(tn, 1);
        let th_state = DebugDumpThreadsHandler
            .invoke(
                &mut ctx,
                &SyscallArgs::new([0, ta as usize, (ta >> 64) as usize, 5, 0, 0]),
            )
            .unwrap();
        assert_eq!(th_state, 1); // Ready
        let th_prio = DebugDumpThreadsHandler
            .invoke(
                &mut ctx,
                &SyscallArgs::new([0, ta as usize, (ta >> 64) as usize, 6, 0, 0]),
            )
            .unwrap();
        assert_eq!(th_prio, 88);
    }

    fn uuid(v: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(v)
    }
}
