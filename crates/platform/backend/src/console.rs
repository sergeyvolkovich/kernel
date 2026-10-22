// ==== Консоль отладки ядра: COM1 как DebugSink ====
//
// Платформенная реализация приёмника ядра (`syscall::debug::DebugSink`):
// байты уходят в COM1 (поллинг 16550 из `arch`), без буферов и блокировок —
// неблокирующий контракт DebugSink выполняется по построению. Отсюда же
// макросы kprint!/kprintln! для ядрового кода (тот же COM1, форматирование
// core::fmt).

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use arch_x86::serial::SerialPort;
use pkg_generic_interface::syscall::debug::{self, DebugSink};

/// Консоль поверх UART (COM1 по умолчанию; `Copy` — порт это адрес).
#[derive(Debug, Clone, Copy)]
pub struct ComConsole {
    port: SerialPort,
}

impl ComConsole {
    /// Консоль на заданном порту.
    pub const fn new(port: SerialPort) -> Self {
        Self { port }
    }

    /// Стандартный COM1.
    pub const COM1: Self = Self {
        port: SerialPort::COM1,
    };

    /// Инициализация UART (115200 8N1, FIFO, поллинг).
    pub fn init(&self) {
        self.port.init();
    }

    /// Сырой вывод байт.
    pub fn write_bytes(&self, bytes: &[u8]) {
        self.port.send_bytes(bytes);
    }
}

impl fmt::Write for ComConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.port.send_bytes(s.as_bytes());
        Ok(())
    }
}

impl DebugSink for ComConsole {
    fn write(&self, bytes: &[u8]) {
        self.port.send_bytes(bytes);
    }
}

/// Единственная консоль ядра (статика: DebugSink требует 'static).
static CONSOLE: ComConsole = ComConsole::COM1;

/// Спин-лок serial (SMP v0.6): несколько CPU пишут в один UART;
/// без замка байты перемешиваются в строчках. Захват — на всю посылку
/// (поллинг внутри); вложенный вывод из panic при захваченном локе —
/// обходится try-путём (паника пишет напрямую, несовместимость строк
//  допустима в аварийном выводе).
static CONSOLE_LOCK: AtomicBool = AtomicBool::new(false);

/// Записать байты с SMP-сериализацией (try: паника/ранний старт пишут
/// без ожидания — взаимное перемешивание аварийного вывода допустимо).
fn write_locked(bytes: &[u8]) {
    let mut spins = 0u32;
    while CONSOLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spins += 1;
        if spins > 100_000 {
            // Не дождались (держатель умер?): писать без лока — лучше
            // перемешанные байты, чем молчание.
            CONSOLE.write_bytes(bytes);
            return;
        }
        core::hint::spin_loop();
    }
    CONSOLE.write_bytes(bytes);
    CONSOLE_LOCK.store(false, Ordering::Release);
}

/// Публичный 'static приёмник (platform::debug_sink): SMP-лок
/// (DEBUG_WRITE пользователя и kprint ядра сериализуются в один UART).
pub struct LockedSink;
impl DebugSink for LockedSink {
    fn write(&self, bytes: &[u8]) {
        write_locked(bytes);
    }
}

pub static CONSOLE_SINK: LockedSink = LockedSink;

/// Инициализация: UART + установка приёмника ядра (одноразовая,
/// повторные вызовы DEBUG_WRITE после этого доходят до порта).
pub fn init_console() {
    CONSOLE.init();
    debug::install_debug_sink(&CONSOLE_SINK);
}

/// Прямой вывод в консоль (минуя DebugSink-реестр: для раннего старта
/// и паник, когда сискольный слой ещё не важен).
pub fn write(bytes: &[u8]) {
    CONSOLE.write_bytes(bytes);
}

/// Строка в консоль (ранний старт/паники; без форматирования).
pub fn kprint_str(s: &str) {
    write_locked(s.as_bytes());
}

/// Форматированный вывод в консоль (код ядра).
pub fn _fmt(args: fmt::Arguments<'_>) {
    use fmt::Write;
    // Формирование строки в стек, затем одна посылка под локом
    // (посимвольный fmt-вывод по 1 байту через write_locked перемешал
    // бы CPU даже при локе — лок держится на всю посылку).
    let mut buf = [0u8; 256];
    let mut len = 0usize;
    let mut w = StackWriter {
        buf: &mut buf,
        len: &mut len,
    };
    let _ = w.write_fmt(args);
    write_locked(&buf[..len]);
}

/// Стековый fmt-writer (без кучи — ранний старт/ядро).
struct StackWriter<'a> {
    buf: &'a mut [u8],
    len: &'a mut usize,
}

impl fmt::Write for StackWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if *self.len >= self.buf.len() {
                break; // обрезка переполнения — не падать же
            }
            self.buf[*self.len] = b;
            *self.len += 1;
        }
        Ok(())
    }
}

/// Печать без перевода строки.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::_fmt(format_args!($($arg)*))
    };
}

/// Печать с переводом строки.
#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($fmt:expr) => { $crate::kprint!(concat!($fmt, "\n")) };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::kprint!(concat!($fmt, "\n"), $($arg)*)
    };
}
