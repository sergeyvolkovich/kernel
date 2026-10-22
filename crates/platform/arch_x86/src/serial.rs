// ==== COM1: последовательный порт 16550 под поллингом ====
//
// Консоль отладки ядра до любых прерываний: поллинг LSR (THRE) —
// неблокирующий контракт `DebugSink` ядра выполняется по построению
// (ждём только аппаратного сдвига передатчика, очередей нет).
// Прерываний не просим (IER=0): IRQ-консоль — политика бекенда,
// если когда-нибудь понадобится — пусть ставит поверх.

/// Порт 16550 UART. `Copy`: порт — адрес, не ресурс.
#[derive(Debug, Clone, Copy)]
pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    /// Стандартный COM1 (QEMU: `-serial stdio` / `-serial file:...`).
    pub const COM1: SerialPort = SerialPort { base: 0x3F8 };

    // Смещения регистров от base:
    //   0: THR (write) / RBR (read) / DLL (DLAB=1)
    //   1: IER / DLH (DLAB=1)
    //   2: IIR (read) / FCR (write)
    //   3: LCR
    //   4: MCR
    //   5: LSR

    /// Инициализация: 115200 8N1, FIFO вкл, прерывания выкл (поллинг).
    pub fn init(&self) {
        unsafe {
            self.write_reg(1, 0x00); // IER: без прерываний
            self.write_reg(3, 0x80); // LCR: DLAB=1 (делитель)
            self.write_reg(0, 0x01); // DLL: делитель 1 -> 115200
            self.write_reg(1, 0x00); // DLH
            self.write_reg(3, 0x03); // LCR: 8 бит, без чётности, 1 стоп
            self.write_reg(2, 0xC7); // FCR: FIFO, очистка, триггер 14Б
            self.write_reg(4, 0x0B); // MCR: DTR|RTS|OUT2
        }
    }

    /// Включить прерывание передатчика (IER bit1, THRE; v0.11).
    ///
    /// Консоль ядра ОСТАЁТСЯ поллинговой (LSR) — это лишь источник линии
    /// IRQ4: IOAPIC-драйвер ведёт её драйверу юзерспейса (L4 irq_attach).
    /// Замаскированная линия хранит события — потери нет и до привязки.
    pub fn enable_thre_irq(&self) {
        unsafe {
            self.write_reg(1, 0x02); // IER: THRE
        }
    }

    /// Отправить байт (поллинг THRE). Байты — как есть: трансляцию
    /// `\n` -> `\r\n` делает вызывающий, если его терминалу нужно.
    pub fn send(&self, byte: u8) {
        unsafe {
            // LSR bit5 (THRE): передатчик свободен.
            while self.read_reg(5) & 0x20 == 0 {}
            self.write_reg(0, byte);
        }
    }

    /// Массив байт (трассировка/дампы).
    pub fn send_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.send(b);
        }
    }

    /// Прочитать байт, если пришёл (`None` — пусто). Читалка для
    /// будущей консоли; ядро пока только пишет.
    pub fn try_recv(&self) -> Option<u8> {
        unsafe {
            if self.read_reg(5) & 0x01 != 0 {
                Some(self.read_reg(0))
            } else {
                None
            }
        }
    }

    // ── сырой доступ к регистрам ──

    /// SAFETY: `off < 8` — регистры порта; вызовы не реентерабельны
    /// относительно самого UART (поллинговый контракт).
    unsafe fn read_reg(&self, off: u16) -> u8 {
        unsafe { x86_64::instructions::port::Port::new(self.base + off).read() }
    }

    /// SAFETY: см. `read_reg`.
    unsafe fn write_reg(&self, off: u16, value: u8) {
        unsafe { x86_64::instructions::port::Port::new(self.base + off).write(value) }
    }
}
