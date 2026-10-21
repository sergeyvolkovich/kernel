// ==== x86 I/O-порты: платформенная реализация IoPortOps (v0.14) ====
//
// Медитированный доступ юзерспейса к портам: syscall-хендлер IOP_IN/
// IOP_OUT проверил IoResource(IoPort)-cap — исполнение инструкции
// in/out происходит здесь, в контексте ядра (IOPL пользовательских
// контекстов = 0: прямых обращений не существует). Ширины 1/2/4 байта.

use pkg_generic_interface::hal::traits::ioport::IoPortOps;

/// Сервис портов x86_64 (единственный экземпляр; ставится в run()).
pub struct X86Ports;

impl IoPortOps for X86Ports {
    fn port_in(&self, port: u16, width: u8) -> u32 {
        // SAFETY: пространство портов валидно всегда на x86_64; доступ
        // медитирован IoResource(IoPort)-cap (хендлер IOP_IN выше).
        unsafe {
            match width {
                1 => {
                    let mut p: x86_64::instructions::port::Port<u8> =
                        x86_64::instructions::port::Port::new(port);
                    p.read() as u32
                }
                2 => {
                    let mut p: x86_64::instructions::port::Port<u16> =
                        x86_64::instructions::port::Port::new(port);
                    p.read() as u32
                }
                _ => {
                    let mut p: x86_64::instructions::port::Port<u32> =
                        x86_64::instructions::port::Port::new(port);
                    p.read()
                }
            }
        }
    }

    fn port_out(&self, port: u16, width: u8, value: u32) {
        // SAFETY: см. port_in.
        unsafe {
            match width {
                1 => {
                    let mut p: x86_64::instructions::port::Port<u8> =
                        x86_64::instructions::port::Port::new(port);
                    p.write(value as u8);
                }
                2 => {
                    let mut p: x86_64::instructions::port::Port<u16> =
                        x86_64::instructions::port::Port::new(port);
                    p.write(value as u16);
                }
                _ => {
                    let mut p: x86_64::instructions::port::Port<u32> =
                        x86_64::instructions::port::Port::new(port);
                    p.write(value);
                }
            }
        }
    }
}

/// Статический экземпляр (установка — platform::run).
pub static X86_PORTS: X86Ports = X86Ports;
