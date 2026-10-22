// ==== МЕНЮ ВЫБОРА ПЕЙЛОАДА: GOP-рендер + клавиатура/serial + отсчёт ====
//
// Вызывается заглушкой ДО каких-либо аллокаций цепочки rust-l4: сначала
// пользователь выбирает пейлоад, потом ветвление (своя цепочка или
// chainload). Логика выбора — чистая модель bootcfg::menu (host-тесты);
// здесь — только рендер и опрос устройств.
//
// Рендер: прямая запись в линейный кадровый буфер GOP (текущий режим,
// режим не переключаем). Форматы: Bgr8888 / Rgb8888 / Bitmask (если
// каналы байтовыровнены; иначе — serial-режим). Шрифт — font8x8
// (public domain), масштаб x2; тайтл x3.
//
// Ввод: UEFI ConIn (стрелки/Enter/Esc/цифры) И COM1 в поллинге
// (j/k — вверх/вниз, 1..9 — прыжок, CR/LF — загрузка, Esc — default).
// Serial-путь важен для headless-прогонов: меню управляется без GOP.
//
// Таймаут (boot_cfg.xml `timeout`): >0 — обратный отсчёт до default;
// ЛЮБАЯ распознанная клавиша снимает отсчёт (меню ждёт Enter/Esc).
// <=0 — без отсчёта (0 до меню не доходит: заглушка грузит default
// сразу; <0 — ждать вечно).

use core::time::Duration;

use alloc::string::String;

use bootcfg::menu::{MenuAction, MenuKey, MenuModel};
use bootcfg::{BootConfig, PayloadKind};
use font8x8::legacy::BASIC_LEGACY;
use uefi::boot::{SearchType, open_protocol_exclusive, stall};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::console::text::{Key, ScanCode};
use uefi::system::with_stdin;

use crate::{log, uart_read_byte};

/// Период опроса ввода (мс). Отсчёт секунды собирается из тиков.
const POLL_MS: u64 = 20;

// ───────────────────── Палитра (холодная сталь, как серия PDF) ─────────────────────

const BG: [u8; 3] = [0x0d, 0x11, 0x17]; // почти чёрный
const ROW_BG: [u8; 3] = [0x16, 0x1b, 0x22]; // плашка выделенной строки
const ACCENT: [u8; 3] = [0x22, 0x7f, 0xad]; // сталь
const TEXT: [u8; 3] = [0xe6, 0xed, 0xf3]; // почти белый
const DIM: [u8; 3] = [0x8b, 0x94, 0x9e]; // серый

// ───────────────────── Поверхность GOP ─────────────────────

/// Линейный кадровый буфер (текущий режим GOP).
///
/// Владение: указатель живёт, пока открыт протокол GOP (заглушка держит
/// ScopedProtocol всё время меню и не меняет режим). Записи — volatile:
/// буфер — MMIO-подобная память прошивки.
struct Surface {
    base: *mut u8,
    /// Ширина/высота, пиксели.
    w: usize,
    h: usize,
    /// Строка развёртки, ПИКСЕЛИ (>= w).
    stride: usize,
    /// Смещения каналов в 4-байтовом пикселе.
    ro: usize,
    go: usize,
    bo: usize,
}

impl Surface {
    /// Открыть первый доступный GOP с линейным буфером.
    fn open() -> Option<Self> {
        let handles =
            uefi::boot::locate_handle_buffer(SearchType::from_proto::<GraphicsOutput>()).ok()?;
        for handle in handles.iter() {
            let Ok(mut gop) = open_protocol_exclusive::<GraphicsOutput>(*handle) else {
                continue;
            };
            let info = gop.current_mode_info();
            let (w, h) = info.resolution();
            if w == 0 || h == 0 {
                continue;
            }
            let fmt = info.pixel_format();
            let (ro, go, bo) = match fmt {
                PixelFormat::Bgr => (2, 1, 0),
                PixelFormat::Rgb => (0, 1, 2),
                PixelFormat::Bitmask => {
                    let m = info.pixel_bitmask()?;
                    // Каналы должны быть байтовыровнены и <= 8 бит
                    // (OVMF: 00FF0000/0000FF00/000000FF — подходит).
                    let off = |mask: u32| -> Option<usize> {
                        let shift = mask.trailing_zeros();
                        let bits = mask.count_ones();
                        (bits <= 8 && shift % 8 == 0 && shift < 32).then_some(shift as usize / 8)
                    };
                    (off(m.red)?, off(m.green)?, off(m.blue)?)
                }
                // BltOnly: линейного буфера нет — рисовать некуда.
                PixelFormat::BltOnly => continue,
            };
            let base = gop.frame_buffer().as_mut_ptr();
            let stride = info.stride();
            return Some(Self {
                base,
                w,
                h,
                stride,
                ro,
                go,
                bo,
            });
        }
        None
    }

    /// Один пиксель (вне экрана — игнор).
    fn px(&mut self, x: usize, y: usize, c: [u8; 3]) {
        if x >= self.w || y >= self.h {
            return;
        }
        // SAFETY: (x,y) в границах; base/stride/каналы валидны, пока
        // открыт GOP и режим не меняется (инвариант Surface).
        unsafe {
            let p = self.base.add((y * self.stride + x) * 4);
            p.add(self.ro).write_volatile(c[0]);
            p.add(self.go).write_volatile(c[1]);
            p.add(self.bo).write_volatile(c[2]);
        }
    }

    /// Заливка прямоугольника.
    fn rect(&mut self, x: usize, y: usize, w: usize, h: usize, c: [u8; 3]) {
        for yy in y..y.saturating_add(h) {
            for xx in x..x.saturating_add(w) {
                self.px(xx, yy, c);
            }
        }
    }

    /// Строка 8x8-шрифтом с целочисленным масштабом (LSB глифа = левый
    /// столбец — конвенция font8x8). Не-ASCII печатается как '?'.
    fn text(&mut self, x: usize, y: usize, s: &str, scale: usize, c: [u8; 3]) {
        let mut cx = x;
        for ch in s.chars() {
            let glyph = &BASIC_LEGACY[(if ch.is_ascii() {
                ch as usize
            } else {
                b'?' as usize
            }) & 0x7F];
            for (row, &bits) in glyph.iter().enumerate() {
                for col in 0..8 {
                    if bits & (1 << col) != 0 {
                        self.rect(cx + col * scale, y + row * scale, scale, scale, c);
                    }
                }
            }
            cx += 8 * scale;
        }
    }

    /// Ширина строки в пикселях (для центровки).
    fn text_w(s: &str, scale: usize) -> usize {
        s.chars().count() * 8 * scale
    }
}

// ───────────────────── Ввод ─────────────────────

/// Доступен ли UEFI ConIn (with_stdin паникует, если нет — проверяем).
fn stdin_available() -> bool {
    match uefi::table::system_table_raw() {
        Some(st) => {
            // SAFETY: system table валидна, пока активны boot services
            // (меню до EBS по построению).
            let st = unsafe { st.as_ref() };
            !st.stdin.is_null()
        }
        None => false,
    }
}

/// Приведение клавиши UEFI к модели меню.
fn uefi_key(k: Key) -> MenuKey {
    match k {
        Key::Special(ScanCode::UP) => MenuKey::Up,
        Key::Special(ScanCode::DOWN) => MenuKey::Down,
        Key::Special(ScanCode::ESCAPE) => MenuKey::Escape,
        Key::Printable(c) => {
            let ch = char::from(c);
            match ch {
                '\r' | '\n' => MenuKey::Enter,
                '0'..='9' => MenuKey::Digit(ch as u8 - b'0'),
                // vi-стиль работает и на клавиатуре — дублируем serial.
                'k' | 'K' => MenuKey::Up,
                'j' | 'J' => MenuKey::Down,
                _ => MenuKey::Ignore,
            }
        }
        _ => MenuKey::Ignore,
    }
}

/// Один такт опроса: UEFI-клавиатура + COM1.
fn poll_input() -> MenuKey {
    // Клавиатура.
    if stdin_available()
        && let Ok(Some(k)) = with_stdin(|stdin| stdin.read_key())
    {
        let mk = uefi_key(k);
        if mk != MenuKey::Ignore {
            return mk;
        }
    }
    // Serial: сливаем всё, что накопилось, последняя распознанная.
    let mut last = MenuKey::Ignore;
    while let Some(b) = uart_read_byte() {
        let mk = MenuKey::from_ascii(b);
        if mk != MenuKey::Ignore {
            last = mk;
        }
    }
    last
}

// ───────────────────── Меню ─────────────────────

/// Подпись пейлоада для меню/serial.
fn entry_label(idx: usize, cfg: &BootConfig) -> String {
    let p = &cfg.payloads[idx];
    alloc::format!("{}. {}  [{}]", idx + 1, p.menu_title(), p.kind.as_str())
}

/// Показать меню и вернуть индекс выбранного пейлоада.
///
/// `force_wait`: после возврата из chainload заглушка НЕ хочет обратного
/// отсчёта (иначе неудачный default пинг-понгнет перезагрузку той же
/// цепочки) — меню ждёт явного выбора.
pub fn choose(cfg: &BootConfig, force_wait: bool) -> usize {
    let default = cfg.resolve_default();
    let mut model = MenuModel::new(cfg.payloads.len(), default);
    let mut surface = Surface::open();

    // Дублируем меню в serial: headless-прогоны видят список и выбор.
    log("[menu] payloads:");
    for i in 0..cfg.payloads.len() {
        let mark = if i == default { " *" } else { "" };
        log(&alloc::format!(
            "[menu]   {}{}\r\n",
            entry_label(i, cfg),
            mark
        ));
    }
    if surface.is_none() {
        log("[menu] no linear GOP — serial mode only");
    }

    let countdown_from = if force_wait {
        None
    } else if cfg.timeout_s > 0 {
        Some(cfg.timeout_s)
    } else {
        None // 0 сюда не доходит; <0 — ждать вечно
    };
    let mut remaining = countdown_from;
    let mut paused = countdown_from.is_none();

    // Перерисовка: первый кадр, смена выделения, тик секунды.
    let mut last_second = -1i64;
    let mut last_selected = usize::MAX;
    let mut ticks_to_second = 1000 / POLL_MS;

    loop {
        // Тик.
        ticks_to_second -= 1;
        if ticks_to_second == 0 {
            ticks_to_second = 1000 / POLL_MS;
            if let Some(r) = remaining {
                if r <= 1 {
                    log(&alloc::format!(
                        "[menu] timeout -> default: {}\r\n",
                        entry_label(default, cfg)
                    ));
                    return default;
                }
                remaining = Some(r - 1);
            }
        }

        // Ввод (каждый такт).
        let key = poll_input();
        if key != MenuKey::Ignore {
            if !paused {
                paused = true;
                remaining = None;
                log("[menu] countdown paused");
            }
            match model.feed(key) {
                MenuAction::Boot(i) => {
                    log(&alloc::format!("[menu] boot: {}\r\n", entry_label(i, cfg)));
                    return i;
                }
                MenuAction::BootDefault => {
                    log(&alloc::format!(
                        "[menu] esc -> default: {}\r\n",
                        entry_label(default, cfg)
                    ));
                    return default;
                }
                MenuAction::None => {
                    if model.selected() != last_selected {
                        log(&alloc::format!(
                            "[menu] -> {}\r\n",
                            entry_label(model.selected(), cfg)
                        ));
                    }
                }
            }
        }

        // Рендер.
        if let Some(s) = surface.as_mut() {
            let sec = remaining.unwrap_or(-1);
            if model.selected() != last_selected || sec != last_second {
                last_selected = model.selected();
                last_second = sec;
                draw(s, cfg, &model, sec);
            }
        }

        stall(Duration::from_millis(POLL_MS));
    }
}

/// Полный кадр меню.
fn draw(s: &mut Surface, cfg: &BootConfig, model: &MenuModel, sec: i64) {
    let w = s.w;
    let margin = (w / 24).clamp(24, 64);

    // Фон.
    s.rect(0, 0, w, s.h, BG);

    // Заголовок.
    let title = "rust-l4 boot manager";
    let tx = (w - Surface::text_w(title, 3)) / 2;
    s.text(tx, margin, title, 3, TEXT);
    let sub = "select payload";
    let sx = (w - Surface::text_w(sub, 1)) / 2;
    s.text(sx, margin + 3 * 8 * 3 + 8, sub, 1, DIM);

    // Записи.
    let row_h = 2 * 8 * 2 + 14; // глиф x2 + воздух
    let mut y = margin + 3 * 8 * 3 + 8 + 8 + 24;
    for (i, p) in cfg.payloads.iter().enumerate() {
        let selected = i == model.selected();
        if selected {
            s.rect(0, y - 7, w, row_h, ROW_BG);
            s.rect(margin - 14, y - 7, 5, row_h, ACCENT);
        }
        let badge = match p.kind {
            PayloadKind::RustL4 => "rust-l4",
            PayloadKind::EfiChainload => "efi",
        };
        let label = alloc::format!("{}. {}   <{}>", i + 1, p.menu_title(), badge);
        s.text(margin, y, &label, 2, if selected { TEXT } else { DIM });
        y += row_h + 6;
    }

    // Отсчёт.
    let fy = s.h.saturating_sub(margin + 3 * 8);
    if sec >= 0 {
        let line = alloc::format!("booting default in {}s - any key to pause", sec);
        s.text(margin, fy - 14, &line, 1, ACCENT);
    }

    // Подсказки.
    let hints = "up/down: select    enter: boot    esc: default    1-9: jump    serial: j/k/enter";
    s.text(margin, fy, hints, 1, DIM);
}
