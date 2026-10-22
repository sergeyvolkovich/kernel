// ==== МЕНЮ ВЫБОРА ПЕЙЛОАДА: чистая модель (host-тестируемая) ====
//
// Рендер и опрос устройств живут в UEFI-заглушке (GOP/клавиатура/serial);
// здесь — только логика выбора: навигация, цифры, Enter/Esc, обратная
// связь для отрисовки. Разделение позволяет гонять поведение меню
// юнит-тестами на хосте (bootcfg входит в default-members workspace).

/// Клавиша меню в терминах модели (источник: UEFI ReadKeyStroke или
/// байт с COM1 — приведение делает вызывающая сторона).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuKey {
    /// Стрелка вверх (или 'k' по serial).
    Up,
    /// Стрелка вниз (или 'j' по serial).
    Down,
    /// Enter: загрузить текущий выбор.
    Enter,
    /// Esc: загрузить ПЕЙЛОАД ПО УМОЛЧАНИЮ немедленно.
    Escape,
    /// Цифра 1..=9: выделить запись (без загрузки).
    Digit(u8),
    /// Всё остальное — игнор.
    Ignore,
}

impl MenuKey {
    /// Приведение байта COM1 (ASCII) к клавише.
    ///
    /// Стрелки по serial — ESC-последовательности («\x1b[A»), их разбор
    /// не стоит усложнения: меню дополнительно понимает vi-стиль
    /// j/k. Enter — CR или LF.
    pub fn from_ascii(b: u8) -> Self {
        match b {
            b'k' | b'K' => Self::Up,
            b'j' | b'J' => Self::Down,
            b'\r' | b'\n' => Self::Enter,
            0x1B => Self::Escape,
            b'0'..=b'9' => Self::Digit(b - b'0'),
            _ => Self::Ignore,
        }
    }
}

/// Реакция модели на клавишу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    /// Ничего (выделение могло сместиться — перерисовать).
    None,
    /// Загрузить запись `usize`.
    Boot(usize),
    /// Загрузить запись по умолчанию (Esc).
    BootDefault,
}

/// Состояние меню: число записей + текущее выделение.
#[derive(Debug, Clone)]
pub struct MenuModel {
    len: usize,
    /// Запись по умолчанию (Esc): фиксируется при создании.
    default: usize,
    selected: usize,
}

impl MenuModel {
    /// Пустое меню (0 записей) — валидно: всякая клавиша → BootDefault,
    /// вызывающая сторона в таком случае меню не показывает вовсе.
    pub fn new(len: usize, default: usize) -> Self {
        let default = default.min(len.saturating_sub(1));
        Self {
            len,
            default,
            selected: default,
        }
    }

    /// Индекс выделенной записи.
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Запись по умолчанию (стартовое выделение, Esc).
    pub fn default(&self) -> usize {
        self.default
    }

    /// Выделить запись (клэмп по границам).
    pub fn select(&mut self, i: usize) {
        if self.len == 0 {
            return;
        }
        self.selected = i.min(self.len - 1);
    }

    /// Провести клавишу через модель.
    pub fn feed(&mut self, key: MenuKey) -> MenuAction {
        match key {
            MenuKey::Ignore => MenuAction::None,
            MenuKey::Up => {
                if self.len > 0 {
                    // wrap-around: верхняя запись → нижняя.
                    self.selected = if self.selected == 0 {
                        self.len - 1
                    } else {
                        self.selected - 1
                    };
                }
                MenuAction::None
            }
            MenuKey::Down => {
                if self.len > 0 {
                    self.selected = (self.selected + 1) % self.len;
                }
                MenuAction::None
            }
            MenuKey::Digit(d) => {
                // 1-based; 0 и записи за пределами списка — игнор.
                if d >= 1 && (d as usize) <= self.len {
                    self.select(d as usize - 1);
                }
                MenuAction::None
            }
            MenuKey::Enter => {
                if self.len == 0 {
                    MenuAction::BootDefault
                } else {
                    MenuAction::Boot(self.selected)
                }
            }
            MenuKey::Escape => MenuAction::BootDefault,
        }
    }
}

// ───────────────────────────── Тесты ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_wraps_both_ways() {
        let mut m = MenuModel::new(3, 0);
        assert_eq!(m.selected(), 0);
        m.feed(MenuKey::Down);
        assert_eq!(m.selected(), 1);
        m.feed(MenuKey::Down);
        m.feed(MenuKey::Down);
        assert_eq!(m.selected(), 0, "down wraps to first");
        m.feed(MenuKey::Up);
        assert_eq!(m.selected(), 2, "up wraps to last");
    }

    #[test]
    fn enter_boots_current_selection() {
        let mut m = MenuModel::new(3, 2);
        assert_eq!(m.selected(), 2, "initial = default");
        assert_eq!(m.feed(MenuKey::Enter), MenuAction::Boot(2));
    }

    #[test]
    fn escape_boots_default_not_selection() {
        let mut m = MenuModel::new(3, 1);
        m.feed(MenuKey::Down); // selected = 2
        assert_eq!(m.feed(MenuKey::Escape), MenuAction::BootDefault);
    }

    #[test]
    fn digits_select_without_boot() {
        let mut m = MenuModel::new(9, 0);
        assert_eq!(m.feed(MenuKey::Digit(3)), MenuAction::None);
        assert_eq!(m.selected(), 2);
        assert_eq!(m.feed(MenuKey::Digit(9)), MenuAction::None);
        assert_eq!(m.selected(), 8);
        // 0 и за пределами — игнор (выделение не меняется).
        assert_eq!(m.feed(MenuKey::Digit(0)), MenuAction::None);
        assert_eq!(m.selected(), 8);
    }

    #[test]
    fn ascii_mapping() {
        assert_eq!(MenuKey::from_ascii(b'k'), MenuKey::Up);
        assert_eq!(MenuKey::from_ascii(b'J'), MenuKey::Down);
        assert_eq!(MenuKey::from_ascii(b'\r'), MenuKey::Enter);
        assert_eq!(MenuKey::from_ascii(b'\n'), MenuKey::Enter);
        assert_eq!(MenuKey::from_ascii(0x1B), MenuKey::Escape);
        assert_eq!(MenuKey::from_ascii(b'5'), MenuKey::Digit(5));
        assert_eq!(MenuKey::from_ascii(b'x'), MenuKey::Ignore);
        // 0 — цифра, но вне диапазона записей (модель игнорирует).
        assert_eq!(MenuKey::from_ascii(b'0'), MenuKey::Digit(0));
    }

    #[test]
    fn digit_then_enter_path() {
        let mut m = MenuModel::new(2, 0);
        m.feed(MenuKey::Digit(2));
        assert_eq!(m.feed(MenuKey::Enter), MenuAction::Boot(1));
    }

    #[test]
    fn empty_menu_boots_default() {
        let mut m = MenuModel::new(0, 0);
        assert_eq!(m.feed(MenuKey::Enter), MenuAction::BootDefault);
        assert_eq!(m.feed(MenuKey::Up), MenuAction::None);
    }

    #[test]
    fn initial_default_clamped() {
        let m = MenuModel::new(2, 7);
        assert_eq!(m.selected(), 1, "default beyond list clamps to last");
        assert_eq!(m.default(), 1);
    }
}
