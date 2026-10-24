// ==== BOOTCFG: модель + разбор + запись boot_cfg.xml (v3: boot-архив) ====
//
// XML живёт ТОЛЬКО по эту сторону протокола загрузки: заглушка (UEFI)
// читает boot_cfg.xml из каталога СВОЕГО образа на ESP, разбирает его
// здесь в [`BootConfig`] и транслирует в плоский boot_info::BootInfo
// (модуль [0] = boot-архив + boot_state). Ядро XML не видит вовсе:
// переносимость протокола загрузки не должна зависеть от формата
// конфигурации.
//
// Схема v3 (жёсткий разрыв с v2: список серверов и легаси-корень <boot>
// УДАЛЕНЫ — см. docs/boot-protocol-v3.md):
//   <bootloader timeout="5" default="rust-l4">
//     <payload id="rust-l4" type="rust-l4" title="rust-l4"
//              cmdline="arch=x86_64 console=com1"
//              archive="boot.cpio" archive_crc32="0x1a2b3c4d">
//       <boot_state>
//         <var name="console" value="com1"/>
//       </boot_state>
//     </payload>
//     <payload id="win" type="efi" title="Windows Boot Manager"
//              path="\EFI\Microsoft\Boot\bootmgfw.efi"/>
//   </bootloader>
//
// Типы пейлоадов:
//   * rust-l4 — своя цепочка: встроенное ядро + ОДИН boot-архив RLBA
//     (`archive`): заглушка читает файл как есть (модуль [0] BootInfo),
//     ядро поднимает flat-бутстрап, бутстрап спавнит init из каталога;
//   * efi     — chainload произвольного EFI-образа (bootmgfw/grub/...):
//     LoadImage по device path (том + файл) + StartImage; загрузчик
//     сам находит свои данные по собственному device path.
//
// Атрибут `archive_crc32` (опционально): чексумма файла архива; пока
// заглушка читает blob с ESP, она подсчитывает CRC32 и сверяет —
// ловим битность ДО выхода из boot services (fail рано).
//
// Атрибут `timeout` (секунды): >0 — меню с обратным отсчётом; 0 — без
// меню, грузить default немедленно; <0 — ждать вечно. Отсутствует —
// [DEFAULT_TIMEOUT_SECS]. `default` — id пейлоада по умолчанию
// (отсутствует → первый).
//
// Разбор — собственный микро-XML (minixml.rs): готовые крейты тянули std
// в UEFI-заглушку, а схема фиксирована и мала. Наш код — сверка событий
// со схемой (машина контекста). Запись (to_xml) — для host-инструмента
// cfgtool (crates/misc); заглушка конфигурацию не пишет.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod menu;
pub mod minixml;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use boot_info::{BootStateVar, MAX_BOOT_STATE};
use minixml::{Event, Reader};

/// Таймаут меню по умолчанию (сек), если атрибут `timeout` не задан.
pub const DEFAULT_TIMEOUT_SECS: i64 = 5;

// ───────────────────────────── Модель ─────────────────────────────

/// Тип пейлоада.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayloadKind {
    /// Своя цепочка: встроенное ядро + boot-архив RLBA (cmdline/state).
    #[default]
    RustL4,
    /// Chainload стороннего EFI-образа по `path`.
    EfiChainload,
}

impl PayloadKind {
    /// Строковый тег схемы (`type="..."`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustL4 => "rust-l4",
            Self::EfiChainload => "efi",
        }
    }

    /// Разбор тега схемы.
    pub fn from_tag(s: &str) -> Option<Self> {
        match s {
            "rust-l4" => Some(Self::RustL4),
            "efi" => Some(Self::EfiChainload),
            _ => None,
        }
    }
}

/// Один загружаемый пейлоад.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payload {
    /// Идентификатор (уникален; на него ссылается `default`).
    pub id: String,
    /// Заголовок меню (отсутствует в схеме → id).
    pub title: String,
    /// Тип цепочки загрузки.
    pub kind: PayloadKind,
    /// efi: путь к образу от корня тома.
    pub path: String,
    /// rust-l4: командная строка ядра (BootInfo.cmdline; пустая —
    /// заглушка поставит свою по умолчанию).
    pub kernel_cmdline: String,
    /// rust-l4: путь к boot-архиву RLBA от корня тома (модуль [0]).
    pub archive: String,
    /// rust-l4: контрольная CRC32 архива (опционально; заглушка
    /// сверяет при чтении — порча ловится до ExitBootServices).
    pub archive_crc32: Option<u32>,
    /// rust-l4: переменные состояния загрузки (транзит бутстрап → init).
    pub state: Vec<(String, String)>,
}

impl Payload {
    /// Собрать boot_state в формат протокола BootInfo (транзит).
    ///
    /// Отказ — ДО ExitBootServices: переполнение фиксированных полей
    /// протокола (число переменных, длина имени/значения) обязано
    /// останавливать загрузку, а не молча обрезаться.
    pub fn boot_state_vars(&self) -> Result<Vec<BootStateVar>, BootcfgError> {
        if self.state.len() > MAX_BOOT_STATE {
            return Err(BootcfgError::Schema(
                "too many <var> entries (protocol limit)",
            ));
        }
        let mut out = Vec::with_capacity(self.state.len());
        for (name, value) in &self.state {
            out.push(
                BootStateVar::from_strs(name, value).ok_or(BootcfgError::Schema(
                    "boot_state name/value too long (protocol limit)",
                ))?,
            );
        }
        Ok(out)
    }

    /// Заголовок для меню (title, если задан, иначе id).
    pub fn menu_title(&self) -> &str {
        if self.title.is_empty() {
            &self.id
        } else {
            &self.title
        }
    }
}

/// Разобранный boot_cfg.xml.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootConfig {
    /// Таймаут меню, сек: >0 — отсчёт; 0 — грузить default сразу;
    /// <0 — ждать вечно. [`DEFAULT_TIMEOUT_SECS`] если не задан.
    pub timeout_s: i64,
    /// id пейлоада по умолчанию (None → первый в списке).
    pub default_id: Option<String>,
    /// Пейлоады в порядке меню; загрузка любого — по выбору/умолчанию.
    pub payloads: Vec<Payload>,
}

impl BootConfig {
    /// Индекс пейлоада по умолчанию (default_id → индекс; иначе 0).
    pub fn resolve_default(&self) -> usize {
        if let Some(id) = &self.default_id {
            for (i, p) in self.payloads.iter().enumerate() {
                if &p.id == id {
                    return i;
                }
            }
        }
        0
    }

    /// Поиск пейлоада по id.
    pub fn payload(&self, id: &str) -> Option<&Payload> {
        self.payloads.iter().find(|p| p.id == id)
    }

    /// Семантическая валидация (после разбора структуры):
    ///
    /// * хотя бы один пейлоад, id уникальны;
    /// * `default` (если задан) существует;
    /// * rust-l4: архив задан, boot_state влезает в протокол;
    /// * efi: путь не пуст.
    ///
    /// Структурные ошибки (элемент не на своём месте, нет обязательного
    /// атрибута) ловит [`parse`]; здесь — то, что видно только по
    /// конфигурации целиком.
    pub fn validate(&self) -> Result<(), BootcfgError> {
        if self.payloads.is_empty() {
            return Err(BootcfgError::Schema("no <payload> entries"));
        }
        for (i, p) in self.payloads.iter().enumerate() {
            if p.id.is_empty() {
                return Err(BootcfgError::Schema("payload with empty id"));
            }
            for q in &self.payloads[..i] {
                if q.id == p.id {
                    return Err(BootcfgError::Schema("duplicate payload id"));
                }
            }
            match p.kind {
                PayloadKind::RustL4 => {
                    if p.archive.is_empty() {
                        return Err(BootcfgError::Schema("rust-l4 payload without archive"));
                    }
                    // Поля протокола проверяем здесь же: лучше отказать
                    // в cfgtool, чем FATAL-ом в заглушке на машине.
                    p.boot_state_vars()?;
                }
                PayloadKind::EfiChainload => {
                    if p.path.is_empty() {
                        return Err(BootcfgError::Schema("efi payload without path"));
                    }
                }
            }
        }
        if let Some(id) = &self.default_id
            && self.payload(id).is_none()
        {
            return Err(BootcfgError::Schema("default payload id not found"));
        }
        Ok(())
    }
}

/// Ошибка разбора конфигурации.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootcfgError {
    /// minixml не смог токенизировать документ.
    Xml(String),
    /// Структура не соответствует схеме: подробности в строке.
    Schema(&'static str),
    /// Отсутствует обязательный атрибут (имя — в строке).
    MissingAttr(&'static str),
}

impl core::fmt::Display for BootcfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "boot_cfg.xml: ill-formed XML: {e}"),
            Self::Schema(what) => write!(f, "boot_cfg.xml: schema violation: {what}"),
            Self::MissingAttr(a) => write!(f, "boot_cfg.xml: missing required attribute '{a}'"),
        }
    }
}

// ───────────────────────────── Разбор ─────────────────────────────

/// Позиция в дереве схемы (машина контекста).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Вне пейлоадов: корень <bootloader>.
    Root,
    /// Внутри <payload>.
    Payload,
    /// Внутри <boot_state>.
    BootState,
}

/// Разобрать текст boot_cfg.xml (схема v3).
pub fn parse(input: &str) -> Result<BootConfig, BootcfgError> {
    let mut reader = Reader::new(input);
    let mut cfg = BootConfig::default();
    let mut ctx = Ctx::Root;

    loop {
        match reader
            .next_event()
            .map_err(|e| BootcfgError::Xml(e.to_string()))?
        {
            Event::Start {
                name,
                attrs,
                self_closing,
            } => handle_start(&mut cfg, &mut ctx, name, &attrs, self_closing)?,
            Event::End { name } => match name {
                "boot_state" => ctx = Ctx::Payload,
                "payload" => ctx = Ctx::Root,
                _ => {}
            },
            Event::Text(_) => {}
            Event::Eof => break,
        }
    }

    Ok(cfg)
}

/// Общий обработчик Start/Empty (`self_closing` — `<payload/>` без детей).
fn handle_start(
    cfg: &mut BootConfig,
    ctx: &mut Ctx,
    name: &str,
    attrs: &[(&str, String)],
    self_closing: bool,
) -> Result<(), BootcfgError> {
    match name {
        "bootloader" => {
            if !cfg.payloads.is_empty() {
                return Err(BootcfgError::Schema("duplicate root element"));
            }
            // Дефолт таймаута живёт здесь, а не в Default: модель
            // используется и как строитель (cfgtool), где «не задано»
            // легитимно; схема же без атрибута = DEFAULT_TIMEOUT_SECS.
            cfg.timeout_s = DEFAULT_TIMEOUT_SECS;
            if let Some(t) = attrs.iter().find(|(k, _)| *k == "timeout") {
                cfg.timeout_s = parse_timeout(&t.1)?;
            }
            if let Some(d) = attrs.iter().find(|(k, _)| *k == "default") {
                cfg.default_id = Some(d.1.clone());
            }
        }
        "boot" => {
            // Легаси-корень v1/v2 удалён схемой v3: честный отказ вместо
            // молчаливой интерпретации (конфиг без <archive> бесполезен).
            return Err(BootcfgError::Schema(
                "legacy <boot> root removed in schema v3 (use <bootloader> + archive)",
            ));
        }
        "payload" => {
            if *ctx != Ctx::Root {
                return Err(BootcfgError::Schema("<payload> must be at root level"));
            }
            let id = required_attr(attrs, "id")?;
            if id.is_empty() {
                return Err(BootcfgError::Schema("<payload> id must not be empty"));
            }
            let ty = required_attr(attrs, "type")?;
            let kind = PayloadKind::from_tag(&ty).ok_or(BootcfgError::Schema(
                "<payload> type must be 'rust-l4' or 'efi'",
            ))?;
            let mut p = Payload {
                id,
                title: String::new(),
                kind,
                ..Payload::default()
            };
            if let Some(t) = attrs.iter().find(|(k, _)| *k == "title") {
                p.title = t.1.clone();
            }
            match kind {
                PayloadKind::EfiChainload => {
                    p.path = required_attr(attrs, "path")?;
                    reject_attr(attrs, "cmdline", "cmdline only for rust-l4 payloads")?;
                    reject_attr(attrs, "archive", "archive only for rust-l4 payloads")?;
                }
                PayloadKind::RustL4 => {
                    reject_attr(attrs, "path", "path only for efi payloads")?;
                    if let Some(cl) = attrs.iter().find(|(k, _)| *k == "cmdline") {
                        p.kernel_cmdline = cl.1.clone();
                    }
                    p.archive = required_attr(attrs, "archive")?;
                    if let Some(c) = attrs.iter().find(|(k, _)| *k == "archive_crc32") {
                        p.archive_crc32 = Some(parse_crc32(&c.1)?);
                    }
                }
            }
            cfg.payloads.push(p);
            if !self_closing {
                *ctx = Ctx::Payload;
            }
        }
        "boot_state" => {
            if *ctx != Ctx::Payload {
                return Err(BootcfgError::Schema(
                    "<boot_state> must be inside <payload>",
                ));
            }
            *ctx = Ctx::BootState;
        }
        "var" => {
            if *ctx != Ctx::BootState {
                return Err(BootcfgError::Schema("<var> must be inside <boot_state>"));
            }
            let name = required_attr(attrs, "name")?;
            let value = required_attr(attrs, "value")?;
            cfg.payloads
                .last_mut()
                .ok_or(BootcfgError::Schema("<var> without payload"))?
                .state
                .push((name, value));
        }
        // Чужие элементы игнорируются: схема растёт вперёд без поломки
        // старых заглушек; известные элементы вне места пойманы выше.
        _ => {}
    }
    Ok(())
}

/// Обязательный строковый атрибут элемента.
fn required_attr(attrs: &[(&str, String)], key: &str) -> Result<String, BootcfgError> {
    for (k, v) in attrs {
        if *k == key {
            return Ok(v.clone());
        }
    }
    Err(BootcfgError::MissingAttr(match key {
        "id" => "id",
        "type" => "type",
        "name" => "name",
        "path" => "path",
        "archive" => "archive",
        "value" => "value",
        _ => "attribute",
    }))
}

/// Атрибут, запрещённый для данного типа пейлоада (ловит copy-paste).
fn reject_attr(attrs: &[(&str, String)], key: &str, why: &'static str) -> Result<(), BootcfgError> {
    if attrs.iter().any(|(k, _)| *k == key) {
        return Err(BootcfgError::Schema(why));
    }
    Ok(())
}

/// Разбор таймаута: i64; пустая строка — ошибка (typo-страж).
fn parse_timeout(s: &str) -> Result<i64, BootcfgError> {
    s.trim()
        .parse::<i64>()
        .map_err(|_| BootcfgError::Schema("timeout must be an integer (seconds)"))
}

/// Разбор CRC32: hex с `0x` или десятичный; пустой/чужой — ошибка.
fn parse_crc32(s: &str) -> Result<u32, BootcfgError> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map_err(|_| BootcfgError::Schema("archive_crc32 must be hex (0x…) or decimal"))
    } else {
        t.parse::<u32>()
            .map_err(|_| BootcfgError::Schema("archive_crc32 must be hex (0x…) or decimal"))
    }
}

// ───────────────────────────── Запись (cfgtool) ─────────────────────────────

/// Экранирование значения атрибута / текста (<>&"' → сущности).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Сериализовать конфигурацию в v3-XML (канонический вид cfgtool:
/// 2 пробела отступа, атрибуты в фиксированном порядке).
pub fn to_xml(cfg: &BootConfig) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<bootloader");
    if cfg.timeout_s < 0 {
        out.push_str(" timeout=\"-1\"");
    } else {
        out.push_str(&alloc::format!(" timeout=\"{}\"", cfg.timeout_s));
    }
    if let Some(d) = &cfg.default_id {
        out.push_str(&alloc::format!(" default=\"{}\"", escape(d)));
    }
    out.push_str(">\n");
    for p in &cfg.payloads {
        out.push_str("  <payload");
        out.push_str(&alloc::format!(" id=\"{}\"", escape(&p.id)));
        out.push_str(&alloc::format!(" type=\"{}\"", p.kind.as_str()));
        if !p.title.is_empty() {
            out.push_str(&alloc::format!(" title=\"{}\"", escape(&p.title)));
        }
        match p.kind {
            PayloadKind::EfiChainload => {
                out.push_str(&alloc::format!(" path=\"{}\"", escape(&p.path)));
                out.push_str("/>\n");
            }
            PayloadKind::RustL4 => {
                if !p.kernel_cmdline.is_empty() {
                    out.push_str(&alloc::format!(
                        " cmdline=\"{}\"",
                        escape(&p.kernel_cmdline)
                    ));
                }
                out.push_str(&alloc::format!(" archive=\"{}\"", escape(&p.archive)));
                if let Some(crc) = p.archive_crc32 {
                    out.push_str(&alloc::format!(" archive_crc32=\"0x{crc:08x}\""));
                }
                out.push_str(">\n");
                if !p.state.is_empty() {
                    out.push_str("    <boot_state>\n");
                    for (k, v) in &p.state {
                        out.push_str(&alloc::format!(
                            "      <var name=\"{}\" value=\"{}\"/>\n",
                            escape(k),
                            escape(v)
                        ));
                    }
                    out.push_str("    </boot_state>\n");
                }
                out.push_str("  </payload>\n");
            }
        }
    }
    out.push_str("</bootloader>\n");
    out
}

// ───────────────────────────── Тесты ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_V3: &str = r#"<bootloader timeout="7" default="win">
        <payload id="rust" type="rust-l4" title="rust-l4" cmdline="arch=x86_64"
                 archive="boot.cpio" archive_crc32="0x1a2b3c4d">
            <boot_state>
                <var name="console" value="com1"/>
            </boot_state>
        </payload>
        <payload id="win" type="efi" title="Windows" path="\EFI\Microsoft\Boot\bootmgfw.efi"/>
    </bootloader>"#;

    #[test]
    fn v3_multi_payload_parses() {
        let cfg = parse(FULL_V3).unwrap();
        assert_eq!(cfg.timeout_s, 7);
        assert_eq!(cfg.default_id.as_deref(), Some("win"));
        assert_eq!(cfg.payloads.len(), 2);

        let p0 = &cfg.payloads[0];
        assert_eq!(p0.id, "rust");
        assert_eq!(p0.kind, PayloadKind::RustL4);
        assert_eq!(p0.title, "rust-l4");
        assert_eq!(p0.kernel_cmdline, "arch=x86_64");
        assert_eq!(p0.archive, "boot.cpio");
        assert_eq!(p0.archive_crc32, Some(0x1a2b_3c4d));
        assert_eq!(p0.state, vec![("console".into(), "com1".into())]);

        let p1 = &cfg.payloads[1];
        assert_eq!(p1.id, "win");
        assert_eq!(p1.kind, PayloadKind::EfiChainload);
        assert_eq!(p1.path, "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        assert_eq!(p1.archive, "");

        cfg.validate().unwrap();
        assert_eq!(cfg.resolve_default(), 1, "default=win");
        assert_eq!(p1.menu_title(), "Windows");
        assert_eq!(p0.menu_title(), "rust-l4");
    }

    #[test]
    fn legacy_schema_is_rejected() {
        // Легаси-корень <boot> удалён схемой v3 — честный отказ.
        assert!(matches!(
            parse("<boot><boot_state><var name=\"a\" value=\"b\"/></boot_state></boot>"),
            Err(BootcfgError::Schema(_))
        ));
        // Старый список серверов: <archive> обязателен уже на разборе —
        // конфиг без архива бесполезен, отказ ранний и честный.
        assert!(matches!(
            parse(
                "<bootloader><payload id=\"a\" type=\"rust-l4\" \
                 cmdline=\"x\"><servers><server name=\"init\" path=\"init.elf\"/></servers></payload></bootloader>"
            ),
            Err(BootcfgError::MissingAttr("archive"))
        ));
    }

    #[test]
    fn archive_crc32_formats() {
        let mk = |v: &str| {
            parse(&alloc::format!(
                "<bootloader><payload id=\"a\" type=\"rust-l4\" archive=\"b.cpio\" archive_crc32=\"{v}\"/></bootloader>"
            ))
            .unwrap()
            .payloads[0]
            .archive_crc32
        };
        assert_eq!(mk("0x1a2b3c4d"), Some(0x1a2b_3c4d));
        assert_eq!(mk("0X1A2B3C4D"), Some(0x1a2b_3c4d));
        assert_eq!(mk("439041101"), Some(439_041_101));
        assert_eq!(mk("0"), Some(0));
        // Мусор — ошибка схемы.
        assert!(parse("<bootloader><payload id=\"a\" type=\"rust-l4\" archive=\"b\" archive_crc32=\"zzz\"/></bootloader>").is_err());
        // Атрибут отсутствует — None (опционален).
        let no_attr = parse(
            "<bootloader><payload id=\"a\" type=\"rust-l4\" archive=\"b.cpio\"/></bootloader>",
        )
        .unwrap();
        assert_eq!(no_attr.payloads[0].archive_crc32, None);
    }

    #[test]
    fn timeout_variants() {
        // Отсутствует → DEFAULT.
        assert_eq!(
            parse("<bootloader><payload id=\"a\" type=\"efi\" path=\"x.efi\"/></bootloader>")
                .unwrap()
                .timeout_s,
            DEFAULT_TIMEOUT_SECS
        );
        // 0 — мгновенный default; отрицательный — ждать вечно.
        assert_eq!(parse("<bootloader timeout=\"0\"><payload id=\"a\" type=\"efi\" path=\"x.efi\"/></bootloader>").unwrap().timeout_s, 0);
        assert_eq!(parse("<bootloader timeout=\"-1\"><payload id=\"a\" type=\"efi\" path=\"x.efi\"/></bootloader>").unwrap().timeout_s, -1);
        // Не число — schema violation.
        assert!(parse("<bootloader timeout=\"soon\"><payload id=\"a\" type=\"efi\" path=\"x.efi\"/></bootloader>").is_err());
    }

    #[test]
    fn payload_type_and_attrs_validated() {
        // Неизвестный type.
        assert!(parse("<bootloader><payload id=\"a\" type=\"multiboot\"/></bootloader>").is_err());
        // efi без path.
        assert!(parse("<bootloader><payload id=\"a\" type=\"efi\"/></bootloader>").is_err());
        // rust-l4 с path — copy-paste-страж.
        assert!(
            parse("<bootloader><payload id=\"a\" type=\"rust-l4\" path=\"x\"/></bootloader>")
                .is_err()
        );
        // efi с archive — тоже.
        assert!(
            parse(
                "<bootloader><payload id=\"a\" type=\"efi\" path=\"x\" archive=\"y\"/></bootloader>"
            )
            .is_err()
        );
        // Без id.
        assert!(parse("<bootloader><payload type=\"efi\" path=\"x\"/></bootloader>").is_err());
    }

    #[test]
    fn semantic_validation() {
        // Дубликаты id.
        let cfg = parse("<bootloader><payload id=\"a\" type=\"efi\" path=\"x\"/><payload id=\"a\" type=\"efi\" path=\"y\"/></bootloader>").unwrap();
        assert!(matches!(cfg.validate(), Err(BootcfgError::Schema(_))));
        // default не существует.
        let cfg = parse(
            "<bootloader default=\"nope\"><payload id=\"a\" type=\"efi\" path=\"x\"/></bootloader>",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
        // rust-l4 без архива — уже разбор отказывает (обязательный атрибут).
        assert!(matches!(
            parse("<bootloader><payload id=\"a\" type=\"rust-l4\"/></bootloader>"),
            Err(BootcfgError::MissingAttr("archive"))
        ));
        // Пустой документ.
        assert!(parse("").unwrap().validate().is_err());
        // Пустой archive (атрибут есть, значения нет) — валидация.
        let cfg =
            parse("<bootloader><payload id=\"a\" type=\"rust-l4\" archive=\"\"/></bootloader>")
                .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn misplaced_elements_rejected() {
        // var вне boot_state
        assert!(parse("<bootloader><payload id=\"a\" type=\"efi\" path=\"x\"><var name=\"a\" value=\"b\"/></payload></bootloader>").is_err());
        // boot_state на верхнем уровне
        assert!(parse("<bootloader><boot_state/></bootloader>").is_err());
        // <payload> внутри <payload>
        assert!(parse("<bootloader><payload id=\"a\" type=\"efi\" path=\"x\"><payload id=\"b\" type=\"efi\" path=\"y\"/></payload></bootloader>").is_err());
    }

    #[test]
    fn boot_state_translates_to_protocol() {
        let cfg = parse(FULL_V3).unwrap();
        let vars = cfg.payloads[0].boot_state_vars().unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name_str(), "console");
        assert_eq!(vars[0].value_str(), "com1");
    }

    #[test]
    fn boot_state_overflow_refused() {
        let mut xml = String::from(
            "<bootloader><payload id=\"a\" type=\"rust-l4\" archive=\"b.cpio\"><boot_state>",
        );
        for i in 0..(MAX_BOOT_STATE + 1) {
            xml.push_str(&format!("<var name=\"k{i}\" value=\"v\"/>"));
        }
        xml.push_str("</boot_state></payload></bootloader>");
        let cfg = parse(&xml).unwrap();
        assert!(cfg.validate().is_err(), "overflow must fail validation");
        assert!(cfg.payloads[0].boot_state_vars().is_err());
    }

    #[test]
    fn unknown_elements_ignored() {
        // Комментарий + чужой элемент + DECL: парсер не спотыкается.
        let xml = "<?xml version=\"1.0\"?><!-- hi --><bootloader><meta x=\"1\"/><payload id=\"a\" type=\"rust-l4\" archive=\"b.cpio\"/></bootloader>";
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.payloads[0].archive, "b.cpio");
        cfg.validate().unwrap();
    }

    #[test]
    fn to_xml_roundtrip() {
        // v3 → write → parse: та же модель (кроме title-fallback: пустой
        // title не пишем, после roundtrip он и не нужен — menu_title).
        let cfg = parse(FULL_V3).unwrap();
        let xml = to_xml(&cfg);
        let cfg2 = parse(&xml).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn to_xml_escapes_specials() {
        let cfg = BootConfig {
            timeout_s: 3,
            default_id: None,
            payloads: vec![Payload {
                id: "a&b".into(),
                kind: PayloadKind::EfiChainload,
                path: "\\EFI\\a<b>'c'".into(),
                ..Payload::default()
            }],
        };
        let xml = to_xml(&cfg);
        let back = parse(&xml).unwrap();
        assert_eq!(back.payloads[0].id, "a&b");
        assert_eq!(back.payloads[0].path, "\\EFI\\a<b>'c'");
    }

    /// Регрессия v0.5.2 (QEMU): в реальном образе var[1] теряла значение
    /// («test_mode=qemu» приходил как «test_mode=»). Тест гоняет парсер
    /// на ТОЧНОМ байтовом содержимом boot/boot_cfg.xml (DECL + длинный
    /// комментарий + все элементы схемы v3).
    #[test]
    fn real_boot_cfg_all_state_values_transit() {
        let xml = include_str!("../../../../boot/boot_cfg.xml");
        let cfg = parse(xml).expect("real boot_cfg.xml must parse");
        cfg.validate().expect("real boot_cfg.xml must validate");
        let p = &cfg.payloads[0];
        assert_eq!(p.kind, PayloadKind::RustL4);
        assert_eq!(p.archive, "boot.cpio");
        assert!(p.archive_crc32.is_some(), "reference config carries CRC");
        let vars = p.boot_state_vars().expect("boot_state must pack");
        assert_eq!(vars.len(), 4);
        assert_eq!(vars[1].name_str(), "test_mode");
        assert_eq!(vars[1].value_str(), "qemu", "var[1] value lost in transit");
        for (k, v) in &p.state {
            assert!(!v.is_empty(), "empty value for state var {k}");
        }
    }
}
