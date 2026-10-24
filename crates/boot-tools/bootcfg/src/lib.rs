//! bootcfg v2 — модель `boot_cfg.xml` на serde + quick-xml.
//!
//! Один крейт для всех: и `cfgtool`, и UEFI-заглушка зовут
//! `parse` → `validate` → `to_xml`, поэтому «валидно для тула» =
//! «валидно для прошивки».
//!
//! Формат файла:
//! ```xml
//! <bootloader timeout="2" default="rust-l4">
//!   <payload id="rust-l4" type="rust-l4" title="Rust L4">
//!     <cmdline>arch=x86_64 console=com1</cmdline>
//!     <server name="init" path="init.elf">
//!       <arg>stage=one</arg>
//!     </server>
//!     <state name="console">com1</state>
//!   </payload>
//!   <payload id="win" type="efi" path="\EFI\Microsoft\Boot\bootmgfw.efi"/>
//! </bootloader>
//! ```

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Таймаут меню по умолчанию (сек).
pub const DEFAULT_TIMEOUT_SECS: i64 = 5;

// ───────────────────── Ошибки ─────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// XML не разобрался / не сериализовался (в т.ч. неизвестный `type`).
    Xml(String),
    /// XML корректен, но конфиг семантически неверен.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Xml(m) => write!(f, "xml: {m}"),
            Error::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for Error {}

fn invalid<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error::Invalid(msg.into()))
}

// ───────────────────── Модель ─────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "bootloader")]
pub struct BootConfig {
    /// Секунды до автозагрузки; `-1` — ждать вечно, `0` — сразу default.
    #[serde(rename = "@timeout", default = "default_timeout")]
    pub timeout_s: i64,
    /// id payload'а по умолчанию; `None` → первый.
    #[serde(rename = "@default", default, skip_serializing_if = "Option::is_none")]
    pub default_id: Option<String>,
    #[serde(rename = "payload", default)]
    pub payloads: Vec<Payload>,
}

fn default_timeout() -> i64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub kind: PayloadKind,
    #[serde(rename = "@title", default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// Только `efi`: путь от корня тома.
    #[serde(rename = "@path", default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Только `rust-l4`.
    #[serde(rename = "cmdline", default, skip_serializing_if = "String::is_empty")]
    pub kernel_cmdline: String,
    /// Только `rust-l4`.
    #[serde(rename = "server", default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ServerSpec>,
    /// Только `rust-l4` (boot_state).
    #[serde(rename = "state", default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<StateVar>,
}

impl Payload {
    /// Заголовок для меню: `title`, а если пуст — `id`.
    pub fn menu_title(&self) -> &str {
        if self.title.is_empty() {
            &self.id
        } else {
            &self.title
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadKind {
    #[serde(rename = "efi")]
    EfiChainload,
    #[serde(rename = "rust-l4")]
    RustL4,
}

impl PayloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadKind::EfiChainload => "efi",
            PayloadKind::RustL4 => "rust-l4",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSpec {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@path")]
    pub path: String,
    #[serde(rename = "arg", default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateVar {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "$text", default)]
    pub value: String,
}

// ───────────────────── API ─────────────────────

/// Разобрать XML. Семантику проверяет отдельно [`BootConfig::validate`].
pub fn parse(text: &str) -> Result<BootConfig, Error> {
    quick_xml::de::from_str(text).map_err(|e| Error::Xml(e.to_string()))
}

/// Канонический XML (отступ 2 пробела, `\n` в конце).
pub fn to_xml(cfg: &BootConfig) -> Result<String, Error> {
    let mut buf = String::new();
    let mut ser = quick_xml::se::Serializer::new(&mut buf);
    ser.indent(' ', 2);
    cfg.serialize(ser).map_err(|e| Error::Xml(e.to_string()))?;
    buf.push('\n');
    Ok(buf)
}

impl BootConfig {
    pub fn payload(&self, id: &str) -> Option<&Payload> {
        self.payloads.iter().find(|p| p.id == id)
    }

    /// Индекс payload'а по умолчанию (0, если `default` не задан).
    pub fn resolve_default(&self) -> usize {
        self.default_id
            .as_deref()
            .and_then(|d| self.payloads.iter().position(|p| p.id == d))
            .unwrap_or(0)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.timeout_s < -1 {
            return invalid(format!(
                "timeout must be >= -1 (-1 = forever), got {}",
                self.timeout_s
            ));
        }
        if self.payloads.is_empty() {
            return invalid("at least one <payload> required");
        }
        let mut seen = HashSet::new();
        for p in &self.payloads {
            if p.id.is_empty() {
                return invalid("payload id must not be empty");
            }
            if !seen.insert(p.id.as_str()) {
                return invalid(format!("duplicate payload id '{}'", p.id));
            }
            p.validate()?;
        }
        if let Some(d) = &self.default_id
            && !seen.contains(d.as_str())
        {
            return invalid(format!("default '{d}' does not match any payload"));
        }
        Ok(())
    }
}

impl Payload {
    fn validate(&self) -> Result<(), Error> {
        let id = &self.id;
        match self.kind {
            PayloadKind::EfiChainload => {
                if self.path.is_empty() {
                    return invalid(format!("efi payload '{id}': path required"));
                }
                if !self.kernel_cmdline.is_empty()
                    || !self.servers.is_empty()
                    || !self.state.is_empty()
                {
                    return invalid(format!(
                        "efi payload '{id}': cmdline/server/state are rust-l4 only"
                    ));
                }
            }
            PayloadKind::RustL4 => {
                if !self.path.is_empty() {
                    return invalid(format!("rust-l4 payload '{id}': path is efi only"));
                }
                if self.servers.is_empty() {
                    return invalid(format!(
                        "rust-l4 payload '{id}': at least one server required"
                    ));
                }
                for s in &self.servers {
                    if s.name.is_empty() || s.path.is_empty() {
                        return invalid(format!(
                            "rust-l4 payload '{id}': server needs name and path"
                        ));
                    }
                }
                let mut names = HashSet::new();
                for v in &self.state {
                    if v.name.is_empty() {
                        return invalid(format!("payload '{id}': state name must not be empty"));
                    }
                    if !names.insert(v.name.as_str()) {
                        return invalid(format!("payload '{id}': duplicate state '{}'", v.name));
                    }
                }
            }
        }
        Ok(())
    }
}

// ───────────────────── Тесты ─────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BootConfig {
        BootConfig {
            timeout_s: 2,
            default_id: Some("rust-l4".into()),
            payloads: vec![
                Payload {
                    id: "rust-l4".into(),
                    kind: PayloadKind::RustL4,
                    title: "Rust & L4".into(),
                    path: String::new(),
                    kernel_cmdline: "arch=x86_64 console=com1".into(),
                    servers: vec![ServerSpec {
                        name: "init".into(),
                        path: "init.elf".into(),
                        argv: vec!["stage=one".into(), "log=<full>".into()],
                    }],
                    state: vec![StateVar {
                        name: "console".into(),
                        value: "com1".into(),
                    }],
                },
                Payload {
                    id: "win".into(),
                    kind: PayloadKind::EfiChainload,
                    title: String::new(),
                    path: "\\EFI\\Microsoft\\Boot\\bootmgfw.efi".into(),
                    kernel_cmdline: String::new(),
                    servers: vec![],
                    state: vec![],
                },
            ],
        }
    }

    #[test]
    fn roundtrip_and_escaping() {
        let cfg = sample();
        cfg.validate().unwrap();
        let xml = to_xml(&cfg).unwrap();
        assert!(xml.contains("&amp;") && xml.contains("&lt;full&gt;"), "{xml}");
        let back = parse(&xml).unwrap();
        assert_eq!(back, cfg, "{xml}");
        // Каноничность: повторная сериализация даёт тот же текст.
        assert_eq!(to_xml(&back).unwrap(), xml);
    }

    #[test]
    fn parses_handwritten_xml() {
        let xml = r#"
            <bootloader timeout="-1">
              <payload id="a" type="rust-l4">
                <server name="init" path="init.elf"/>
              </payload>
            </bootloader>"#;
        let cfg = parse(xml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.timeout_s, -1);
        assert_eq!(cfg.resolve_default(), 0);
    }

    #[test]
    fn missing_timeout_uses_default() {
        let cfg =
            parse(r#"<bootloader><payload id="w" type="efi" path="w.efi"/></bootloader>"#).unwrap();
        assert_eq!(cfg.timeout_s, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn bad_type_is_parse_error() {
        let e = parse(r#"<bootloader><payload id="a" type="bogus"/></bootloader>"#).unwrap_err();
        assert!(matches!(e, Error::Xml(_)));
        assert!(e.to_string().contains("bogus"), "{e}");
    }

    #[test]
    fn validation_rules() {
        let mut c = sample();
        c.payloads[1].id = "rust-l4".into();
        assert!(c.validate().unwrap_err().to_string().contains("duplicate"));

        let mut c = sample();
        c.default_id = Some("ghost".into());
        assert!(c.validate().unwrap_err().to_string().contains("ghost"));

        let mut c = sample();
        c.payloads[1].path.clear();
        assert!(c.validate().unwrap_err().to_string().contains("path required"));

        let mut c = sample();
        c.payloads[0].servers.clear();
        assert!(c.validate().unwrap_err().to_string().contains("server"));

        let mut c = sample();
        c.timeout_s = -5;
        assert!(c.validate().is_err());

        let mut c = sample();
        c.payloads.clear();
        assert!(c.validate().is_err());
    }
}
