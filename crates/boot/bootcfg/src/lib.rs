// ==== BOOTCFG: модель + разбор boot_cfg.xml ====
//
// XML живёт ТОЛЬКО по эту сторону протокола загрузки: заглушка (UEFI)
// читает boot_cfg.xml из каталога СВОЕГО образа на ESP, разбирает его
// здесь в [`BootConfig`] и транслирует в плоский boot_info::BootInfo
// (модули + boot_state). Ядро XML не видит вовсе: переносимость
// протокола загрузки не должна зависеть от формата конфигурации.
//
// Схема (boot_cfg.xml рядом с заглушкой):
//   <boot cmdline="arch=x86_64 console=com1">
//     <servers>
//       <server name="init" path="init.elf">
//         <arg>log=verbose</arg>
//       </server>
//       <server name="fs" path="servers/fs.elf"/>
//     </servers>
//     <boot_state>
//       <var name="console" value="com1"/>
//       <var name="test_mode" value="qemu"/>
//     </boot_state>
//   </boot>
//
// Атрибут `cmdline` корня — КОМАНДНАЯ СТРОКА ЯДРА (в BootInfo.cmdline;
// читает ядро: arch/console/meltdown). Это НЕ boot_state: переменные
// boot_state — транзит init через стартовый IPC, ядро их не трактует.
//
// Первый сервер — init-сервер по договорённости протокола (модуль [0]
// в BootInfo); без серверов конфигурация отказывает сразу.
//
// Разбор — собственный микро-XML (minixml.rs): готовые крейты тянули std
// в UEFI-заглушку, а схема фиксирована и мала — потоковый разбор
// подмножества XML 1.0 (элементы/атрибуты/текст/сущности) короче чужих
// зависимостей. Наш код — сверка событий со схемой (машина контекста).
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod minixml;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use boot_info::{BootStateVar, MAX_BOOT_STATE};
use minixml::{Event, Reader};

// ───────────────────────────── Модель ─────────────────────────────

/// Сервер из конфигурации: образ + argv старта.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerSpec {
    /// Логическое имя (→ имя модуля в BootInfo).
    pub name: String,
    /// Путь к файлу образа ОТНОСИТЕЛЬНО каталога заглушки («./»).
    pub path: String,
    /// Аргументы старта (start-IPC после boot_state).
    pub argv: Vec<String>,
}

/// Разобранный boot_cfg.xml.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootConfig {
    /// Командная строка ядра (атрибут `cmdline` корня <boot>; может быть
    /// пустой — тогда заглушка ставит свою по умолчанию).
    pub kernel_cmdline: String,
    /// Серверы в порядке загрузки; `[0]` — init-сервер (обязателен).
    pub servers: Vec<ServerSpec>,
    /// Переменные состояния загрузки `(key, value)`: транзитом в init.
    pub state: Vec<(String, String)>,
}

/// Ошибка разбора конфигурации.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootcfgError {
    /// quick-xml не смог токенизировать документ.
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

impl BootConfig {
    /// Собрать boot_state в формат протокола BootInfo (транзит init).
    ///
    /// Отказ — ДО ExitBootServices: переполнение фиксированных полей
    /// протокола (число переменных, длина имени/значения) обязано
    /// останавливать загрузку, а не молча обрезаться — усечённое имя
    /// это потерянная переменная.
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
}

// ───────────────────────────── Разбор ─────────────────────────────

/// Позиция в дереве схемы (машина контекста).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Корень <boot> / вне элементов схемы.
    Root,
    /// Внутри <servers>.
    Servers,
    /// Внутри <server>.
    Server,
    /// Внутри <arg> (текст — элемент argv).
    Arg,
    /// Внутри <boot_state>.
    BootState,
}

/// Разобрать текст boot_cfg.xml.
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
                "arg" => ctx = Ctx::Server,
                "server" => ctx = Ctx::Servers,
                "servers" | "boot_state" | "boot" => ctx = Ctx::Root,
                _ => {}
            },
            Event::Text(t) => {
                if ctx == Ctx::Arg {
                    // Текст <arg> (сущности уже резолвлены в minixml):
                    // дописываем в слот, созданный Start.
                    append_arg_text(&mut cfg, t)?;
                }
            }
            Event::Eof => break,
        }
    }

    if cfg.servers.is_empty() {
        return Err(BootcfgError::Schema(
            "no <server> entries: init server is required",
        ));
    }
    Ok(cfg)
}

/// Дописать текст в текущий argv-слот.
fn append_arg_text(cfg: &mut BootConfig, text: String) -> Result<(), BootcfgError> {
    let last = cfg
        .servers
        .last_mut()
        .and_then(|s| s.argv.last_mut())
        .ok_or(BootcfgError::Schema("text outside <arg>"))?;
    last.push_str(&text);
    Ok(())
}

/// Общий обработчик Start/Empty (`self_closing` — `<server/>` без детей).
fn handle_start(
    cfg: &mut BootConfig,
    ctx: &mut Ctx,
    name: &str,
    attrs: &[(&str, String)],
    self_closing: bool,
) -> Result<(), BootcfgError> {
    match name {
        "boot" => {
            // Атрибут корня: командная строка ядра (необязателен).
            if let Some(cl) = attrs.iter().find(|(k, _)| *k == "cmdline") {
                cfg.kernel_cmdline = cl.1.clone();
            }
        }
        "servers" => {
            if *ctx != Ctx::Root {
                return Err(BootcfgError::Schema("<servers> must be at <boot> level"));
            }
            *ctx = Ctx::Servers;
        }
        "server" => {
            if *ctx != Ctx::Servers {
                return Err(BootcfgError::Schema("<server> must be inside <servers>"));
            }
            let name = required_attr(attrs, "name")?;
            let path = required_attr(attrs, "path")?;
            if name.is_empty() || path.is_empty() {
                return Err(BootcfgError::Schema("<server> name/path must not be empty"));
            }
            cfg.servers.push(ServerSpec {
                name,
                path,
                argv: Vec::new(),
            });
            // `<server/>` — детей нет, остаёмся в <servers>.
            if !self_closing {
                *ctx = Ctx::Server;
            }
        }
        "arg" => {
            if *ctx != Ctx::Server {
                return Err(BootcfgError::Schema("<arg> must be inside <server>"));
            }
            // Слот под текст: сущности могут резать Text на части.
            cfg.servers
                .last_mut()
                .ok_or(BootcfgError::Schema("<arg> without <server>"))?
                .argv
                .push(String::new());
            if !self_closing {
                *ctx = Ctx::Arg;
            }
        }
        "boot_state" => {
            if *ctx != Ctx::Root {
                return Err(BootcfgError::Schema("<boot_state> must be at <boot> level"));
            }
            *ctx = Ctx::BootState;
        }
        "var" => {
            if *ctx != Ctx::BootState {
                return Err(BootcfgError::Schema("<var> must be inside <boot_state>"));
            }
            let name = required_attr(attrs, "name")?;
            let value = required_attr(attrs, "value")?;
            cfg.state.push((name, value));
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
        "name" => "name",
        "path" => "path",
        "value" => "value",
        _ => "attribute",
    }))
}

// ───────────────────────────── Тесты ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"<boot>
        <servers>
            <server name="init" path="init.elf">
                <arg>log=verbose</arg>
                <arg>mode=qemu&amp;debug</arg>
            </server>
            <server name="fs" path="servers/fs.elf"/>
        </servers>
        <boot_state>
            <var name="console" value="com1"/>
            <var name="root" value="nvme0:0"/>
        </boot_state>
    </boot>"#;

    #[test]
    fn kernel_cmdline_attr_parsed() {
        let xml = "<boot cmdline=\"arch=x86_64 console=com1 meltdown=allow\"><servers><server name=\"init\" path=\"i.elf\"/></servers></boot>";
        let cfg = parse(xml).unwrap();
        assert_eq!(
            cfg.kernel_cmdline,
            "arch=x86_64 console=com1 meltdown=allow"
        );
        // Без атрибута — пустая (заглушка поставит дефолт).
        let cfg2 = parse(FULL).unwrap();
        assert_eq!(cfg2.kernel_cmdline, "");
    }

    #[test]
    fn full_config_parses() {
        let cfg = parse(FULL).unwrap();
        assert_eq!(cfg.servers.len(), 2);

        assert_eq!(cfg.servers[0].name, "init");
        assert_eq!(cfg.servers[0].path, "init.elf");
        assert_eq!(
            cfg.servers[0].argv,
            vec!["log=verbose".to_string(), "mode=qemu&debug".to_string()]
        );

        assert_eq!(cfg.servers[1].name, "fs");
        assert_eq!(cfg.servers[1].path, "servers/fs.elf");
        assert!(cfg.servers[1].argv.is_empty());

        assert_eq!(
            cfg.state,
            vec![
                ("console".to_string(), "com1".to_string()),
                ("root".to_string(), "nvme0:0".to_string()),
            ]
        );
    }

    #[test]
    fn boot_state_translates_to_protocol() {
        let cfg = parse(FULL).unwrap();
        let vars = cfg.boot_state_vars().unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].name_str(), "console");
        assert_eq!(vars[0].value_str(), "com1");
        assert_eq!(vars[1].name_str(), "root");
        assert_eq!(vars[1].value_str(), "nvme0:0");
    }

    #[test]
    fn boot_state_overflow_refused() {
        let mut xml = String::from(
            "<boot><servers><server name=\"i\" path=\"i.elf\"/></servers><boot_state>",
        );
        for i in 0..(MAX_BOOT_STATE + 1) {
            xml.push_str(&format!("<var name=\"k{i}\" value=\"v\"/>"));
        }
        xml.push_str("</boot_state></boot>");
        assert!(parse(&xml).unwrap().boot_state_vars().is_err());
    }

    #[test]
    fn misplaced_elements_rejected() {
        // arg вне server
        assert!(matches!(
            parse("<boot><servers><arg>x</arg></servers></boot>"),
            Err(BootcfgError::Schema(_))
        ));
        // var вне boot_state
        assert!(parse("<boot><var name=\"a\" value=\"b\"/></boot>").is_err());
        // server вне servers
        assert!(parse("<boot><server name=\"a\" path=\"b\"/></boot>").is_err());
        // servers внутри server (вложенность)
        assert!(
            parse(
                "<boot><servers><server name=\"a\" path=\"b\"><servers/></server></servers></boot>"
            )
            .is_err()
        );
    }

    #[test]
    fn server_requires_name_and_path() {
        assert!(parse("<boot><servers><server name=\"a\"/></servers></boot>").is_err());
        assert!(parse("<boot><servers><server path=\"a.elf\"/></servers></boot>").is_err());
        assert!(parse("<boot><servers><server name=\"\" path=\"x\"/></servers></boot>").is_err());
    }

    #[test]
    fn no_servers_rejected() {
        assert!(
            parse("<boot><boot_state><var name=\"a\" value=\"b\"/></boot_state></boot>").is_err()
        );
        assert!(parse("").is_err());
    }

    #[test]
    fn unknown_elements_ignored() {
        // Комментарий + чужой элемент + DECL: парсер не спотыкается.
        let xml = "<?xml version=\"1.0\"?><!-- hi --><boot><meta x=\"1\"/><servers><server name=\"init\" path=\"i.elf\"/></servers></boot>";
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].name, "init");
    }

    /// Регрессия v0.5.2 (QEMU): в реальном образе var[1] теряла значение
    /// («test_mode=qemu» приходил как «test_mode=»). Тест гоняет парсер
    /// на ТОЧНОМ байтовом содержимом boot/boot_cfg.xml (DECL + длинный
    /// комментарий + все элементы схемы).
    #[test]
    fn real_boot_cfg_all_state_values_transit() {
        let xml = include_str!("../../../../boot/boot_cfg.xml");
        let cfg = parse(xml).expect("real boot_cfg.xml must parse");
        let vars = cfg.boot_state_vars().expect("boot_state must pack");
        assert_eq!(vars.len(), 4);
        assert_eq!(vars[1].name_str(), "test_mode");
        assert_eq!(vars[1].value_str(), "qemu", "var[1] value lost in transit");
        for (k, v) in &cfg.state {
            assert!(!v.is_empty(), "empty value for state var {k}");
        }
    }
}
