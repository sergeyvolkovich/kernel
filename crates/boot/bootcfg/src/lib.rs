// ==== BOOTCFG: модель + разбор + запись boot_cfg.xml (v2: пейлоады) ====
//
// XML живёт ТОЛЬКО по эту сторону протокола загрузки: заглушка (UEFI)
// читает boot_cfg.xml из каталога СВОЕГО образа на ESP, разбирает его
// здесь в [`BootConfig`] и транслирует в плоский boot_info::BootInfo
// (модули + boot_state). Ядро XML не видит вовсе: переносимость
// протокола загрузки не должна зависеть от формата конфигурации.
//
// Схема v2 (несколько пейлоадов + меню выбора):
//   <bootloader timeout="5" default="rust-l4">
//     <payload id="rust-l4" type="rust-l4" title="rust-l4"
//              cmdline="arch=x86_64 console=com1">
//       <servers>
//         <server name="init" path="init.elf">
//           <arg>log=verbose</arg>
//         </server>
//       </servers>
//       <boot_state>
//         <var name="console" value="com1"/>
//       </boot_state>
//     </payload>
//     <payload id="win" type="efi" title="Windows Boot Manager"
//              path="\EFI\Microsoft\Boot\bootmgfw.efi"/>
//   </bootloader>
//
// Типы пейлоадов:
//   * rust-l4 — своя цепочка: встроенное ядро + серверы конфигурации
//     (первый = init, модуль [0] BootInfo) → ExitBootServices → вход;
//   * efi     — chainload произвольного EFI-образа (bootmgfw/grub/...):
//     LoadImage по device path (том + файл) + StartImage; загрузчик
//     сам находит свои данные по собственному device path.
//
// Атрибут `timeout` (секунды): >0 — меню с обратным отсчётом; 0 — без
// меню, грузить default немедленно; <0 — ждать вечно. Отсутствует —
// [DEFAULT_TIMEOUT_SECS]. `default` — id пейлоада по умолчанию
// (отсутствует → первый).
//
// Схема v1 (легаси, поддерживается наравне): корень <boot cmdline="...">
// с <servers>/<boot_state> внутри — эквивалентен одиночному пейлоаду
// rust-l4 (id "rust-l4"). Старые конфиги грузятся без правки.
//
// `path` пейлоада типа efi — путь от КОРНЯ тома (с '\' или без);
// серверы rust-l4 — относительно корня тома (как и раньше: заглушка
// читает их через SimpleFileSystem своего образа).
//
// Первый сервер rust-l4-пейлоада — init-сервер по договорённости
// протокола (модуль [0] в BootInfo).
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

/// Сервер из конфигурации: образ + argv старта.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerSpec {
    /// Логическое имя (→ имя модуля в BootInfo).
    pub name: String,
    /// Путь к файлу образа ОТНОСИТЕЛЬНО корня тома заглушки.
    pub path: String,
    /// Аргументы старта (start-IPC после boot_state).
    pub argv: Vec<String>,
}

/// Тип пейлоада.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayloadKind {
    /// Своя цепочка: встроенное ядро + серверы (cmdline/servers/state).
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
    /// rust-l4: серверы в порядке загрузки; `[0]` — init (обязателен).
    pub servers: Vec<ServerSpec>,
    /// rust-l4: переменные состояния загрузки (транзит init).
    pub state: Vec<(String, String)>,
}

impl Payload {
    /// Собрать boot_state в формат протокола BootInfo (транзит init).
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
    /// * rust-l4: есть init-сервер, boot_state влезает в протокол;
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
                    if p.servers.is_empty() {
                        return Err(BootcfgError::Schema(
                            "rust-l4 payload without <server>: init is required",
                        ));
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
///
/// Уровень «пейлоад» объединяет v2-<payload> и легаси-<boot>: дети
/// (<servers>/<boot_state>) одни и те же, все операции — над последним
/// элементом `payloads`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Вне пейлоадов: корень <bootloader> (v2) / до <boot> (легаси).
    Root,
    /// Внутри <payload> (v2) или <boot> (легаси).
    Payload,
    /// Внутри <servers>.
    Servers,
    /// Внутри <server>.
    Server,
    /// Внутри <arg> (текст — элемент argv).
    Arg,
    /// Внутри <boot_state>.
    BootState,
}

/// Разобрать текст boot_cfg.xml (v2 или легаси).
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
                "servers" | "boot_state" => ctx = Ctx::Payload,
                "payload" | "boot" => ctx = Ctx::Root,
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

    Ok(cfg)
}

/// Дописать текст в текущий argv-слот (последний сервер последнего
/// пейлоада).
fn append_arg_text(cfg: &mut BootConfig, text: String) -> Result<(), BootcfgError> {
    let last = cfg
        .payloads
        .last_mut()
        .and_then(|p| p.servers.last_mut())
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
        // ── Корни: v2 <bootloader>, легаси <boot> ──
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
            // Легаси: неявный одиночный rust-l4 пейлоад.
            if !cfg.payloads.is_empty() {
                return Err(BootcfgError::Schema("duplicate root element"));
            }
            cfg.timeout_s = DEFAULT_TIMEOUT_SECS;
            let mut p = Payload {
                id: alloc::string::String::from("rust-l4"),
                kind: PayloadKind::RustL4,
                ..Payload::default()
            };
            if let Some(cl) = attrs.iter().find(|(k, _)| *k == "cmdline") {
                p.kernel_cmdline = cl.1.clone();
            }
            cfg.payloads.push(p);
            *ctx = Ctx::Payload;
        }

        // ── v2: пейлоад ──
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
                }
                PayloadKind::RustL4 => {
                    reject_attr(attrs, "path", "path only for efi payloads")?;
                    if let Some(cl) = attrs.iter().find(|(k, _)| *k == "cmdline") {
                        p.kernel_cmdline = cl.1.clone();
                    }
                }
            }
            cfg.payloads.push(p);
            if !self_closing {
                *ctx = Ctx::Payload;
            }
        }

        // ── Общее дерево пейлоада (v2-<payload> и легаси-<boot>) ──
        "servers" => {
            if *ctx != Ctx::Payload {
                return Err(BootcfgError::Schema(
                    "<servers> must be inside <payload>/<boot>",
                ));
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
            cfg.payloads
                .last_mut()
                .ok_or(BootcfgError::Schema("<server> without payload"))?
                .servers
                .push(ServerSpec {
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
            cfg.payloads
                .last_mut()
                .and_then(|p| p.servers.last_mut())
                .ok_or(BootcfgError::Schema("<arg> without <server>"))?
                .argv
                .push(String::new());
            if !self_closing {
                *ctx = Ctx::Arg;
            }
        }
        "boot_state" => {
            if *ctx != Ctx::Payload {
                return Err(BootcfgError::Schema(
                    "<boot_state> must be inside <payload>/<boot>",
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

// ───────────────────────────── Запись (cfgtool) ─────────────────────

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

/// Сериализовать конфигурацию в v2-XML (канонический вид cfgtool:
/// 2 пробела отступа, атрибуты в фиксированном порядке).
///
/// Легаси-вход нормализуется: одиночный <boot> перепишется как
/// <bootloader> с одним пейлоадом — формат один, правки идемпотентны.
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
                out.push_str(">\n");
                if !p.servers.is_empty() {
                    out.push_str("    <servers>\n");
                    for s in &p.servers {
                        out.push_str(&alloc::format!(
                            "      <server name=\"{}\" path=\"{}\"",
                            escape(&s.name),
                            escape(&s.path)
                        ));
                        if s.argv.is_empty() {
                            out.push_str("/>\n");
                        } else {
                            out.push_str(">\n");
                            for a in &s.argv {
                                out.push_str(&alloc::format!("        <arg>{}</arg>\n", escape(a)));
                            }
                            out.push_str("      </server>\n");
                        }
                    }
                    out.push_str("    </servers>\n");
                }
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

    const FULL_V2: &str = r#"<bootloader timeout="7" default="win">
        <payload id="rust" type="rust-l4" title="rust-l4" cmdline="arch=x86_64">
            <servers>
                <server name="init" path="init.elf">
                    <arg>log=verbose</arg>
                    <arg>mode=qemu&amp;debug</arg>
                </server>
                <server name="fs" path="servers/fs.elf"/>
            </servers>
            <boot_state>
                <var name="console" value="com1"/>
            </boot_state>
        </payload>
        <payload id="win" type="efi" title="Windows" path="\EFI\Microsoft\Boot\bootmgfw.efi"/>
    </bootloader>"#;

    const FULL_LEGACY: &str = r#"<boot>
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
    fn v2_multi_payload_parses() {
        let cfg = parse(FULL_V2).unwrap();
        assert_eq!(cfg.timeout_s, 7);
        assert_eq!(cfg.default_id.as_deref(), Some("win"));
        assert_eq!(cfg.payloads.len(), 2);

        let p0 = &cfg.payloads[0];
        assert_eq!(p0.id, "rust");
        assert_eq!(p0.kind, PayloadKind::RustL4);
        assert_eq!(p0.title, "rust-l4");
        assert_eq!(p0.kernel_cmdline, "arch=x86_64");
        assert_eq!(p0.servers.len(), 2);
        assert_eq!(p0.servers[0].name, "init");
        assert_eq!(
            p0.servers[0].argv,
            vec!["log=verbose".to_string(), "mode=qemu&debug".to_string()]
        );
        assert!(p0.servers[1].argv.is_empty());
        assert_eq!(p0.state, vec![("console".into(), "com1".into())]);

        let p1 = &cfg.payloads[1];
        assert_eq!(p1.id, "win");
        assert_eq!(p1.kind, PayloadKind::EfiChainload);
        assert_eq!(p1.path, "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        assert!(p1.servers.is_empty());

        cfg.validate().unwrap();
        assert_eq!(cfg.resolve_default(), 1, "default=win");
        assert_eq!(p1.menu_title(), "Windows");
        assert_eq!(p0.menu_title(), "rust-l4");
    }

    #[test]
    fn legacy_boot_wraps_into_single_payload() {
        let cfg = parse(FULL_LEGACY).unwrap();
        assert_eq!(cfg.payloads.len(), 1);
        let p = &cfg.payloads[0];
        assert_eq!(p.id, "rust-l4");
        assert_eq!(p.kind, PayloadKind::RustL4);
        assert_eq!(p.title, "");
        assert_eq!(p.menu_title(), "rust-l4");
        assert_eq!(p.servers.len(), 2);
        assert_eq!(p.servers[0].argv.len(), 2);
        assert_eq!(
            p.state,
            vec![
                ("console".to_string(), "com1".to_string()),
                ("root".to_string(), "nvme0:0".to_string()),
            ]
        );
        assert_eq!(cfg.timeout_s, DEFAULT_TIMEOUT_SECS);
        assert_eq!(cfg.resolve_default(), 0);
        cfg.validate().unwrap();
    }

    #[test]
    fn legacy_kernel_cmdline_attr() {
        let xml = "<boot cmdline=\"arch=x86_64 console=com1 meltdown=allow\"><servers><server name=\"init\" path=\"i.elf\"/></servers></boot>";
        let cfg = parse(xml).unwrap();
        assert_eq!(
            cfg.payloads[0].kernel_cmdline,
            "arch=x86_64 console=com1 meltdown=allow"
        );
        // Без атрибута — пустая (заглушка поставит дефолт).
        let cfg2 = parse(FULL_LEGACY).unwrap();
        assert_eq!(cfg2.payloads[0].kernel_cmdline, "");
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
        // efi с cmdline — тоже.
        assert!(
            parse(
                "<bootloader><payload id=\"a\" type=\"efi\" path=\"x\" cmdline=\"y\"/></bootloader>"
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
        // rust-l4 без серверов — валидация (не парс).
        let cfg = parse("<bootloader><payload id=\"a\" type=\"rust-l4\"/></bootloader>").unwrap();
        assert!(cfg.validate().is_err());
        // Пустой документ.
        assert!(parse("").unwrap().validate().is_err());
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
        // v2: <servers> на верхнем уровне bootloader
        assert!(parse("<bootloader><servers/></bootloader>").is_err());
        // v2: <payload> внутри <payload>
        assert!(parse("<bootloader><payload id=\"a\" type=\"efi\" path=\"x\"><payload id=\"b\" type=\"efi\" path=\"y\"/></payload></bootloader>").is_err());
        // Легаси + v2 корни в одном документе.
        assert!(
            parse("<boot><servers><server name=\"i\" path=\"i\"/></servers></boot><bootloader/>")
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
    fn boot_state_translates_to_protocol() {
        let cfg = parse(FULL_LEGACY).unwrap();
        let vars = cfg.payloads[0].boot_state_vars().unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].name_str(), "console");
        assert_eq!(vars[1].value_str(), "nvme0:0");
    }

    #[test]
    fn boot_state_overflow_refused() {
        let mut xml = String::from(
            "<bootloader><payload id=\"a\" type=\"rust-l4\"><servers><server name=\"i\" path=\"i.elf\"/></servers><boot_state>",
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
        let xml = "<?xml version=\"1.0\"?><!-- hi --><boot><meta x=\"1\"/><servers><server name=\"init\" path=\"i.elf\"/></servers></boot>";
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.payloads[0].servers.len(), 1);
        assert_eq!(cfg.payloads[0].servers[0].name, "init");
    }

    #[test]
    fn to_xml_roundtrip() {
        // v2 → write → parse: та же модель (кроме title-fallback: пустой
        // title не пишем, после roundtrip он и не нужен — menu_title).
        let cfg = parse(FULL_V2).unwrap();
        let xml = to_xml(&cfg);
        let cfg2 = parse(&xml).unwrap();
        assert_eq!(cfg, cfg2);

        // Легаси → write → v2: одиночный пейлоад сохраняется.
        let legacy = parse(FULL_LEGACY).unwrap();
        let xml2 = to_xml(&legacy);
        let round = parse(&xml2).unwrap();
        assert_eq!(round.payloads.len(), 1);
        assert_eq!(round.payloads[0].id, "rust-l4");
        assert_eq!(round.payloads[0].servers, legacy.payloads[0].servers);
        assert_eq!(round.payloads[0].state, legacy.payloads[0].state);
        assert_eq!(
            round.payloads[0].kernel_cmdline,
            legacy.payloads[0].kernel_cmdline
        );
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
    /// комментарий + все элементы схемы).
    #[test]
    fn real_boot_cfg_all_state_values_transit() {
        let xml = include_str!("../../../../boot/boot_cfg.xml");
        let cfg = parse(xml).expect("real boot_cfg.xml must parse");
        cfg.validate().expect("real boot_cfg.xml must validate");
        let p = &cfg.payloads[0];
        assert_eq!(p.kind, PayloadKind::RustL4);
        let vars = p.boot_state_vars().expect("boot_state must pack");
        assert_eq!(vars.len(), 4);
        assert_eq!(vars[1].name_str(), "test_mode");
        assert_eq!(vars[1].value_str(), "qemu", "var[1] value lost in transit");
        for (k, v) in &p.state {
            assert!(!v.is_empty(), "empty value for state var {k}");
        }
    }
}
