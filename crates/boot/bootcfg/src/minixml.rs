// ==== Микро-XML для boot_cfg.xml (заглушка; без зависимостей) ====
//
// Схема конфигурации фиксирована и мала (boot/servers/server/arg/
// boot_state/var), поэтому полный XML-парсер — оверкилл (и готовые
// крейты тянут std). Здесь — потоковый разбор подмножества XML 1.0,
// достаточного для СХЕМЫ (см. lib.rs):
//
//   * элементы: <name>, </name>, <name/>; имена — ASCII;
//   * атрибуты: name="value" или name='value'; &-сущности и символьные
//     ссылки (&#123; / &#x1F;) в значениях;
//   * текст: любые символы; сущности резолвятся;
//   * комментарии <!--..-->, PI <?..?>, DECL <!DOCTYPE..> — пропускаются;
//   * CDATA — не поддержан (схеме не нужен).
//
// Ошибки — строки с позицией (отладка конфигурации на реальной машине).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Ошибка микропарсера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError(pub String);

impl core::fmt::Display for XmlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "boot_cfg.xml: {}", self.0)
    }
}

/// Токен-событие потокового разбора.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// Открытие элемента; self_closing — `<name/>`.
    Start {
        name: &'a str,
        attrs: Vec<(&'a str, String)>,
        self_closing: bool,
    },
    /// Закрытие элемента.
    End { name: &'a str },
    /// Текстовое содержимое (сущности уже резолвлены; без trim).
    Text(String),
    /// Конец документа.
    Eof,
}

/// Потоковый парсер подмножества XML.
pub struct Reader<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn err<T>(&self, what: &str) -> Result<T, XmlError> {
        // Позиция в БАЙТАХ — для отладки достаточно.
        Err(XmlError(alloc::format!("{what} at byte {}", self.pos)))
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        self.input[self.pos..].starts_with(s)
    }

    /// Следующее событие.
    pub fn next_event(&mut self) -> Result<Event<'a>, XmlError> {
        // Пропуск пробелов между узлами (не внутри текста).
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
        let Some(c) = self.peek() else {
            return Ok(Event::Eof);
        };
        if c != b'<' {
            return self.read_text();
        }
        // Комментарий / DECL / PI.
        if self.starts_with("<!--") {
            self.pos += 4;
            let Some(end) = self.input[self.pos..].find("-->") else {
                return self.err("unterminated comment");
            };
            self.pos += end + 3;
            return self.next_event();
        }
        if self.starts_with("<![CDATA[") {
            return self.err("CDATA is not supported by the boot schema");
        }
        if self.starts_with("<!") || self.starts_with("<?") {
            let close = if self.starts_with("<?") { "?>" } else { ">" };
            self.pos += 2;
            let Some(end) = self.input[self.pos..].find(close) else {
                return self.err("unterminated declaration/PI");
            };
            self.pos += end + close.len();
            return self.next_event();
        }
        // Закрытие.
        if self.starts_with("</") {
            self.pos += 2;
            let name = self.read_name()?;
            self.skip_ws();
            if self.peek() != Some(b'>') {
                return self.err("expected '>' after </name");
            }
            self.pos += 1;
            return Ok(Event::End { name });
        }
        // Открытие.
        self.pos += 1; // '<'
        let name = self.read_name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'>') => {
                    self.pos += 1;
                    return Ok(Event::Start {
                        name,
                        attrs,
                        self_closing: false,
                    });
                }
                Some(b'/') => {
                    self.pos += 1;
                    if self.peek() != Some(b'>') {
                        return self.err("expected '>' after '/'");
                    }
                    self.pos += 1;
                    return Ok(Event::Start {
                        name,
                        attrs,
                        self_closing: true,
                    });
                }
                Some(_) => {
                    let aname = self.read_name()?;
                    self.skip_ws();
                    if self.peek() != Some(b'=') {
                        return self.err("expected '=' in attribute");
                    }
                    self.pos += 1;
                    self.skip_ws();
                    let quote = self.peek();
                    if quote != Some(b'"') && quote != Some(b'\'') {
                        return self.err("attribute value must be quoted");
                    }
                    let q = quote.unwrap();
                    self.pos += 1;
                    let raw = self.read_until_quote(q)?;
                    let value = self.unescape(&raw)?;
                    attrs.push((aname, value));
                }
                None => return self.err("unterminated tag"),
            }
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    /// Имя: буквы/цифры/-/_/:/. (ASCII; схема наша).
    fn read_name(&mut self) -> Result<&'a str, XmlError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            let ok = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.');
            if !ok {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return self.err("expected element/attribute name");
        }
        Ok(&self.input[start..self.pos])
    }

    fn read_until_quote(&mut self, q: u8) -> Result<&'a str, XmlError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == q {
                let s = &self.input[start..self.pos];
                self.pos += 1;
                return Ok(s);
            }
            if c == b'<' {
                return self.err("'<' is not allowed in attribute value");
            }
            self.pos += 1;
        }
        self.err("unterminated attribute value")
    }

    /// Текст до следующего '<' (сущности резолвим).
    fn read_text(&mut self) -> Result<Event<'a>, XmlError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'<' {
                break;
            }
            self.pos += 1;
        }
        let raw = &self.input[start..self.pos];
        if raw.is_empty() {
            return self.err("unexpected character");
        }
        Ok(Event::Text(self.unescape(raw)?))
    }

    /// Резолв &amp;/&lt;/&gt;/&quot;/&apos;/&#N;/&#xN;.
    fn unescape(&self, raw: &str) -> Result<String, XmlError> {
        if !raw.contains('&') {
            return Ok(alloc::string::String::from(raw));
        }
        let mut out = alloc::string::String::with_capacity(raw.len());
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'&' {
                // Копируем байт (UTF-8 последовательности пройдут как есть:
                // многобайтные продолжения не содержат '&').
                let ch_start = i;
                i += 1;
                while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
                    i += 1;
                }
                out.push_str(&raw[ch_start..i]);
                continue;
            }
            // Сущность: до ';'.
            let Some(semi) = raw[i..].find(';') else {
                return self.err("unterminated entity reference");
            };
            let ent = &raw[i + 1..i + semi];
            let replacement: alloc::string::String = match ent {
                "amp" => "&".into(),
                "lt" => "<".into(),
                "gt" => ">".into(),
                "quot" => "\"".into(),
                "apos" => "'".into(),
                _ => {
                    // Символьная ссылка.
                    let (radix, digits) = if let Some(h) = ent.strip_prefix("#x") {
                        (16, h)
                    } else if let Some(d) = ent.strip_prefix('#') {
                        (10, d)
                    } else {
                        return Err(XmlError(alloc::format!("undefined entity &{ent};")));
                    };
                    let code = u32::from_str_radix(digits, radix)
                        .map_err(|_| XmlError(alloc::format!("bad char ref &{ent};")))?;
                    char::from_u32(code)
                        .ok_or_else(|| XmlError(alloc::format!("invalid char ref &{ent};")))?
                        .to_string()
                }
            };
            out.push_str(&replacement);
            i += semi + 1;
        }
        Ok(out)
    }
}
