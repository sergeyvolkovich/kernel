//! cfgtool — host-редактор `boot_cfg.xml` (логика CLI).
//!
//! Тул гоняет конфиг через ТОТ ЖЕ крейт `bootcfg`, что и UEFI-заглушка
//! (parse + validate + to_xml): что валидно для тула — валидно для
//! прошивки, и наоборот. Бинарник (`main.rs`) — тонкая обёртка над
//! [`run`]; вся логика здесь, чтобы её можно было тестировать.
//!
//! Дисциплина записи: перед КАЖДЫМ сохранением — `validate()`; запись
//! атомарная (tmp + rename): сбой посреди правки не оставляет битый
//! конфиг. Все правки идемпотентны (`to_xml` — канонический формат).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use bootcfg::{BootConfig, DEFAULT_TIMEOUT_SECS, Payload, PayloadKind, ServerSpec, StateVar};

pub const USAGE: &str = "usage: cfgtool <CONFIG> <COMMAND> [args...]
commands:
  show                                  pretty-print config
  validate                              parse + semantic validation
  init [--timeout N] [--force]          create minimal config
  default <id>                          set default payload
  timeout <N | none>                    menu timeout (none = wait forever)
  add efi <id> --path P [--title T] [--default]
  add rust <id> --init P [--arg A]... [--cmdline C] [--title T] [--default]
  remove <id>
  set <id> title|path|cmdline <value>
  arg <id> add|rm|clear [value...]
  state <id> set|rm <name> [value]";

/// Точка входа: `args` без имени программы.
pub fn run(args: &[String]) -> Result<String, String> {
    let Some(path) = args.first() else {
        return Err("config path required".into());
    };
    let Some(cmd) = args.get(1) else {
        return Err("command required".into());
    };
    let rest = &args[2..];
    match cmd.as_str() {
        "init" => cmd_init(path, rest),
        "show" => load(path).map(|c| show(&c)),
        "validate" => load(path).map(|_| "ok: config parses and validates".to_string()),
        "default" => mutate(path, rest, cmd_default),
        "timeout" => mutate(path, rest, cmd_timeout),
        "add" => mutate(path, rest, cmd_add),
        "remove" => mutate(path, rest, cmd_remove),
        "set" => mutate(path, rest, cmd_set),
        "arg" => mutate(path, rest, cmd_arg),
        "state" => mutate(path, rest, cmd_state),
        other => Err(format!("unknown command '{other}'")),
    }
}

// ───────────────────── Файл ─────────────────────

pub fn load(path: &str) -> Result<BootConfig, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let cfg = bootcfg::parse(&text).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn save(path: &str, cfg: &BootConfig) -> Result<(), String> {
    cfg.validate()
        .map_err(|e| format!("refusing to write invalid config: {e}"))?;
    let xml = bootcfg::to_xml(cfg).map_err(|e| e.to_string())?;
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, xml).map_err(|e| format!("write {tmp}: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {tmp} -> {path}: {e}")
    })
}

/// Загрузить — изменить — сохранить (единая дисциплина записи).
fn mutate(
    path: &str,
    args: &[String],
    cmd: fn(&mut BootConfig, &[String]) -> Result<String, String>,
) -> Result<String, String> {
    let mut cfg = load(path)?;
    let msg = cmd(&mut cfg, args)?;
    save(path, &cfg)?;
    Ok(msg)
}

// ───────────────────── Помощники аргументов ─────────────────────

/// Значение флага: `--name value` (первое вхождение).
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Повторяющийся флаг: все `--name value`.
fn flags<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name
            && let Some(v) = args.get(i + 1)
        {
            out.push(v.as_str());
            i += 2;
            continue;
        }
        i += 1;
    }
    out
}

fn payload_mut<'c>(cfg: &'c mut BootConfig, id: &str) -> Result<&'c mut Payload, String> {
    cfg.payloads
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("payload '{id}' not found"))
}

// ───────────────────── Команды ─────────────────────

fn cmd_init(path: &str, args: &[String]) -> Result<String, String> {
    if Path::new(path).exists() && !args.iter().any(|a| a == "--force") {
        return Err(format!("{path} exists (use --force)"));
    }
    let timeout = match flag(args, "--timeout") {
        Some(t) => parse_timeout(t)?,
        None => DEFAULT_TIMEOUT_SECS,
    };
    let cfg = BootConfig {
        timeout_s: timeout,
        default_id: None,
        payloads: vec![Payload {
            id: "rust-l4".into(),
            title: String::new(),
            kind: PayloadKind::RustL4,
            path: String::new(),
            kernel_cmdline: String::new(),
            servers: vec![ServerSpec {
                name: "init".into(),
                path: "init.elf".into(),
                argv: Vec::new(),
            }],
            state: Vec::new(),
        }],
    };
    save(path, &cfg)?;
    Ok(format!("created {path} (1 rust-l4 payload)"))
}

fn cmd_default(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let id = args.first().ok_or("default <id>: id required")?;
    if cfg.payload(id).is_none() {
        return Err(format!("payload '{id}' not found"));
    }
    cfg.default_id = Some(id.clone());
    Ok(format!("default -> {id}"))
}

fn cmd_timeout(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let t = args.first().ok_or("timeout <N | none>: value required")?;
    cfg.timeout_s = parse_timeout(t)?;
    Ok(format!("timeout -> {}s", cfg.timeout_s))
}

fn parse_timeout(t: &str) -> Result<i64, String> {
    if t == "none" {
        return Ok(-1);
    }
    t.parse::<i64>()
        .map_err(|_| format!("timeout must be integer seconds or 'none', got '{t}'"))
}

fn cmd_add(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let kind_tag = args.first().ok_or("add efi|rust <id> ...: kind required")?;
    let kind = match kind_tag.as_str() {
        "efi" => PayloadKind::EfiChainload,
        "rust" | "rust-l4" => PayloadKind::RustL4,
        other => return Err(format!("add: unknown kind '{other}' (efi | rust)")),
    };
    let id = args.get(1).ok_or("add <kind> <id>: id required")?.clone();
    if cfg.payload(&id).is_some() {
        return Err(format!("payload '{id}' already exists"));
    }
    let title = flag(args, "--title").unwrap_or_default().to_string();
    let set_default = args.iter().any(|a| a == "--default");
    let payload = match kind {
        PayloadKind::EfiChainload => Payload {
            id: id.clone(),
            title,
            kind,
            path: flag(args, "--path")
                .ok_or("add efi: --path required (volume-root path)")?
                .to_string(),
            kernel_cmdline: String::new(),
            servers: Vec::new(),
            state: Vec::new(),
        },
        PayloadKind::RustL4 => Payload {
            id: id.clone(),
            title,
            kind,
            path: String::new(),
            kernel_cmdline: flag(args, "--cmdline").unwrap_or_default().to_string(),
            servers: vec![ServerSpec {
                name: "init".into(),
                path: flag(args, "--init")
                    .ok_or("add rust: --init <path> required")?
                    .to_string(),
                argv: flags(args, "--arg").iter().map(|s| s.to_string()).collect(),
            }],
            state: Vec::new(),
        },
    };
    let summary = format!("added {} '{id}'", payload.kind.as_str());
    cfg.payloads.push(payload);
    if set_default {
        cfg.default_id = Some(id);
    }
    Ok(summary)
}

fn cmd_remove(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let id = args.first().ok_or("remove <id>: id required")?;
    let before = cfg.payloads.len();
    cfg.payloads.retain(|p| &p.id != id);
    if cfg.payloads.len() == before {
        return Err(format!("payload '{id}' not found"));
    }
    // default мог указывать на удалённый — сбрасываем (→ первый).
    if let Some(d) = &cfg.default_id
        && cfg.payload(d).is_none()
    {
        cfg.default_id = None;
    }
    Ok(format!("removed '{id}'"))
}

fn cmd_set(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let id = args.first().ok_or("set <id> field value: id required")?;
    let field = args
        .get(1)
        .ok_or("set <id> title|path|cmdline value: field required")?;
    let value = args.get(2).ok_or("set <id> field value: value required")?;
    let p = payload_mut(cfg, id)?;
    match field.as_str() {
        "title" => p.title = value.clone(),
        "path" => {
            if p.kind != PayloadKind::EfiChainload {
                return Err("set path: only efi payloads have path".into());
            }
            p.path = value.clone();
        }
        "cmdline" => {
            if p.kind != PayloadKind::RustL4 {
                return Err("set cmdline: only rust-l4 payloads have cmdline".into());
            }
            p.kernel_cmdline = value.clone();
        }
        other => return Err(format!("set: unknown field '{other}' (title|path|cmdline)")),
    }
    Ok(format!("set {id} {field} = {value}"))
}

fn cmd_arg(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let id = args
        .first()
        .ok_or("arg <id> add|rm|clear [values]: id required")?;
    let op = args.get(1).ok_or("arg <id> add|rm|clear: op required")?;
    let values = &args[2..];
    let p = payload_mut(cfg, id)?;
    if p.kind != PayloadKind::RustL4 {
        return Err(format!("arg: payload '{id}' has no servers (efi payload)"));
    }
    let srv = p
        .servers
        .first_mut()
        .ok_or_else(|| format!("payload '{id}' has no server"))?;
    match op.as_str() {
        "add" => {
            if values.is_empty() {
                return Err("arg add: at least one value required".into());
            }
            srv.argv.extend(values.iter().cloned());
            Ok(format!("argv += {} value(s)", values.len()))
        }
        "rm" => {
            let before = srv.argv.len();
            srv.argv.retain(|a| !values.contains(a));
            let removed = before - srv.argv.len();
            if removed == 0 {
                return Err("arg rm: no matching values".into());
            }
            Ok(format!("argv -= {removed} value(s)"))
        }
        "clear" => {
            srv.argv.clear();
            Ok("argv cleared".into())
        }
        other => Err(format!("arg: unknown op '{other}' (add|rm|clear)")),
    }
}

fn cmd_state(cfg: &mut BootConfig, args: &[String]) -> Result<String, String> {
    let id = args
        .first()
        .ok_or("state <id> set|rm name [value]: id required")?;
    let op = args.get(1).ok_or("state <id> set|rm: op required")?;
    let name = args.get(2).ok_or("state: variable name required")?;
    let p = payload_mut(cfg, id)?;
    if p.kind != PayloadKind::RustL4 {
        return Err(format!(
            "state: payload '{id}' has no boot_state (efi payload)"
        ));
    }
    match op.as_str() {
        "set" => {
            let value = args.get(3).ok_or("state set: value required")?;
            // upsert
            match p.state.iter_mut().find(|v| &v.name == name) {
                Some(v) => v.value = value.clone(),
                None => p.state.push(StateVar {
                    name: name.clone(),
                    value: value.clone(),
                }),
            }
            Ok(format!("state {name} = {value}"))
        }
        "rm" => {
            let before = p.state.len();
            p.state.retain(|v| &v.name != name);
            if p.state.len() == before {
                return Err(format!("state rm: '{name}' not found"));
            }
            Ok(format!("state {name} removed"))
        }
        other => Err(format!("state: unknown op '{other}' (set|rm)")),
    }
}

// ───────────────────── show ─────────────────────

pub fn show(cfg: &BootConfig) -> String {
    let mut out = String::new();
    let timeout = match cfg.timeout_s {
        t if t < 0 => "wait forever".to_string(),
        0 => "instant default".to_string(),
        t => format!("{t}s"),
    };
    let _ = writeln!(
        out,
        "boot_cfg: {} payload(s), timeout: {timeout}",
        cfg.payloads.len()
    );
    let default = cfg.resolve_default();
    for (i, p) in cfg.payloads.iter().enumerate() {
        let mark = if i == default { "  <= default" } else { "" };
        let _ = writeln!(
            out,
            "  [{}] {} '{}' ({}){mark}",
            i + 1,
            p.id,
            p.menu_title(),
            p.kind.as_str()
        );
        match p.kind {
            PayloadKind::EfiChainload => {
                let _ = writeln!(out, "        path:    {}", p.path);
            }
            PayloadKind::RustL4 => {
                if !p.kernel_cmdline.is_empty() {
                    let _ = writeln!(out, "        cmdline: {}", p.kernel_cmdline);
                }
                for s in &p.servers {
                    let args = if s.argv.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", s.argv.join(", "))
                    };
                    let _ = writeln!(out, "        server:  {} ({}){args}", s.name, s.path);
                }
                for v in &p.state {
                    let _ = writeln!(out, "        state:   {}={}", v.name, v.value);
                }
            }
        }
    }
    out
}

// ───────────────────── Тесты ─────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Временный файл (уникальный на тест-процесс).
    fn tmpcfg() -> String {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("cfgtool-test-{}-{n}.xml", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    fn run_ok(args: &[&str]) -> String {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run(&owned).expect("expected success")
    }

    fn run_err(args: &[&str]) -> String {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run(&owned).expect_err("expected failure")
    }

    #[test]
    fn init_show_roundtrip() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        let out = run_ok(&[&p, "show"]);
        assert!(out.contains("1 payload(s)"), "{out}");
        assert!(out.contains("rust-l4"), "{out}");
        assert!(out.contains("<= default"), "{out}");
        assert!(out.contains("init (init.elf)"), "{out}");
        // Повторный init без --force отказывает.
        assert!(run_err(&[&p, "init"]).contains("exists"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn add_efi_and_default() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[
            &p,
            "add",
            "efi",
            "win",
            "--path",
            "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            "--title",
            "Windows Boot Manager",
            "--default",
        ]);
        let out = run_ok(&[&p, "show"]);
        assert!(out.contains("2 payload(s)"), "{out}");
        assert!(out.contains("bootmgfw.efi"), "{out}");
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.resolve_default(), 1, "win должен стать default");
        assert_eq!(cfg.payloads[1].kind, PayloadKind::EfiChainload);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn add_rust_with_args_and_cmdline() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[
            &p,
            "add",
            "rust",
            "test",
            "--init",
            "test.elf",
            "--arg",
            "stage=one",
            "--arg",
            "log=full",
            "--cmdline",
            "arch=x86_64 console=com1",
        ]);
        let cfg = load(&p).unwrap();
        let t = cfg.payload("test").unwrap();
        assert_eq!(
            t.servers[0].argv,
            vec!["stage=one".to_string(), "log=full".to_string()]
        );
        assert_eq!(t.kernel_cmdline, "arch=x86_64 console=com1");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn duplicate_id_rejected() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        let err = run_err(&[&p, "add", "efi", "rust-l4", "--path", "x.efi"]);
        assert!(err.contains("already exists"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn remove_resets_dangling_default() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[&p, "add", "efi", "win", "--path", "win.efi", "--default"]);
        run_ok(&[&p, "remove", "win"]);
        let cfg = load(&p).unwrap();
        assert!(cfg.default_id.is_none());
        assert_eq!(cfg.resolve_default(), 0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn timeout_none_and_seconds() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[&p, "timeout", "none"]);
        assert_eq!(load(&p).unwrap().timeout_s, -1);
        run_ok(&[&p, "timeout", "3"]);
        assert_eq!(load(&p).unwrap().timeout_s, 3);
        assert!(run_err(&[&p, "timeout", "soon"]).contains("integer"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn arg_and_state_ops() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[&p, "arg", "rust-l4", "add", "stage=boot-chain", "log=full"]);
        run_ok(&[&p, "arg", "rust-l4", "rm", "log=full"]);
        let cfg = load(&p).unwrap();
        assert_eq!(
            cfg.payloads[0].servers[0].argv,
            vec!["stage=boot-chain".to_string()]
        );
        run_ok(&[&p, "state", "rust-l4", "set", "console", "com1"]);
        run_ok(&[&p, "state", "rust-l4", "set", "test_mode", "qemu"]);
        run_ok(&[&p, "state", "rust-l4", "set", "console", "com2"]); // upsert
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.payloads[0].state.len(), 2);
        assert_eq!(
            cfg.payloads[0].state[0],
            StateVar {
                name: "console".into(),
                value: "com2".into()
            }
        );
        run_ok(&[&p, "state", "rust-l4", "rm", "test_mode"]);
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.payloads[0].state.len(), 1);
        assert!(run_err(&[&p, "state", "rust-l4", "rm", "nope"]).contains("not found"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn set_field_type_guards() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[&p, "add", "efi", "win", "--path", "win.efi"]);
        // path на rust-l4 — отказ.
        assert!(run_err(&[&p, "set", "rust-l4", "path", "x"]).contains("only efi"));
        // cmdline на efi — отказ.
        assert!(run_err(&[&p, "set", "win", "cmdline", "y"]).contains("only rust-l4"));
        // title — всем.
        run_ok(&[&p, "set", "win", "title", "Windows"]);
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.payload("win").unwrap().title, "Windows");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invalid_mutation_leaves_file_intact() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        let before = std::fs::read_to_string(&p).unwrap();
        // default на несуществующий id — отказ ДО записи.
        assert!(run_err(&[&p, "default", "ghost"]).contains("not found"));
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(before, after, "файл не должен меняться при отказе");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn broken_xml_reported() {
        let p = tmpcfg();
        std::fs::write(
            &p,
            "<bootloader><payload id=\"a\" type=\"bogus\"/></bootloader>",
        )
        .unwrap();
        let err = run_err(&[&p, "show"]);
        // serde сам называет неизвестный вариант и допустимые значения.
        assert!(err.contains("bogus") && err.contains("rust-l4"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn canonical_write_is_stable() {
        let p = tmpcfg();
        run_ok(&[&p, "init"]);
        run_ok(&[&p, "timeout", "2"]);
        let once = std::fs::read_to_string(&p).unwrap();
        run_ok(&[&p, "timeout", "3"]);
        run_ok(&[&p, "timeout", "2"]);
        let twice = std::fs::read_to_string(&p).unwrap();
        assert_eq!(once, twice);
        // Если рядом лежит реальный конфиг репозитория — он обязан
        // парситься и валидироваться (путь от CARGO_MANIFEST_DIR).
        let repo_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../boot/boot_cfg.xml");
        if repo_path.exists() {
            let repo = load(repo_path.to_str().unwrap()).unwrap();
            assert_eq!(repo.payloads.len(), 1);
            assert_eq!(repo.timeout_s, 2);
        }
        let _ = std::fs::remove_file(&p);
    }
}
