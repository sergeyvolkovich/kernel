// Линкер-скрипт init (пользовательский ELF @ 0x40000000).
//
// Цель собирается под x86_64-unknown-none (freestanding); code-model
// задаётся сборкой (scripts/build_image.sh: -C code-model=small —
// низкие пользовательские адреса; «kernel»-модель таргета здесь
// не подходит).
//
// v0.9: вшиваем образ rogue (дочерняя задача песочницы) в init:
// build.sh перед сборкой init экспортирует ROGUE_ELF (путь к
// свежесобранному бинарю crates/rogue); build-скрипт копирует его в
// OUT_DIR/child.bin — init читает include_bytes!(OUT_DIR/child.bin),
// готовит регионы и спавнит домен через TASK_SPAWN_IMAGE (ядро
// принимает только указатели на уже готовую память).
use std::path::Path;

fn main() {
    println!("cargo::rerun-if-changed=init.ld");
    let ld = Path::new(env!("CARGO_MANIFEST_DIR")).join("init.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");

    // v0.9: образ rogue -> OUT_DIR/child.bin (нет env — пустой файл:
    // init печатает «no embedded child image» и пропускает демо;
    // host-сборки cargo test образ не требуют).
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("child.bin");
    match std::env::var("ROGUE_ELF") {
        Ok(p) if !p.is_empty() && Path::new(&p).exists() => {
            println!("cargo::rerun-if-changed={p}");
            println!("cargo::warning=embedding rogue image: {p}");
            std::fs::copy(&p, &out).expect("copy ROGUE_ELF -> OUT_DIR/child.bin");
        }
        _ => {
            println!("cargo::warning=ROGUE_ELF not set: sandbox demo will be skipped");
            let _ = std::fs::remove_file(&out);
            std::fs::write(&out, []).expect("write empty OUT_DIR/child.bin");
        }
    }
}
