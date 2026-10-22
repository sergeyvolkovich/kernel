// Линковка образа rogue. Два режима (v0.11):
//
//   ROGUE_PIE=1 — PIE (ET_DYN, база 0, R_X86_64_RELATIVE в .rela.dyn):
//                позиционно-независимый образ для спавна на ЛЮБОЙ базе;
//                relocation-модель задаёт build.sh (RUSTFLAGS=-C
//                relocation-model=pic — один LTO-мир с userlib), линкер —
//                rust-lld с --pie и дефолтной раскладкой (без кастомного
//                скрипта: vaddr растут от ~0, всё адресуется RIP-относительно
//                либо патчится загрузчиком по DT_RELA).
//
//   без ROGUE_PIE — легаси-режим v0.9: статический ELF @ 0x40000000 по
//                фиксированному линк-скрипту rogue.ld (-no-pie). Оставлен
//                для совместимости и контроля: PIE-сборка — основная
//                (build.sh), статическая — режим отладки загрузчика.
//
// Цель собирается под x86_64-unknown-none; userlib (rlib) даёт _start и
// обёртки l4_*.
fn main() {
    let pie = std::env::var("ROGUE_PIE").is_ok_and(|v| !v.is_empty());
    if pie {
        println!("cargo::rerun-if-env-changed=ROGUE_PIE");
        println!("cargo::rustc-link-arg=-pie");
        println!("cargo::rustc-link-arg=-znoseparate-code");
        return;
    }
    println!("cargo::rerun-if-changed=rogue.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rogue.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
