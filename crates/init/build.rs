// Линкер-скрипт init (пользовательский ELF @ 0x40000000).
//
// Цель собирается под x86_64-unknown-none (freestanding); code-model
// задаётся сборкой (scripts/build_image.sh: -C code-model=small —
// низкие пользовательские адреса; «kernel»-модель таргета здесь
// не подходит).
fn main() {
    println!("cargo::rerun-if-changed=init.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("init.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
