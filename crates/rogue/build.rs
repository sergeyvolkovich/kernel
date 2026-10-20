// Линкер-скрипт rogue (пользовательский ELF @ 0x40000000, как init:
// спавнится через TASK_SPAWN_IMAGE по фиксированным линк-адресам).
//
// Цель собирается под x86_64-unknown-none; userlib (rlib) даёт _start и
// обёртки l4_*; code-model — дефолт таргета (адрес 0x40000000 < 2^31).
fn main() {
    println!("cargo::rerun-if-changed=rogue.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rogue.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
