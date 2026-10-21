// Сборка head.S + линкер-скрипт для bin-цели kernel.
//
// v0.11: link-args (скрипт ядра, -e_start, -no-pie) выдаются ТОЛЬКО под
// x86_64-unknown-none — host-тесты lib (парсеры MADT/ACPI, cargo test
// -p backend) линкуются обычным рантаймом std, кастомный скрипт ядра им
// не нужен (и ломает их: -T kernel.ld + -e_start на PIE-тесте).
// head.S компилируется всегда (символы в либе никому не мешают).
fn main() {
    println!("cargo::rerun-if-changed=src/head.S");
    println!("cargo::rerun-if-changed=kernel.ld");

    let asm = std::path::Path::new("src/head.S");
    cc::Build::new()
        .file(asm)
        .flag("-ffreestanding")
        .flag("-fno-asynchronous-unwind-tables")
        .compile("head");

    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "x86_64-unknown-none" {
        let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("kernel.ld");
        println!("cargo::rustc-link-arg=-T{}", ld.display());
        println!("cargo::rustc-link-arg=-e_start");
        println!("cargo::rustc-link-arg=-no-pie");
        println!("cargo::rustc-link-arg=-znoseparate-code");
    }
}
