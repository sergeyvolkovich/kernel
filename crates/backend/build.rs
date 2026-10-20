// Сборка head.S + линкер-скрипт для bin-цели kernel.
fn main() {
    println!("cargo::rerun-if-changed=src/head.S");
    println!("cargo::rerun-if-changed=kernel.ld");

    let asm = std::path::Path::new("src/head.S");
    cc::Build::new()
        .file(asm)
        .flag("-ffreestanding")
        .flag("-fno-asynchronous-unwind-tables")
        .compile("head");

    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("kernel.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-e_start");
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
