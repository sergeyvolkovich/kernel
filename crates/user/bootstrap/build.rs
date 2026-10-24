// Сборка flat-бутстрапа (@ 0x40000000, bootstrap.ld, -no-pie):
// kinit (flatload) грузит FLX-образ из заголовка RLBA по фиксированным
// адресам; mkarchive.py конвертирует этот ELF в FLAT при сборке образа.
fn main() {
    println!("cargo::rerun-if-changed=bootstrap.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bootstrap.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
