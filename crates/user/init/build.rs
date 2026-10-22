// Сборка статического init-ELF (@ 0x40000000, init.ld, -no-pie):
// startup::elfload грузит модуль [0] по фиксированным линк-адресам.
fn main() {
    println!("cargo::rerun-if-changed=init.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("init.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
