// Сборка статического init-ELF (@ 0x60000000, init.ld, -no-pie):
// бутстрап (v3) спавнит образ через pie+TASK_SPAWN_IMAGE по фиксированным
// линк-адресам (StaticFixed).
fn main() {
    println!("cargo::rerun-if-changed=init.ld");
    let ld = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("init.ld");
    println!("cargo::rustc-link-arg=-T{}", ld.display());
    println!("cargo::rustc-link-arg=-no-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
