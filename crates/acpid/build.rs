// Линковка образа acpid (v0.14). PIE (ET_DYN, база 0,
// R_X86_64_RELATIVE в .rela.dyn) — как у rogue (v0.11): init спавнит
// образ через pie-план на выбранной базе; relocation-модель задаёт
// build.sh (RUSTFLAGS=-C relocation-model=pic — единый LTO-мир с
// userlib), линкер — rust-lld с --pie.
fn main() {
    println!("cargo::rustc-link-arg=-pie");
    println!("cargo::rustc-link-arg=-znoseparate-code");
}
