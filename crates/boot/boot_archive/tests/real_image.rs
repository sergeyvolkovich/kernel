// Интеграционная проверка реального boot.cpio (собран scripts/mkarchive.py):
// Rust-парсер протокола обязан читать то, что пишет Python-сборщик.
// Запуск: RLBA_TEST_ARCHIVE=boot/boot.cpio cargo test -p boot_archive --test real_image
// (без переменной тест молчно пропускается — образ в репо не хранится).

use boot_archive::*;

#[test]
fn real_mkarchive_image_parses() {
    let Ok(path) = std::env::var("RLBA_TEST_ARCHIVE") else {
        return; // образ не собран — пропускаем (сборка = build_image.sh)
    };
    // cwd теста — каталог крейта: относительный путь резолвим от корня
    // workspace (../../.. от crates/boot/boot_archive).
    let path = if std::path::Path::new(&path).exists() {
        path
    } else {
        format!("{}/../../../{}", env!("CARGO_MANIFEST_DIR"), path)
    };
    let blob = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let h = parse_header(&blob).expect("RLBA header");
    verify_header_crc(&blob, &h).expect("header CRC32");

    // FLAT-бутстрап: сегменты валидны, точка входа внутри образа и
    // попадает в исполняемый сегмент (позицию выбирает линкер).
    let (entry, nsegs, segs) = parse_flat(&blob, &h).expect("FLAT");
    assert!(entry >= FLAT_BASE);
    assert!(
        segs.iter()
            .take(nsegs)
            .any(|s| entry >= s.vaddr as u64 && entry < s.vaddr as u64 + s.memsz as u64),
        "entry внутри сегмента образа"
    );
    assert!(nsegs >= 2, "text + data минимум");
    assert!(segs.iter().take(nsegs).all(|s| s.memsz > 0));

    // Каталог: ровно один init, имя/args/данные/CRC.
    let e = find_init(&blob, &h).expect("init entry");
    assert_eq!(entry_name(&blob, &h, &e).unwrap(), "init");
    let args = entry_args(&blob, &h, &e).unwrap().expect("init args");
    assert_eq!(args, "stage=boot-chain log=full");
    let data = entry_data(&blob, &e).unwrap();
    assert_eq!(&data[..4], b"\x7fELF", "init — ELF64");
    entry_verify(&blob, &e).expect("init CRC32");

    // Данные init лежат внутри newc-стрима (гибридный формат).
    assert!(e.data_off >= h.cpio_off);
}
