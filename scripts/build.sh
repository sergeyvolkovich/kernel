#!/usr/bin/env bash
# ==== build.sh: полная сборка загрузочной цепочки rust-l4 ====
#   kernel (x86_64-unknown-none, high-half ELF, release+strip)
#   -> init (user static ELF) -> kernel.bin (встраивание)
#   -> uefi_stub (kernel.efi, UEFI) -> ESP (MBR + FAT).
#
# Release обязателен для загрузки: debug-ядро ~14 MiB, и заглушка
# (с встроенным образом) накрывает фиксированный KERNEL_PHYS_BASE=16 MiB.
#
# Инструменты (mtools из user-space-префикса tools/qemu-usr) ставятся
# scripts/fetch_qemu.sh; rust-objcopy — cargo install cargo-binutils.
set -euo pipefail
# Корень workspace — от расположения скрипта (портируемость свежих клонов).
WS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WS"
export PATH="$HOME/.cargo/bin:$PATH"

TOOLS=${TOOLS:-/home/z/my-project/tools}
OUT=target
ESP_DIR=$OUT/esp
R=--release

echo "== [1/4] kernel (x86_64-unknown-none, release) =="
cargo build -p backend --bin kernel --target x86_64-unknown-none $R
KERNEL=$OUT/x86_64-unknown-none/release/kernel
# Symbols — рядом для отладки; в заглушку — stripped-образ.
cp -f "$KERNEL" "$OUT/kernel.sym"
rust-objcopy --strip-all "$KERNEL" "$WS/crates/uefi_stub/kernel.bin"

echo "== [2/4] init (static user ELF @ 0x40000000) =="
cargo build -p init --target x86_64-unknown-none $R

echo "== [3/4] uefi_stub (kernel.efi: stub + встроенный образ ядра) =="
cargo build -p uefi_stub --target x86_64-unknown-uefi $R

echo "== [4/4] ESP =="
rm -rf "$ESP_DIR"
mkdir -p "$ESP_DIR/EFI/BOOT"
cp -f $OUT/x86_64-unknown-uefi/release/uefi_stub.efi "$ESP_DIR/EFI/BOOT/BOOTX64.EFI"
cp -f $OUT/x86_64-unknown-none/release/init "$ESP_DIR/init"
cp -f scripts/boot_cfg.xml "$ESP_DIR/boot_cfg.xml"

# FAT-образ с MBR-разделом (OVMF требует таблицу разделов).
# Порядок: (1) plain FAT на fs.img; (2) склейка MBR-заголовок + FS.
export LD_LIBRARY_PATH=$TOOLS/qemu-usr/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
MTOOLS=$TOOLS/qemu-usr/usr/bin
PART_START_LBA=2048          # 1 MiB gap
PART_SECTORS=32768           # 16 MiB
FS_IMG="$OUT/esp_fs.img"
rm -f "$OUT/esp.img" "$FS_IMG"
# (1) Файловая система (без смещений).
dd if=/dev/zero of="$FS_IMG" bs=512 count=$PART_SECTORS status=none
$MTOOLS/mformat -i "$FS_IMG" -C -T $PART_SECTORS ::
$MTOOLS/mmd -i "$FS_IMG" ::/EFI ::/EFI/BOOT
$MTOOLS/mcopy -i "$FS_IMG" "$ESP_DIR/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
$MTOOLS/mcopy -i "$FS_IMG" "$ESP_DIR/init" ::/init
$MTOOLS/mcopy -i "$FS_IMG" "$ESP_DIR/boot_cfg.xml" ::/boot_cfg.xml
# (2) MBR + склейка (gap 1 MiB + FS).
dd if=/dev/zero of="$OUT/esp.img" bs=1M count=1 status=none
python3 scripts/esp_mbr.py "$OUT/esp.img" $PART_START_LBA $PART_SECTORS
cat "$FS_IMG" >> "$OUT/esp.img"

echo "OK: $OUT/esp.img"
ls -la "$ESP_DIR/EFI/BOOT/BOOTX64.EFI" "$ESP_DIR/init"
