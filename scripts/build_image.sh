#!/bin/bash
# ==== build_image.sh: полный образ загрузки rust-l4 (v3) ====
#
# Продукт: boot/esp.img — FAT-раздел с:
#   EFI/BOOT/BOOTX64.EFI  — UEFI-заглушка (ядро ВСТРОЕНО в бинарь)
#   boot_cfg.xml          — конфигурация: archive + boot_state (v3)
#   boot.cpio             — boot-архив RLBA (модуль [0] BootInfo v3):
#                           FLAT-бутстрап + cpio(newc) + каталог + CRC32
#
# Цели сборки (смешанные — потому явные --target, а не workspace-дефолт):
#   kernel    (platform/backend/bin) -> x86_64-unknown-none, kernel.ld (high-half)
#   bootstrap (user/bootstrap)       -> x86_64-unknown-none, bootstrap.ld (@0x40000000)
#                                        -> конвертация ELF→FLAT (mkarchive.py)
#   init      (user/init)            -> x86_64-unknown-none, init.ld (@0x60000000)
#   uefi_stub (boot/uefi_stub)       -> x86_64-unknown-uefi (include_bytes kernel.bin)
#
# v3 (протокол загрузки): серверы больше не лежат отдельными файлами —
# единый boot.cpio собирает scripts/mkarchive.py; archive_crc32 в
# boot_cfg.xml патчится той же командой (заглушка сверяет при чтении).
set -euo pipefail

# Корень workspace — от расположения скрипта (портируемость свежих клонов).
WS="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS=${TOOLS:-/home/z/my-project/tools}
QEMU_USR=$TOOLS/qemu-usr
export PATH="$HOME/.cargo/bin:$PATH"
cd "$WS"

echo "== [1/6] kernel (x86_64-unknown-none, high-half) =="
cargo build --target x86_64-unknown-none --release -p backend --bin kernel

echo "== [2/6] bootstrap (x86_64-unknown-none @ 0x40000000, FLAT) =="
cargo build --target x86_64-unknown-none --release -p bootstrap

echo "== [3/6] init server (x86_64-unknown-none @ 0x60000000) =="
cargo build --target x86_64-unknown-none --release -p init

echo "== [4/6] boot archive (RLBA: flat + cpio + каталог + CRC32) =="
python3 scripts/mkarchive.py \
    --flat target/x86_64-unknown-none/release/bootstrap \
    --init target/x86_64-unknown-none/release/init \
    --init-args "stage=boot-chain log=full" \
    --out boot/boot.cpio \
    --xml boot/boot_cfg.xml

echo "== [5/6] uefi stub (x86_64-unknown-uefi) =="
cp target/x86_64-unknown-none/release/kernel crates/boot/uefi_stub/kernel.bin
cargo build --target x86_64-unknown-uefi --release -p uefi_stub

echo "== [6/6] ESP image =="
# FAT-образ с MBR-разделом (OVMF требует таблицу разделов):
# (1) plain FAT16 на fs.img; (2) склейка MBR-заголовок (1 MiB gap) + FS.
mkdir -p boot
MTOOLS_BIN="$QEMU_USR/usr/bin"
PART_START_LBA=2048          # 1 MiB gap
PART_SECTORS=32768           # 16 MiB
FS_IMG=boot/esp_fs.img
rm -f boot/esp.img "$FS_IMG"
dd if=/dev/zero of="$FS_IMG" bs=512 count=$PART_SECTORS status=none
"$MTOOLS_BIN/mformat" -i "$FS_IMG" -C -T $PART_SECTORS ::
"$MTOOLS_BIN/mmd" -i "$FS_IMG" ::/EFI ::/EFI/BOOT
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" \
    target/x86_64-unknown-uefi/release/uefi_stub.efi ::/EFI/BOOT/BOOTX64.EFI
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" boot/boot_cfg.xml ::boot_cfg.xml
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" boot/boot.cpio ::boot.cpio
dd if=/dev/zero of=boot/esp.img bs=1M count=1 status=none
python3 scripts/esp_mbr.py boot/esp.img $PART_START_LBA $PART_SECTORS
cat "$FS_IMG" >> boot/esp.img
rm -f "$FS_IMG"

echo "== done =="
ls -la boot/esp.img boot/boot.cpio
file target/x86_64-unknown-none/release/kernel \
     target/x86_64-unknown-none/release/bootstrap \
     target/x86_64-unknown-none/release/init \
     target/x86_64-unknown-uefi/release/uefi_stub.efi 2>/dev/null || true
