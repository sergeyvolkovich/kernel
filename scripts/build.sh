#!/usr/bin/env bash
# ==== build.sh: полная сборка загрузочной цепочки rust-l4 ====
#   kernel (x86_64-unknown-none, high-half ELF, release+strip)
#   -> init (user static ELF) -> kernel.bin (встраивание)
#   -> uefi_stub (kernel.efi, UEFI) -> ESP (MBR + FAT).
#
# Release обязателен для загрузки: debug-ядро ~14 MiB, и заглушка
# (с встроенным образом) накрывает фиксированный KERNEL_PHYS_BASE=16 MiB.
#
# v0.8: сборка userlib (C-ABI staticlib) + capp (C-сервер на gcc —
# -nostdlib + init.ld) и выбор конфигурации серверов:
#   BOOT_CFG=scripts/boot_cfg_c.xml bash scripts/build.sh   # capp
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

echo "== [1/5] kernel (x86_64-unknown-none, release) =="
cargo build -p backend --bin kernel --target x86_64-unknown-none $R
KERNEL=$OUT/x86_64-unknown-none/release/kernel
# Symbols — рядом для отладки; в заглушку — stripped-образ.
cp -f "$KERNEL" "$OUT/kernel.sym"
rust-objcopy --strip-all "$KERNEL" "$WS/crates/uefi_stub/kernel.bin"

echo "== [2/6] userlib (C-ABI staticlib+rlib) =="
# userlib: статическая C-библиотека (x86_64-unknown-none; code-model
# kernel — единый LTO-мир с core, 0x40000000 < 2^31 — все формы адресации);
# rlib-поверхность — для Rust-приложений (crates/rogue).
cargo build -p userlib --target x86_64-unknown-none $R
USERLIB=$OUT/x86_64-unknown-none/release/libuserlib.a

echo "== [3/6] rogue (дочерний образ песочницы v0.9, ELF @ 0x40000000) =="
cargo build -p rogue --target x86_64-unknown-none $R
ROGUE=$OUT/x86_64-unknown-none/release/rogue

echo "== [4/6] init (static user ELF @ 0x40000000; вшитый образ rogue) =="
# ROGUE_ELF: build-скрипт init копирует бинарь rogue в OUT_DIR/child.bin,
# init читает include_bytes! и спавнит домен через TASK_SPAWN_IMAGE
# (дескриптор: сегменты/стек/argv/лимиты — всё готовит юзерспейс).
ROGUE_ELF=$ROGUE cargo build -p init --target x86_64-unknown-none $R

echo "== [5/6] uefi_stub (kernel.efi: stub + встроенный образ ядра) =="
cargo build -p uefi_stub --target x86_64-unknown-uefi $R

echo "== [6/6] capp (C-сервер) =="
# capp: чистый C — ядро без libc, линк-скрипт init (0x40000000, ENTRY(_start)).
# -ffreestanding (без libc-примитивов в коде), -fno-stack-protector
# (иначе ссылается на __stack_chk_fail — userlib даёт страховку-заглушку),
# -fno-pie/-no-pie (статические фиксированные адреса), -mno-sse...
# НЕ нужно: SSE в ring3 работает (ядро не трогает FPU после загрузки).
CC=${CC:-gcc}
$CC -O2 -Wall -Wextra -ffreestanding -fno-stack-protector -fno-pie \
    -I crates/userlib/include -c examples/capp.c -o $OUT/capp.o
$CC -nostdlib -static -no-pie -Wl,-T,crates/init/init.ld -Wl,--build-id=none \
    -o $OUT/capp $OUT/capp.o "$USERLIB"

echo "== [5/5] ESP =="
rm -rf "$ESP_DIR"
mkdir -p "$ESP_DIR/EFI/BOOT"
cp -f $OUT/x86_64-unknown-uefi/release/uefi_stub.efi "$ESP_DIR/EFI/BOOT/BOOTX64.EFI"
cp -f $OUT/x86_64-unknown-none/release/init "$ESP_DIR/init"
cp -f $OUT/capp "$ESP_DIR/capp"
# Конфигурация серверов: по умолчанию init (Rust); C-демо —
# BOOT_CFG=scripts/boot_cfg_c.xml bash scripts/build.sh.
BOOT_CFG=${BOOT_CFG:-scripts/boot_cfg.xml}
cp -f "$BOOT_CFG" "$ESP_DIR/boot_cfg.xml"

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
$MTOOLS/mcopy -i "$FS_IMG" "$ESP_DIR/capp" ::/capp
$MTOOLS/mcopy -i "$FS_IMG" "$ESP_DIR/boot_cfg.xml" ::/boot_cfg.xml
# (2) MBR + склейка (gap 1 MiB + FS).
dd if=/dev/zero of="$OUT/esp.img" bs=1M count=1 status=none
python3 scripts/esp_mbr.py "$OUT/esp.img" $PART_START_LBA $PART_SECTORS
cat "$FS_IMG" >> "$OUT/esp.img"

echo "OK: $OUT/esp.img"
ls -la "$ESP_DIR/EFI/BOOT/BOOTX64.EFI" "$ESP_DIR/init" "$ESP_DIR/capp"
