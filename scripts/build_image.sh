#!/bin/bash
# ==== build_image.sh: полный образ загрузки rust-l4 ====
#
# Продукт: boot/esp.img — FAT-раздел с:
#   EFI/BOOT/BOOTX64.EFI  — UEFI-заглушка (ядро ВСТРОЕНО в бинарь)
#   boot_cfg.xml          — конфигурация серверов + boot_state
#   init.elf              — первый пользовательский сервер (модуль [0])
#
# Цели сборки (смешанные — потому явные --target, а не workspace-дефолт):
#   kernel (backend/bin)  -> x86_64-unknown-none, kernel.ld (high-half)
#   init                  -> x86_64-unknown-none, init.ld (@0x40000000,
#                            code-model=small: пользовательские адреса)
#   uefi_stub             -> x86_64-unknown-uefi (include_bytes kernel.bin)
set -euo pipefail

WS=/home/z/my-project/work/kernel_ws
QEMU_USR=/home/z/my-project/tools/qemu-usr
export PATH="$HOME/.cargo/bin:$PATH"
cd "$WS"

echo "== [1/5] kernel (x86_64-unknown-none, high-half) =="
cargo build --target x86_64-unknown-none --release -p backend --bin kernel

echo "== [2/5] init server (x86_64-unknown-none @ 0x40000000) =="
# code-model остаётся «kernel» (дефолт таргета): LTO с прекомпилированным
# core требует единой модели; kernel-модель корректна на 0x40000000
# (movabs/RIP-relative/32S — все формы работают < 2^31).
cargo build --target x86_64-unknown-none --release -p init

echo "== [3/5] embed kernel into stub =="
cp target/x86_64-unknown-none/release/kernel crates/uefi_stub/kernel.bin

echo "== [4/5] uefi stub (x86_64-unknown-uefi) =="
cargo build --target x86_64-unknown-uefi --release -p uefi_stub

echo "== [5/5] ESP image =="
mkdir -p boot
rm -f boot/esp.img
dd if=/dev/zero of=boot/esp.img bs=1M count=64 status=none
"$QEMU_USR/usr/sbin/mkfs.fat" -F 16 -n RUSTL4 boot/esp.img
MTOOLS="$QEMU_USR/usr/bin/mcopy -i boot/esp.img"
MD="$QEMU_USR/usr/bin/mmd -i boot/esp.img"
$MD ::EFI ::EFI/BOOT
$MTOOLS target/x86_64-unknown-uefi/release/uefi_stub.efi ::EFI/BOOT/BOOTX64.EFI
$MTOOLS boot/boot_cfg.xml ::boot_cfg.xml
$MTOOLS target/x86_64-unknown-none/release/init ::init.elf

echo "== done =="
ls -la boot/esp.img
file target/x86_64-unknown-none/release/kernel \
     target/x86_64-unknown-none/release/init \
     target/x86_64-unknown-uefi/release/uefi_stub.efi 2>/dev/null || true
