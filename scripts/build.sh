#!/usr/bin/env bash
# ==== build.sh: полная сборка загрузочной цепочки rust-l4 ====
#
# v0.20: образ собирает scripts/build_image.sh (единая точка правды:
# kernel -> init -> uefi_stub -> ESP). Этот скрипт добавляет артефакты
# ОТЛАДКИ: kernel.sym (ELF с символами) и stripped-копию образа ядра.
#
# rust-objcopy — cargo install cargo-binutils.
set -euo pipefail
WS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WS"
export PATH="$HOME/.cargo/bin:$PATH"

bash "$(dirname "$0")/build_image.sh"

KERNEL=target/x86_64-unknown-none/release/kernel
if [ -f "$KERNEL" ] && command -v rust-objcopy >/dev/null 2>&1; then
    cp -f "$KERNEL" target/kernel.sym
    rust-objcopy --strip-all "$KERNEL" target/kernel.bin
    echo "== debug artifacts =="
    ls -la target/kernel.sym target/kernel.bin
fi
