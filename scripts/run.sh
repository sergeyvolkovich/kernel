#!/usr/bin/env bash
# ==== run.sh: QEMU + OVMF загрузка kernel.efi (rust-l4) ====
# Использование: scripts/run.sh [timeout-сек] (по умолчанию 60; 0 = без лимита)
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT=${1:-60}
QROOT=/home/z/my-project/tools/qroot
OVMF=$QROOT/usr/share/OVMF
ESP=target/esp.img
LOG=target/serial.log

export LD_LIBRARY_PATH=$QROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
QEMU=$QROOT/usr/bin/qemu-system-x86_64

[ -f "$ESP" ] || { echo "нет $ESP — запусти scripts/build.sh"; exit 1; }

# Свежие VARS OVMF (копия, чтобы не мутировать эталон).
cp -f "$OVMF/OVMF_VARS_4M.fd" target/OVMF_VARS_4M.fd

rm -f "$LOG"
echo "== qemu-system-x86_64: q35, 512M, OVMF, serial->log =="

ARGS=(
  -machine q35 -m 512M
  -drive if=pflash,format=raw,readonly=on,file="$OVMF/OVMF_CODE_4M.fd"
  -drive if=pflash,format=raw,file=target/OVMF_VARS_4M.fd
  -drive format=raw,file="$ESP"
  -serial file:"$LOG"
  -display none -vga none -net none
  -cpu max
)

if [ "$TIMEOUT" = "0" ]; then
  "$QEMU" "${ARGS[@]}"
else
  timeout --signal=TERM "$TIMEOUT" "$QEMU" "${ARGS[@]}" || true
fi

echo "== serial log: $LOG =="
cat "$LOG"
