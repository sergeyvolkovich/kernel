#!/bin/bash
# ==== smoke.sh: чистый прогон boot-chain smoke в QEMU ====
#
# Полная пересборка (kernel -> init -> встраивание -> заглушка -> ESP с
# MBR) и запуск QEMU с ОЖИДАНИЕМ результата: serial пуллится, при
# появлении маркера успеха («all user threads gone») или беды (PANIC/
# FAULT) QEMU гасится досрочно — не жадаем таймаута наhlt-хвосте.
#
#   SMP=2 bash scripts/smoke.sh        # по умолчанию 2 vCPU
set -euo pipefail
WS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WS"
export PATH="$HOME/.cargo/bin:$PATH"

Q=/home/z/my-project/tools/qemu-usr
export LD_LIBRARY_PATH="$Q/usr/lib/x86_64-linux-gnu:$Q/usr/lib"
MTOOLS_BIN="$Q/usr/bin"
SMP=${SMP:-2}
LOG=/tmp/smoke.log
VARS="$WS/boot/OVMF_VARS.fd"

echo "== [1/6] kernel =="
cargo build --target x86_64-unknown-none --release -p backend --bin kernel

echo "== [2/6] init =="
cargo build --target x86_64-unknown-none --release -p init

echo "== [3/6] embed kernel into stub =="
cp target/x86_64-unknown-none/release/kernel crates/boot/uefi_stub/kernel.bin

echo "== [4/6] uefi stub =="
cargo build --target x86_64-unknown-uefi --release -p uefi_stub

echo "== [5/6] ESP (MBR + FAT16) =="
FS_IMG=boot/esp_fs.img
rm -f boot/esp.img "$FS_IMG"
dd if=/dev/zero of="$FS_IMG" bs=512 count=32768 status=none
"$MTOOLS_BIN/mformat" -i "$FS_IMG" -C -T 32768 ::
"$MTOOLS_BIN/mmd" -i "$FS_IMG" ::/EFI ::/EFI/BOOT
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" \
    target/x86_64-unknown-uefi/release/uefi_stub.efi ::/EFI/BOOT/BOOTX64.EFI
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" boot/boot_cfg.xml ::boot_cfg.xml
"$MTOOLS_BIN/mcopy" -i "$FS_IMG" target/x86_64-unknown-none/release/init ::init.elf
dd if=/dev/zero of=boot/esp.img bs=1M count=1 status=none
python3 scripts/esp_mbr.py boot/esp.img 2048 32768
cat "$FS_IMG" >> boot/esp.img
rm -f "$FS_IMG"

# Контроль образа: размер 1 MiB gap + 16 MiB FS; свежий init внутри
# (строка есть только в текущей версии «workers spawned»).
SIZE=$(stat -c%s boot/esp.img)
[ "$SIZE" = "17825792" ] || { echo "FATAL: esp.img size $SIZE != 17825792"; exit 1; }
if grep -aq 'workers spawned' boot/esp.img; then
    echo "ESP freshness OK (init has the 4-thread smoke scenario)"
else
    echo "FATAL: esp.img does not contain the fresh init" ; exit 1
fi

echo "== [6/6] QEMU (SMP=$SMP), serial -> $LOG =="
rm -f "$LOG" "$VARS"
cp "$Q/usr/share/OVMF/OVMF_VARS_4M.fd" "$VARS"
timeout -k 10 "${QEMU_TIMEOUT:-600}" "$Q/usr/bin/qemu-system-x86_64" \
  -accel tcg,thread=single \
  -L "$Q/usr/share/qemu" -L "$Q/usr/share/seabios" \
  -m 512M -cpu Cascadelake-Server -smp "$SMP" \
  -drive if=pflash,format=raw,readonly=on,file="$Q/usr/share/OVMF/OVMF_CODE_4M.fd" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive format=raw,file="$WS/boot/esp.img" \
  -serial file:"$LOG" \
  -display none -no-reboot -net none -no-fd-bootchk \
  > /tmp/smoke_qemu.log 2>&1 &
QPID=$!

# Пулл serial: маркеры успеха/беды — досрочное завершение.
DEADLINE=$((SECONDS + ${QEMU_TIMEOUT:-600}))
STATUS=timeout
while kill -0 "$QPID" 2>/dev/null && [ "$SECONDS" -lt "$DEADLINE" ]; do
    if grep -aq 'all user threads gone' "$LOG" 2>/dev/null; then
        STATUS=ok; break
    fi
    if grep -aqE 'PANIC|KERNEL FAULT' "$LOG" 2>/dev/null; then
        STATUS=fault; break
    fi
    sleep 5
done
if kill -0 "$QPID" 2>/dev/null; then
    kill "$QPID" 2>/dev/null || true
    sleep 1
    kill -9 "$QPID" 2>/dev/null || true
fi

echo "== result: $STATUS ; serial: $(wc -l < "$LOG" 2>/dev/null || echo 0) lines =="
grep -aE 'lb:|LB:|spin|migrat|OVERLOAD|stole|kick|halting|FAULT|PANIC|worker' "$LOG" | head -60 || true
[ "$STATUS" = "ok" ] || exit 1
