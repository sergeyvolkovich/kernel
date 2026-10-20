#!/bin/bash
# ==== run_qemu.sh: запуск rust-l4 в QEMU (OVMF, UEFI) ====
#
# OVMF из user-space-префикса (tools/qemu-usr), serial -> stdout.
# -cpu max: ARCH_CAPABILITIES.RDCL_NO (kmain требует Meltdown-закрытость).
set -euo pipefail

WS=/home/z/my-project/work/kernel_ws
QEMU_USR=/home/z/my-project/tools/qemu-usr
OVMF_CODE=$QEMU_USR/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_SRC=$QEMU_USR/usr/share/OVMF/OVMF_VARS_4M.fd

export LD_LIBRARY_PATH="$QEMU_USR/usr/lib/x86_64-linux-gnu:$QEMU_USR/lib/x86_64-linux-gnu"

# Свежая копия VARS (pflash пишется).
rm -f "$WS/boot/OVMF_VARS.fd"
cp "$OVMF_VARS_SRC" "$WS/boot/OVMF_VARS.fd"

RAM=${RAM:-512}
TIMEOUT=${QEMU_TIMEOUT:-120}
# SMP: число CPU (v0.6: MADT/SIPI/IPI/BKL/shootdown).
SMP=${QEMU_SMP:-2}
# IOMMU: intel-iommu на q35 (v0.6: DMA-ремаппинг VT-d; IRQ-ремаппинг
# выключен — не реализован в драйвере; без устройств это безопасно).
IOMMU=${QEMU_IOMMU:-0}

EXTRA_ARGS=()
if [ "$IOMMU" = "1" ]; then
  EXTRA_ARGS+=(-machine q35 -device intel-iommu,intremap=off)
fi

# TCG single-thread: в этой сборке QEMU (10.0.13, MTTCG) доставка IPI
# остановленному (hlt) vCPU ненадёжна — resched-IPI терялся, AP не
# просыпался из парковки. Однопоточный TCG даёт корректную SMP-семантику
# (порядок событий эквивалентен реальному железу); на KVM/железе
# проблемы нет.
exec timeout -k 5 "$TIMEOUT" "$QEMU_USR/usr/bin/qemu-system-x86_64" \
  -accel tcg,thread=single \
  -L /home/z/my-project/tools/qemu-roms \
  -m ${RAM}M \
  -cpu ${QEMU_CPU:-Cascadelake-Server} \
  -smp ${SMP} \
  "${EXTRA_ARGS[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WS/boot/OVMF_VARS.fd" \
  -drive format=raw,file="$WS/boot/esp.img" \
  -serial stdio \
  -display none \
  -no-reboot \
  -net none \
  -no-fd-bootchk
