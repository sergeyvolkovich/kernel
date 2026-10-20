#!/bin/bash
# ==== run_qemu.sh: запуск rust-l4 в QEMU (OVMF, UEFI) ====
#
# OVMF из user-space-префикса (tools/qemu-usr, ставится fetch_qemu.sh),
# serial -> stdout. -cpu max/Cascadelake: ARCH_CAPABILITIES.RDCL_NO
# (kmain требует Meltdown-закрытость).
#
# Конфигурация через окружение:
#   RAM=512            — память, МиБ
#   QEMU_SMP=2         — число vCPU
#   QEMU_TIMEOUT=120    — таймаут прогона, с
#   QEMU_IOMMU=0|1|amd  — IOMMU: 0 — нет; 1 — Intel VT-d (q35,
#                        intremap=off); amd — AMD-Vi (q35, amd-iommu).
set -euo pipefail

# Корень workspace — от расположения скрипта (портируемость свежих клонов).
WS="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS=${TOOLS:-/home/z/my-project/tools}
QEMU_USR=$TOOLS/qemu-usr
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
# IOMMU: intel-iommu/amd-iommu на q35 (v0.6+: DMA-ремаппинг; IRQ-ремаппинг
# выключен — не реализован в драйверах; без устройств это безопасно).
IOMMU=${QEMU_IOMMU:-0}

EXTRA_ARGS=()
case "$IOMMU" in
  0|"") ;;
  1|intel)
    EXTRA_ARGS+=(-machine q35 -device intel-iommu,intremap=off) ;;
  amd)
    EXTRA_ARGS+=(-machine q35 -device amd-iommu) ;;
  *)
    echo "QEMU_IOMMU: ожидалось 0 | 1(intel) | amd, получено: $IOMMU" >&2
    exit 2 ;;
esac

# TCG single-thread: в этой сборке QEMU (10.0.13, MTTCG) доставка IPI
# остановленному (hlt) vCPU ненадёжна — resched-IPI терялся, AP не
# просыпался из парковки. Однопоточный TCG даёт корректную SMP-семантику
# (порядок событий эквивалентен реальному железу); на KVM/железе
# проблемы нет.
exec timeout -k 5 "$TIMEOUT" "$QEMU_USR/usr/bin/qemu-system-x86_64" \
  -accel tcg,thread=single \
  -L "$QEMU_USR/usr/share/seabios" \
  -m ${RAM}M \
  -cpu ${QEMU_CPU:-Cascadelake-Server} \
  -smp ${SMP} \
  "${EXTRA_ARGS[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WS/boot/OVMF_VARS.fd" \
  -drive format=raw,file="$WS/target/esp.img" \
  -serial stdio \
  -display none \
  -no-reboot \
  -net none \
  -no-fd-bootchk
