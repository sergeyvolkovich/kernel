#!/bin/bash
# Download qemu-system-x86, ovmf, mtools, dosfstools + all deps and extract
# into a user-space prefix (no root needed).
# Result: /home/z/my-project/tools/qemu-usr/{bin,share,...}
set -u
PREFIX=/home/z/my-project/tools/qemu-usr
DL=/home/z/my-project/tools/debs
mkdir -p "$PREFIX" "$DL"
cd "$DL" || exit 1

PACKAGES="qemu-system-x86 ovmf mtools dosfstools"

# Resolve the full transitive dep set (binary deps only, no recommends).
mapfile -t DEPS < <(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances \
  $PACKAGES 2>/dev/null | grep -E '^\w' | sort -u)

echo ">> $((${#DEPS[@]})) candidate packages"

downloaded=0
failed=0
for p in "${DEPS[@]}"; do
  # skip already downloaded
  ls "${p}"_*.deb >/dev/null 2>&1 && continue
  if ! out=$(apt-get download "$p" 2>&1); then
    failed=$((failed+1))
  else
    downloaded=$((downloaded+1))
  fi
done
echo ">> downloaded=$downloaded virtual/missing=$failed"

# Extract everything into the prefix.
count=0
for f in *.deb; do
  [ -e "$f" ] || continue
  dpkg-deb -x "$f" "$PREFIX" || echo "!! extract failed: $f"
  count=$((count+1))
done
echo ">> extracted $count debs into $PREFIX"

# Show the key binaries.
ls "$PREFIX/usr/bin/" 2>/dev/null | grep -E 'qemu|mtool|mkfs' | head -10
ls "$PREFIX/usr/share/OVMF/" 2>/dev/null | head -10
echo ">> done"
