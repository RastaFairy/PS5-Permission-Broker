#!/usr/bin/env bash
# One-shot WSL build for PS5 Permission Broker.
# Usage: bash wsl-build.sh   (inside WSL, with /mnt/e mounted)
set -Eeuo pipefail

WIN_PROJ=/mnt/e/PS5-Permission-Broker_FW550
PROJ=/root/permission-broker
export PS5_PAYLOAD_SDK=/root/ps5-sdk

mkdir -p /mnt/e
mountpoint -q /mnt/e || mount -t drvfs E: /mnt/e

cd "$PROJ"
cp "$WIN_PROJ/source/main.cpp" "$WIN_PROJ/source/offsets_v940.cpp" source/
echo "[1/4] sources synced"

make clean >/dev/null 2>&1 || true
echo "[2/4] building (jobs: $(nproc))"
set +e
make -j"$(nproc)" 2>&1 | tee /tmp/build.log | tail -30
STATUS=${PIPESTATUS[0]}
set -e
if [[ $STATUS -ne 0 ]]; then
  echo "BUILD_FAILED (make exit $STATUS)"
  exit 1
fi
[[ -s permission_broker.elf ]] || { echo "BUILD_FAILED (no ELF produced)"; exit 1; }
echo "[3/4] build ok"

python3 - permission_broker.elf <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as f:
    h = f.read(64)
assert h[:4] == b'\x7fELF', 'not an ELF'
assert h[4] == 2, 'not 64-bit'
endian = '<' if h[5] == 1 else '>'
e_type, machine = struct.unpack(endian + 'HH', h[16:20])
assert machine == 62, f'wrong arch {machine}'
print(f'ELF OK: 64-bit x86-64 e_type={e_type}')
PY

mkdir -p "$WIN_PROJ/dist"
cp -f permission_broker.elf "$WIN_PROJ/dist/permission_broker.elf"
sha256sum "$WIN_PROJ/dist/permission_broker.elf" | tee "$WIN_PROJ/dist/permission_broker.elf.sha256"
echo "[4/4] deployed to dist/ ($(stat -c%s permission_broker.elf) bytes)"
