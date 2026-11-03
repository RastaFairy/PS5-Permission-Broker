#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS="$ROOT/.deps/PS5-Lapy-JB-Daemon"
mkdir -p "$ROOT/.deps" "$ROOT/extern"
if [[ ! -d "$DEPS/.git" ]]; then
  git clone --depth 1 https://github.com/ArkSama/PS5-Lapy-JB-Daemon.git "$DEPS"
else
  git -C "$DEPS" pull --ff-only
fi
if [[ ! -f "$DEPS/extern/libhijacker/libhijacker.a" ]]; then
  echo "The upstream checkout does not contain extern/libhijacker/libhijacker.a" >&2
  exit 1
fi
rm -rf "$ROOT/extern/libhijacker"
cp -a "$DEPS/extern/libhijacker" "$ROOT/extern/libhijacker"
echo "libhijacker dependency prepared in $ROOT/extern/libhijacker"
