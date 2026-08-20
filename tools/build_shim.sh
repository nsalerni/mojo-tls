#!/bin/bash
# Builds the libssl shim into build/libmojotls.{dylib,so}.
# Uses the C compiler and openssl from the pixi environment; idempotent
# (skips the compile when the source is older than the artifact).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/shim/mojotls_shim.c"
mkdir -p "$ROOT/build"

case "$(uname -s)" in
  Darwin) OUT="$ROOT/build/libmojotls.dylib" ;;
  *)      OUT="$ROOT/build/libmojotls.so" ;;
esac

if [ -f "$OUT" ] && [ "$OUT" -nt "$SRC" ]; then
  echo "shim up to date: $OUT"
  exit 0
fi

: "${CONDA_PREFIX:?run inside the pixi environment (pixi run ...)}"
CC_BIN="${CC:-cc}"

"$CC_BIN" -shared -fPIC -O2 -Wall -Werror \
  -I"$CONDA_PREFIX/include" \
  -L"$CONDA_PREFIX/lib" -lssl -lcrypto \
  -Wl,-rpath,"$CONDA_PREFIX/lib" \
  -o "$OUT" "$SRC"

echo "built $OUT"
