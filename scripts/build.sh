#!/bin/sh
# Build archbox-rootenv. Called by archbox-android's workflows.
#
#   scripts/build.sh aarch64   glibc aarch64 shared object for the APK (libfakeroot-credentials.so)
#   scripts/build.sh host      native build plus the test harness, for running tests here
#
# Environment: CC overrides the compiler; OUT overrides the output directory (default: build).
set -eu

cd "$(dirname "$0")/.."

ARCH="${1:-aarch64}"
OUT="${OUT:-build}"
mkdir -p "$OUT"

case "$ARCH" in
    aarch64) CC="${CC:-aarch64-linux-gnu-gcc}" ;;
    host)    CC="${CC:-cc}" ;;
    *) echo "build.sh: unknown arch '$ARCH' (use aarch64 or host)" >&2; exit 2 ;;
esac

FLAGS="-O2 -Wall -Wextra -Werror"

"$CC" $FLAGS -fPIC -shared -o "$OUT/libfakeroot-credentials.so" src/credentials.c
echo "built $OUT/libfakeroot-credentials.so ($ARCH)"

if [ "$ARCH" = host ]; then
    "$CC" $FLAGS -o "$OUT/test_credentials" tests/test_credentials.c
    LD_PRELOAD="$PWD/$OUT/libfakeroot-credentials.so" "$OUT/test_credentials"
fi
