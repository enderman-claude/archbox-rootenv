#!/bin/sh
# NOT RUN. Tests T5: the loader path can be read from the binary, not hardcoded.
#
# usage: test_loader_interp.sh <rootfs-dir>
#
# For each candidate binary, print its PT_INTERP (the program interpreter), or "static" if none.
# Expected: glibc rootfs -> /lib/ld-linux-aarch64.so.1 (or /usr/lib/...); musl rootfs (Alpine)
# -> /lib/ld-musl-aarch64.so.1; a static binary -> no interpreter.
set -eu
ROOT=${1:?usage: test_loader_interp.sh <rootfs>}

for bin in /bin/sh /bin/bash /usr/bin/bash /bin/busybox; do
    f="$ROOT$bin"
    [ -e "$f" ] || continue
    interp=$(readelf -l "$f" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p')
    if [ -n "$interp" ]; then
        echo "$bin -> $interp"
    else
        echo "$bin -> static (no PT_INTERP)"
    fi
done
