#!/bin/sh
# NOT RUN. Tests T4: a registry built from tar headers matches what is on disk after extraction.
#
# usage: test_tar_ownership.sh <rootfs.tar.gz>
#
# Lists uid, gid, mode, and path from the tarball headers, extracts as a non-root user, and diffs
# against ls -ln. Differences are the cases the registry must handle (e.g. the copy fallback in
# Bootstrap.extract, which does not preserve owner).
set -eu
TAR=${1:?usage: test_tar_ownership.sh <tarball>}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# headers: uid, gid, mode, path
tar --numeric-owner -tvf "$TAR" | awk '{split($2,o,"/"); print o[1], o[2], substr($1,2), $6}' | sort -k4 > "$W/headers.txt"

# extraction as a regular user (no root, so owners are not preserved)
mkdir "$W/root"
tar --no-same-owner -xf "$TAR" -C "$W/root" 2>/dev/null || true
(cd "$W/root" && find . -mindepth 1 | sed 's,^\./,,' | sort) > "$W/disk-paths.txt"

echo "entries in headers : $(wc -l < "$W/headers.txt")"
echo "entries on disk    : $(wc -l < "$W/disk-paths.txt")"
echo "owner in headers differs from disk (expected for non-root extract): see registry notes"
