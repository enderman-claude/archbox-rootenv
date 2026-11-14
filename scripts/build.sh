#!/bin/sh
# Build the fake-root credential layer for Archbox. Called by archbox-android's release workflow.
# Stub: there are no sources yet, so this exits non-zero on purpose and does not pretend to build.
set -eu

ARCH="${1:-aarch64}"
echo "archbox-rootenv: build.sh is a stub (arch=$ARCH). No sources in src/ yet." >&2
exit 2
