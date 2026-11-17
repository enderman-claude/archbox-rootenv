# archbox-rootenv

Fake-root credential layer for Archbox. It lets the fakechroot tier answer uid and gid calls
(`setuid`, `setgid`, `setgroups`, `setresgid`, `getgroups`, ...) inside the process, so that
`su`, `sudo`, and package installs that switch users keep working without real root.

Status: early. `src/credentials.c` is a working in-process credential shim with host tests
(`scripts/build.sh host`). It is not yet bundled into archbox-android. See `docs/design.md`.

## Build

    scripts/build.sh aarch64

Builds `libfakeroot-credentials.so` (glibc aarch64 for the APK, or host for tests). Nothing calls
this script yet: archbox-android does not bundle the shim, and this repo has no CI of its own.

## Layout

- `docs/design.md`: what the layer must answer, and why
- `scripts/build.sh`: build entry point (stub)
- `src/`: C sources (`credentials.c`)
- `tests/`: host test harness (`test_credentials.c`)
