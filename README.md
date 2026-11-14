# archbox-rootenv

Fake-root credential layer for Archbox. It lets the fakechroot tier answer uid and gid calls
(`setuid`, `setgid`, `setgroups`, `setresgid`, `getgroups`, ...) inside the process, so that
`su`, `sudo`, and package installs that switch users keep working without real root.

Status: design only. No runtime code yet. See `docs/design.md`.

## Build

    scripts/build.sh aarch64

Produces the glibc objects that archbox-android bundles as `lib*.so` (see the archbox-android
release workflow). This repo has no CI of its own: the archbox-android build calls this script.

## Layout

- `docs/design.md`: what the layer must answer, and why
- `scripts/build.sh`: build entry point (stub)
- `src/`: C sources (empty for now)
