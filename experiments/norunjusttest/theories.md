# Theories (unverified)

## T1: Android's seccomp filter always wins over ours
- Claim: when the app process already has a filter that returns ERRNO/KILL for setgroups,
  setresgid, mount, chroot, kcmp, rseq, a later filter we install cannot turn that into ALLOW.
- Basis: the kernel applies the most restrictive verdict across stacked filters.
- Confirm: test_seccomp_precedence shows our ALLOW is ignored for a blocked syscall.
- Kill: our ALLOW is honored for a syscall Android blocks. Then notify-based emulation is viable.

## T2: USER_NOTIF is reachable for syscalls Android does not block
- Claim: getppid, openat, and similar calls can be routed to a supervisor without changing their
  result from Android's point of view.
- Confirm: notify round trip works from the app process for an allowed syscall.
- Kill: the notify filter itself is refused (EPERM/ENOSYS) on this kernel.

## T3: The supervisor round trip is too slow for every syscall
- Claim: at ~tens of microseconds per notify, routing all syscalls is unusable. Route only
  emulation-needing calls.
- Confirm: measured cost per call above ~20 us for a no-op getppid.
- Kill: cost is low enough that routing everything is fine. Unlikely, but measure.

## T4: The ownership registry can be built from the rootfs tarball
- Claim: every tar header carries uid, gid, and mode, so the registry is a direct read at install.
- Confirm: tar ownership matches `ls -ln` after extraction on a real rootfs.
- Kill: extraction changes owners (e.g. our copy fallback drops ownership). Check the copy path
  in Bootstrap.extract: copyFile does not preserve owner, so the registry must not trust the disk.

## T5: The loader can be read from the rootfs's own ELF PT_INTERP
- Claim: the loader path can be taken from the binary, so musl (Alpine) and glibc both work
  without hardcoding /usr/lib/ld-linux-aarch64.so.1.
- Confirm: test_loader_interp.sh returns the right path for an Arch, Alpine, and Debian /bin/sh.
- Kill: a rootfs whose /bin/sh has no PT_INTERP (static) breaks the assumption. Handle separately.

## T6: Raw syscall() and static binaries are the gap in the in-process shim
- Claim: libc-linked dynamic programs go through the shim; static binaries and direct `syscall`
  inline asm do not.
- Confirm: a static binary calling setgroups gets EPERM even with the shim preloaded.
- Kill: none expected. This is a known limit, so the question is how many packages ship static
  binaries that matter.

## T7: faked fails on the phone because of the same seccomp filter
- Claim: faked blocks on a syscall Android kills before it writes its key.
- Confirm: strace or the archbox-android probe shows the blocked syscall number.
- Kill: faked starts when run with the TCP flavour directly under the same loader.
