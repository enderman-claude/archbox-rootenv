# norunjusttest

Scratch area. Nothing in here has been executed. Nothing is wired into the archbox repos.

Each theory is written so a test can prove or kill it on the test phone (Galaxy A55, kernel 6.1.157,
Android app context, targetSdk 28).

## Files

- `theories.md`: the claims being tested, and what result would confirm or kill each one.
- `test_seccomp_precedence.c`: installs a seccomp filter that allows a syscall, then a notify filter,
  and reports which verdict the kernel applies. Tests whether Android's filter always wins.
- `test_notify_supervisor.c`: minimal USER_NOTIF supervisor. Checks the round trip for one
  intercepted syscall (`getppid`) and the cost per call.
- `test_loader_interp.sh`: reads `PT_INTERP` from an ELF to find the loader for any rootfs,
  instead of hardcoding `/usr/lib/ld-linux-aarch64.so.1`.
- `test_tar_ownership.sh`: confirms that tar headers carry uid, gid, and mode per entry, and that
  a registry built from them matches `ls -ln` after extraction.

## Order (if ever run)

1. `test_seccomp_precedence` first. If Android's filter overrides a later ALLOW, the notify
   design is dead and the rest is moot.
2. `test_notify_supervisor` only if (1) passes.
3. The two shell tests are host-side and can run on any Linux machine.
