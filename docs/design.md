# Design: fake-root credential layer

## Problem

On the fakechroot tier, the guest runs under Android's seccomp filter. Six syscalls are blocked
for the app process (measured on the Samsung Galaxy A55, kernel 6.1.157, beta 3 and beta 4):

| Syscall    | nr  | Why the guest needs it                         |
|------------|-----|------------------------------------------------|
| setgroups  | 159 | initgroups(), su, sudo, login                   |
| setresgid  | 149 | su, sudo, faked                                 |
| rseq       | 293 | glibc thread registration (tunable set to 0)    |
| mount      | 40  | not needed in a shell                           |
| chroot     | 51  | not needed in a shell                           |
| kcmp       | 272 | not needed in a shell                           |

The app also cannot call setuid to another user, because it has one real uid. faked is
supposed to fake those calls, but it does not start on the test device (no key returned).

## Goal

Answer credential calls in-process, so that the guest believes it switched users, and keep the
fake uid/gid state and file ownership in faked. Nothing reaches the kernel for these calls.

## Plan

1. Get faked's exit status and the syscall it dies on (archbox-android, next release).
2. Preload a shim (`libfakeroot-credentials.so`) that wraps setuid, setgid, setgroups,
   setresuid, setresgid, getgroups, getuid, geteuid, getgid, getegid.
3. The shim asks faked for state over the existing TCP protocol. If faked is down, the shim
   keeps state in process memory and stays consistent for the life of the process.
4. Measure again with the archbox-android probe. The target is zero blocked calls among the
   ones the shim answers.

## Not in scope

- Real privilege separation. Files are owned by the app uid at the kernel level.
- Network namespaces (no CAP_NET_ADMIN on the host).
- Any change to PRoot or the namespace tier.

## Open questions

- Whether glibc 2.43 honors `glibc.pthread.rseq=0`. The probe says rseq is blocked, but the
  tunable is set on every tier, and PRoot runs with the same setting.
- Whether faked itself calls a blocked syscall before it writes its key.
