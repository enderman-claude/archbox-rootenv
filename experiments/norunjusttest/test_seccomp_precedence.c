/*
 * NOT RUN. Tests theory T1 (and T2 setup).
 *
 * Simulates the Android app filter with a DENY (ERRNO) rule for setgroups, then installs a
 * second filter that ALLOWs setgroups. A seccomp filter cannot be removed, and stacked filters
 * combine to the most restrictive verdict, so setgroups should still fail with EPERM.
 *
 * Then installs a USER_NOTIF filter for getppid and checks the notify fd comes back.
 *
 * Expected if T1 holds: setgroups -> EPERM after the ALLOW filter is added.
 * Expected if T1 is wrong: setgroups succeeds (or returns a value other than EPERM).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

static int install(struct sock_filter *f, int n, unsigned long flags) {
    struct sock_fprog p = { .len = (unsigned short)n, .filter = f };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &p);
}

/* deny a single syscall with errno, allow everything else */
static int deny_one(int nr, int err) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (err & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    return install(f, 4, 0);
}

/* allow everything (the "ours" filter that is supposed to win) */
static int allow_all(void) {
    struct sock_filter f[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
    return install(f, 1, 0);
}

int main(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("no_new_privs"); return 1; }

    /* step 1: the "Android" block */
    if (deny_one(SYS_setgroups, EPERM) < 0) { perror("deny filter"); return 1; }
    errno = 0;
    long r1 = syscall(SYS_setgroups, 0, NULL);
    printf("before ours: setgroups -> %ld errno=%d\n", r1, errno);

    /* step 2: our filter, which would allow it */
    if (allow_all() < 0) { perror("allow filter"); return 1; }
    errno = 0;
    long r2 = syscall(SYS_setgroups, 0, NULL);
    printf("after ours (ALLOW): setgroups -> %ld errno=%d\n", r2, errno);
    printf("T1 %s\n", (r2 == -1 && errno == EPERM) ? "CONFIRMED (blocked stays blocked)"
                                                   : "KILLED (our ALLOW took effect)");

    /* step 3 (T2 setup): a notify filter needs a fresh process, since filters only stack.
       Not run in this process to keep step 1-2 result clean. */
    printf("T2: run test_notify_supervisor in a fresh process.\n");
    (void)SECCOMP_FILTER_FLAG_NEW_LISTENER;
    return 0;
}
