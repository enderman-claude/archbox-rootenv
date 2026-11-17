/* Run with: LD_PRELOAD=build/libfakeroot-credentials.so build/test_credentials
 * Exits non-zero on the first failure. Checks the shim's answers and that the kernel's real
 * credentials are never changed by the calls. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int failures = 0;

/* kernel's own view of the real/effective uid and gid (not interposed: plain file read) */
static void kernel_ids(uid_t *u, gid_t *g) {
    *u = (uid_t)-1; *g = (gid_t)-1;               /* -1 stays if /proc is unreadable: the check then fails */
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    while (f && fgets(line, sizeof line, f)) {
        unsigned ru, gg;
        if (sscanf(line, "Uid: %u", &ru) == 1) *u = ru;
        if (sscanf(line, "Gid: %u", &gg) == 1) *g = gg;
    }
    if (f) fclose(f);
}

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (cond) printf("ok   %s\n", msg);                               \
        else { printf("FAIL %s (errno=%d)\n", msg, errno); failures++; }  \
    } while (0)

int main(void) {
    uid_t kuid; gid_t kgid;
    kernel_ids(&kuid, &kgid);

    CHECK(getuid() == 0 && geteuid() == 0, "starts as fake root (uid 0)");
    CHECK(getgid() == 0 && getegid() == 0, "starts as fake root (gid 0)");
    CHECK(getgroups(0, NULL) == 0, "starts with no supplementary groups");

    gid_t want[2] = {5, 6};
    errno = 0;
    CHECK(setgroups(2, want) == 0, "setgroups as fake root succeeds");
    gid_t got[4] = {0};
    int n = getgroups(4, got);
    CHECK(n == 2 && got[0] == 5 && got[1] == 6, "getgroups reports the set list");

    errno = 0;
    CHECK(getgroups(1, got) == -1 && errno == EINVAL, "getgroups with too small a buffer fails");

    /* drop to an unprivileged identity, the way su/sudo do */
    errno = 0;
    CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid to 1000 as fake root succeeds");
    CHECK(getuid() == 1000 && geteuid() == 1000, "getuid/geteuid report 1000 after the change");
    uid_t r, e, s;
    CHECK(getresuid(&r, &e, &s) == 0 && r == 1000 && e == 1000 && s == 1000,
          "getresuid reports 1000 for all three ids");

    errno = 0;
    CHECK(setuid(0) == -1 && errno == EPERM, "unprivileged setuid(0) is refused");
    errno = 0;
    CHECK(setgroups(1, want) == -1 && errno == EPERM, "unprivileged setgroups is refused");
    errno = 0;
    CHECK(setresuid(0, 0, 0) == -1 && errno == EPERM, "unprivileged setresuid to 0 is refused");

    /* raw syscall() path: credential numbers are answered in-process too */
    errno = 0;
    CHECK(syscall(SYS_setgroups, 1, want) == -1 && errno == EPERM,
          "raw syscall(SYS_setgroups) is refused when unprivileged");
    CHECK(syscall(SYS_getuid) == 1000, "raw syscall(SYS_getuid) reports the fake uid");
    uid_t sr = 0, se = 0, ss = 0;
    CHECK(syscall(SYS_getresuid, &sr, &se, &ss) == 0 && sr == 1000 && se == 1000 && ss == 1000,
          "raw syscall(SYS_getresuid) reports the fake ids");
    gid_t sgr = 0, sge = 0, sgs = 0;
    CHECK(syscall(SYS_getresgid, &sgr, &sge, &sgs) == 0 && sgr == 0 && sge == 0 && sgs == 0,
          "raw syscall(SYS_getresgid) reports the fake gids");
    CHECK(syscall(SYS_getpid) == getpid(), "raw syscall(SYS_getpid) passes through to the kernel");

    /* the kernel's real ids must not have moved */
    uid_t ku; gid_t kg;
    kernel_ids(&ku, &kg);
    CHECK(ku == kuid, "kernel real uid unchanged by the shim");
    CHECK(kg == kgid, "kernel real gid unchanged by the shim");

    printf("%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
