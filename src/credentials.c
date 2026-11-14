/*
 * archbox-rootenv: in-process credential state for the fakechroot tier.
 *
 * Preloaded with LD_PRELOAD. Wraps the libc calls that change or report uid/gid/groups and
 * answers them from process-local state. Nothing here calls the kernel for these calls, so the
 * seccomp filter on Android (which blocks setgroups and setresgid, see docs/design.md) never sees
 * them.
 *
 * Model: the guest starts as root (uid 0, gid 0, no supplementary groups). A privileged process
 * (effective uid 0) may set any id. An unprivileged one may only pick among its current ids, like
 * the kernel does. The real kernel credentials are never changed.
 *
 * Limits (v1):
 *   - State is per process. fork() copies it; exec() does not carry it over yet.
 *   - Calls made inside libc without going through the PLT are not interposed. This must be
 *     checked on the target (glibc's initgroups() may be one of them).
 *   - File ownership is not handled here. That is faked's job.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#define CRED_MAX_GROUPS 64

static struct {
    int ready;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    int ngroups;
    gid_t groups[CRED_MAX_GROUPS];
} cred;

static void cred_init(void) {
    if (cred.ready) return;
    cred.ready = 1;
    /* fake root by default */
    cred.ruid = cred.euid = cred.suid = 0;
    cred.rgid = cred.egid = cred.sgid = 0;
    cred.ngroups = 0;
}

__attribute__((constructor)) static void cred_ctor(void) { cred_init(); }

static int privileged(void) { return cred.euid == 0; }

static int uid_allowed(uid_t v) {
    return v == cred.ruid || v == cred.euid || v == cred.suid;
}

static int gid_allowed(gid_t v) {
    return v == cred.rgid || v == cred.egid || v == cred.sgid;
}

/* ---- uid ---------------------------------------------------------------------------------- */

int setresuid(uid_t r, uid_t e, uid_t s) {
    cred_init();
    if (!privileged()) {
        if ((r != (uid_t)-1 && !uid_allowed(r)) || (e != (uid_t)-1 && !uid_allowed(e)) ||
            (s != (uid_t)-1 && !uid_allowed(s))) {
            errno = EPERM;
            return -1;
        }
    }
    if (r != (uid_t)-1) cred.ruid = r;
    if (e != (uid_t)-1) cred.euid = e;
    if (s != (uid_t)-1) cred.suid = s;
    return 0;
}

int setuid(uid_t u) {
    cred_init();
    if (privileged()) {
        cred.ruid = cred.euid = cred.suid = u;
        return 0;
    }
    if (u != cred.ruid && u != cred.suid) {
        errno = EPERM;
        return -1;
    }
    cred.euid = u;
    return 0;
}

int seteuid(uid_t e) {
    cred_init();
    if (!privileged() && !uid_allowed(e)) {
        errno = EPERM;
        return -1;
    }
    cred.euid = e;
    return 0;
}

int getresuid(uid_t *r, uid_t *e, uid_t *s) {
    cred_init();
    if (r) *r = cred.ruid;
    if (e) *e = cred.euid;
    if (s) *s = cred.suid;
    return 0;
}

uid_t getuid(void) { cred_init(); return cred.ruid; }
uid_t geteuid(void) { cred_init(); return cred.euid; }

/* ---- gid ---------------------------------------------------------------------------------- */

int setresgid(gid_t r, gid_t e, gid_t s) {
    cred_init();
    if (!privileged()) {
        if ((r != (gid_t)-1 && !gid_allowed(r)) || (e != (gid_t)-1 && !gid_allowed(e)) ||
            (s != (gid_t)-1 && !gid_allowed(s))) {
            errno = EPERM;
            return -1;
        }
    }
    if (r != (gid_t)-1) cred.rgid = r;
    if (e != (gid_t)-1) cred.egid = e;
    if (s != (gid_t)-1) cred.sgid = s;
    return 0;
}

int setgid(gid_t g) {
    cred_init();
    if (privileged()) {
        cred.rgid = cred.egid = cred.sgid = g;
        return 0;
    }
    if (g != cred.rgid && g != cred.sgid) {
        errno = EPERM;
        return -1;
    }
    cred.egid = g;
    return 0;
}

int setegid(gid_t e) {
    cred_init();
    if (!privileged() && !gid_allowed(e)) {
        errno = EPERM;
        return -1;
    }
    cred.egid = e;
    return 0;
}

int getresgid(gid_t *r, gid_t *e, gid_t *s) {
    cred_init();
    if (r) *r = cred.rgid;
    if (e) *e = cred.egid;
    if (s) *s = cred.sgid;
    return 0;
}

gid_t getgid(void) { cred_init(); return cred.rgid; }
gid_t getegid(void) { cred_init(); return cred.egid; }

/* ---- supplementary groups ----------------------------------------------------------------- */

int setgroups(size_t size, const gid_t *list) {
    cred_init();
    if (!privileged()) {
        errno = EPERM;
        return -1;
    }
    if (size > CRED_MAX_GROUPS) {
        errno = EINVAL;
        return -1;
    }
    if (size > 0 && !list) {
        errno = EFAULT;
        return -1;
    }
    for (size_t i = 0; i < size; i++) cred.groups[i] = list[i];
    cred.ngroups = (int)size;
    return 0;
}

int getgroups(int size, gid_t list[]) {
    cred_init();
    if (size == 0) return cred.ngroups;
    if (size < cred.ngroups) {
        errno = EINVAL;
        return -1;
    }
    for (int i = 0; i < cred.ngroups; i++) list[i] = cred.groups[i];
    return cred.ngroups;
}
