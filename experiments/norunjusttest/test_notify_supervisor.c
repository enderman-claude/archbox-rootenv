/*
 * NOT RUN. Tests T2 (notify reachable) and T3 (per-call cost).
 *
 * Installs a filter with SECCOMP_FILTER_FLAG_NEW_LISTENER that routes getppid to a supervisor
 * (the parent process). The child calls getppid N times; the parent answers each notification
 * with a fixed value. Reports round-trip time per call.
 *
 * Expected if T2 holds: the child gets the fake value 4242 back on every call.
 * Expected if T3 is a problem: per-call time above ~20 us.
 *
 * Only the notified syscall is routed; everything else is ALLOW.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#define N 10000

static int notify_fd_from_filter(void) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { .len = 4, .filter = f };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
}

static double now_us(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

int main(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("no_new_privs"); return 1; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

    pid_t child = fork();
    if (child == 0) {
        int lfd = notify_fd_from_filter();
        if (lfd < 0) { perror("notify filter"); _exit(10); }
        /* hand the listener fd to the parent */
        struct msghdr m = {0}; char buf[CMSG_SPACE(sizeof(int))] = {0}; char d = 'x';
        struct iovec iv = { &d, 1 };
        m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = buf; m.msg_controllen = sizeof buf;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &lfd, sizeof(int));
        sendmsg(sv[1], &m, 0);
        for (int i = 0; i < N; i++) {
            long r = syscall(SYS_getppid);
            if (r != 4242) { fprintf(stderr, "child: getppid -> %ld\n", r); _exit(2); }
        }
        _exit(0);
    }

    /* parent: receive the listener fd */
    struct msghdr m = {0}; char buf[CMSG_SPACE(sizeof(int))] = {0}; char d;
    struct iovec iv = { &d, 1 };
    m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = buf; m.msg_controllen = sizeof buf;
    if (recvmsg(sv[0], &m, 0) < 0) { perror("recvmsg"); return 1; }
    int lfd; memcpy(&lfd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof lfd);

    struct seccomp_notif req; struct seccomp_notif_resp resp;
    double t0 = now_us();
    int served = 0;
    while (served < N) {
        memset(&req, 0, sizeof req);
        if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) break;
        memset(&resp, 0, sizeof resp);
        resp.id = req.id; resp.val = 4242; resp.flags = 0; /* spoof the return value */
        if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) break;
        served++;
    }
    double dt = now_us() - t0;
    int st; waitpid(child, &st, 0);
    printf("served %d/%d, %.2f us per call, child exit %d\n",
           served, N, dt / (served ? served : 1), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    printf("T2 %s, T3 %s\n", (served == N && WIFEXITED(st) && WEXITSTATUS(st) == 0) ? "CONFIRMED" : "KILLED",
           (dt / (served ? served : 1)) < 20 ? "not a blocker" : "a blocker (route only what needs it)");
    return 0;
}
