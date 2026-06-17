/*
 * termux-etc-seccomp.c — seccomp + ptrace interceptor for Termux
 *
 * Uses two complementary mechanisms:
 *
 * 1. seccomp USER_NOTIF: Intercepts openat() syscalls and redirects
 *    reads of /etc/resolv.conf, /etc/hosts, /etc/nsswitch.conf, and
 *    SSL certificate paths to their Termux equivalents under $PREFIX/etc/.
 *
 * 2. ptrace SIGSYS suppression: Android's seccomp policy blocks certain
 *    syscalls (like faccessat2) with SECCOMP_RET_TRAP, sending SIGSYS.
 *    The kernel calls syscall_rollback() which restores x0 to the
 *    original first argument (NOT -ENOSYS). By ptracing the child,
 *    catching the SIGSYS stop, and explicitly setting x0 to -ENOSYS
 *    before resuming, the child falls back to an allowed syscall
 *    (e.g., faccessat). This is essential for Go binaries that use
 *    os/exec.LookPath.
 *
 * Works on ALL binaries, including statically linked Go programs
 * that bypass libc entirely.
 *
 * DESIGN — race-free ptrace model
 * ================================
 * Go's runtime spawns many OS threads (M's) via clone() in rapid succession,
 * and each thread immediately issues faccessat2 (syscall 439) via
 * os/exec.LookPath. Android's seccomp policy responds to faccessat2 with
 * SECCOMP_RET_TRAP, delivering SIGSYS to the calling thread.
 *
 * The previous design used PTRACE_SEIZE from the parent *after* fork(),
 * combined with a poll(notif_fd) + SIGCHLD event loop. This creates a
 * race window: new threads cloned between the fork() and PTRACE_SEIZE
 * are not yet traced. If such a thread hits faccessat2 before the parent
 * processes its PTRACE_EVENT_CLONE stop, the unhandled SIGSYS kills the
 * whole process.
 *
 * The fix uses the classical TRACEME+SIGSTOP approach:
 *
 *   Child: ptrace(PTRACE_TRACEME) → raise(SIGSTOP)          [before execvp]
 *   Parent: waitpid(child) for that stop                     [blocking]
 *           ptrace(PTRACE_SETOPTIONS, TRACECLONE|…)          [before exec]
 *           → ack child to continue → execvp runs
 *
 * Because PTRACE_O_TRACECLONE is set *before* execvp, every clone() the
 * Go runtime issues after exec is intercepted atomically — there is no
 * window between clone() and tracing.
 *
 * Two parent threads run concurrently after setup:
 *   TRACER thread: blocking waitpid(-1, __WALL) loop — handles SIGSYS,
 *                  CLONE/FORK events, and child exit. Must stay on the
 *                  same OS thread that called PTRACE_SETOPTIONS (Linux
 *                  ptrace requires all ptrace calls on one thread).
 *   NOTIF thread:  poll(notif_fd) loop — handles openat() USER_NOTIF
 *                  redirects. Runs concurrently with no ptrace calls.
 *
 * Why a pure seccomp SECCOMP_RET_ERRNO filter CANNOT work
 * ========================================================
 * Android's per-process seccomp policy uses SECCOMP_RET_TRAP for
 * faccessat2. BPF filter rules are composed with OR-priority semantics:
 * the *highest-priority* matching action wins. SECCOMP_RET_TRAP (0x00030000)
 * outranks SECCOMP_RET_ERRNO (0x00050000 — confusingly, lower numeric value
 * means higher priority). A user-installed SECCOMP_RET_ERRNO|ENOSYS rule for
 * faccessat2 is therefore silently overridden by Android's TRAP rule.
 * ptrace interception of the resulting SIGSYS is the only mechanism that
 * can intercept and redirect the signal after the kernel has already acted.
 *
 * Usage: termux-etc-seccomp <command> [args...]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__aarch64__)
#error "termux-etc-seccomp requires aarch64 (ARM64). Other architectures are not supported."
#endif

#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#define TERMUX_DEFAULT_PREFIX "/data/data/com.termux/files/usr"

/*
 * Env-var marker shared with Tier 3 (termux-etc-mount). Any termux-etc-*
 * supervisor sets this in its child's environment immediately before
 * execve. Nested invocations see it on startup and short-circuit to a
 * plain execvp, relying on the outer wrapper's already-installed filter.
 *
 * The contract is symmetric with src/termux-etc-mount.c — the two tiers
 * use the same env-var name so they compose in either order.
 */
#define TERMUX_ETC_WRAP_ENV "TERMUX_ETC_WRAP_ACTIVE"

/*
 * Redirect table: source path -> destination suffix (appended to $PREFIX).
 * The destination is relative to $PREFIX, so "/etc/hosts" means $PREFIX/etc/hosts.
 *
 * For SSL certs, Go looks in several hardcoded paths. We redirect them all
 * to Termux's cert bundle at $PREFIX/etc/tls/cert.pem.
 */
typedef struct {
    const char *src;   /* Path the program tries to open */
    const char *dest;  /* Path relative to $PREFIX to redirect to */
} redirect_entry;

static const redirect_entry REDIRECT_TABLE[] = {
    /* DNS/network configuration */
    { "/etc/resolv.conf",       "/etc/resolv.conf" },
    { "/etc/hosts",             "/etc/hosts" },
    { "/etc/nsswitch.conf",     "/etc/nsswitch.conf" },
    /* SSL CA certificates (Go's crypto/x509/root_linux.go paths) */
    { "/etc/ssl/certs/ca-certificates.crt", "/etc/tls/cert.pem" },
    { "/etc/pki/tls/certs/ca-bundle.crt",   "/etc/tls/cert.pem" },
    { "/etc/ssl/ca-bundle.pem",              "/etc/tls/cert.pem" },
    { "/etc/pki/tls/cacert.pem",             "/etc/tls/cert.pem" },
    { "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/tls/cert.pem" },
    { "/etc/ssl/cert.pem",                   "/etc/tls/cert.pem" },
    { NULL, NULL }
};

static char g_prefix[PATH_MAX];

/*
 * Read TracerPid from /proc/self/status. Returns -1 on failure, 0 if no
 * tracer is attached, otherwise the tracer's pid. A non-zero value means
 * we are already being traced — we cannot safely PTRACE_TRACEME in the
 * child (only one tracer per task), so the supervisor must short-circuit
 * to execvp and let the outer tracer handle SIGSYS.
 */
static long read_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long value = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            value = strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    return value;
}

static void build_prefix(void) {
    const char *p = getenv("PREFIX");
    if (!p || !*p) p = TERMUX_DEFAULT_PREFIX;
    size_t len = strlen(p);
    if (len >= sizeof(g_prefix)) {
        fprintf(stderr, "termux-etc-seccomp: PREFIX too long\n");
        exit(1);
    }
    memcpy(g_prefix, p, len + 1);
}

/*
 * Send a file descriptor over a Unix socket using SCM_RIGHTS.
 */
static int send_fd(int sock, int fd) {
    char buf[1] = {'F'};
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = sizeof(cmsg_buf.buf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    return (sendmsg(sock, &msg, 0) >= 0) ? 0 : -1;
}

/*
 * Receive a file descriptor over a Unix socket using SCM_RIGHTS.
 */
static int recv_fd(int sock) {
    char buf[1];
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = sizeof(cmsg_buf.buf),
    };

    if (recvmsg(sock, &msg, 0) < 0) return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
        return -1;

    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/*
 * Read a NUL-terminated string from another process's memory.
 */
static ssize_t read_proc_string(pid_t pid, unsigned long addr,
                                char *buf, size_t bufsz) {
    char proc_mem[64];
    snprintf(proc_mem, sizeof(proc_mem), "/proc/%d/mem", (int)pid);

    int fd = open(proc_mem, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = pread(fd, buf, bufsz - 1, (off_t)addr);
    close(fd);

    if (n <= 0) return -1;
    buf[n] = '\0';

    char *nul = memchr(buf, '\0', (size_t)n);
    return nul ? (nul - buf + 1) : -1;
}

/*
 * Check if `path` matches a redirectable file.
 * Returns fd to the Termux file, or -1 if no redirect needed.
 */
static int try_redirect(const char *path, int original_flags) {
    if (!path || path[0] != '/') return -1;

    for (int i = 0; REDIRECT_TABLE[i].src; i++) {
        if (strcmp(path, REDIRECT_TABLE[i].src) != 0) continue;

        char redir[PATH_MAX];
        int n = snprintf(redir, sizeof(redir), "%s%s",
                         g_prefix, REDIRECT_TABLE[i].dest);
        if (n < 0 || (size_t)n >= sizeof(redir)) return -1;

        if (access(redir, F_OK) != 0) return -1;

        int flags = original_flags & ~(O_CREAT | O_EXCL | O_TRUNC | O_WRONLY);
        if ((original_flags & O_ACCMODE) == O_WRONLY)
            flags = (flags & ~O_ACCMODE) | O_RDONLY;

        return open(redir, flags);
    }
    return -1;
}

/*
 * Install the seccomp-bpf filter that triggers USER_NOTIF on openat().
 */
static int install_seccomp_filter(void) {
    struct sock_filter filter[] = {
        /* Load architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        /* If not aarch64, allow */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 3),
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        /* If not openat, allow */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        /* USER_NOTIF */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        /* ALLOW */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

/*
 * Handle a single seccomp notification (openat redirect).
 */
static int handle_notification(int notif_fd) {
    struct seccomp_notif req;
    struct seccomp_notif_resp resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    resp.id = req.id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp.val = 0;
    resp.error = 0;

    unsigned long path_addr = req.data.args[1];
    int flags = (int)req.data.args[2];
    char path_buf[PATH_MAX];

    if (path_addr == 0) goto pass_through;

    ssize_t path_len = read_proc_string(req.pid, path_addr,
                                        path_buf, sizeof(path_buf));
    if (path_len <= 0) goto pass_through;

    int redir_fd = try_redirect(path_buf, flags);
    if (redir_fd < 0) goto pass_through;

    /* TOCTOU check */
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) < 0) {
        close(redir_fd);
        return 0;
    }

    /* Inject our fd into the child, replacing the openat() return value. */
    struct seccomp_notif_addfd addfd = {
        .id = req.id,
        .flags = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd = (unsigned int)redir_fd,
        .newfd = 0,
        .newfd_flags = 0,
    };

    int ret = ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    close(redir_fd);

    if (ret >= 0) return 0;
    if (errno == ENOENT) return 0;

pass_through:
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    return 0;
}

/*
 * Set the syscall return register (x0) to -ENOSYS for a stopped tracee.
 *
 * When SECCOMP_RET_TRAP fires, the kernel calls syscall_rollback()
 * which restores x0 to the original first syscall argument (e.g.,
 * AT_FDCWD = -100 for faccessat2). It does NOT set x0 to -ENOSYS.
 * We must explicitly set x0 so the child's runtime (e.g., Go's
 * exec.LookPath) sees -ENOSYS and falls back to allowed syscalls.
 */
static int set_return_enosys(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) {
        fprintf(stderr, "termux-etc-seccomp: PTRACE_GETREGSET failed for "
                "pid %d: %s\n", (int)pid, strerror(errno));
        return -1;
    }

    regs.regs[0] = (unsigned long long)(-ENOSYS);
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) {
        fprintf(stderr, "termux-etc-seccomp: PTRACE_SETREGSET failed for "
                "pid %d: %s\n", (int)pid, strerror(errno));
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * NOTIF thread: polls the seccomp notification fd and services openat()
 * redirects. Runs concurrently with the tracer loop on the main thread.
 * ----------------------------------------------------------------------- */

struct notif_thread_args {
    int notif_fd;
};

static void *notif_thread_func(void *arg) {
    struct notif_thread_args *a = (struct notif_thread_args *)arg;
    int notif_fd = a->notif_fd;
    free(a);

    while (1) {
        struct pollfd pfd = { .fd = notif_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, -1);

        if (ret < 0) {
            if (errno == EINTR) continue;
            /* EBADF / EINVAL: notif_fd was closed — child exited */
            break;
        }

        if (ret > 0) {
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
                break;
            if (pfd.revents & POLLIN) {
                int hn_ret = handle_notification(notif_fd);
                if (hn_ret < 0) {
                    fprintf(stderr, "termux-etc-seccomp: "
                            "handle_notification() failed\n");
                    break;
                }
            }
        }
    }

    return NULL;
}

/* -----------------------------------------------------------------------
 * TRACER loop (main thread): blocking waitpid(-1, __WALL).
 *
 * All ptrace calls MUST happen on the same OS thread that initially
 * called ptrace(PTRACE_SETOPTIONS, …). We lock this to the main thread
 * by never spawning a separate tracer thread — the main thread runs
 * this loop directly after launching the notif thread.
 * ----------------------------------------------------------------------- */

static void tracer_loop(pid_t main_child, int *exit_status_out) {
    int status;
    pid_t pid;
    int main_exited = 0;
    int exit_status = 0;

    while (!main_exited) {
        pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            perror("termux-etc-seccomp: waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == main_child) {
                main_exited = 1;
                exit_status = status;
            }
            /* Thread/subprocess exits: nothing to do, don't ptrace. */
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;

        if (event != 0) {
            /* ptrace event (CLONE, FORK, VFORK, EXEC, …): continue. */
            ptrace(PTRACE_CONT, pid, 0, 0);
        } else if (sig == SIGSYS) {
            /*
             * SIGSYS from Android's SECCOMP_RET_TRAP: rewrite x0 to
             * -ENOSYS and suppress the signal so Go's runtime falls back.
             */
            if (set_return_enosys(pid) != 0)
                fprintf(stderr, "termux-etc-seccomp: warning: "
                        "failed to set -ENOSYS for pid %d, "
                        "child may see wrong errno\n", (int)pid);
            ptrace(PTRACE_CONT, pid, 0, 0); /* suppress signal */
        } else if (sig == SIGSTOP || sig == SIGTRAP) {
            /*
             * Initial stop for newly traced threads/processes arriving
             * via PTRACE_O_TRACECLONE/TRACEFORK. Suppress and continue.
             */
            ptrace(PTRACE_CONT, pid, 0, 0);
        } else {
            /* Deliver other signals normally. */
            ptrace(PTRACE_CONT, pid, 0, sig);
        }
    }

    /* Reap any stray children. */
    while (waitpid(-1, NULL, WNOHANG | __WALL) > 0) {}

    *exit_status_out = exit_status;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <command> [args...]\n\n"
            "Intercepts openat() to redirect /etc/ paths to $PREFIX/etc/,\n"
            "and suppresses SIGSYS from Android's seccomp policy so that\n"
            "blocked syscalls (like faccessat2) return -ENOSYS gracefully.\n"
            "Works on all binaries, including statically linked Go programs.\n",
            argv0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /*
     * Reentrancy guard. Two conditions short-circuit to a plain execvp:
     *
     *   1. TERMUX_ETC_WRAP_ACTIVE is set — an outer termux-etc-* wrapper
     *      already installed a redirecting filter for this process tree.
     *      The kernel allows only one SECCOMP_FILTER_FLAG_NEW_LISTENER
     *      per task; a second install returns EBUSY. Inheriting the
     *      outer filter is sufficient to keep /etc/ redirects working.
     *
     *   2. A tracer is attached (TracerPid > 0). With TRACEME, the child
     *      would call ptrace(PTRACE_TRACEME) but the kernel rejects it if
     *      the parent is already traced (the grandparent's tracer would
     *      own the parent, and TRACEME attaches the child's parent as
     *      its tracer — only one tracer per task is permitted). Skip the
     *      supervisor and let the existing tracer handle SIGSYS.
     *
     * Deliberately NOT checking /proc/self/status:Seccomp — Termux's
     * Android zygote leaves every app process at Seccomp=2 from the
     * inherited system filter, so that field cannot distinguish "our
     * outer wrapper" from Android's always-on baseline.
     *
     * Run the guard BEFORE build_prefix() so the short-circuit path is
     * independent of PREFIX validation: a malformed/too-long PREFIX must
     * not block the pass-through exec when an outer wrapper is already
     * doing the redirect work for us.
     */
    if (getenv(TERMUX_ETC_WRAP_ENV) != NULL || read_tracer_pid() > 0) {
        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        return 127;
    }

    build_prefix();

    /* Unix socketpair for passing the seccomp notif fd via SCM_RIGHTS. */
    int sock_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) < 0) {
        perror("termux-etc-seccomp: socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("termux-etc-seccomp: fork");
        return 1;
    }

    if (child == 0) {
        /* --- Child --- */
        close(sock_fds[0]);

        /*
         * TRACEME + SIGSTOP before exec: registers this process as a
         * tracee of the parent, then stops to let the parent install
         * PTRACE_O_TRACECLONE before any Go thread is ever spawned.
         * This is the key to race-free clone() interception.
         */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            perror("termux-etc-seccomp: ptrace TRACEME");
            _exit(1);
        }
        raise(SIGSTOP);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("termux-etc-seccomp: prctl(NO_NEW_PRIVS)");
            _exit(1);
        }

        int notif_fd = install_seccomp_filter();
        if (notif_fd < 0) {
            perror("termux-etc-seccomp: seccomp install");
            _exit(1);
        }

        /* Send the notif fd to parent via SCM_RIGHTS. */
        if (send_fd(sock_fds[1], notif_fd) < 0) {
            perror("termux-etc-seccomp: send_fd");
            _exit(1);
        }

        /* Wait for parent to acknowledge receipt. */
        char ack;
        if (read(sock_fds[1], &ack, 1) <= 0) {
            _exit(1);
        }

        close(notif_fd);
        close(sock_fds[1]);

        /* Mark the subtree as already-wrapped so nested invocations of
         * termux-etc-seccomp / termux-etc-mount short-circuit. */
        setenv(TERMUX_ETC_WRAP_ENV, "1", 1);

        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    /* --- Parent (supervisor) --- */
    close(sock_fds[1]);

    /*
     * Wait for the child's initial SIGSTOP from PTRACE_TRACEME.
     * This is a blocking wait — we MUST receive this stop before
     * calling PTRACE_SETOPTIONS so that the options are installed
     * before the child proceeds to exec and spawns Go threads.
     */
    int init_status;
    if (waitpid(child, &init_status, 0) < 0) {
        perror("termux-etc-seccomp: waitpid (initial stop)");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        close(sock_fds[0]);
        return 1;
    }

    if (!WIFSTOPPED(init_status)) {
        fprintf(stderr, "termux-etc-seccomp: expected initial stop, "
                "got status 0x%x\n", init_status);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        close(sock_fds[0]);
        return 1;
    }

    /*
     * Install ptrace options BEFORE child continues.
     * TRACECLONE ensures every Go runtime thread is auto-traced the
     * instant it is cloned — no race window exists because SIGSTOP
     * is still pending and the child hasn't called execvp yet.
     */
    if (ptrace(PTRACE_SETOPTIONS, child, 0,
               (void *)(long)(PTRACE_O_TRACECLONE |
                              PTRACE_O_TRACEFORK |
                              PTRACE_O_TRACEVFORK)) != 0) {
        fprintf(stderr, "termux-etc-seccomp: PTRACE_SETOPTIONS failed: %s\n"
                "clone/fork tracing unavailable — SIGSYS suppression on newly "
                "cloned Go threads is not guaranteed\n", strerror(errno));
        /*
         * Non-fatal: the child is still traced via its own PTRACE_TRACEME, so
         * the main thread's SIGSYS stops are still caught. Only reliable
         * TRACECLONE/FORK/VFORK coverage of spawned threads/processes is lost.
         */
    }

    /* Release child from its initial SIGSTOP. */
    ptrace(PTRACE_CONT, child, 0, 0);

    /*
     * Receive the seccomp notif fd from the child.
     * The child is now running (after PTRACE_CONT) and will install the
     * seccomp filter, send us the fd, then wait for our ack.
     *
     * This recv is a plain blocking SCM_RIGHTS handshake: the child sends
     * the fd over the socket and then blocks on read() for our ack, so the
     * ordering is guaranteed by the socket itself, not by ptrace. We do NOT
     * enable PTRACE_O_TRACESECCOMP, and seccomp USER_NOTIF does not by itself
     * raise ptrace stops, so no PTRACE_EVENT_SECCOMP occurs here.
     */
    int notif_fd = recv_fd(sock_fds[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "termux-etc-seccomp: failed to receive notif fd\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        close(sock_fds[0]);
        return 1;
    }

    /*
     * Spawn the NOTIF thread BEFORE acknowledging the child.
     *
     * The child's first execvp() call opens the binary via openat(), which
     * triggers the USER_NOTIF filter immediately. If the notif thread is not
     * already polling when the child receives the ack and calls execvp(), the
     * kernel-queued notification has no consumer and the child blocks
     * indefinitely. Starting the thread before the ack eliminates this race.
     */
    struct notif_thread_args *nta = malloc(sizeof(*nta));
    if (!nta) {
        fprintf(stderr, "termux-etc-seccomp: malloc failed\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        close(notif_fd);
        return 1;
    }
    nta->notif_fd = notif_fd;

    pthread_t notif_tid;
    if (pthread_create(&notif_tid, NULL, notif_thread_func, nta) != 0) {
        perror("termux-etc-seccomp: pthread_create");
        free(nta);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        close(notif_fd);
        return 1;
    }
    pthread_detach(notif_tid);

    /* Acknowledge so child can proceed to execvp. */
    char ack = 'A';
    if (write(sock_fds[0], &ack, 1) < 0) {
        /* Best-effort; child will proceed anyway on socket close. */
    }
    close(sock_fds[0]);

    /*
     * TRACER LOOP (main thread, blocking waitpid).
     *
     * Handles all ptrace events:
     *   - SIGSYS: x0 set to -ENOSYS, signal suppressed
     *   - CLONE/FORK events: new thread/process, continue immediately
     *   - Other signals: delivered to the child
     *   - Child exit: loop terminates
     */
    int exit_status = 0;
    tracer_loop(child, &exit_status);

    /* Signal the notif thread to exit by closing notif_fd.
     * poll() will return POLLHUP/POLLERR and the thread will exit. */
    close(notif_fd);

    if (WIFEXITED(exit_status))
        return WEXITSTATUS(exit_status);
    if (WIFSIGNALED(exit_status)) {
        signal(WTERMSIG(exit_status), SIG_DFL);
        raise(WTERMSIG(exit_status));
    }
    return 1;
}
