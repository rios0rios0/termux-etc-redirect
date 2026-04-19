/*
 * termux-etc-mount.c — narrow seccomp redirector for Termux (Tier 3)
 *
 * Intercepts openat() via seccomp user_notif and redirects a fixed set of
 * /etc/ paths to their Termux equivalents under $PREFIX/etc/. Unlike Tier 2
 * (termux-etc-seccomp), this supervisor does NOT ptrace the child and does
 * NOT rewrite SIGSYS to -ENOSYS. It is designed for dynamic musl binaries
 * (notably Claude Code's linux-arm64-musl build) whose libc issues DNS reads
 * through direct __syscall — invisible to LD_PRELOAD — and whose Node/V8
 * runtime tolerates no spurious ENOSYS.
 *
 * Tier 3 is also reentrancy-safe: if the process already has a seccomp
 * filter installed (e.g. this wrapper is itself wrapped by Tier 2 or another
 * Tier 3) or is already ptraced, the supervisor machinery is skipped and
 * the target is execve'd directly. The inherited filter keeps redirecting.
 *
 * Usage: termux-etc-mount <command> [args...]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__aarch64__)
#error "termux-etc-mount requires aarch64 (ARM64). Other architectures are not supported."
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define TERMUX_DEFAULT_PREFIX "/data/data/com.termux/files/usr"

/*
 * Redirect table: source path -> destination suffix (appended to $PREFIX).
 *
 * This is a superset of Tier 1 / Tier 2 — it adds paths that dynamic musl
 * binaries (Claude Code, and anything else linked against Alpine's musl)
 * open via direct __syscall, which LD_PRELOAD cannot intercept:
 *   - /etc/ssl/cert.pem       : Node's default CA bundle location
 *   - /etc/services           : musl's getservbyname() data file
 */
typedef struct {
    const char *src;   /* Path the program tries to open */
    const char *dest;  /* Path relative to $PREFIX to redirect to */
} redirect_entry;

static const redirect_entry REDIRECT_TABLE[] = {
    /* DNS / network configuration */
    { "/etc/resolv.conf",       "/etc/resolv.conf" },
    { "/etc/hosts",             "/etc/hosts" },
    { "/etc/nsswitch.conf",     "/etc/nsswitch.conf" },
    { "/etc/services",          "/etc/services" },
    /* SSL CA certificates (Go + Node hardcoded paths) */
    { "/etc/ssl/certs/ca-certificates.crt", "/etc/tls/cert.pem" },
    { "/etc/pki/tls/certs/ca-bundle.crt",   "/etc/tls/cert.pem" },
    { "/etc/ssl/ca-bundle.pem",              "/etc/tls/cert.pem" },
    { "/etc/pki/tls/cacert.pem",             "/etc/tls/cert.pem" },
    { "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/tls/cert.pem" },
    { "/etc/ssl/cert.pem",                   "/etc/tls/cert.pem" },
    { NULL, NULL }
};

static char g_prefix[PATH_MAX];

static void build_prefix(void) {
    const char *p = getenv("PREFIX");
    if (!p || !*p) p = TERMUX_DEFAULT_PREFIX;
    size_t len = strlen(p);
    if (len >= sizeof(g_prefix)) {
        fprintf(stderr, "termux-etc-mount: PREFIX too long\n");
        exit(1);
    }
    memcpy(g_prefix, p, len + 1);
}

/*
 * Read a single integer field from /proc/self/status. Returns -1 if the
 * field cannot be read; non-negative otherwise. Used to detect an inherited
 * seccomp filter or an attached tracer, either of which indicates that
 * Tier 3 should short-circuit to a direct exec.
 */
static long read_status_field(const char *name) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    size_t name_len = strlen(name);
    long value = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, name_len) == 0 && line[name_len] == ':') {
            value = strtol(line + name_len + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return value;
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
 * Identical to Tier 2 — aarch64-only, openat-only, everything else ALLOW.
 */
static int install_seccomp_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
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
 * Handle a single seccomp notification: redirect matching openat calls,
 * otherwise CONTINUE so the kernel executes the original syscall.
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

    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) < 0) {
        close(redir_fd);
        return 0;
    }

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

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s <command> [args...]\n\n"
        "Narrow seccomp redirector for /etc/ paths — no ptrace, no SIGSYS\n"
        "rewriting. Intended for dynamic musl binaries (Claude Code,\n"
        "Alpine-linked tools) whose libc bypasses LD_PRELOAD.\n\n"
        "If the process already has a seccomp filter or tracer attached,\n"
        "the command is exec'd directly without adding another layer.\n",
        argv0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    build_prefix();

    /*
     * Reentrancy guard. If we're already wrapped (by Tier 2, by another
     * Tier 3, or by any other seccomp-using launcher), the inherited
     * filter already services our openat redirects. Installing a second
     * listener fd would force every openat through two supervisors for
     * no gain and would invite subprocess-collision bugs. Similarly, if
     * a tracer is attached, we can't safely install our own fd-injection
     * machinery. Short-circuit to a plain execvp.
     */
    long seccomp_mode  = read_status_field("Seccomp");
    long tracer_pid    = read_status_field("TracerPid");
    if (seccomp_mode > 0 || tracer_pid > 0) {
        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        return 127;
    }

    int sock_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) < 0) {
        perror("termux-etc-mount: socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("termux-etc-mount: fork");
        return 1;
    }

    if (child == 0) {
        /* --- Child --- */
        close(sock_fds[0]);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("termux-etc-mount: prctl(NO_NEW_PRIVS)");
            _exit(1);
        }

        int notif_fd = install_seccomp_filter();
        if (notif_fd < 0) {
            perror("termux-etc-mount: seccomp install");
            _exit(1);
        }

        if (send_fd(sock_fds[1], notif_fd) < 0) {
            perror("termux-etc-mount: send_fd");
            _exit(1);
        }

        /* Wait for parent acknowledgement before exec. */
        char ack;
        if (read(sock_fds[1], &ack, 1) <= 0) {
            _exit(1);
        }

        close(notif_fd);
        close(sock_fds[1]);

        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    /* --- Parent (supervisor) --- */
    close(sock_fds[1]);

    int notif_fd = recv_fd(sock_fds[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "termux-etc-mount: failed to receive notif fd\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    char ack = 'A';
    (void)!write(sock_fds[0], &ack, 1);
    close(sock_fds[0]);

    /*
     * Main event loop.
     *
     * Unlike Tier 2 there is no ptrace — SIGCHLD is only used to notice
     * the child's exit. The loop is a plain poll() on both the notify fd
     * and a wait-for-child path via waitpid(..., WNOHANG). When the child
     * exits, the notify fd's POLLHUP/POLLERR wakes us up too, but we
     * reap it explicitly to pick up a clean exit status.
     */
    for (;;) {
        int status;
        pid_t w = waitpid(child, &status, WNOHANG);
        if (w == child) {
            close(notif_fd);
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) {
                signal(WTERMSIG(status), SIG_DFL);
                raise(WTERMSIG(status));
            }
            return 1;
        }

        struct pollfd pfd = { .fd = notif_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, -1);

        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == EBADF || errno == EINVAL) break;
            continue;
        }

        if (ret > 0) {
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                /* Child is gone — fall through to waitpid on next iter. */
                continue;
            }
            if (pfd.revents & POLLIN) {
                if (handle_notification(notif_fd) < 0) {
                    fprintf(stderr, "termux-etc-mount: handle_notification() "
                            "failed, exiting event loop\n");
                    break;
                }
            }
        }
    }

    close(notif_fd);
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        signal(WTERMSIG(status), SIG_DFL);
        raise(WTERMSIG(status));
    }
    return 1;
}
