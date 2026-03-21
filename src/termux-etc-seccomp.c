/*
 * termux-etc-seccomp.c — seccomp user_notif interceptor for Termux
 *
 * Intercepts openat() syscalls at kernel level using seccomp
 * SECCOMP_RET_USER_NOTIF and redirects reads of
 *   /etc/resolv.conf, /etc/hosts, /etc/nsswitch.conf
 * to their Termux equivalents under $PREFIX/etc/.
 *
 * Works on ALL binaries, including statically linked Go programs
 * that bypass libc entirely.
 *
 * Usage: termux-etc-seccomp <command> [args...]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
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
#include <sys/wait.h>
#include <unistd.h>

#define TERMUX_DEFAULT_PREFIX "/data/data/com.termux/files/usr"

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
 * Handle a single seccomp notification.
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

static volatile sig_atomic_t g_child_exited = 0;

static void sigchld_handler(int sig) {
    (void)sig;
    g_child_exited = 1;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <command> [args...]\n\n"
            "Intercepts openat() syscalls and redirects /etc/resolv.conf,\n"
            "/etc/hosts, /etc/nsswitch.conf to $PREFIX/etc/ equivalents.\n"
            "Works on all binaries, including statically linked Go programs.\n",
            argv0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    build_prefix();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

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

        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    /* --- Parent (supervisor) --- */
    close(sock_fds[1]);

    int notif_fd = recv_fd(sock_fds[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "termux-etc-seccomp: failed to receive notif fd\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    /* Acknowledge so child can proceed to exec. */
    char ack = 'A';
    if (write(sock_fds[0], &ack, 1) < 0) {
        /* Best-effort; child will proceed anyway on socket close. */
    }
    close(sock_fds[0]);

    /* Notification loop.
     * SIGCHLD will interrupt the blocking ioctl with EINTR,
     * allowing us to check g_child_exited and exit cleanly. */
    while (!g_child_exited) {
        int ret = handle_notification(notif_fd);
        if (ret < 0) {
            if (errno == EINTR) continue; /* Interrupted by signal */
            if (errno == EBADF || errno == EINVAL) break;
            continue;
        }
    }

    close(notif_fd);
    int status = 0;
    waitpid(child, &status, 0);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        signal(WTERMSIG(status), SIG_DFL);
        raise(WTERMSIG(status));
    }
    return 1;
}
