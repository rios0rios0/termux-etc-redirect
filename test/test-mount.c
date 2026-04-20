/*
 * test-mount.c -- integration test for termux-etc-mount (Tier 3)
 *
 * Validates three invariants:
 *
 *   1. Under termux-etc-mount, opening /etc/resolv.conf succeeds and yields
 *      the Termux nameservers (same redirect semantics as Tier 1 / Tier 2).
 *   2. The reentrancy guard actually engages: the supervisor exports
 *      TERMUX_ETC_WRAP_ACTIVE=1 into the child's env, and a re-exec of the
 *      same wrapper around any trivial child must short-circuit to execvp
 *      instead of installing a second listener fd (which would double-
 *      service every openat and invite notification-routing bugs).
 *   3. Unrelated /etc/ paths are NOT redirected — /etc/passwd (which
 *      exists on Android) must still be readable with its original content.
 *
 * Run with: termux-etc-mount build/test-mount
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int test_resolv_conf_redirect(void) {
    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open(/etc/resolv.conf) failed: %s\n",
                strerror(errno));
        return 1;
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "FAIL: read(/etc/resolv.conf) returned %zd\n", n);
        return 1;
    }
    buf[n] = '\0';
    if (!strstr(buf, "nameserver")) {
        fprintf(stderr, "FAIL: /etc/resolv.conf has no 'nameserver' line\n");
        return 1;
    }
    printf("PASS: /etc/resolv.conf redirected (contains 'nameserver')\n");
    return 0;
}

static int test_wrap_env_var(void) {
    /* The Tier 3 supervisor exports TERMUX_ETC_WRAP_ACTIVE=1 into the child
     * env right before execve. If it's absent here, either we were not
     * launched under the supervisor or the guard wasn't wired up. */
    const char *v = getenv("TERMUX_ETC_WRAP_ACTIVE");
    if (!v || strcmp(v, "1") != 0) {
        fprintf(stderr, "FAIL: TERMUX_ETC_WRAP_ACTIVE missing or wrong (%s)\n",
                v ? v : "(null)");
        return 1;
    }
    printf("PASS: TERMUX_ETC_WRAP_ACTIVE=1 exported by supervisor\n");
    return 0;
}

static int test_unrelated_path_not_redirected(void) {
    /* /etc/passwd exists on Android and is NOT in the Tier 3 redirect table.
     * Verify we still get the Android file by comparing stat() of /etc/passwd
     * against /system/etc/passwd (the canonical location /etc aliases to on
     * modern Android). Equal inode+device means the kernel resolved /etc the
     * same way it always does — i.e. no redirect happened. Only treat
     * EACCES as a graceful skip; any other failure is a real test failure. */
    struct stat st1, st2;
    if (stat("/etc/passwd", &st1) < 0) {
        if (errno == EACCES) {
            printf("PASS: /etc/passwd unreadable (EACCES) — skipped\n");
            return 0;
        }
        fprintf(stderr, "FAIL: stat(/etc/passwd): %s\n", strerror(errno));
        return 1;
    }
    if (stat("/system/etc/passwd", &st2) < 0) {
        fprintf(stderr, "FAIL: stat(/system/etc/passwd): %s\n",
                strerror(errno));
        return 1;
    }
    if (st1.st_ino != st2.st_ino || st1.st_dev != st2.st_dev) {
        fprintf(stderr, "FAIL: /etc/passwd diverges from /system/etc/passwd "
                "(ino=%llu/%llu dev=%llu/%llu) — path was redirected\n",
                (unsigned long long)st1.st_ino,
                (unsigned long long)st2.st_ino,
                (unsigned long long)st1.st_dev,
                (unsigned long long)st2.st_dev);
        return 1;
    }
    printf("PASS: /etc/passwd matches /system/etc/passwd — not redirected\n");
    return 0;
}

static int test_reentrancy_guard(void) {
    /* Re-exec the same supervisor around `true`. If the guard is broken,
     * this either hangs (double listener) or fails with EPERM/EBUSY.
     *
     * The wrapper binary is resolved from /proc/<PPID>/exe so the test is
     * hermetic — it works against build/termux-etc-mount without requiring
     * `make install` or a specific PATH. The inner command is looked up via
     * PATH (execvp), which on Termux resolves `true` to $PREFIX/bin/true
     * regardless of how PREFIX was configured. */
    char wrapper[PATH_MAX];
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)getppid());
    ssize_t n = readlink(link, wrapper, sizeof(wrapper) - 1);
    if (n <= 0) {
        fprintf(stderr, "FAIL: readlink(%s): %s\n", link, strerror(errno));
        return 1;
    }
    wrapper[n] = '\0';

    pid_t pid = fork();
    if (pid < 0) {
        perror("FAIL: fork");
        return 1;
    }
    if (pid == 0) {
        char *argv[] = { wrapper, "true", NULL };
        execvp(argv[0], argv);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("FAIL: waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: nested termux-etc-mount exited abnormally "
                "(status=%d)\n", status);
        return 1;
    }
    printf("PASS: nested termux-etc-mount invocation short-circuits cleanly\n");
    return 0;
}

int main(void) {
    printf("--- termux-etc-mount (Tier 3) integration tests ---\n");
    int rc = 0;
    rc |= test_resolv_conf_redirect();
    rc |= test_wrap_env_var();
    rc |= test_unrelated_path_not_redirected();
    rc |= test_reentrancy_guard();
    if (rc == 0) printf("--- all tests passed ---\n");
    return rc;
}
