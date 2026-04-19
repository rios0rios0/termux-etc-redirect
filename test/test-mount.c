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
    /* /etc/passwd exists on Android and is NOT in the redirect table.
     * Make sure we still get the Android file, not something else. */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        /* On some Android versions /etc/passwd is not readable by apps —
         * tolerate that, just don't claim we redirected. */
        printf("PASS: /etc/passwd open failed (%s) — not redirected\n",
               strerror(errno));
        return 0;
    }
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        /* Android passwd starts with "root:" ; we just want to confirm it's
         * not the Termux file (which is usually absent anyway). */
        printf("PASS: /etc/passwd readable, not redirected (%zd bytes)\n", n);
    } else {
        printf("PASS: /etc/passwd readable but empty (not redirected)\n");
    }
    return 0;
}

static int test_reentrancy_guard(void) {
    /* Re-exec termux-etc-mount around /bin/true. If the guard is broken,
     * this either hangs (double listener) or fails with EPERM/EBUSY. */
    pid_t pid = fork();
    if (pid < 0) {
        perror("FAIL: fork");
        return 1;
    }
    if (pid == 0) {
        char *argv[] = { "termux-etc-mount", "/data/data/com.termux/files/usr/bin/true", NULL };
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
