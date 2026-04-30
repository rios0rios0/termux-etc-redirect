/*
 * test-seccomp-reentrancy.c -- reentrancy-guard test for termux-etc-seccomp (Tier 2)
 *
 * Validates two invariants of the Tier 2 reentrancy guard introduced to let
 * Tier 2 compose inside an outer wrapper (Tier 2 or Tier 3) without colliding
 * on `SECCOMP_FILTER_FLAG_NEW_LISTENER` (which would return EBUSY) or on
 * `PTRACE_SEIZE` (which fails when a tracer is already attached):
 *
 *   1. The Tier 2 supervisor exports TERMUX_ETC_WRAP_ACTIVE=1 into the child
 *      env right before execve. If it's absent here, the guard isn't wired up.
 *   2. A nested `termux-etc-seccomp termux-etc-seccomp <cmd>` invocation
 *      short-circuits cleanly to execvp. If the guard is broken, this either
 *      hangs (double listener) or fails with EBUSY/EPERM.
 *
 * Run with: termux-etc-seccomp build/test-seccomp-reentrancy
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int test_wrap_env_var(void) {
    const char *v = getenv("TERMUX_ETC_WRAP_ACTIVE");
    if (!v || strcmp(v, "1") != 0) {
        fprintf(stderr, "FAIL: TERMUX_ETC_WRAP_ACTIVE missing or wrong (%s)\n",
                v ? v : "(null)");
        return 1;
    }
    printf("PASS: TERMUX_ETC_WRAP_ACTIVE=1 exported by supervisor\n");
    return 0;
}

static int test_reentrancy_guard(void) {
    /* Re-exec the same supervisor around `true`. The wrapper binary is
     * resolved from /proc/<PPID>/exe so the test is hermetic — it works
     * against build/termux-etc-seccomp without requiring `make install`
     * or a specific PATH. The inner command is looked up via PATH (execvp),
     * which on Termux resolves `true` to $PREFIX/bin/true. */
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
        fprintf(stderr, "FAIL: nested termux-etc-seccomp exited abnormally "
                "(status=%d)\n", status);
        return 1;
    }
    printf("PASS: nested termux-etc-seccomp invocation short-circuits cleanly\n");
    return 0;
}

int main(void) {
    printf("--- termux-etc-seccomp (Tier 2) reentrancy-guard tests ---\n");
    int rc = 0;
    rc |= test_wrap_env_var();
    rc |= test_reentrancy_guard();
    if (rc == 0) printf("--- all tests passed ---\n");
    return rc;
}
