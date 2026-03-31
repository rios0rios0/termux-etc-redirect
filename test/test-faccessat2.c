/*
 * test-faccessat2.c -- verify SIGSYS suppression for faccessat2
 *
 * On Android, faccessat2 is blocked by the system seccomp policy
 * (SECCOMP_RET_TRAP → SIGSYS). Without termux-etc-seccomp's ptrace
 * handler, the process would crash. With it, x0 is set to -ENOSYS
 * and the signal is suppressed, allowing Go's runtime to fall back
 * to faccessat.
 *
 * Run with: termux-etc-seccomp build/test-faccessat2
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

int main(void) {
    printf("--- faccessat2 SIGSYS suppression test ---\n");

    /*
     * Call faccessat2 directly via syscall(). On Android this triggers
     * SECCOMP_RET_TRAP → SIGSYS. The ptrace handler in termux-etc-seccomp
     * should catch the SIGSYS, set x0 = -ENOSYS, and suppress the signal.
     */
    long ret = syscall(__NR_faccessat2, AT_FDCWD, "/proc/self/exe", F_OK, 0);

    if (ret == 0) {
        /* Syscall succeeded (kernel allows faccessat2) -- still a pass */
        printf("PASS: faccessat2 succeeded (syscall allowed on this kernel)\n");
        return 0;
    }

    if (ret == -1 && errno == ENOSYS) {
        printf("PASS: faccessat2 returned -ENOSYS (SIGSYS properly suppressed)\n");
        return 0;
    }

    /* Any other result means the suppression is broken */
    printf("FAIL: faccessat2 returned %ld, errno=%d (%s), expected ENOSYS\n",
           ret, errno, strerror(errno));
    return 1;
}
