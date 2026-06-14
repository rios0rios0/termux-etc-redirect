/*
 * test-sigsys-threads.c -- multithreaded faccessat2 SIGSYS race test
 *
 * This is the regression test for the clone() race that motivates
 * sigsys_launcher (Tier 4). It mirrors what Go's runtime does: spawn
 * many threads in quick succession, each of which immediately issues a
 * faccessat2 syscall (exactly what os/exec.LookPath does on every PATH
 * entry). On Android, faccessat2 is blocked (SECCOMP_RET_TRAP -> SIGSYS),
 * so any thread whose SIGSYS is not intercepted by the supervisor kills
 * the whole process with "bad system call" (exit 128+31 = 159).
 *
 * Run DIRECTLY (no wrapper): every thread's faccessat2 traps -> the
 * process dies with SIGSYS. Run under `sigsys_launcher`: the supervisor's
 * blocking-waitpid loop handles each PTRACE_EVENT_CLONE stop the instant
 * it happens (before the new thread runs), then rewrites x0 to -ENOSYS on
 * every SIGSYS, so all threads observe ENOSYS and the process exits 0.
 *
 * A poll()+SIGCHLD supervisor (Tier 2) can lose this race: a freshly
 * cloned thread can run and hit faccessat2 before the supervisor drains
 * its clone stop, which is precisely why a dedicated TRACEME + blocking
 * waitpid launcher exists.
 *
 * Run with: sigsys_launcher build/test-sigsys-threads
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
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

#define NUM_THREADS 32
#define CALLS_PER_THREAD 8

static atomic_int g_fail = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < CALLS_PER_THREAD; i++) {
        /*
         * Direct faccessat2 syscall -- this is what triggers
         * SECCOMP_RET_TRAP -> SIGSYS on Android. If the supervisor is
         * race-free, x0 is rewritten to -ENOSYS and we return here; if a
         * thread slips through untraced, the whole process is SIGSYS-killed
         * and this return value is never observed.
         */
        long ret = syscall(__NR_faccessat2, AT_FDCWD, "/proc/self/exe", F_OK, 0);
        if (!(ret == 0 || (ret == -1 && errno == ENOSYS))) {
            atomic_store(&g_fail, 1);
        }
    }
    return NULL;
}

int main(void) {
    printf("--- multithreaded faccessat2 SIGSYS race test ---\n");
    printf("spawning %d threads x %d faccessat2 calls each\n",
           NUM_THREADS, CALLS_PER_THREAD);

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_create(%d): %s\n", i, strerror(errno));
            return 1;
        }
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    if (atomic_load(&g_fail)) {
        printf("FAIL: a faccessat2 call returned an unexpected result\n");
        return 1;
    }

    /* Reaching this line at all means no thread was SIGSYS-killed. */
    printf("PASS: all %d threads survived faccessat2 (SIGSYS suppressed "
           "race-free)\n", NUM_THREADS);
    return 0;
}
