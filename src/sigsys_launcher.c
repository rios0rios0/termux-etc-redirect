/*
 * sigsys_launcher.c - Minimal ptrace-based SIGSYS suppressor for Go on Android
 *
 * Forks a child that calls PTRACE_TRACEME + raise(SIGSTOP) before exec, then
 * the parent installs PTRACE_O_TRACECLONE and suppresses SIGSYS by rewriting
 * x0 to -ENOSYS on the fly. Uses a BLOCKING waitpid loop instead of
 * poll()+SIGCHLD to avoid the race window.
 *
 * Usage: sigsys_launcher <binary> [args...]
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <linux/elf.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

static int set_return_enosys(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0)
        return -1;

    regs.regs[0] = (unsigned long long)(-(long long)ENOSYS);
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0)
        return -1;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }

    if (child == 0) {
        /* Child: mark as traceable, then exec */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            perror("ptrace TRACEME");
            _exit(1);
        }
        /* Cause initial stop so parent can set options */
        raise(SIGSTOP);
        /* Exec the target binary */
        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    /* Parent: wait for initial SIGSTOP from child */
    int status;
    pid_t w;
    do {
        w = waitpid(child, &status, 0);
    } while (w < 0 && errno == EINTR);
    if (w < 0) {
        perror("waitpid (initial stop)");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Expected stop, got status 0x%x\n", status);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    /* Set ptrace options: track all clones/forks */
    long opts = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, (void*)opts) != 0) {
        perror("ptrace SETOPTIONS");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    /* Release child to run */
    ptrace(PTRACE_CONT, child, 0, 0);

    /* Event loop: process all ptrace events */
    pid_t main_child = child;
    int exit_status = 0;
    int main_exited = 0;

    while (!main_exited) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == main_child) {
                main_exited = 1;
                exit_status = status;
            }
            /* Don't need to do anything for thread exits */
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;

        if (event != 0) {
            /* ptrace event (CLONE, FORK, EXEC, etc.): set options on new process and continue */
            if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK) {
                /* Get the new child's pid */
                unsigned long new_pid = 0;
                ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid);
                /* New child will be auto-stopped; we'll catch it via waitpid */
            }
            ptrace(PTRACE_CONT, pid, 0, 0);
        } else if (sig == SIGSYS) {
            /* SIGSYS from Android seccomp TRAP: rewrite x0 to -ENOSYS and suppress */
            if (set_return_enosys(pid) != 0) {
                fprintf(stderr, "Warning: failed to set -ENOSYS for pid %d\n", (int)pid);
            }
            ptrace(PTRACE_CONT, pid, 0, 0); /* suppress signal */
        } else if (sig == SIGSTOP || sig == SIGTRAP) {
            /* Initial stop from new thread/process; suppress and continue */
            ptrace(PTRACE_CONT, pid, 0, 0);
        } else {
            /* Deliver other signals normally */
            ptrace(PTRACE_CONT, pid, 0, sig);
        }
    }

    /* Collect remaining children */
    while (waitpid(-1, NULL, WNOHANG | __WALL) > 0) {}

    if (WIFEXITED(exit_status))
        return WEXITSTATUS(exit_status);
    if (WIFSIGNALED(exit_status)) {
        signal(WTERMSIG(exit_status), SIG_DFL);
        raise(WTERMSIG(exit_status));
    }
    return 1;
}
