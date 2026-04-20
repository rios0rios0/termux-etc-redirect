# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Transparent `/etc/` path redirection for Termux on Android. Enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) and dynamic musl binaries (Claude Code's `linux-arm64-musl` build) to resolve DNS and verify TLS certificates without proot. The project provides three complementary C programs that intercept file-access calls and rewrite hardcoded `/etc/` paths to their Termux `$PREFIX/etc/` equivalents.

## Build & Test Commands

```bash
make              # Build all three artifacts: libtermux-etc-redirect.so (Tier 1),
                  # termux-etc-seccomp (Tier 2), termux-etc-mount (Tier 3)
make test         # Run Tier 1 (LD_PRELOAD) unit tests, Tier 2 (seccomp + ptrace)
                  # integration + faccessat2 SIGSYS tests, and Tier 3
                  # (narrow seccomp) integration + reentrancy-guard tests
make install      # Install libtermux-etc-redirect.so to $PREFIX/lib/ and both
                  # termux-etc-seccomp + termux-etc-mount to $PREFIX/bin/
make clean        # Remove build/ directory
./scripts/install.sh  # Full build + install + create missing config files
```

The compiler is clang (`CC ?= clang`). Build artifacts go to `build/`.

## Architecture

The project has three tiers that share the same core redirect table but operate at different levels:

### Tier 1: `src/termux-etc-redirect.c` → `libtermux-etc-redirect.so`
An `LD_PRELOAD` shared library that intercepts libc functions (`open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat`) via `dlsym(RTLD_NEXT, ...)`. Works only for dynamically linked bionic/glibc binaries. Each intercepted function calls `redirect()` which checks the path against `REDIRECT_TABLE`, builds the Termux-prefixed path, verifies the target exists (via raw syscall to avoid recursion), and returns the rewritten path.

### Tier 2: `src/termux-etc-seccomp.c` → `termux-etc-seccomp`
A hybrid seccomp + ptrace supervisor. Uses two complementary mechanisms:
1. **seccomp `user_notif`**: Intercepts `openat` syscalls via BPF and redirects `/etc/` paths to `$PREFIX/etc/`.
2. **ptrace SIGSYS suppression**: Android's seccomp policy blocks certain syscalls (like `faccessat2`) with `SECCOMP_RET_TRAP`, sending SIGSYS. The kernel calls `syscall_rollback()` which restores x0 to the original first argument (e.g., `AT_FDCWD = -100`), NOT `-ENOSYS`. The ptrace handler catches the SIGSYS stop, explicitly sets x0 to `-ENOSYS` via `PTRACE_SETREGSET`, and suppresses the signal. This lets Go's runtime see `-ENOSYS` and fall back to allowed syscalls (e.g., `faccessat`).

The supervisor forks a child, the child installs the BPF filter and sends the notification fd to the parent via `SCM_RIGHTS` over a Unix socketpair. The parent `PTRACE_SEIZE`s the child with `TRACECLONE|TRACEFORK|TRACEVFORK` to auto-trace all threads and child processes. A `poll()`-based event loop handles both seccomp notifications (openat redirect) and ptrace events (SIGSYS suppression).

### Tier 3: `src/termux-etc-mount.c` → `termux-etc-mount`
A narrow seccomp supervisor tuned for dynamic musl binaries (Claude Code's `linux-arm64-musl` build, other Alpine-linked tools). Same BPF filter as Tier 2 (aarch64, `openat`-only) and the same SCM_RIGHTS fd-passing pattern, but:
- **No ptrace at all.** Avoids the "only one tracer per process" kernel rule, so Tier 3 composes cleanly with `strace`/`gdb`, and a Tier 3 child can spawn a Tier 2 subprocess without collision.
- **No SIGSYS rewriting.** musl/Node has no fallback for `statx` or `newfstatat` returning `-ENOSYS`; Tier 2's blanket rewrite surfaces as confusing `ENOSYS: lstat` errors in Claude. Tier 3 lets Android's global policy handle SIGSYS natively — Claude and similar workloads never trigger it during normal operation.
- **Reentrancy guard.** Before forking, the supervisor checks two signals: the `TERMUX_ETC_WRAP_ACTIVE` environment variable (exported by any outer `termux-etc-*` wrapper immediately before its `execve`) and `/proc/self/status:TracerPid`. If either is non-zero/present, it `execvp`s the target immediately. The proc `Seccomp:` field is deliberately **not** consulted — Termux's zygote leaves every app process at `Seccomp=2` from an inherited system filter, so that field cannot distinguish "our outer wrapper" from Android's always-on baseline. An inherited filter from an outer Tier 2 or Tier 3 is sufficient; stacking a second listener would only add latency and invite notification-routing bugs.

### Key design decisions
- **Fail-open**: if the Termux destination file doesn't exist, the original path passes through unchanged.
- **BPF filter is aarch64-only** (`AUDIT_ARCH_AARCH64` hardcoded in the filter).
- **Redirect table is duplicated** across Tier 1, Tier 2, and Tier 3 source files — any path change must be applied to all three: `src/termux-etc-redirect.c`, `src/termux-etc-seccomp.c`, `src/termux-etc-mount.c`. Tier 3's table is a superset (adds `/etc/services`).
- **`$PREFIX` defaults to `/data/data/com.termux/files/usr`** when the environment variable is not set.
- **Tier 2 traces all descendants**: `PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK` ensures SIGSYS is caught on Go runtime threads and spawned child processes (e.g., `terra` spawning `terragrunt`). Tier 3 deliberately omits this — it relies on inherited seccomp filters instead of tracer ancestry.

## Testing

- `test/test-redirect.c`: Unit tests for the LD_PRELOAD library. Tests `fopen`, `open`, `access`, `stat` interception and verifies unrelated paths are not redirected. Run via `LD_PRELOAD=build/libtermux-etc-redirect.so build/test-redirect`.
- `test/test-faccessat2.c`: Validates Tier 2's ptrace SIGSYS-to-ENOSYS rewrite for `faccessat2`. Run via `termux-etc-seccomp build/test-faccessat2`.
- `test/test-mount.c`: Integration test for Tier 3 — verifies `/etc/resolv.conf` redirect, inherited-filter presence, unrelated-path passthrough, and the reentrancy guard. Run via `termux-etc-mount build/test-mount`.
- `test/test-terraform/main.tf`: Manual integration test for Terraform TLS via `termux-etc-seccomp terraform init`.
- `make test` runs all three tiers' unit/integration tests plus a `termux-etc-seccomp cat /etc/resolv.conf` and `termux-etc-mount cat /etc/resolv.conf` smoke test.

## Target Platform

Termux on Android aarch64. Requires Linux kernel seccomp `user_notif` support (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_IOCTL_NOTIF_ADDFD`). No root required.
