# Copilot Instructions

## Project Context

This is a C project that provides transparent `/etc/` path redirection for Termux on Android (aarch64). It enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) and dynamic musl binaries (Claude Code's `linux-arm64-musl` build) to resolve DNS and verify TLS certificates without proot.

## Build & Validate

```bash
make          # Build all four artifacts: libtermux-etc-redirect.so, termux-etc-seccomp, termux-etc-mount, sigsys_launcher
make test     # Run Tier 1 unit tests, Tier 2 integration + faccessat2 SIGSYS + multithreaded clone-race + reentrancy tests, Tier 3 integration + reentrancy tests
make install  # Install .so to $PREFIX/lib/, the three binaries to $PREFIX/bin/
make clean    # Remove build/ directory
```

Compiler: `clang`. Build output: `build/`. No external dependencies beyond libc and Linux kernel headers.

## Architecture

Three tiers sharing a duplicated redirect table (`REDIRECT_TABLE`):

- **Tier 1** (`src/termux-etc-redirect.c` → `libtermux-etc-redirect.so`): `LD_PRELOAD` library intercepting libc functions (`open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat`) via `dlsym(RTLD_NEXT, ...)`. Dynamically linked bionic/glibc binaries only.
- **Tier 2** (`src/termux-etc-seccomp.c` → `termux-etc-seccomp`): Hybrid seccomp `user_notif` + ptrace supervisor. Intercepts `openat` at kernel level via BPF and rewrites `SIGSYS` from Android's `faccessat2` trap to `-ENOSYS` so Go's runtime falls back. Uses `fork` + `SCM_RIGHTS` fd passing + `SECCOMP_IOCTL_NOTIF_ADDFD`. **Race-free ptrace model (TRACEME + blocking `waitpid`):** the child calls `ptrace(PTRACE_TRACEME)` + `raise(SIGSTOP)` *before* `execvp`, so `PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK` is installed before any Go runtime thread is cloned; the parent's main thread runs a blocking `waitpid(-1, __WALL)` tracer loop (all ptrace ops on one OS thread) while a dedicated pthread runs `poll(notif_fd)` + handles `openat` redirects (linked with `-lpthread`). The notif thread is spawned before the ack is written to the child, so the child's first `execvp`-triggered `openat` always has a consumer. The old `PTRACE_SEIZE` + `poll(notif_fd)` + `SIGCHLD` design raced with Go's rapid `clone()` thread creation. Includes a reentrancy guard (`TERMUX_ETC_WRAP_ACTIVE` env var + `/proc/self/status:TracerPid`) that short-circuits to `execvp` when already wrapped; the guard runs before `build_prefix()` so the short-circuit is independent of `PREFIX` validation.
- **Tier 3** (`src/termux-etc-mount.c` → `termux-etc-mount`): Narrow seccomp `user_notif` supervisor for dynamic musl binaries. Same BPF filter as Tier 2 but no ptrace and no SIGSYS rewriting. Composes cleanly with `strace`/`gdb` and nested wrappers. Same reentrancy guard as Tier 2.
- **`sigsys_launcher`** (`src/sigsys_launcher.c`): Standalone SIGSYS-only ptrace supervisor using the same TRACEME + blocking-`waitpid` model, but with no seccomp filter and no `openat` redirect. Because it installs no `NEW_LISTENER` fd it is reentrancy-safe and composable, so `make test` uses it (not `termux-etc-seccomp` directly) to run the SIGSYS tests from any environment, including inside an already-wrapped shell.

## Key Constraints

- The redirect table is **duplicated** across all three source files. Any path change must be applied to all three. Tier 3's table is a superset (adds `/etc/services`).
- The BPF filter is **hardcoded for aarch64** (`AUDIT_ARCH_AARCH64`).
- **Fail-open design**: if the Termux destination doesn't exist, the original path is used unchanged.
- `$PREFIX` defaults to `/data/data/com.termux/files/usr`.
- Tier 1 uses raw `syscall(__NR_faccessat, ...)` to check file existence, avoiding infinite recursion through the intercepted `access()`.
- Nesting `termux-etc-*` wrappers (Tier 2 → Tier 2, Tier 3 → Tier 2, etc.) is handled by the reentrancy guard — the inner wrapper short-circuits to `execvp` and relies on the outer filter. Wrapping Tier 2 under a non-redirect tracer (e.g. `strace`) also triggers the guard, so no redirects happen; use Tier 3 when you need composable tracing.

## Testing

- `test/test-redirect.c`: Unit tests for Tier 1 — validates `fopen`, `open`, `access`, `stat` interception and unrelated-path passthrough.
- `test/test-faccessat2.c`: Validates Tier 2's ptrace SIGSYS-to-ENOSYS rewrite for a single-threaded `faccessat2`. Run via `sigsys_launcher` (not `termux-etc-seccomp`) so it works from any environment.
- `test/test-sigsys-threads.c`: Multithreaded regression test for the `clone()` race — 32 threads × 8 direct `faccessat2` syscalls, verifying no thread escapes the SIGSYS supervisor. Run via `sigsys_launcher`; the old `poll+SIGCHLD` design would exit 159 (SIGSYS kill).
- `test/test-seccomp-reentrancy.c`: Validates Tier 2's reentrancy guard — checks `TERMUX_ETC_WRAP_ACTIVE` export and nested invocation short-circuit.
- `test/test-mount.c`: Integration tests for Tier 3 — validates `/etc/resolv.conf` redirect, inherited-filter presence, unrelated-path passthrough, and reentrancy guard.
- `make test` runs all three tiers' tests plus smoke tests (`cat /etc/resolv.conf` under both Tier 2 and Tier 3). The SIGSYS tests run under `sigsys_launcher` so the full suite passes even from inside a wrapped shell.

## Code Style

- C with `-O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE`.
- SPDX license headers (`Apache-2.0`) on all source files.
- Functions use `snake_case`. Macros use `UPPER_CASE`. Type aliases use `snake_case` with descriptive suffix (e.g., `redirect_entry`, `open_fn`).
