# Copilot Instructions

## Project Context

This is a C project that provides transparent `/etc/` path redirection for Termux on Android (aarch64). It enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) and dynamic musl binaries (Claude Code's `linux-arm64-musl` build) to resolve DNS and verify TLS certificates without proot.

## Build & Validate

```bash
make          # Build all three artifacts: libtermux-etc-redirect.so, termux-etc-seccomp, termux-etc-mount
make test     # Run Tier 1 unit tests, Tier 2 integration + faccessat2 SIGSYS tests, Tier 3 integration + reentrancy tests
make install  # Install .so to $PREFIX/lib/, both binaries to $PREFIX/bin/
make clean    # Remove build/ directory
```

Compiler: `clang`. Build output: `build/`. No external dependencies beyond libc and Linux kernel headers.

## Architecture

Three tiers sharing a duplicated redirect table (`REDIRECT_TABLE`):

- **Tier 1** (`src/termux-etc-redirect.c` → `libtermux-etc-redirect.so`): `LD_PRELOAD` library intercepting libc functions (`open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat`) via `dlsym(RTLD_NEXT, ...)`. Dynamically linked bionic/glibc binaries only.
- **Tier 2** (`src/termux-etc-seccomp.c` → `termux-etc-seccomp`): Hybrid seccomp `user_notif` + ptrace supervisor. Intercepts `openat` at kernel level via BPF and rewrites `SIGSYS` from Android's `faccessat2` trap to `-ENOSYS` so Go's runtime falls back. Uses `fork` + `SCM_RIGHTS` fd passing + `SECCOMP_IOCTL_NOTIF_ADDFD`. Traces all descendants via `PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK`.
- **Tier 3** (`src/termux-etc-mount.c` → `termux-etc-mount`): Narrow seccomp `user_notif` supervisor for dynamic musl binaries. Same BPF filter as Tier 2 but no ptrace and no SIGSYS rewriting. Composes cleanly with `strace`/`gdb` and nested wrappers. Includes a reentrancy guard (`TERMUX_ETC_WRAP_ACTIVE` env var + `/proc/self/status:TracerPid`) that short-circuits to `execvp` when already wrapped.

## Key Constraints

- The redirect table is **duplicated** across all three source files. Any path change must be applied to all three. Tier 3's table is a superset (adds `/etc/services`).
- The BPF filter is **hardcoded for aarch64** (`AUDIT_ARCH_AARCH64`).
- **Fail-open design**: if the Termux destination doesn't exist, the original path is used unchanged.
- `$PREFIX` defaults to `/data/data/com.termux/files/usr`.
- Tier 1 uses raw `syscall(__NR_faccessat, ...)` to check file existence, avoiding infinite recursion through the intercepted `access()`.
- Do not wrap Tier 2 inside another tracer or nest Tier 2 inside Tier 2 — ptrace ancestry collides. Use Tier 3 for composable wrapping.

## Testing

- `test/test-redirect.c`: Unit tests for Tier 1 — validates `fopen`, `open`, `access`, `stat` interception and unrelated-path passthrough.
- `test/test-faccessat2.c`: Validates Tier 2's ptrace SIGSYS-to-ENOSYS rewrite for `faccessat2`.
- `test/test-mount.c`: Integration tests for Tier 3 — validates `/etc/resolv.conf` redirect, inherited-filter presence, unrelated-path passthrough, and reentrancy guard.
- `make test` runs all three tiers' tests plus smoke tests (`cat /etc/resolv.conf` under both Tier 2 and Tier 3).

## Code Style

- C with `-O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE`.
- SPDX license headers (`Apache-2.0`) on all source files.
- Functions use `snake_case`. Macros use `UPPER_CASE`. Type aliases use `snake_case` with descriptive suffix (e.g., `redirect_entry`, `open_fn`).
