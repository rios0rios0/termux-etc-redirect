# Copilot Instructions

## Project Context

This is a C project that provides transparent `/etc/` path redirection for Termux on Android (aarch64). It enables statically linked Go CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) to resolve DNS and verify TLS certificates without proot.

## Build & Validate

```bash
make          # Build both targets
make test     # Run unit + integration tests
make clean    # Remove build artifacts
```

Compiler: `clang`. Build output: `build/`. No external dependencies beyond libc and Linux kernel headers.

## Architecture

Two tiers sharing a duplicated redirect table (`REDIRECT_TABLE`):

- **Tier 1** (`src/termux-etc-redirect.c` → `libtermux-etc-redirect.so`): `LD_PRELOAD` library intercepting libc functions (`open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat`) via `dlsym(RTLD_NEXT, ...)`. Dynamically linked binaries only.
- **Tier 2** (`src/termux-etc-seccomp.c` → `termux-etc-seccomp`): seccomp `user_notif` supervisor intercepting `openat` at kernel level via BPF. Works on all binaries including statically linked Go programs. Uses `fork` + `SCM_RIGHTS` fd passing + `SECCOMP_IOCTL_NOTIF_ADDFD` for fd injection.

## Key Constraints

- The redirect table is **duplicated** in both source files. Any path change must be applied to both.
- The BPF filter is **hardcoded for aarch64** (`AUDIT_ARCH_AARCH64`).
- **Fail-open design**: if the Termux destination doesn't exist, the original path is used unchanged.
- `$PREFIX` defaults to `/data/data/com.termux/files/usr`.
- Tier 1 uses raw `syscall(__NR_faccessat, ...)` to check file existence, avoiding infinite recursion through the intercepted `access()`.

## Testing

- `test/test-redirect.c`: Unit tests for Tier 1 — validates `fopen`, `open`, `access`, `stat` interception and that unrelated `/etc/` paths are not redirected.
- `make test` runs Tier 1 unit tests via `LD_PRELOAD` and a Tier 2 integration test via `termux-etc-seccomp cat /etc/resolv.conf`.

## Code Style

- C with `-O2 -Wall -Wextra -Werror -fPIC -D_GNU_SOURCE`.
- SPDX license headers (`Apache-2.0`) on all source files.
- Functions use `snake_case`. Macros use `UPPER_CASE`. Type aliases use `snake_case` with `_t` or descriptive suffix (e.g., `redirect_entry`, `open_fn`).
