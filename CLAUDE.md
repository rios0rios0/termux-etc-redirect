# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Transparent `/etc/` path redirection for Termux on Android. Enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) to resolve DNS and verify TLS certificates without proot. The project provides two complementary C programs that intercept file-access calls and rewrite hardcoded `/etc/` paths to their Termux `$PREFIX/etc/` equivalents.

## Build & Test Commands

```bash
make              # Build both the shared library and the seccomp binary
make test         # Run Tier 1 (LD_PRELOAD) unit tests + Tier 2 (seccomp) integration test
make install      # Install library to $PREFIX/lib/ and binary to $PREFIX/bin/
make clean        # Remove build/ directory
./scripts/install.sh  # Full build + install + create missing config files
```

The compiler is clang (`CC ?= clang`). Build artifacts go to `build/`.

## Architecture

The project has two tiers that share the same redirect table but operate at different levels:

### Tier 1: `src/termux-etc-redirect.c` → `libtermux-etc-redirect.so`
An `LD_PRELOAD` shared library that intercepts libc functions (`open`, `openat`, `fopen`, `access`, `faccessat`, `stat`, `lstat`) via `dlsym(RTLD_NEXT, ...)`. Works only for dynamically linked binaries. Each intercepted function calls `redirect()` which checks the path against `REDIRECT_TABLE`, builds the Termux-prefixed path, verifies the target exists (via raw syscall to avoid recursion), and returns the rewritten path.

### Tier 2: `src/termux-etc-seccomp.c` → `termux-etc-seccomp`
A seccomp `user_notif` supervisor that intercepts `openat` syscalls at the kernel level via BPF. Works on **all** binaries including statically linked Go programs. The supervisor forks a child, the child installs the BPF filter and sends the notification fd to the parent via `SCM_RIGHTS` over a Unix socketpair, then execs the target command. The parent loops on `SECCOMP_IOCTL_NOTIF_RECV`, reads paths from `/proc/<pid>/mem`, and injects replacement fds via `SECCOMP_IOCTL_NOTIF_ADDFD`.

### Key design decisions
- **Fail-open**: if the Termux destination file doesn't exist, the original path passes through unchanged.
- **BPF filter is aarch64-only** (`AUDIT_ARCH_AARCH64` hardcoded in the filter).
- **Redirect table is duplicated** in both source files — changes to redirected paths must be updated in both `src/termux-etc-redirect.c` and `src/termux-etc-seccomp.c`.
- **`$PREFIX` defaults to `/data/data/com.termux/files/usr`** when the environment variable is not set.

## Testing

- `test/test-redirect.c`: Unit tests for the LD_PRELOAD library. Tests `fopen`, `open`, `access`, `stat` interception and verifies unrelated paths are not redirected. Run via `LD_PRELOAD=build/libtermux-etc-redirect.so build/test-redirect`.
- `test/test-terraform/main.tf`: Manual integration test for Terraform TLS via `termux-etc-seccomp terraform init`.
- The `make test` target runs both the unit test and a seccomp integration test (`termux-etc-seccomp cat /etc/resolv.conf`).

## Target Platform

Termux on Android aarch64. Requires Linux kernel seccomp `user_notif` support (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_IOCTL_NOTIF_ADDFD`). No root required.
