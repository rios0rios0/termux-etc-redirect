# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- added compile-time `#if !defined(__aarch64__)` guard with `#error` to make the aarch64 requirement explicit at build time
- added automated `faccessat2` SIGSYS suppression test (`test/test-faccessat2.c`) to `make test` as Tier 3

### Fixed

- fixed SIGSYS handler to explicitly set x0 to `-ENOSYS` via `PTRACE_SETREGSET` instead of relying on the kernel (which restores x0 to the original first argument via `syscall_rollback`, not `-ENOSYS`)
- fixed `set_return_enosys()` to check and report `PTRACE_SETREGSET` failures instead of silently ignoring them

## [0.2.0] - 2026-03-30

### Added

- added `poll()`-based event loop combining seccomp notifications with ptrace event handling
- added `PTRACE_O_TRACECLONE`, `PTRACE_O_TRACEFORK`, and `PTRACE_O_TRACEVFORK` to auto-trace all threads and child processes
- added ptrace SIGSYS suppression to `termux-etc-seccomp` for syscalls blocked by Android's seccomp policy (e.g., `faccessat2`)

### Changed

- changed `termux-etc-seccomp` from seccomp-only to a hybrid seccomp + ptrace architecture, enabling Go binaries that use `os/exec.LookPath` (which calls `faccessat2`) to work on Android
- changed the BPF filter to intercept only `openat` (reverted `faccessat2` interception since Android's `SECCOMP_RET_TRAP` has higher priority than `SECCOMP_RET_USER_NOTIF`)

## [0.1.0] - 2026-03-22

### Added

- added DNS path redirection (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`)
- added install script with automatic `nsswitch.conf` and `resolv.conf` creation
- added LD_PRELOAD shared library (`libtermux-etc-redirect.so`) for dynamically linked binaries
- added seccomp user_notif interceptor (`termux-etc-seccomp`) for all binaries including statically linked Go programs
- added TLS CA certificate path redirection for Go's hardcoded SSL paths
- added unit tests for LD_PRELOAD library and integration tests for seccomp interceptor

