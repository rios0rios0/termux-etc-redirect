# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- added Tier 3 `termux-etc-mount` — a narrow seccomp `user_notif` supervisor on `openat` only, with no ptrace and no SIGSYS rewriting, tuned for dynamic musl binaries such as Claude Code's `linux-arm64-musl` build whose libc issues DNS reads via direct `__syscall` and whose Node/V8 runtime tolerates no spurious `ENOSYS`
- added `/etc/services` to the Tier 3 redirect table (musl's `getservbyname()` data file)
- added reentrancy guard in `termux-etc-mount`: on startup the supervisor checks the `TERMUX_ETC_WRAP_ACTIVE` environment variable (exported by any outer `termux-etc-*` wrapper immediately before its `execve`) and `/proc/self/status:TracerPid`, short-circuiting to `execvp` if either signal is present. Nested Tier 2 → Tier 3 or Tier 3 → Tier 3 wrappers therefore compose cleanly instead of deadlocking on a duplicate listener fd. The proc `Seccomp` field is deliberately **not** consulted, because Android's zygote leaves every Termux process at `Seccomp=2` from an inherited system filter — a condition indistinguishable from "our outer wrapper"
- added `test/test-mount.c` integration test covering the `/etc/` redirect, the inherited-filter check, unrelated-path passthrough (validated by comparing `stat` inode+device of `/etc/passwd` against `/system/etc/passwd`), and the reentrancy guard (which resolves the wrapper binary from `/proc/<PPID>/exe` and looks up `true` via `PATH`, so the test stays hermetic without requiring `make install`)
- added `examples/claude-code.md` worked example documenting the end-to-end install (musl loader seed + `patchelf --set-interpreter` + Tier 3 wrapper) for Claude Code on Termux
- added compatibility matrix and "When NOT to use this tool" section to `README.md` covering Tier 2 ptrace-collision failure modes and why Tier 1/2 cannot serve dynamic musl binaries

### Changed

- refreshed `CLAUDE.md` project overview and `Build & Test Commands` block so they describe all three tiers (`libtermux-etc-redirect.so`, `termux-etc-seccomp`, `termux-etc-mount`) instead of only the first two

## [0.3.0] - 2026-03-31

### Added

- added automated `faccessat2` SIGSYS suppression test (`test/test-faccessat2.c`) to `make test` as Tier 3
- added compile-time `#if !defined(__aarch64__)` guard with `#error` to make the `aarch64` requirement explicit at build time

### Fixed

- fixed `set_return_enosys()` to check and report `PTRACE_SETREGSET` failures instead of silently ignoring them
- fixed SIGSYS handler to explicitly set `x0` to `-ENOSYS` via `PTRACE_SETREGSET` instead of relying on the kernel (which restores `x0` to the original first argument via `syscall_rollback`, not `-ENOSYS`)

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

