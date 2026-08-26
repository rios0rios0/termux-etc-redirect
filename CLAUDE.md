# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Transparent `/etc/` path redirection for Termux on Android. Enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) and dynamic musl binaries (Claude Code's `linux-arm64-musl` build) to resolve DNS and verify TLS certificates without proot. The project provides three complementary C programs that intercept file-access calls and rewrite hardcoded `/etc/` paths to their Termux `$PREFIX/etc/` equivalents.

## Build & Test Commands

```bash
make              # Build all four artifacts: libtermux-etc-redirect.so (Tier 1),
                  # termux-etc-seccomp (Tier 2), termux-etc-mount (Tier 3),
                  # sigsys_launcher (SIGSYS-only ptrace supervisor)
make test         # Run Tier 1 (LD_PRELOAD) unit tests, Tier 2 (seccomp openat
                  # redirect + faccessat2 SIGSYS via sigsys_launcher +
                  # multithreaded clone race via sigsys_launcher +
                  # reentrancy-guard), and Tier 3 (narrow seccomp) integration
                  # + reentrancy-guard tests.
                  # NOTE: Tier 2 SIGSYS tests use sigsys_launcher (not
                  # termux-etc-seccomp directly) so they work from any
                  # environment including inside a wrapped shell.
make install      # Install libtermux-etc-redirect.so to $PREFIX/lib/ and
                  # termux-etc-seccomp + termux-etc-mount + sigsys_launcher
                  # to $PREFIX/bin/
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

**Race-free ptrace model (TRACEME + blocking waitpid):** The previous `PTRACE_SEIZE` + `poll(notif_fd)` + `SIGCHLD` design raced with Go's rapid `clone()` thread creation — a thread could hit `faccessat2` before its `PTRACE_EVENT_CLONE` stop was drained, causing an unhandled SIGSYS. The current design uses TRACEME + SIGSTOP before exec: the child calls `ptrace(PTRACE_TRACEME)` + `raise(SIGSTOP)` before `execvp`, the parent waits for the stop (blocking), installs `PTRACE_O_TRACECLONE` before any Go thread exists, then continues. Two parent threads run concurrently: (1) the **TRACER thread** (main thread) runs a blocking `waitpid(-1, __WALL)` loop; (2) a **NOTIF thread** runs `poll(notif_fd)` + `handle_notification`. The notif thread is started before the ack is written to the child, so the child's first `execvp`-triggered `openat` always has a consumer.

**Why `SECCOMP_RET_ERRNO` cannot work:** Android's `SECCOMP_RET_TRAP` for `faccessat2` has higher BPF priority than user-installed `SECCOMP_RET_ERRNO` rules — it silently wins. ptrace is the only viable interception mechanism.

### Tier 3: `src/termux-etc-mount.c` → `termux-etc-mount`
A narrow seccomp supervisor tuned for dynamic musl binaries (Claude Code's `linux-arm64-musl` build, other Alpine-linked tools). Same BPF filter as Tier 2 (aarch64, `openat`-only) and the same SCM_RIGHTS fd-passing pattern, but:
- **No ptrace at all.** Avoids the "only one tracer per process" kernel rule, so Tier 3 composes cleanly with `strace`/`gdb`, and a Tier 3 child can spawn a Tier 2 subprocess without collision.
- **No SIGSYS rewriting.** musl/Node has no fallback for `statx` or `newfstatat` returning `-ENOSYS`; Tier 2's blanket rewrite surfaces as confusing `ENOSYS: lstat` errors in Claude. Tier 3 lets Android's global policy handle SIGSYS natively — Claude and similar workloads never trigger it during normal operation.

### Key design decisions
- **Fail-open**: if the Termux destination file doesn't exist, the original path passes through unchanged.
- **BPF filter is aarch64-only** (`AUDIT_ARCH_AARCH64` hardcoded in the filter).
- **Redirect table is duplicated** across Tier 1, Tier 2, and Tier 3 source files — any path change must be applied to all three: `src/termux-etc-redirect.c`, `src/termux-etc-seccomp.c`, `src/termux-etc-mount.c`. Tier 3's table is a superset (adds `/etc/services`).
- **`$PREFIX` defaults to `/data/data/com.termux/files/usr`** when the environment variable is not set.
- **Tier 2 uses TRACEME+blocking waitpid (not PTRACE_SEIZE+poll)**: `PTRACE_TRACEME`+`raise(SIGSTOP)` in the child before `execvp` guarantees `PTRACE_O_TRACECLONE` is installed before any Go runtime thread is cloned. The parent runs a blocking `waitpid(-1, __WALL)` loop on the main thread (all ptrace ops on one OS thread). The old `PTRACE_SEIZE`+`poll(notif_fd)`+`SIGCHLD` design had a race window between `SEIZE` and the first `PTRACE_EVENT_CLONE` stop. `PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK` ensures SIGSYS is caught on all Go runtime threads and spawned child processes. Tier 3 deliberately omits ptrace entirely — it relies on inherited seccomp filters.
- **Reentrancy guard (Tier 2 + Tier 3)**: on startup both supervisors check two signals — the `TERMUX_ETC_WRAP_ACTIVE` environment variable (exported by any outer `termux-etc-*` wrapper immediately before its `execve`) and `/proc/self/status:TracerPid`. If either is non-zero/present, the supervisor short-circuits to `execvp` and inherits the outer wrapper's already-installed filter. The kernel allows only one `SECCOMP_FILTER_FLAG_NEW_LISTENER` per task, so without this guard nested wrappers (e.g. Tier 3 → Tier 2 when Claude Code launches `op` whose wrapper invokes `termux-etc-seccomp`, or Tier 2 → Tier 2, or Tier 3 → Tier 3) would fail with `EBUSY` on the duplicate listener install. The proc `Seccomp:` field is deliberately **not** consulted — Termux's Android zygote leaves every app process at `Seccomp=2` from an inherited system filter, so that field cannot distinguish "our outer wrapper" from Android's always-on baseline.

## Testing

- `test/test-redirect.c`: Unit tests for the LD_PRELOAD library. Tests `fopen`, `open`, `access`, `stat` interception and verifies unrelated paths are not redirected. Run via `LD_PRELOAD=build/libtermux-etc-redirect.so build/test-redirect`.
- `test/test-faccessat2.c`: Validates SIGSYS-to-ENOSYS rewrite for a single-threaded `faccessat2` call. Run via `sigsys_launcher build/test-faccessat2` (uses `sigsys_launcher` rather than `termux-etc-seccomp` so the test works from any environment, including from inside an already-wrapped shell where a second `SECCOMP_FILTER_FLAG_NEW_LISTENER` would fail with EBUSY).
- `test/test-sigsys-threads.c`: Multithreaded regression test for the `clone()` race — 32 threads × 8 direct `faccessat2` syscalls. Verifies that no thread escapes the SIGSYS supervisor before being traced. Run via `sigsys_launcher build/test-sigsys-threads`. The same test run under the old `poll+SIGCHLD` design would exit 159 (SIGSYS kill) — demonstrates the race that motivated the TRACEME+blocking-`waitpid` redesign.
- `test/test-seccomp-reentrancy.c`: Reentrancy-guard test for Tier 2 — verifies that the supervisor exports `TERMUX_ETC_WRAP_ACTIVE=1` into the child env and that a nested `termux-etc-seccomp` → `termux-etc-seccomp` invocation short-circuits cleanly (no `EBUSY` on duplicate listener install). Run via `termux-etc-seccomp build/test-seccomp-reentrancy`. Note: the PPID-based wrapper-binary discovery in this test requires `termux-etc-seccomp` to be the actual supervisor (not short-circuiting via the reentrancy guard), so this test must be run from a fresh terminal that is not already wrapped.
- `test/test-mount.c`: Integration test for Tier 3 — verifies `/etc/resolv.conf` redirect, inherited-filter presence, unrelated-path passthrough, and the reentrancy guard. Run via `termux-etc-mount build/test-mount`.
- `test/test-terraform/main.tf`: Manual integration test for Terraform TLS via `termux-etc-seccomp terraform init`.
- `make test` runs all tiers' unit/integration tests. Tier 2 SIGSYS tests use `sigsys_launcher` (not `termux-etc-seccomp` directly) so the full suite can run from inside a wrapped shell.

## Target Platform

Termux on Android aarch64. Requires Linux kernel seccomp `user_notif` support (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_IOCTL_NOTIF_ADDFD`). No root required.

<!-- chlog:start -->
## Changelog (chlog) — MANDATORY

If the repository you are working in uses chlog (a `.chlog.yaml` or `.chlog.yml`
config file, or a `.changes/` directory, exists at the project root), the
following is binding and ALWAYS applies: whenever you make ANY change, you MUST
create a changelog fragment as part of the same change — automatically, without
being asked, before committing.

- Do NOT edit CHANGELOG.md directly; it is generated from fragments.
- Create the fragment with:
  `chlog new --kind <Kind> --body "<imperative description>"`
- Valid kinds: Added, Changed, Deprecated, Removed, Fixed, Security
- Choose the kind that best matches the change (e.g., new feature → Added,
  bug fix → Fixed, behavior change → Changed, removal → Removed, security fix → Security).
- If the change is backward-INCOMPATIBLE with the public API (a breaking
  change), you MUST add the `--breaking` flag:
  `chlog new --kind <Kind> --breaking --body "<description>"`.
  This is the ONLY thing that triggers a major version bump — the kind alone
  never does (per SemVer, major = incompatible change). When unsure whether a
  change breaks compatibility, ask the user instead of guessing.
- Fragments are YAML files in `.changes/unreleased/`; stage them with your commit.
- `chlog check` fails the build when a fragment is missing — never skip it.
<!-- chlog:end -->
