# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is not edited by hand. Every change writes its own fragment under
`.changes/unreleased/` with [chlog](https://github.com/luizjhonata/chlog), and a release compiles
the pending fragments into a version section here — so two branches each adding an entry no
longer touch the same lines, and a rebase that used to conflict on this file now conflicts on
nothing.

## [Unreleased]

## [0.8.0] - 2026-09-02

### Added

- added the `checks` workflow, so pull requests here run the shared `code-check > quality:basic-checks` gate (rebase status and the changelog rule) that every repository with a language pipeline already gets as that pipeline's first job. This repository has no build to attach it to, so it had no changelog enforcement at all — which is how the weekly configuration and documentation refresh hand-edited a generated `CHANGELOG.md` across the fleet before anything objected

## [0.7.1] - 2026-08-28

### Changed

- changed the Claude workflows to call the reusable workflows in `rios0rios0/pipelines` instead of `rios0rios0/.github`, renamed them to `claude-review.yaml` and `claude-mention.yaml`, matching the `reusable-claude-review.yaml` / `reusable-claude-mention.yaml` definitions they call, and changed them to pass `CLAUDE_CODE_OAUTH_TOKEN` explicitly rather than with `secrets: inherit`, which fails Semgrep's `yaml.github-actions.security.secrets-inherit` rule

### Fixed

- changed the Claude workflow callers to single-quote every `types:` sequence entry, per the account YAML standard, and renamed the changelog fragment added by the previous change to chlog's documented `<unix-nanoseconds>-<four hex characters>.yaml` form -- its former suffix was not hexadecimal. The mention workflow is now named `Claude Mention` with a matching `claude-mention` job id.
- restored the `.changes/unreleased/` directory with a `.gitkeep`, so the release tooling keeps recognising this project as [chlog](https://github.com/luizjhonata/chlog)-based after a release consumes the last fragment. Git tracks files rather than directories, so the bump commit that removed the final fragment removed the directory too, and the next run read the empty `[Unreleased]` section as "nothing to release"
- restored the `id-token: write` permission on both Claude workflow callers. Without it the caller grants less than the reusable workflow declares, which GitHub rejects before the job starts -- runs ended in `startup_failure`. The action needs the scope because `setupGitHubToken()` exchanges a GitHub OIDC token for the GitHub App token it posts with, unless a `github_token` is passed explicitly.

### Removed

- removed the unused `id-token: write` permission from the Claude workflow callers, and changed `claude-review.yaml`'s display name to `Claude Review` so it matches its file name and its `Claude Mention` sibling. `anthropics/claude-code-action` needs `id-token: write` only for workload identity federation or the Bedrock / Vertex / Foundry OIDC paths; these authenticate with `claude_code_oauth_token`, so the scope allowed minting OIDC tokens for any audience without ever being used.

## [0.7.0] - 2026-08-26

### Added

- added a tailored `code-review` skill under `.github/skills/` so GitHub Copilot reviews changes against the [rios0rios0/guide](https://github.com/rios0rios0/guide/wiki) standards and this repository's own load-bearing invariants

### Changed

- changed the changelog to [chlog](https://github.com/luizjhonata/chlog) fragments: a change now writes its own YAML file under `.changes/unreleased/` through `chlog new --kind <Kind> --body "..."`, and `CHANGELOG.md` is GENERATED from them at release time by `chlog batch auto && chlog merge`. That is the one thing a single shared file cannot do — two branches each adding an entry no longer touch the same lines, so a rebase that used to conflict on `CHANGELOG.md` now conflicts on nothing. The `[Unreleased]` section was empty, so nothing had to be carried across. AutoBump already reads the fragments directly, so the release flow is unchanged.

### Fixed

- listed Go in the contributing prerequisites, since installing `chlog` goes through `go install` and the list did not mention it

## [0.6.1] - 2026-06-22

### Changed

- refreshed `.github/copilot-instructions.md` to document the `sigsys_launcher` artifact, the TRACEME + blocking-`waitpid` race-free ptrace model, and the `test/test-sigsys-threads.c` multithreaded clone-race test added in 0.6.0; corrected the build/install commands to reflect four artifacts and three installed binaries

## [0.6.0] - 2026-06-18

### Added

- added `sigsys_launcher` to the `make test` suite as the authoritative SIGSYS suppression validator; the test is race-safe from any environment (no double-`NEW_LISTENER` issue since `sigsys_launcher` installs no seccomp filter)
- added `src/sigsys_launcher.c` — a standalone SIGSYS-only ptrace supervisor using TRACEME+blocking `waitpid` (no seccomp filter, no openat redirect). Useful as a composable SIGSYS layer when chaining tools that cannot share a seccomp `NEW_LISTENER` fd. Built and installed alongside `termux-etc-seccomp` and `termux-etc-mount` (`make all` / `make install`)
- added `test/test-sigsys-threads.c` — multithreaded `faccessat2` race test: 32 threads × 8 direct `faccessat2` syscalls, verifying that no thread escapes the supervisor and causes a SIGSYS kill. Run via `sigsys_launcher` in `make test` (regression guard for the clone-race fix)

### Changed

- changed `LDFLAGS` for `termux-etc-seccomp` to link `-lpthread` (required for the notif thread)
- changed `termux-etc-seccomp` ptrace model from `PTRACE_SEIZE`+`poll(notif_fd)`+`SIGCHLD` to a race-free two-thread design: (1) the child calls `ptrace(PTRACE_TRACEME)` and `raise(SIGSTOP)` **before** `execvp`, so `PTRACE_O_TRACECLONE` is installed before any Go runtime thread is ever cloned; (2) the main thread runs a blocking `waitpid(-1, __WALL)` loop (all ptrace calls on one OS thread, no signal-delivery race); (3) a dedicated notif thread runs `poll(notif_fd)` + `handle_notification` concurrently. The notif thread is spawned **before** the ack is written to the child, eliminating the window where `execvp`'s own `openat` call could block with no consumer on the notif fd. The old design raced between `PTRACE_SEIZE` and Go's rapid `clone()` thread creation — a thread could hit `faccessat2` before its `PTRACE_EVENT_CLONE` stop was drained, causing an unhandled SIGSYS that killed the whole process

## [0.5.1] - 2026-05-19

### Changed

- refreshed `.github/copilot-instructions.md` to document Tier 2's reentrancy guard, update nesting advice to reflect the guard's short-circuit behavior, and add the missing `test/test-seccomp-reentrancy.c` entry

## [0.5.0] - 2026-04-30

### Added

- added `test/test-seccomp-reentrancy.c` integration test (run as Tier 2's reentrancy stage of `make test`) verifying that the supervisor exports `TERMUX_ETC_WRAP_ACTIVE=1` into the child env and that a nested `termux-etc-seccomp` → `termux-etc-seccomp` invocation short-circuits cleanly. The test resolves the wrapper from `/proc/<PPID>/exe` so it stays hermetic without `make install`
- added reentrancy guard in `termux-etc-seccomp` mirroring Tier 3: on startup the supervisor checks `TERMUX_ETC_WRAP_ACTIVE` and `/proc/self/status:TracerPid`, short-circuiting to `execvp` when either signal is present, and exports `TERMUX_ETC_WRAP_ACTIVE=1` in the child's environment before `execve`. Nested `termux-etc-mount` → `termux-etc-seccomp` (e.g. the `op` wrapper inside Claude Code) and `termux-etc-seccomp` → `termux-etc-seccomp` invocations now compose cleanly instead of failing with `EBUSY` on the duplicate `SECCOMP_FILTER_FLAG_NEW_LISTENER` install

### Changed

- moved the `termux-etc-seccomp` reentrancy guard ahead of `build_prefix()` so the short-circuit `execvp` path no longer depends on `PREFIX` validation — a malformed or oversized `PREFIX` can no longer block the pass-through exec when an outer wrapper already redirects `/etc/`

## [0.4.1] - 2026-04-28

### Changed

- refreshed `.github/copilot-instructions.md` to document all three tiers (`libtermux-etc-redirect.so`, `termux-etc-seccomp`, `termux-etc-mount`) instead of only the first two

## [0.4.0] - 2026-04-20

### Added

- added `/etc/services` to the Tier 3 redirect table (musl's `getservbyname()` data file)
- added `examples/claude-code.md` worked example documenting the end-to-end install (musl loader seed + `patchelf --set-interpreter` + Tier 3 wrapper) for Claude Code on Termux
- added `test/test-mount.c` integration test covering the `/etc/` redirect, the inherited-filter check, unrelated-path passthrough (validated by comparing `stat` inode+device of `/etc/passwd` against `/system/etc/passwd`), and the reentrancy guard (which resolves the wrapper binary from `/proc/<PPID>/exe` and looks up `true` via `PATH`, so the test stays hermetic without requiring `make install`)
- added compatibility matrix and "When NOT to use this tool" section to `README.md` covering Tier 2 ptrace-collision failure modes and why Tier 1/2 cannot serve dynamic musl binaries
- added reentrancy guard in `termux-etc-mount`: on startup the supervisor checks the `TERMUX_ETC_WRAP_ACTIVE` environment variable (exported by any outer `termux-etc-*` wrapper immediately before its `execve`) and `/proc/self/status:TracerPid`, short-circuiting to `execvp` if either signal is present. Nested Tier 2 → Tier 3 or Tier 3 → Tier 3 wrappers therefore compose cleanly instead of deadlocking on a duplicate listener fd. The proc `Seccomp` field is deliberately **not** consulted, because Android's zygote leaves every Termux process at `Seccomp=2` from an inherited system filter — a condition indistinguishable from "our outer wrapper"
- added Tier 3 `termux-etc-mount` — a narrow seccomp `user_notif` supervisor on `openat` only, with no ptrace and no SIGSYS rewriting, tuned for dynamic musl binaries such as Claude Code's `linux-arm64-musl` build whose libc issues DNS reads via direct `__syscall` and whose Node/V8 runtime tolerates no spurious `ENOSYS`

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

