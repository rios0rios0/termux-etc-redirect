<h1 align="center">termux-etc-redirect</h1>
<p align="center">
    <a href="https://github.com/rios0rios0/termux-etc-redirect/releases/latest">
        <img src="https://img.shields.io/github/release/rios0rios0/termux-etc-redirect.svg?style=for-the-badge&logo=github" alt="Latest Release"/></a>
    <a href="https://github.com/rios0rios0/termux-etc-redirect/blob/main/LICENSE">
        <img src="https://img.shields.io/github/license/rios0rios0/termux-etc-redirect.svg?style=for-the-badge&logo=github" alt="License"/></a>
</p>

Transparent `/etc/` path redirection for Termux. Enables Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) and dynamic musl binaries (Claude Code) to resolve DNS and verify TLS certificates without proot.

## Problem

On Android/Termux, standard Linux paths like `/etc/resolv.conf`, `/etc/hosts`, and `/etc/ssl/certs/` either don't exist or contain incomplete data. Termux maintains proper versions under `$PREFIX/etc/`, but binaries built for vanilla Linux hardcode the standard `/etc/` paths.

This project provides three complementary solutions, each tuned for a different libc × linkage combination:

| Tier | Mechanism | Targets | Subprocesses | Overhead |
|------|-----------|---------|--------------|----------|
| **Tier 1** | `LD_PRELOAD` shared library | Dynamic bionic / glibc binaries (Python, Node.js, Termux packages) | Via env var inheritance (bionic only) | Near-zero |
| **Tier 2** | `seccomp user_notif` + ptrace SIGSYS suppression | **All** binaries, incl. static Go programs | `PTRACE_O_TRACEFORK` auto-traces descendants | Minimal (kernel BPF) |
| **Tier 3** | Narrow `seccomp user_notif`, no ptrace | Dynamic musl binaries (Claude Code, Alpine tools) | Inherited filter, reentrancy-safe | Minimal (kernel BPF) |

### Compatibility matrix

| Target binary                                   | Tier 1 | Tier 2 | Tier 3 |
|-------------------------------------------------|:------:|:------:|:------:|
| Bionic dynamic (Termux-native, Python, Node.js) |   ✅   |   ✅   |   ✅   |
| glibc-runner dynamic                            |   ✅   |   ✅   |   ✅   |
| Static Go (`gh`, `terraform`, `kubectl`, `op`)  |   ❌   |   ✅   |   ⚠️ (openat-only; no `faccessat2` fallback)   |
| **Dynamic musl (Claude Code, Alpine builds)**   |   ❌¹  |   ❌²  |   ✅   |

¹ musl's DNS code uses direct `__syscall` that bypasses PLT-based `LD_PRELOAD` overrides.
² Tier 2's blanket `SIGSYS → -ENOSYS` rewrite is intolerable to Node/V8; and Tier 2's ptrace conflicts with any subprocess wrapped in another ptracer (see "When NOT to use").

## Features

- **DNS resolution**: redirects `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/services`
- **TLS certificates**: redirects every common hardcoded CA bundle path (Go, OpenSSL, Node) to `$PREFIX/etc/tls/cert.pem`
- **Zero configuration**: auto-detects `$PREFIX` from environment
- **Fail-open**: if the Termux file doesn't exist, the original path is used
- **No root required**: uses unprivileged seccomp and LD_PRELOAD

## Installation

```bash
git clone https://github.com/rios0rios0/termux-etc-redirect.git
cd termux-etc-redirect
./scripts/install.sh
```

Or manually:

```bash
make
make install
```

## Usage

### Tier 1: LD_PRELOAD library (for dynamic bionic binaries)

Add to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export LD_PRELOAD="$PREFIX/lib/libtermux-etc-redirect.so${LD_PRELOAD:+:$LD_PRELOAD}"
```

This transparently redirects `/etc/` paths for all dynamically linked programs. Musl-linked programs cannot load this library (bionic ABI).

### Tier 2: seccomp + ptrace supervisor (for static Go binaries)

```bash
termux-etc-seccomp terraform init
termux-etc-seccomp gh auth status
termux-etc-seccomp terragrunt plan
termux-etc-seccomp kubectl get pods
```

Tier 2 also installs a ptrace-based `SIGSYS → -ENOSYS` rewriter for Android's `faccessat2` trap, which Go's `os/exec.LookPath` expects to fall back from.

### Tier 3: narrow seccomp (for dynamic musl binaries)

```bash
termux-etc-mount ~/.local/share/claude/versions/<version> -p "say ok"
```

Tier 3 is ptrace-free and does **not** rewrite SIGSYS. Its BPF filter is identical to Tier 2's (openat-only on aarch64), but the supervisor is simpler and safer to nest inside other tracers. See `examples/claude-code.md` for an end-to-end Claude Code walkthrough.

## How It Works

### Tier 1: LD_PRELOAD

Intercepts libc functions (`open`, `openat`, `fopen`, `access`, `stat`, `lstat`, `faccessat`) and rewrites paths before they reach the kernel. Each override consults a shared `REDIRECT_TABLE`, probes the Termux target's existence via a raw `__NR_faccessat` syscall (to avoid recursing through its own intercepted `access`), and passes the rewritten path to the real function.

### Tier 2: seccomp user_notif + ptrace SIGSYS

1. Installs a BPF filter targeting `openat` with `SECCOMP_RET_USER_NOTIF`; everything else is `ALLOW`.
2. Non-matching syscalls pass through the kernel at full speed.
3. For matching `openat` calls, the supervisor reads the path from the child's memory, opens the Termux file, and injects the fd back into the child via `SECCOMP_IOCTL_NOTIF_ADDFD`.
4. A ptrace handler catches Android's own `SECCOMP_RET_TRAP → SIGSYS` on blocked syscalls (e.g. `faccessat2`), sets x0 to `-ENOSYS` via `PTRACE_SETREGSET`, and suppresses the signal so the child's runtime falls back to an allowed syscall.

### Tier 3: narrow seccomp user_notif, no ptrace

Same BPF filter as Tier 2, same fd-injection path. The differences are deliberate subtractions:

- **No ptrace.** A tracer is required on exactly one process at a time; that's fatal for musl binaries like Claude that spawn seccomp-wrapped children or run under `strace`/`gdb`. Without ptrace, Tier 3 composes with any other supervisor.
- **No SIGSYS rewriting.** Claude's Node/V8 runtime has no fallback for `statx`/`newfstatat` returning `-ENOSYS`; blanket rewriting (Tier 2's approach) produces confusing `ENOSYS: lstat` errors. Tier 3 lets Android's global policy handle SIGSYS natively.
- **Reentrancy guard.** Before forking, the supervisor checks `TERMUX_ETC_WRAP_ACTIVE` — the env var it exports into the child immediately before `execve`ing the target. If present, or if `/proc/self/status:TracerPid` is non-zero, Tier 3 `execvp`s the target directly and relies on the outer wrapper's already-installed filter. The `/proc/self/status:Seccomp` field is deliberately not consulted — Android's zygote leaves every Termux process at `Seccomp=2` from an inherited system filter, indistinguishable from "our outer wrapper".

## When NOT to use this tool

- **Do not wrap Tier 2 inside another tracer.** `strace termux-etc-seccomp ...` and `termux-etc-seccomp termux-etc-seccomp ...` both fail with `ptrace seize failed (Operation not permitted)` because `PTRACE_O_TRACEFORK` from the outer tracer grabs Tier 2's forked child before Tier 2 can seize it. Use Tier 3 when you need composable wrapping.
- **Do not wrap a program in Tier 2 if it will spawn other Tier 2-wrapped subprocesses** (e.g. Claude → `gh`). The inherited seccomp filter and ptrace ancestry collide, surfacing as `Device or resource busy, failed to receive notif fd`. Tier 3's reentrancy guard + no-ptrace design avoids this.
- **Do not use Tier 1 on musl binaries.** Termux's `libtermux-etc-redirect.so` is linked against bionic; the musl dynamic loader cannot load it. Even if you build a musl-linked copy, musl's DNS resolver uses direct `__syscall` invocations that never reach the PLT.
- **Do not use Tier 3 as a general static-Go replacement.** If the target relies on `faccessat2 → ENOSYS` fallback (Go's `exec.LookPath`), use Tier 2 — only it rewrites that SIGSYS.

## Redirected Paths

| Source Path | Destination | Tiers |
|-------------|-------------|-------|
| `/etc/resolv.conf` | `$PREFIX/etc/resolv.conf` | 1, 2, 3 |
| `/etc/hosts` | `$PREFIX/etc/hosts` | 1, 2, 3 |
| `/etc/nsswitch.conf` | `$PREFIX/etc/nsswitch.conf` | 1, 2, 3 |
| `/etc/services` | `$PREFIX/etc/services` | 3 |
| `/etc/ssl/certs/ca-certificates.crt` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |
| `/etc/pki/tls/certs/ca-bundle.crt` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |
| `/etc/ssl/ca-bundle.pem` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |
| `/etc/pki/tls/cacert.pem` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |
| `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |
| `/etc/ssl/cert.pem` | `$PREFIX/etc/tls/cert.pem` | 1, 2, 3 |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](LICENSE) file for details.
