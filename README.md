<h1 align="center">termux-etc-redirect</h1>
<p align="center">
    <a href="https://github.com/rios0rios0/termux-etc-redirect/releases/latest">
        <img src="https://img.shields.io/github/release/rios0rios0/termux-etc-redirect.svg?style=for-the-badge&logo=github" alt="Latest Release"/></a>
    <a href="https://github.com/rios0rios0/termux-etc-redirect/blob/main/LICENSE">
        <img src="https://img.shields.io/github/license/rios0rios0/termux-etc-redirect.svg?style=for-the-badge&logo=github" alt="License"/></a>
</p>

Transparent `/etc/` path redirection for Termux, enabling Go-based CLIs (GitHub CLI, Terraform, Terragrunt, 1Password CLI, kubectl) to resolve DNS and verify TLS certificates without proot.

## Problem

On Android/Termux, standard Linux paths like `/etc/resolv.conf`, `/etc/hosts`, and `/etc/ssl/certs/` either don't exist or contain incomplete data. Termux maintains proper versions under `$PREFIX/etc/`, but statically linked Go binaries hardcode the standard `/etc/` paths.

This project provides two complementary solutions:

| Tier | Mechanism | Targets | Overhead |
|------|-----------|---------|----------|
| **Tier 1** | `LD_PRELOAD` shared library | Dynamically linked binaries (Python, Node.js, Termux packages) | Near-zero |
| **Tier 2** | `seccomp user_notif` interceptor | **All** binaries, including statically linked Go programs | Minimal (kernel BPF filtering) |

## Features

- **DNS resolution**: redirects `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`
- **TLS certificates**: redirects Go's hardcoded CA certificate paths to `$PREFIX/etc/tls/cert.pem`
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

### Tier 2: seccomp interceptor (for static Go binaries)

```bash
termux-etc-seccomp terraform init
termux-etc-seccomp gh auth status
termux-etc-seccomp terragrunt plan
termux-etc-seccomp kubectl get pods
```

### Tier 1: LD_PRELOAD library (for dynamic binaries)

Add to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export LD_PRELOAD="$PREFIX/lib/libtermux-etc-redirect.so${LD_PRELOAD:+:$LD_PRELOAD}"
```

This transparently redirects `/etc/` paths for all dynamically linked programs.

## How It Works

### Tier 1: LD_PRELOAD

Intercepts libc functions (`open`, `openat`, `fopen`, `access`, `stat`, `lstat`, `faccessat`) and rewrites paths before they reach the kernel.

### Tier 2: seccomp user_notif

1. Installs a BPF filter targeting `openat` syscalls with `SECCOMP_RET_USER_NOTIF`
2. Non-matching syscalls (99.9%+) pass through the kernel at full speed with zero overhead
3. For matching `openat` calls, the supervisor reads the path from the child's memory
4. If the path matches the redirect table, the supervisor opens the Termux file and injects the fd into the child via `SECCOMP_IOCTL_NOTIF_ADDFD`

This is fundamentally more efficient than proot (ptrace), which intercepts **every** syscall.

## Redirected Paths

| Source Path | Destination |
|-------------|-------------|
| `/etc/resolv.conf` | `$PREFIX/etc/resolv.conf` |
| `/etc/hosts` | `$PREFIX/etc/hosts` |
| `/etc/nsswitch.conf` | `$PREFIX/etc/nsswitch.conf` |
| `/etc/ssl/certs/ca-certificates.crt` | `$PREFIX/etc/tls/cert.pem` |
| `/etc/pki/tls/certs/ca-bundle.crt` | `$PREFIX/etc/tls/cert.pem` |
| `/etc/ssl/ca-bundle.pem` | `$PREFIX/etc/tls/cert.pem` |
| `/etc/pki/tls/cacert.pem` | `$PREFIX/etc/tls/cert.pem` |
| `/etc/ssl/cert.pem` | `$PREFIX/etc/tls/cert.pem` |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](LICENSE) file for details.
