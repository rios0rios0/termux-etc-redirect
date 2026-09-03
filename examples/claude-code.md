# Running Claude Code on Termux with Tier 3

Claude Code's `linux-arm64-musl` release ships a dynamically-linked musl binary. musl's DNS resolver issues direct `__syscall` invocations, so `LD_PRELOAD` interception cannot rewrite `/etc/resolv.conf`. Tier 2 (seccomp + ptrace) can intercept the syscall, but its SIGSYS rewriter produces spurious `ENOSYS: lstat` errors against Node/V8, and its ptrace-based descendant tracking collides with any tool-call subprocess that wants its own tracer (e.g. a `termux-etc-seccomp gh` spawn).

Tier 3 (`termux-etc-mount`) is the right wrapper for Claude: narrow seccomp on `openat`, no ptrace, no SIGSYS rewriting, reentrancy-safe.

## Prerequisites

```bash
pkg install -y patchelf binutils wget clang make
git clone https://github.com/rios0rios0/termux-etc-redirect.git
cd termux-etc-redirect
make && make install
```

Confirm Termux's config files exist (the install script creates them if missing):

```bash
cat "$PREFIX/etc/resolv.conf"        # must contain real nameservers
ls   "$PREFIX/etc/tls/cert.pem"      # must exist (install CA bundle if not)
```

## Install Claude Code's musl build

The official `linux-arm64-musl` release is hosted at:

```
https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases
```

Minimal install (see the user's `~/install-my-claude.sh` for a hardened version with auto-update handling and version cleanup):

```bash
GCS="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases"
VERSION=$(wget -qO- "$GCS/latest")
mkdir -p "$HOME/.local/share/claude/versions" "$HOME/.local/musl-loader/lib"

# Fetch the binary.
wget -O "$HOME/.local/share/claude/versions/$VERSION" \
     "$GCS/$VERSION/linux-arm64-musl/claude"
chmod +x "$HOME/.local/share/claude/versions/$VERSION"

# Seed the musl loader from Alpine (one-time).
if [ ! -f "$HOME/.local/musl-loader/lib/ld-musl-aarch64.so.1" ]; then
    TMP=$(mktemp -d)
    wget -O "$TMP/musl.apk" \
         "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/aarch64/musl-1.2.5-r9.apk"
    tar -xzf "$TMP/musl.apk" -C "$TMP"
    find "$TMP" -name 'ld-musl-aarch64.so.1' -type f -exec \
         cp {} "$HOME/.local/musl-loader/lib/" \;
    rm -rf "$TMP"
fi

# Patch PT_INTERP so the kernel can find the loader on Android.
patchelf --set-interpreter "$HOME/.local/musl-loader/lib/ld-musl-aarch64.so.1" \
         --remove-rpath \
         "$HOME/.local/share/claude/versions/$VERSION"
```

Verify the patch:

```bash
readelf -l "$HOME/.local/share/claude/versions/$VERSION" | awk '/interpreter/'
# Requesting program interpreter: /data/data/com.termux/files/home/.local/musl-loader/lib/ld-musl-aarch64.so.1
```

## The Tier 3 wrapper

Create `~/.local/bin/claude`:

```bash
cat > "$HOME/.local/bin/claude" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Identity + HOME for glibc fallbacks (Android /etc/passwd is missing most fields).
export USER="${USER:-$(id -un)}"
export HOME="${HOME:-/data/data/com.termux/files/home}"

# Termux's bionic LD_PRELOAD shims (termux-exec, Tier 1) cannot load into a
# musl process, but the shells behind Claude's tool calls need them back --
# without termux-exec every `#!/usr/bin/env` script they run exits 127.
# termux-etc-mount parks the variable in TERMUX_ETC_LD_PRELOAD for exactly
# that round trip, so it is deliberately NOT unset here. See "Give tool-call
# shells their shims back" below.

# Point Node at Termux's CA bundle so TLS works without /etc/ssl/certs.
export NODE_EXTRA_CA_CERTS="$PREFIX/etc/tls/cert.pem"

# Disable the in-binary auto-updater (otherwise it replaces this wrapper with a
# symlink to an unpatched binary and Claude breaks until patchelf re-runs).
export DISABLE_AUTOUPDATER=1

# Pick the newest version under $HOME/.local/share/claude/versions/.
CLAUDE_BIN=$(ls -1 "$HOME/.local/share/claude/versions" | sort -V | tail -1)
exec termux-etc-mount \
    "$HOME/.local/share/claude/versions/$CLAUDE_BIN" "$@"
EOF
chmod +x "$HOME/.local/bin/claude"
```

Smoke test:

```bash
claude --version        # should print "X.Y.Z (Claude Code)"
claude -p "say ok"      # should print "ok" (or similar) from Anthropic API
```

## Give tool-call shells their shims back

`termux-etc-mount` copies `LD_PRELOAD` to `TERMUX_ETC_LD_PRELOAD` and removes it before starting Claude, because the musl loader would otherwise fail to relocate Termux's bionic shims and exit before `main()`. Claude never sources a shell rc file, but every shell it spawns for a tool call does — which makes the rc file the one place that can hand the shims back to bionic descendants. Add it to `~/.zshenv`, which every zsh sources whether interactive or not. For bash, put it in its own file and `export BASH_ENV=<that file>` from your login profile: a non-interactive `bash -c` reads `BASH_ENV` and never `~/.bashrc`, so a snippet placed there would not reach tool-call shells.

```bash
if [ -z "${LD_PRELOAD:-}" ] && [ -n "${TERMUX_ETC_LD_PRELOAD:-}" ]; then
    export LD_PRELOAD="$TERMUX_ETC_LD_PRELOAD"
fi
```

With that in place `make lint`, `make test` and any other `#!/usr/bin/env sh` script run unchanged inside a tool call, exactly as they do from a plain Termux tab.

## Why Tier 3 and not Tier 2 / proot

- **Tier 2** wraps the binary in `termux-etc-seccomp`, whose ptrace supervisor auto-traces all descendants. When Claude spawns a tool-call subprocess — especially one that itself wants to install seccomp (`termux-etc-seccomp gh`) — the inner supervisor fails with `failed to receive notif fd`. Tier 2 also rewrites every `SIGSYS → -ENOSYS`, which is fine for Go's `os/exec.LookPath` but surfaces as `ENOSYS: lstat` in Claude's Node runtime.
- **proot** works correctly (bind-mounts `$PREFIX/etc` over `/etc`), but adds ptrace overhead to every syscall, noticeable on subprocess-heavy workflows.
- **User-namespace bind mount** would be the ideal approach but is blocked by Android's SELinux policy: `untrusted_app_*` domains are denied the `user_namespace` class, so `unshare(CLONE_NEWUSER)` returns `EINVAL` and `/proc/self/ns/user` doesn't exist.
- **Tier 3** installs the same narrow `openat` seccomp filter as Tier 2 without any of the supervisor-collision liabilities. Claude starts cleanly, DNS reaches the nameservers in `$PREFIX/etc/resolv.conf`, and spawning `gh`/`git`/`bash` as tool calls works unchanged — those children inherit the filter, which keeps redirecting for them too.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No such file or directory` on the binary | `patchelf` didn't set `PT_INTERP`, or the musl loader is missing | Re-run the `patchelf --set-interpreter` step; verify `~/.local/musl-loader/lib/ld-musl-aarch64.so.1` exists |
| `EAI_AGAIN` / 403 from Anthropic API | `$PREFIX/etc/resolv.conf` missing or contains unreachable nameservers | `./scripts/install.sh` re-runs the resolv.conf seeder; or edit it manually |
| `failed to receive notif fd` | Something already wraps Claude in Tier 2 or another ptracer | Switch that outer wrapper to Tier 3; Tier 3's reentrancy guard handles nesting cleanly |
| `/usr/bin/env: No such file or directory`, or exit 127, from scripts run by tool calls | `LD_PRELOAD` was dropped for the musl binary and never restored for its bionic children, so `termux-exec` is not rewriting shebangs | Use a `termux-etc-mount` that parks the value in `TERMUX_ETC_LD_PRELOAD`, and restore it from `~/.zshenv` as shown above |
| Version auto-updates and breaks | Anthropic's self-updater replaced `~/.local/bin/claude` with a symlink to an unpatched binary | Re-run the patchelf step; keep `DISABLE_AUTOUPDATER=1` in the wrapper to prevent recurrence |
