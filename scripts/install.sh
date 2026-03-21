#!/data/data/com.termux/files/usr/bin/bash
# install.sh — Install termux-etc-redirect components
set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Building..."
cd "$SCRIPT_DIR"
make clean
make all

echo "Installing binaries..."
make install

# Create nsswitch.conf if it doesn't exist (needed for Go's pure resolver
# to check /etc/hosts before falling back to DNS).
if [ ! -f "$PREFIX/etc/nsswitch.conf" ]; then
    echo "Creating $PREFIX/etc/nsswitch.conf..."
    cat > "$PREFIX/etc/nsswitch.conf" << 'EOF'
# Created by termux-etc-redirect.
# Tells Go's pure resolver to check /etc/hosts before DNS.
hosts: files dns
EOF
fi

# Ensure resolv.conf exists with working nameservers.
if [ ! -f "$PREFIX/etc/resolv.conf" ]; then
    echo "Creating $PREFIX/etc/resolv.conf..."
    cat > "$PREFIX/etc/resolv.conf" << 'EOF'
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF
fi

echo ""
echo "Installation complete."
echo ""
echo "Tier 1 (LD_PRELOAD for dynamic binaries):"
echo "  Add to your shell profile:"
echo "    export LD_PRELOAD=\"$PREFIX/lib/libtermux-etc-redirect.so\${LD_PRELOAD:+:\$LD_PRELOAD}\""
echo ""
echo "Tier 2 (seccomp for static binaries):"
echo "  Use as a wrapper:"
echo "    termux-etc-seccomp <command> [args...]"
echo "  Example:"
echo "    termux-etc-seccomp terraform init"
