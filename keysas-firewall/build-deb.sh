#!/bin/bash
# build-deb.sh — Génère le paquet keysas-firewall_*.deb
#
# Prérequis :
#   rustup toolchain install nightly
#   rustup component add rust-src --toolchain nightly
#   cargo install bpf-linker
#   cargo install cargo-deb
#   apt install -y libudev-dev clang llvm
#
# Prérequis tray-app (si on compile aussi la tray-app) :
#   apt install -y libsoup2.4-dev libgtk-3-dev libwebkit2gtk-4.1-dev nodejs
#
# Usage :
#   ./build-deb.sh            # build debug eBPF + release daemon
#   ./build-deb.sh --release  # build release eBPF + release daemon

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EBPF_DIR="$SCRIPT_DIR/ebpfilter"
DAEMON_DIR="$SCRIPT_DIR/daemon"
RELEASE_FLAG=""

if [[ "${1:-}" == "--release" ]]; then
    RELEASE_FLAG="--release"
fi

echo "==> [1/3] Compilation du programme eBPF..."
(
    cd "$EBPF_DIR"
    cargo xtask build-ebpf $RELEASE_FLAG
)

echo "==> [2/3] Compilation du daemon (release)..."
(
    cd "$DAEMON_DIR"
    cargo build --release
)

echo "==> [3/4] Compression de la page de manuel..."
gzip -k -f "$DAEMON_DIR/pkg/keysas-usbfilter-daemon.8"

echo "==> [4/4] Génération du paquet .deb..."
(
    cd "$DAEMON_DIR"
    cargo deb --no-build
)

DEB=$(find "$DAEMON_DIR/target/debian" -name "keysas-firewall_*.deb" | sort | tail -1)
echo ""
echo "Paquet généré : $DEB"
echo ""
echo "Installation :"
echo "  apt install ./$DEB"
echo "  # Déposer les certificats dans /etc/keysas/firewall/"
echo "  systemctl enable --now keysas-firewall"
