#!/bin/bash
# build-deb.sh — Génère les deux paquets .deb :
#   - keysas-firewall_*.deb       (daemon + udev + polkit + D-Bus)
#   - keysas-tray-app_*.deb       (interface graphique + autostart)
#
# Prérequis communs :
#   rustup toolchain install stable
#   cargo install cargo-deb
#   apt install -y libudev-dev pkg-config
#
# Prérequis tray-app (Tauri 2, Ubuntu 22.04+) :
#   apt install -y libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev
#   node / npm (ex. via nvm ou nodejs >= 18)
#
# Usage :
#   ./build-deb.sh            # compile tout et génère les deux .deb
#   ./build-deb.sh --no-tray  # génère uniquement le .deb du daemon

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_DIR="$SCRIPT_DIR/daemon"
TRAY_DIR="$SCRIPT_DIR/tray-app"

BUILD_TRAY=true
for arg in "$@"; do
    [[ "$arg" == "--no-tray" ]] && BUILD_TRAY=false
done

# ── Prérequis ─────────────────────────────────────────────────────────────────

check_tray_deps() {
    local missing_pkgs=()
    local missing_tools=()

    # pkg-config lui-même
    command -v pkg-config >/dev/null 2>&1 || missing_tools+=("pkg-config")

    # npm / node
    command -v npm >/dev/null 2>&1 || missing_tools+=("npm (nodejs >= 18)")

    # Bibliothèques système via pkg-config
    pkg-config --exists webkit2gtk-4.1               2>/dev/null || missing_pkgs+=("libwebkit2gtk-4.1-dev")
    pkg-config --exists gtk+-3.0                     2>/dev/null || missing_pkgs+=("libgtk-3-dev")
    pkg-config --exists ayatana-appindicator3-0.1    2>/dev/null || missing_pkgs+=("libayatana-appindicator3-dev")

    if [[ ${#missing_pkgs[@]} -gt 0 || ${#missing_tools[@]} -gt 0 ]]; then
        echo "Erreur : prérequis manquants pour la tray-app."
        if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
            echo ""
            echo "  Installer les bibliothèques (Ubuntu 22.04+) :"
            echo "    sudo apt install -y ${missing_pkgs[*]}"
        fi
        if [[ ${#missing_tools[@]} -gt 0 ]]; then
            echo ""
            echo "  Outils manquants : ${missing_tools[*]}"
        fi
        echo ""
        echo "Relancez ./build-deb.sh après installation,"
        echo "ou utilisez ./build-deb.sh --no-tray pour ignorer la tray-app."
        exit 1
    fi
}

# ── Daemon ────────────────────────────────────────────────────────────────────

echo "==> [1/3] Compilation du daemon (release)..."
(
    cd "$DAEMON_DIR"
    cargo build --release
)

echo "==> [2/3] Compression de la page de manuel..."
gzip -k -f "$DAEMON_DIR/pkg/keysas-usbfilter-daemon.8"

echo "==> [3/3] Génération du paquet .deb (daemon)..."
(
    cd "$DAEMON_DIR"
    cargo deb --no-build
)

DAEMON_DEB=$(find "$DAEMON_DIR/target/debian" -name "keysas-firewall_*.deb" | sort | tail -1)

# ── Tray-app ──────────────────────────────────────────────────────────────────

if $BUILD_TRAY; then
    check_tray_deps

    echo ""
    echo "==> [4/5] Installation des dépendances frontend..."
    (
        cd "$TRAY_DIR"
        npm ci
    )

    echo "==> [5/5] Génération du paquet .deb (tray-app)..."
    (
        cd "$TRAY_DIR"
        npm run tauri build -- --bundles deb
    )

    TRAY_DEB=$(find "$TRAY_DIR/src-tauri/target/release/bundle/deb" -name "*.deb" | sort | tail -1)
fi

# ── Résumé ───────────────────────────────────────────────────────────────────

echo ""
echo "Paquets générés :"
echo "  $DAEMON_DEB"
$BUILD_TRAY && echo "  $TRAY_DEB"
echo ""
echo "Installation :"
echo "  sudo apt install ./$DAEMON_DEB"
$BUILD_TRAY && echo "  sudo apt install ./$TRAY_DEB"
echo ""
echo "Post-installation daemon :"
echo "  # Déposer les certificats dans /etc/keysas/firewall/"
echo "  systemctl enable --now keysas-firewall"
