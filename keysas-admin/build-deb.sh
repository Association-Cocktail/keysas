#!/bin/bash
# build-deb.sh — Génère le paquet .deb de keysas-admin (application Tauri 2)
#
# Prérequis (Ubuntu 22.04+) :
#   rustup toolchain install stable
#   apt install -y libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
#                  pkg-config build-essential libudev-dev
#   node / npm >= 18 (ex. via nvm)
#
# Usage :
#   ./build-deb.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Vérification des prérequis ────────────────────────────────────────────────

check_deps() {
    local missing_pkgs=()
    local missing_tools=()

    command -v pkg-config >/dev/null 2>&1 || missing_tools+=("pkg-config")
    command -v npm        >/dev/null 2>&1 || missing_tools+=("npm (nodejs >= 18)")
    command -v rustc      >/dev/null 2>&1 || missing_tools+=("rustc (rustup)")

    pkg-config --exists webkit2gtk-4.1            2>/dev/null || missing_pkgs+=("libwebkit2gtk-4.1-dev")
    pkg-config --exists gtk+-3.0                  2>/dev/null || missing_pkgs+=("libgtk-3-dev")
    pkg-config --exists ayatana-appindicator3-0.1 2>/dev/null || missing_pkgs+=("libayatana-appindicator3-dev")

    if [[ ${#missing_pkgs[@]} -gt 0 || ${#missing_tools[@]} -gt 0 ]]; then
        echo "Erreur : prérequis manquants."
        if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
            echo ""
            echo "  Installer les bibliothèques (Ubuntu 22.04+) :"
            echo "    sudo apt install -y ${missing_pkgs[*]}"
        fi
        if [[ ${#missing_tools[@]} -gt 0 ]]; then
            echo ""
            echo "  Outils manquants : ${missing_tools[*]}"
        fi
        exit 1
    fi
}

check_deps

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> [1/2] Installation des dépendances frontend..."
(
    cd "$SCRIPT_DIR"
    npm ci
)

echo "==> [2/2] Génération du paquet .deb (Tauri)..."
(
    cd "$SCRIPT_DIR"
    npm run tauri build -- --bundles deb
)

# ── Résumé ───────────────────────────────────────────────────────────────────

DEB=$(find "$SCRIPT_DIR/src-tauri/target/release/bundle/deb" -name "*.deb" | sort | tail -1)

echo ""
echo "Paquet généré :"
echo "  $DEB"
echo ""
echo "Installation :"
echo "  sudo apt install ./$DEB"
