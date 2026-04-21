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

# ── Vérification des outils essentiels ───────────────────────────────────────

for tool in npm rustc fakeroot; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Erreur : '$tool' introuvable."; exit 1; }
done

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> [1/2] Installation des dépendances frontend..."
(
    cd "$SCRIPT_DIR"
    npm ci
)

echo "==> [2/2] Génération du paquet .deb (Tauri)..."
(
    cd "$SCRIPT_DIR"
    fakeroot npx tauri build --bundles deb
)

DEB=$(find "$SCRIPT_DIR/src-tauri/target/release/bundle/deb" -name "*.deb" | sort | tail -1)

# ── Résumé ───────────────────────────────────────────────────────────────────

echo ""
echo "Paquet généré :"
echo "  $DEB"
echo ""
echo "Installation :"
echo "  sudo apt install ./$DEB"
