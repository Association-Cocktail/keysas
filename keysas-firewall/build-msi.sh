#!/bin/bash
# build-msi.sh — Génère le MSI du daemon Keysas Firewall via Docker
#
# Stratégie :
#   1. Cross-compile le daemon pour x86_64-pc-windows-gnu (MinGW dans le
#      conteneur Docker).
#   2. Empaquète le binaire en .msi via wixl (implémentation Linux de WiX v3).
#
# Prérequis hôte :
#   docker (Engine ou Desktop)
#
# Usage :
#   ./build-msi.sh [--output <répertoire>]
#
#   --output  Répertoire de sortie du .msi  (défaut : ./dist)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Le contexte Docker doit être la racine du dépôt (parent de keysas-firewall/)
# car le Dockerfile copie keysas_lib/ et keysas-firewall/ comme frères.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="keysas-firewall/daemon/Dockerfile.msi"
OUTPUT_DIR="$SCRIPT_DIR/dist"

# ── Parsing des arguments ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_DIR="$(realpath "$2")"
            shift 2
            ;;
        -h|--help)
            sed -n '2,/^set/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Option inconnue : $1" >&2
            exit 1
            ;;
    esac
done

# ── Vérifications préalables ──────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "Erreur : docker n'est pas installé ou pas dans le PATH." >&2
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "Erreur : le daemon Docker n'est pas accessible (permissions ou non démarré)." >&2
    exit 1
fi

if [[ ! -f "$REPO_ROOT/$DOCKERFILE" ]]; then
    echo "Erreur : $REPO_ROOT/$DOCKERFILE introuvable." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> Contexte Docker : $REPO_ROOT"
echo "==> Dockerfile      : $DOCKERFILE"
echo "==> Sortie          : $OUTPUT_DIR"
echo ""
echo "==> Lancement du build Docker..."

docker build \
    --file  "$REPO_ROOT/$DOCKERFILE" \
    --output "type=local,dest=$OUTPUT_DIR" \
    "$REPO_ROOT"

# ── Résultat ─────────────────────────────────────────────────────────────────
MSI=$(find "$OUTPUT_DIR" -maxdepth 1 -name "keysas-firewall-*.msi" | sort | tail -1)

if [[ -z "$MSI" ]]; then
    echo ""
    echo "Erreur : aucun fichier .msi trouvé dans $OUTPUT_DIR" >&2
    exit 1
fi

echo ""
echo "MSI généré : $MSI"
echo ""
echo "Installation silencieuse sur Windows :"
echo "  msiexec /i \"$(basename "$MSI")\" /quiet"
echo ""
echo "Désinstallation :"
echo "  msiexec /x \"$(basename "$MSI")\" /quiet"
