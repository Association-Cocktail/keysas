# Keysas USB Firewall — Installation et utilisation (Linux)

> **Statut** : implémentation Linux en cours (branche `cert-agent`).
> La partie Windows (minifilter, service SCM) est documentée séparément.

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Architecture](#2-architecture)
3. [Compilation](#3-compilation)
   - [3.1 Programme eBPF](#31-programme-ebpf)
   - [3.2 Daemon userspace](#32-daemon-userspace)
4. [Packaging Debian (.deb)](#4-packaging-debian-deb)
5. [Certificats](#5-certificats)
6. [Fichier de configuration](#6-fichier-de-configuration)
7. [Déploiement manuel](#7-déploiement-manuel)
   - [7.1 Installation des fichiers](#71-installation-des-fichiers)
   - [7.2 Service systemd](#72-service-systemd)
8. [Utilisation](#8-utilisation)
   - [7.1 Lancement manuel](#71-lancement-manuel)
   - [7.2 Comportement à l'insertion d'une clé USB](#72-comportement-à-linsertion-dune-clé-usb)
   - [7.3 Politique de sécurité](#73-politique-de-sécurité)
8. [Journaux et diagnostic](#8-journaux-et-diagnostic)
9. [Limitations connues](#9-limitations-connues)

---

## 1. Prérequis

### Système

| Composant | Version minimale | Notes |
|---|---|---|
| Linux kernel | **5.15** | BTF activé (`CONFIG_DEBUG_INFO_BTF=y`), LSM eBPF (`CONFIG_BPF_LSM=y`) |
| Debian / Ubuntu | Bullseye+ / 22.04+ | BTF activé par défaut |
| udev | toute version récente | fourni par `systemd` |
| systemd | toute version récente | pour le service |

Vérifier que le noyau supporte eBPF LSM :

```bash
# BTF présent
ls /sys/kernel/btf/vmlinux

# LSM eBPF activé
cat /sys/kernel/security/lsm | grep -o bpf

# Monter le BPF filesystem si absent
mount -t bpf bpf /sys/fs/bpf
```

### Outillage de compilation

```bash
# Rust nightly (requis pour le programme eBPF)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Linker BPF
cargo install bpf-linker

# Dépendances système — daemon (Debian/Ubuntu)
apt install -y libudev-dev clang llvm pkg-config

# Dépendances système — tray-app (Debian/Ubuntu)
# libsoup-2.4, GTK 3 et WebKitGTK requis par Tauri
apt install -y libsoup2.4-dev libgtk-3-dev \
    libwebkit2gtk-4.1-dev || \
apt install -y libsoup2.4-dev libgtk-3-dev \
    libwebkit2gtk-4.0-dev
# Node.js requis par Tauri pour compiler le frontend
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt install -y nodejs
```

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Espace utilisateur                                     │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  keysas-usbfilter-daemon                         │  │
│  │                                                  │  │
│  │  ServiceController                               │  │
│  │   ├─ LinuxUsbMonitor  (udev → authorize_usb)    │  │
│  │   ├─ LinuxFileFilterInterface (aya → POLICY_MAP) │  │
│  │   └─ LinuxGuiInterface (D-Bus)                   │  │
│  └─────────────────┬────────────────────────────────┘  │
│                    │ BPF map (pinned /sys/fs/bpf/keysas)│
└────────────────────┼────────────────────────────────────┘
                     │
┌────────────────────┼────────────────────────────────────┐
│  Espace noyau      │                                    │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Programme eBPF LSM  (hook file_open)           │   │
│  │                                                 │   │
│  │  Pour chaque ouverture de fichier :             │   │
│  │   1. bpf_d_path → chemin du fichier             │   │
│  │   2. Cherche un préfixe dans POLICY_MAP         │   │
│  │   3. Si trouvé → applique la décision           │   │
│  │       Block      → -EACCES                      │   │
│  │       AllowRead  → -EACCES si écriture          │   │
│  │       AllowRW+   → 0 (autorisé)                 │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Flux complet à l'insertion d'une clé USB :**

```
Insertion clé USB
  → événement udev (partition/add)
  → lecture signature à l'offset 512 du MBR
  → authorize_usb() : vérification Ed25519 + ML-DSA87 contre CA USB
  → décision (Block / AllowRead / AllowRW / AllowAll)
  → attente montage (/proc/mounts, max 30 s)
  → update_usb() : insertion dans POLICY_MAP
     clé   = point de montage (ex: "/media/user/KEYSAS", null-padé 64 octets)
     valeur = décision (u32)
  → eBPF file_open applique la décision à chaque accès fichier
```

---

## 3. Compilation

### 3.1 Programme eBPF

Le programme eBPF doit être compilé **en premier** car le daemon l'embarque en tant que bytes au moment de sa propre compilation.

```bash
cd keysas-firewall/ebpfilter

# Build debug
cargo xtask build-ebpf

# Build release
cargo xtask build-ebpf --release
```

Les artefacts générés :
- `target/bpfel-unknown-none/debug/lsm-file`
- `target/bpfel-unknown-none/release/lsm-file`

### 3.2 Daemon userspace

```bash
cd keysas-firewall/daemon

# Build debug
cargo build

# Build release
cargo build --release
```

Binaire produit : `target/release/keysas-usbfilter-daemon`

> **Note** : le daemon embarque le binaire eBPF via `include_bytes_aligned!`. Si le programme eBPF n'a pas été compilé au préalable, le build du daemon échoue.

---

## 4. Packaging Debian (.deb)

La méthode recommandée pour déployer le firewall sur plusieurs postes est de générer un `.deb`.

### Prérequis supplémentaires

```bash
cargo install cargo-deb
```

### Générer le paquet

```bash
# Depuis la racine keysas-firewall/
./build-deb.sh

# Build release du programme eBPF + release daemon
./build-deb.sh --release
```

Le `.deb` est produit dans `daemon/target/debian/keysas-firewall_<version>_amd64.deb`.

### Contenu du paquet

| Chemin installé | Contenu |
|---|---|
| `/usr/bin/keysas-usbfilter-daemon` | Daemon (binaire eBPF embarqué) |
| `/etc/keysas/firewall/keysas-firewall-conf.toml` | Configuration par défaut (mode restrictif) |
| `/lib/systemd/system/keysas-firewall.service` | Unité systemd |

### Dépendances déclarées dans le `.deb`

`cargo-deb` utilise `ldd` pour détecter automatiquement les bibliothèques dynamiques liées au binaire et les résout en paquets Debian. Dépendances typiques :

- `libc6` (≥ 2.17)
- `libudev1` (≥ 204) — monitoring USB via udev
- `systemd` — requis pour le service

### Installation

```bash
apt install ./daemon/target/debian/keysas-firewall_*.deb

# Déposer ensuite les certificats (voir section 5)
# puis activer le service
systemctl enable --now keysas-firewall
```

### Désinstallation

```bash
apt remove keysas-firewall       # conserve /etc/keysas/firewall/
apt purge  keysas-firewall       # supprime la config (mais pas les certificats)
```

---

## 5. Certificats

Le daemon nécessite **quatre certificats** au format PEM :

| Paramètre | Description | Exemple de chemin |
|---|---|---|
| `--ca_cl` | CA station — clé publique Ed25519 | `/etc/keysas/firewall/st-ca-cl.pem` |
| `--ca_pq` | CA station — clé publique ML-DSA87 | `/etc/keysas/firewall/st-ca-pq.pem` |
| `--usb_cl` | CA USB — clé publique Ed25519 | `/etc/keysas/firewall/usb-ca-cl.pem` |
| `--usb_pq` | CA USB — clé publique ML-DSA87 | `/etc/keysas/firewall/usb-ca-pq.pem` |

Les CA USB sont générés et gérés par `keysas-admin`. Les clés publiques sont à exporter depuis l'interface d'administration et déposées sur le poste de travail.

**Rôle de chaque CA :**

- **CA station** (`st-ca-*`) : valide les rapports d'analyse `.krp` produits par la station keysas. Utilisé pour vérifier les fichiers transférés.
- **CA USB** (`usb-ca-*`) : valide la signature hybride inscrite à l'offset 512 du MBR des clés USB enrôlées. C'est ce qui distingue une clé autorisée d'une clé inconnue.

---

## 6. Fichier de configuration

Créer `/etc/keysas/firewall/keysas-firewall-conf.toml` :

```toml
# Politique de sécurité du pare-feu USB Keysas
# Toutes les valeurs sont optionnelles et valent false par défaut.

# Si true : les clés USB non signées sont autorisées (mode permissif).
# ATTENTION : désactive la vérification de signature.
disable_unsigned_usb = false

# Si true : l'utilisateur peut manuellement autoriser une clé non signée
# via l'interface graphique (tray-app). Sans effet si disable_unsigned_usb = true.
allow_user_usb_authorization = false

# Si true : l'utilisateur peut autoriser la lecture d'un fichier sans rapport .krp valide.
allow_user_file_read = false

# Si true : l'utilisateur peut autoriser l'écriture sur la clé USB.
# Requiert allow_user_file_read = true.
allow_user_file_write = false
```

**Matrice de comportement selon la politique :**

| Clé signée | `disable_unsigned_usb` | `allow_user_file_write` | Résultat |
|---|---|---|---|
| Oui | — | false | Lecture seule (AllowRead) |
| Oui | — | true | Lecture + écriture (AllowRW) |
| Non | false | — | Bloquée (Block) |
| Non | true | — | Accès complet (AllowAll) |

---

## 7. Déploiement manuel

### 6.1 Installation des fichiers

```bash
# Répertoires
install -d /etc/keysas/firewall
install -d /usr/local/lib/keysas
install -d /var/log/keysas

# Binaire
install -m 755 target/release/keysas-usbfilter-daemon /usr/local/bin/

# Certificats (depuis keysas-admin)
install -m 640 st-ca-cl.pem  /etc/keysas/firewall/
install -m 640 st-ca-pq.pem  /etc/keysas/firewall/
install -m 640 usb-ca-cl.pem /etc/keysas/firewall/
install -m 640 usb-ca-pq.pem /etc/keysas/firewall/

# Configuration
install -m 640 keysas-firewall-conf.toml /etc/keysas/firewall/

# Montage BPF filesystem au démarrage (si non déjà configuré)
echo 'bpf /sys/fs/bpf bpf defaults 0 0' >> /etc/fstab
```

### 6.2 Service systemd

Créer `/etc/systemd/system/keysas-firewall.service` :

```ini
[Unit]
Description=Keysas USB Firewall Daemon
Documentation=https://github.com/Association-Cocktail/keysas
After=systemd-udev-settle.service sys-fs-bpf.mount
Requires=sys-fs-bpf.mount

[Service]
Type=simple
ExecStart=/usr/local/bin/keysas-usbfilter-daemon \
    --config /etc/keysas/firewall/keysas-firewall-conf.toml \
    --ca_cl  /etc/keysas/firewall/st-ca-cl.pem \
    --ca_pq  /etc/keysas/firewall/st-ca-pq.pem \
    --usb_cl /etc/keysas/firewall/usb-ca-cl.pem \
    --usb_pq /etc/keysas/firewall/usb-ca-pq.pem

# Le daemon doit charger des programmes eBPF — accès root requis
User=root
Restart=on-failure
RestartSec=5

# Journalisation
StandardOutput=journal
StandardError=journal
SyslogIdentifier=keysas-firewall

[Install]
WantedBy=multi-user.target
```

Activer et démarrer :

```bash
systemctl daemon-reload
systemctl enable --now keysas-firewall
systemctl status keysas-firewall
```

---

## 8. Utilisation

### 7.1 Lancement manuel

```bash
keysas-usbfilter-daemon \
    --config /etc/keysas/firewall/keysas-firewall-conf.toml \
    --ca_cl  /etc/keysas/firewall/st-ca-cl.pem \
    --ca_pq  /etc/keysas/firewall/st-ca-pq.pem \
    --usb_cl /etc/keysas/firewall/usb-ca-cl.pem \
    --usb_pq /etc/keysas/firewall/usb-ca-pq.pem
```

Options complètes :

```
Usage: keysas-usbfilter-daemon [OPTIONS]

Options:
  -c, --config <fichier>   Politique de sécurité TOML   [défaut: ./keysas-firewall-conf.toml]
  -l, --ca_cl  <fichier>   CA station Ed25519 (PEM)     [défaut: ./st-ca-cl.pem]
  -q, --ca_pq  <fichier>   CA station ML-DSA87 (PEM)    [défaut: ./st-ca-pq.pem]
      --usb_cl <fichier>   CA USB Ed25519 (PEM)          [défaut: ./usb-ca-cl.pem]
      --usb_pq <fichier>   CA USB ML-DSA87 (PEM)         [défaut: ./usb-ca-pq.pem]
  -h, --help               Afficher l'aide
  -V, --version            Afficher la version
```

### 7.2 Comportement à l'insertion d'une clé USB

1. **Clé signée et enrôlée** (`disable_unsigned_usb = false`)
   Le daemon lit la signature hybride à l'offset 512 du MBR.
   La signature est vérifiée contre le CA USB.
   - Succès → point de montage inséré dans la POLICY_MAP avec `AllowRead` ou `AllowRW`
   - Échec → `Block` → tout accès fichier retourne `EACCES`

2. **Clé non signée** (`disable_unsigned_usb = false`)
   → `Block` immédiat. La clé peut être montée par le système mais eBPF bloque tous les accès fichiers.

3. **Mode permissif** (`disable_unsigned_usb = true`)
   → `AllowAll` sans vérification de signature. Toutes les clés USB sont accessibles.

### 7.3 Politique de sécurité

Modifier `/etc/keysas/firewall/keysas-firewall-conf.toml` puis redémarrer le service :

```bash
systemctl restart keysas-firewall
```

> Les décisions déjà présentes dans la POLICY_MAP (clés actuellement montées)
> ne sont pas rétroactivement mises à jour. Redémarrer le service recharge
> la politique proprement.

---

## 9. Journaux et diagnostic

```bash
# Journaux du daemon
journalctl -u keysas-firewall -f

# Journaux eBPF (nécessite bpftool ou bpf_trace_printk)
cat /sys/kernel/debug/tracing/trace_pipe

# Vérifier que le hook LSM est chargé
bpftool prog list | grep file_open

# Inspecter la POLICY_MAP
bpftool map show pinned /sys/fs/bpf/keysas/POLICY_MAP
bpftool map dump pinned /sys/fs/bpf/keysas/POLICY_MAP

# Vérifier que le BPF filesystem est monté
mount | grep bpf
ls /sys/fs/bpf/keysas/
```

**Erreurs fréquentes :**

| Erreur | Cause probable | Solution |
|---|---|---|
| `Failed to open POLICY_MAP` | eBPF pas encore chargé | Attendre le démarrage complet du daemon |
| `No public key found in USB CA certificates` | Mauvais fichier PEM | Vérifier le chemin `--usb_cl` / `--usb_pq` |
| `Failed to load eBPF program` | Noyau sans BTF ou sans `CONFIG_BPF_LSM` | Vérifier `/sys/kernel/btf/vmlinux` et `cat /sys/kernel/security/lsm` |
| `ppoll error` | udev non disponible | Vérifier que udev/systemd-udev est actif |
| Clé USB accessible malgré Block | eBPF non chargé | `bpftool prog list` pour vérifier |

---

## 10. Limitations connues

| # | Limitation | Contournement / plan |
|---|---|---|
| 1 | Le programme eBPF inspecte les 64 premiers octets du chemin. Les points de montage > 63 caractères ne sont pas reconnus. | Utiliser des chemins courts ; augmenter `PATH_LENGTH` dans `lsm-file-ebpf/src/main.rs` |
| 2 | `update_usb_auth()` du monitor (remontage forcé) n'est pas implémenté. | Priorité 3 complétée pour le stop ; le remontage est prévu (priorité 5) |
| 3 | L'interface GUI D-Bus (`linux/gui_interface.rs`) est vide. L'utilisateur ne peut pas autoriser manuellement une clé même si `allow_user_usb_authorization = true`. | Priorité 5 du plan d'implémentation |
| 4 | Le daemon doit tourner en root pour charger des programmes eBPF. | Envisager `CAP_BPF` + `CAP_NET_ADMIN` via capabilities Linux |
| 5 | La décision dans la POLICY_MAP n'est pas mise à jour si la politique change à chaud. | Redémarrer le service après modification du fichier TOML |
