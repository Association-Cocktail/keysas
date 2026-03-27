# Keysas USB Firewall

Le pare-feu USB Keysas s'installe sur les postes de travail pour garantir que :

- Les clés USB connectées ont été enrôlées dans le système (signées par le CA USB de `keysas-admin`)
- Les fichiers sur les clés USB ont été validés par une station Keysas (rapport `.krp` signé)

Supporte **Windows** et **Linux**.

---

## Architecture

Le pare-feu est composé de plusieurs éléments selon la plateforme :

### Linux

```
Espace utilisateur
├── keysas-usbfilter-daemon
│   ├── LinuxUsbMonitor        — écoute udev, lit la signature MBR, décide (Block/AllowRead/AllowRW)
│   ├── LinuxFileFilterInterface — met à jour la POLICY_MAP eBPF via syscall bpf(2)
│   └── LinuxGuiInterface      — expose l'interface D-Bus (fr.asso-cocktail.keysas.Firewall1)
└── tray-app (Tauri)
    └── LinuxServiceInterface  — interroge le daemon via D-Bus toutes les 5 s

Espace noyau
└── Programme eBPF LSM (hook file_open)
    └── POLICY_MAP : point de montage → décision
        Block      → -EACCES (lecture et écriture)
        AllowRead  → -EACCES (écriture uniquement)
        AllowRW+   → 0 (autorisé)
```

### Windows

```
Espace noyau
├── Pilote filtre bus USB  — intercepte les connexions USB
└── Minifilter            — intercepte les appels système vers le système de fichiers

Espace utilisateur
├── Service Windows (SCM)  — supervise les pilotes, vérifie fichiers et rapports
└── Tray app (Tauri)       — interface utilisateur dans la barre système
```

---

## Politique de sécurité

| Paramètre | Valeur par défaut | Description |
|---|---|---|
| `disable_unsigned_usb` | `false` | Si `true`, les clés non signées sont autorisées sans vérification |
| `allow_user_usb_authorization` | `false` | Si `true`, l'utilisateur peut manuellement autoriser une clé non signée |
| `allow_user_file_read` | `false` | Si `true`, l'utilisateur peut autoriser la lecture d'un fichier sans rapport valide |
| `allow_user_file_write` | `false` | Si `true`, l'utilisateur peut autoriser l'écriture. Requiert `allow_user_file_read = true` |

Si un paramètre est absent, il vaut `false`.

**Linux** : configuration via `/etc/keysas/firewall/keysas-firewall-conf.toml`

**Windows** : configuration via le registre `HKLM\SYSTEM\CurrentControlSet\Services\Keysas Service\config` (configuré automatiquement par l'installeur)

---

## Certificats

Le daemon nécessite quatre certificats CA au format **PEM X.509** (cryptographie hybride Ed25519 + ML-DSA87) :

| Fichier attendu | Rôle |
|---|---|
| `st-ca-cl.pem` | CA station — Ed25519 (valide les rapports `.krp`) |
| `st-ca-pq.pem` | CA station — ML-DSA87 (valide les rapports `.krp`) |
| `usb-ca-cl.pem` | CA USB — Ed25519 (valide la signature MBR des clés USB) |
| `usb-ca-pq.pem` | CA USB — ML-DSA87 (valide la signature MBR des clés USB) |

Ces certificats sont générés et gérés par `keysas-admin`. Pour les déployer sur un poste :

```bash
# Depuis le poste admin, copier les certificats publics (.pem uniquement, pas les .p8)
scp {PKI_DIR}/CA/st/st-ca-cl.pem   keysas@POSTE:/etc/keysas/firewall/st-ca-cl.pem
scp {PKI_DIR}/CA/st/st-ca-pq.pem   keysas@POSTE:/etc/keysas/firewall/st-ca-pq.pem
scp {PKI_DIR}/CA/usb/usb-cl.pem    keysas@POSTE:/etc/keysas/firewall/usb-ca-cl.pem
scp {PKI_DIR}/CA/usb/usb-pq.pem    keysas@POSTE:/etc/keysas/firewall/usb-ca-pq.pem
```

**Windows** : chemins configurés dans le registre (`StCaClCert`, `StCaPqCert`, `UsbCaClCert`, `UsbCaPqCert`).

---

## Installation Linux

Voir [INSTALL.md](INSTALL.md) pour les instructions complètes.

### Méthode recommandée — paquet Debian

```bash
# Prérequis
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo install cargo-deb
apt install -y libudev-dev clang llvm pkg-config

# Générer le .deb (depuis keysas-firewall/)
./build-deb.sh

# Installer
apt install ./daemon/target/debian/keysas-firewall_*.deb

# Déposer les certificats dans /etc/keysas/firewall/
# puis activer le service
systemctl enable --now keysas-firewall
```

### Ligne de commande du daemon

```
keysas-usbfilter-daemon [OPTIONS]

Options:
  -c, --config <fichier>   Politique de sécurité TOML   [défaut: ./keysas-firewall-conf.toml]
  -l, --ca_cl  <fichier>   CA station Ed25519 (PEM)     [défaut: ./st-ca-cl.pem]
  -q, --ca_pq  <fichier>   CA station ML-DSA87 (PEM)    [défaut: ./st-ca-pq.pem]
      --usb_cl <fichier>   CA USB Ed25519 (PEM)          [défaut: ./usb-ca-cl.pem]
      --usb_pq <fichier>   CA USB ML-DSA87 (PEM)         [défaut: ./usb-ca-pq.pem]
```

---

## Installation Windows

### Prérequis

- Rust : <https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup>
- Clang (pour bindgen) : <https://rust-lang.github.io/rust-bindgen/requirements.html>
- CMake : <https://cmake.org/>
- Node.js / npm : <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm>
- Tauri : <https://tauri.app/>
- Visual Studio 2022 avec SDK et WDK 10.0.22621.0 (pour les pilotes)
- Inno Setup : <https://jrsoftware.org/>

### Compilation des pilotes

Les pilotes (bus filter + minifilter) sont compilés avec Visual Studio 2022 et ont été testés sur Windows 10 en mode debug (pilote non signé autorisé).

### Création de l'installeur

Une fois tous les artefacts compilés (minifilter, pilote, service, tray-app), générer l'installeur avec Inno Setup en utilisant le script `installer/keysas_firewall_install.iss`.

---

## Intégration continue

Une pipeline GitHub Actions valide le build à chaque PR ou push sur `main`/`develop` :

- **build-ebpf** — compile le programme eBPF (toolchain nightly)
- **check-daemon** — `cargo check` sur le daemon Linux (dépend de build-ebpf)
- **check-tray-app** — `cargo check` sur la tray-app Linux (toolchain stable)

Voir `.github/workflows/keysas-firewall.yml`.

---

## État d'avancement

### Linux

- [x] Monitoring USB via udev
- [x] Vérification de signature hybride (Ed25519 + ML-DSA87) sur les clés USB
- [x] Filtrage des accès fichiers via eBPF LSM (`file_open`)
- [x] Interface D-Bus vers la tray-app
- [x] Tray-app : affichage des clés USB, autorisation manuelle
- [x] Packaging Debian (`.deb`)
- [x] Pipeline CI GitHub Actions
- [ ] Interface IOCTL vers la tray-app pour les fichiers (non implémenté)

### Windows

- [x] Minifilter : interception et filtrage des appels système
- [x] Minifilter : contexte par fichier, filtre open/create/write
- [x] Service Windows : vérification des rapports et fichiers, politique de sécurité
- [x] Installeur Inno Setup
- [ ] Communication IOCTL daemon → minifilter (WIP)
- [ ] Support GPO / MSI
- [ ] Nettoyage minifilter : IRQL, paging, fastIO, sparse files
