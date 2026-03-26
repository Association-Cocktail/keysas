<div align="center">
<img  src ="img/logo-keysas-github.png"  alt="Keysas"  width=300px/>
</div>

# USB virus cleaning station

# 🚀 Main Features

- **File Retrieval**
  - From unsigned/untrusted USB keys (via **keysas-io**)
  - From remote network sources

- **Multi-layer File Scanning**
  - ClamAV antivirus integration
  - YARA rules parsing
  - File extension, type and size checks
  - **Specialized file analysis** (via **keysas-analyze**):
    - PE/ELF executables (via Detect-It-Easy)
    - PDF documents (via pdfid)
    - Office files — OLE and OpenXML (via oletools)
    - Archives — ZIP, tar, gzip, bzip2, xz (recursive inspection)
    - Scripts — shell, PowerShell, VBS
    - ISO images
    - Windows LNK shortcuts
  - **VirusTotal integration** (via **keysas-virustotal**): optional cloud lookup with configurable block threshold and cache

- **Real-time Progress Tracking**
  - `keysas-in` and `keysas-transit` publish live progress to `/run/keysas-{in,transit}/progress.json`
  - The frontend displays per-file progress bars and per-check status icons (hash, size, type, AV, YARA, specialized analysis, VirusTotal)

- **Digital Signatures**
  - All scanned files and USB devices can be signed
  - Uses **hybrid post-quantum signature** (Ed25519 + ML-DSA-87)
  - Private keys stored in PKCS#8 format
  - Certificates issued and managed by **keysas-admin** internal PKI
  - Each verified file gets a **.krp** report; the report-writing policy is configurable (`--krp_mode always|never|pass_only|fail_only`)

- **Authentication**
  - Support for user authentication using YubiKey 5 (via **keysas-fido**)

---

# 🔒 Security
  This project underwent a **professional security audit** conducted by [Amossys](https://www.amossys.fr/) an external company specialized in cybersecurity.

  Since this audit, all security patches have been applied to the current v2.6. See SECURITY.md for more information.

---

# Keysas-core

## 🧱 Architecture Overview

<div align="center">
<img  src ="img/keysas-core-architecture.png"  alt="keysas-core architecture"  width=900px/>
</div>


- Daemons communicate via **abstract sockets** and **raw file descriptors** (Linux only)
- Each daemon adds **metadata** and passes the file to the next
- `keysas-transit` can optionally call **keysas-analyze** (specialized analysis) and **keysas-virustotal** (cloud lookup) via abstract sockets
- The last daemon (`keysas-out`) determines if the file is accepted and writes it to the output directory (`sas_out`)
- A detailed **report** is generated for every file; `keysas-out-idle` (systemd timer) handles cleanup when no files are in transit
- A detailed **report** is generated for every file


## 🔒 Daemons Security Hardening

- Run as **unprivileged users** (`keysas-in`, `keysas-transit`, `keysas-out`, `keysas-analyze`, `keysas-virustotal`)
- Isolated using:
  - **Systemd** security drop-in
  - **Landlock** sandbox
  - **Seccomp** filters (x86_64 & aarch64)

---

## 🧩 Project Components

| Name                    | Description |
|-------------------------|-------------|
| **keysas-core**         | Core daemon pipeline for file scanning and report generation |
| **keysas-analyze**      | Specialized file analyzer daemon (PE, PDF, Office, archives, scripts, ISO, LNK) |
| **keysas-virustotal**   | VirusTotal lookup daemon with caching and configurable block threshold |
| **keysas-io**           | Monitors USB device insertions and verifies signatures (via `udev`) |
| **keysas-admin**        | Desktop GUI (Tauri) to manage devices, issue certificates and sign USB keys |
| **keysas-sign**         | CLI tool to import PEM certificates and manage signatures |
| **keysas-fido**         | CLI tool for managing YubiKey 5 user enrollment |
| **keysas-backend**      | WebSocket backend providing data and progress to frontend |
| **keysas-frontend**     | Read-only Vue.js interface for end-users |
| **keysas-firewall**     | (WIP) Windows app to verify file origin from a Keysas station |

---

## Build && Installation


### 🐧 On Debian stable (Trixie):

```bash
sudo apt -qy install -y libyara-dev libyara10 wget cmake make lsb-release libseccomp-dev clamav-daemon clamav-freshclam pkg-config git bash libudev-dev libwebkit2gtk-4.1-dev build-essential curl wget libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev acl xinit sudo
sudo bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
source "$HOME/.cargo/env"
git clone --depth=1 https://github.com/keysas-fr/keysas && cd keysas
rustup default nightly
make help
make build
sudo make install
```

`sudo make install` also installs the external tools required by **keysas-analyze**:
- **oletools** (`olevba`) — Office document analysis
- **pdfid** (Didier Stevens) — PDF structure analysis
- **Detect-It-Easy** (`diec`) — PE/ELF executable identification

### ⚙️ keysas-virustotal configuration

Edit `/etc/keysas/keysas-virustotal.conf` after installation to set your API key and policy:

```ini
VT_API_KEY=<your_virustotal_api_v3_key>
VT_BLOCK_THRESHOLD=3       # number of malicious detections to block a file
VT_FAIL_OPEN=true          # pass the file if VT is unreachable
VT_TIMEOUT_MS=3000         # HTTP timeout in milliseconds
VT_CACHE_TTL_SECS=3600     # cache duration in seconds
```

Leave `VT_API_KEY` empty to disable VirusTotal lookups entirely.

## User documentation & SBOMs

Latest versions of:

    User Documentation

    Software Bill of Materials (SBOMs)

...are auto-generated via GitHub Actions and available here: [https://keysas-fr.github.io/keysas/](https://keysas-fr.github.io/keysas/)

---
