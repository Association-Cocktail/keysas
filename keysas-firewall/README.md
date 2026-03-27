# Keysas USB Firewall

The Keysas USB firewall runs on end-user workstations to enforce that:

- USB devices connected to the machine have been enrolled in the system (signed by the USB CA from `keysas-admin`)
- Files on USB devices have been validated by a Keysas scanning station (signed `.krp` report)

Supports **Windows** and **Linux**.

---

## Architecture

The firewall components differ by platform:

### Linux

```
Userspace
├── keysas-usbfilter-daemon
│   ├── LinuxUsbMonitor           — listens to udev, reads MBR signature, decides (Block/AllowRead/AllowRW)
│   ├── LinuxFileFilterInterface  — updates the eBPF POLICY_MAP via bpf(2) syscall
│   └── LinuxGuiInterface         — exposes the D-Bus interface (fr.asso-cocktail.keysas.Firewall1)
└── tray-app (Tauri)
    └── LinuxServiceInterface     — polls the daemon over D-Bus every 5 s

Kernel space
└── eBPF LSM program (file_open hook)
    └── POLICY_MAP : mount point → decision
        Block      → -EACCES (all accesses)
        AllowRead  → -EACCES (writes only)
        AllowRW+   → 0 (allowed)
```

### Windows

```
Kernel space
├── USB bus filter driver  — intercepts USB connection events
└── Minifilter             — intercepts filesystem syscalls

Userspace
├── Windows service (SCM)  — supervises drivers, verifies files and reports
└── Tray app (Tauri)       — system tray user interface
```

---

## Security Policy

| Parameter | Default | Description |
|---|---|---|
| `disable_unsigned_usb` | `false` | If `true`, unsigned USB devices are allowed without signature check |
| `allow_user_usb_authorization` | `false` | If `true`, the user can manually allow an unsigned USB device |
| `allow_user_file_read` | `false` | If `true`, the user can manually allow reading a file without a valid report |
| `allow_user_file_write` | `false` | If `true`, the user can manually allow writing to a USB device. Requires `allow_user_file_read = true` |

Missing parameters default to `false`.

**Linux**: configuration file at `/etc/keysas/firewall/keysas-firewall-conf.toml`

**Windows**: registry key `HKLM\SYSTEM\CurrentControlSet\Services\Keysas Service\config` (set automatically by the installer)

---

## Certificates

The daemon requires four CA certificates in **PEM X.509** format (hybrid cryptography: Ed25519 + ML-DSA87):

| Expected file | Role |
|---|---|
| `st-ca-cl.pem` | Station CA — Ed25519 (validates `.krp` reports) |
| `st-ca-pq.pem` | Station CA — ML-DSA87 (validates `.krp` reports) |
| `usb-ca-cl.pem` | USB CA — Ed25519 (validates the MBR signature of enrolled USB devices) |
| `usb-ca-pq.pem` | USB CA — ML-DSA87 (validates the MBR signature of enrolled USB devices) |

Certificates are generated and managed by `keysas-admin`. To deploy them on a workstation:

```bash
# From the admin workstation, copy the public certificates (.pem only, not the .p8 private keys)
scp {PKI_DIR}/CA/st/st-ca-cl.pem   keysas@WORKSTATION:/etc/keysas/firewall/st-ca-cl.pem
scp {PKI_DIR}/CA/st/st-ca-pq.pem   keysas@WORKSTATION:/etc/keysas/firewall/st-ca-pq.pem
scp {PKI_DIR}/CA/usb/usb-cl.pem    keysas@WORKSTATION:/etc/keysas/firewall/usb-ca-cl.pem
scp {PKI_DIR}/CA/usb/usb-pq.pem    keysas@WORKSTATION:/etc/keysas/firewall/usb-ca-pq.pem
```

**Windows**: paths are stored in the registry (`StCaClCert`, `StCaPqCert`, `UsbCaClCert`, `UsbCaPqCert`).

---

## Linux Installation

See [INSTALL.md](INSTALL.md) for full instructions.

### Recommended — Debian package

```bash
# Prerequisites
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo install cargo-deb
apt install -y libudev-dev clang llvm pkg-config

# Build the .deb (from keysas-firewall/)
./build-deb.sh

# Install
apt install ./daemon/target/debian/keysas-firewall_*.deb

# Deploy certificates to /etc/keysas/firewall/
# then enable the service
systemctl enable --now keysas-firewall
```

### Daemon command line

```
keysas-usbfilter-daemon [OPTIONS]

Options:
  -c, --config <file>   Security policy TOML file    [default: ./keysas-firewall-conf.toml]
  -l, --ca_cl  <file>   Station CA Ed25519 (PEM)     [default: ./st-ca-cl.pem]
  -q, --ca_pq  <file>   Station CA ML-DSA87 (PEM)    [default: ./st-ca-pq.pem]
      --usb_cl <file>   USB CA Ed25519 (PEM)          [default: ./usb-ca-cl.pem]
      --usb_pq <file>   USB CA ML-DSA87 (PEM)         [default: ./usb-ca-pq.pem]
```

---

## Windows Installation

### Prerequisites

- Rust: <https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup>
- Clang (for bindgen): <https://rust-lang.github.io/rust-bindgen/requirements.html>
- CMake: <https://cmake.org/>
- Node.js / npm: <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm>
- Tauri: <https://tauri.app/>
- Visual Studio 2022 with SDK and WDK 10.0.22621.0 (for kernel drivers)
- Inno Setup: <https://jrsoftware.org/>

### Driver compilation

The bus filter driver and minifilter are compiled with Visual Studio 2022 and have been tested on Windows 10 in debug mode (unsigned driver allowed).

### Installer creation

Once all build artifacts are ready (minifilter, driver, service, tray-app), build the installer with Inno Setup using the script `installer/keysas_firewall_install.iss`.

---

## Continuous Integration

A GitHub Actions pipeline validates builds on every PR or push to `main`/`develop`:

- **build-ebpf** — compiles the eBPF program (nightly toolchain)
- **check-daemon** — `cargo check` on the Linux daemon (depends on build-ebpf)
- **check-tray-app** — `cargo check` on the Linux tray-app (stable toolchain)

See `.github/workflows/keysas-firewall.yml`.

---

## Status

### Linux

- [x] USB monitoring via udev
- [x] Hybrid signature verification (Ed25519 + ML-DSA87) on USB devices
- [x] File access filtering via eBPF LSM (`file_open`)
- [x] D-Bus interface to the tray-app
- [x] Tray-app: USB device display, manual authorization
- [x] Debian packaging (`.deb`)
- [x] GitHub Actions CI pipeline
- [ ] File-level IOCTL interface for the tray-app (not yet implemented)

### Windows

- [x] Minifilter: syscall interception and filtering
- [x] Minifilter: per-file context, open/create/write filtering
- [x] Windows service: report and file verification, security policy enforcement
- [x] Inno Setup installer
- [ ] IOCTL communication daemon → minifilter (WIP)
- [ ] GPO / MSI support
- [ ] Minifilter cleanup: IRQL, paging, fastIO, sparse files
