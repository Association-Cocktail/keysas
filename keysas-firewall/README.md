# Keysas USB Firewall

The Keysas USB firewall runs on end-user workstations to enforce that:

- USB devices connected to the machine have been enrolled in the system (signed by the USB CA from `keysas-admin`)
- Files on USB devices have been validated by a Keysas scanning station (signed `.krp` report)

Supports **Windows** and **Linux**.

---

## Architecture

### Linux

```
Userspace
├── keysas-usbfilter-daemon
│   ├── LinuxUsbMonitor           — listens to udev events, strips partition suffix to read
│   │                               the MBR signature from the raw disk at offset 512,
│   │                               decides Block / AllowRead / AllowRW
│   │                               → blocked devices: writes 0 to /sys/.../authorized
│   ├── LinuxFileFilterInterface  — updates mount-point policy (read/write permissions)
│   └── LinuxGuiInterface         — exposes the D-Bus interface (fr.asso-cocktail.keysas.Firewall1)
└── tray-app (Tauri)
    └── LinuxServiceInterface     — polls the daemon over D-Bus every 5 s
```

USB blocking uses the kernel USB deauthorization mechanism (`/sys/bus/usb/devices/.../authorized`). No eBPF or kernel module is required.

### Windows

```
Userspace
└── Windows service (SCM)
    ├── WindowsUsbMonitor         — polls GetLogicalDrives() every 500 ms, detects new
    │                               removable drives, maps volume → PhysicalDriveN via
    │                               IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, reads MBR
    │                               signature at offset 512, decides Block / AllowRead / AllowRW
    │                               → blocked devices: FSCTL_LOCK + FSCTL_DISMOUNT + EJECT
    └── WindowsGuiInterface       — (planned) tray-app interface
```

No kernel driver is required. The service runs entirely in userspace.

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

Certificates are generated and managed by `keysas-admin`. To deploy them on a Linux workstation:

```bash
# Copy the public certificates (.pem only, not the .p8 private keys)
scp {PKI_DIR}/CA/st/st-ca-cl.pem   keysas@WORKSTATION:/etc/keysas/firewall/st-ca-cl.pem
scp {PKI_DIR}/CA/st/st-ca-pq.pem   keysas@WORKSTATION:/etc/keysas/firewall/st-ca-pq.pem
scp {PKI_DIR}/CA/usb/usb-cl.pem    keysas@WORKSTATION:/etc/keysas/firewall/usb-ca-cl.pem
scp {PKI_DIR}/CA/usb/usb-pq.pem    keysas@WORKSTATION:/etc/keysas/firewall/usb-ca-pq.pem
```

**Windows**: copy the four `.pem` files to `C:\ProgramData\Keysas\Firewall\` (paths configurable in registry).

---

## Linux Installation

### Recommended — Debian package

```bash
# Prerequisites (stable toolchain only — no nightly required)
apt install -y libudev-dev clang llvm pkg-config
cargo install cargo-deb

# Build the .deb (from keysas-firewall/daemon/)
cargo deb

# Install
apt install ./target/debian/keysas-firewall_*.deb

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

See [docs/installation-windows-msi.md](../docs/installation-windows-msi.md) for the full guide.

### Build the MSI (GitHub Actions / Windows)

The MSI is built automatically by the `build-windows-msi` job in
`.github/workflows/keysas-firewall.yml` on every push to `main`, `develop`,
or `cert-agent`. The artifact `keysas-firewall-full-msi` is available for
download from the Actions run for 7 days.

The job compiles the minifilter with the WDK, self-signs it (test signing),
builds the daemon with MSVC, and packages everything with `cargo-wix`.

> **Note:** test-signed drivers require `bcdedit /set testsigning on` + reboot
> on the target machine.

### Install

```cmd
msiexec /i keysas-firewall-0.1.0-x64.msi /quiet /norestart
```

The installer registers the service in manual start mode. After deploying the certificates to `C:\ProgramData\Keysas\Firewall\`, start the service:

```powershell
Start-Service "Keysas Service"
# Optional: enable autostart
Set-Service "Keysas Service" -StartupType Automatic
```

---

## Continuous Integration

A GitHub Actions pipeline validates builds on every PR or push to `main`, `develop`, or `cert-agent`:

- **build-ebpf** — compiles the eBPF kernel program (nightly)
- **check-daemon** — `cargo check` on the Linux daemon (nightly)
- **check-tray-app** — `cargo check` on the tray-app (stable, ubuntu-22.04)
- **build-tray-app-msi** — Tauri MSI for the tray-app (Windows, stable)
- **build-windows-msi** — minifilter (WDK) + daemon (MSVC) + full MSI (Windows)

See `.github/workflows/keysas-firewall.yml`.

---

## Status

### Linux

- [x] USB monitoring via udev
- [x] Hybrid signature verification (Ed25519 + ML-DSA87) on USB devices
- [x] USB blocking via kernel sysfs deauthorization (`authorized=0`)
- [x] D-Bus interface to the tray-app
- [x] Tray-app: USB device display, manual authorization
- [x] Debian packaging (`.deb`)
- [ ] File-level access filtering (read/write policy enforcement)
- [ ] File-level IOCTL interface for the tray-app

### Windows

- [x] USB monitoring via drive polling (GetLogicalDrives)
- [x] Hybrid signature verification (Ed25519 + ML-DSA87) on USB devices
- [x] USB blocking via volume eject (lock + dismount + eject IOCTLs)
- [x] Security policy via registry
- [x] Certificate loading via registry
- [x] MSI installer (GitHub Actions Windows runner, WDK + cargo-wix)
- [ ] Tray-app interface
- [ ] File-level access filtering
