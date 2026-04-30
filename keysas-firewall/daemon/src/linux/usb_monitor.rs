// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! USB monitor implementation for Linux

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use libc::{c_int, c_short, c_ulong, c_void};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::fd::AsRawFd,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use udev::{Device, Enumerator, Event, MonitorBuilder};

use crate::controller::{ServiceController, UsbDevice};
use crate::usb_monitor::UsbMonitor;

#[repr(C)]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[repr(C)]
struct sigset_t {
    __private: c_void,
}

#[allow(non_camel_case_types)]
type nfds_t = c_ulong;

const POLLIN: c_short = 0x0001;

extern "C" {
    fn ppoll(
        fds: *mut pollfd,
        nfds: nfds_t,
        timeout_ts: *mut libc::timespec,
        sigmask: *const sigset_t,
    ) -> c_int;
}

#[derive(Debug, Clone)]
pub struct LinuxUsbMonitor {
    /// Shared flag to request the monitor thread to stop
    stop_flag: Arc<AtomicBool>,
}

impl LinuxUsbMonitor {
    pub fn init() -> Result<LinuxUsbMonitor, anyhow::Error> {
        Ok(LinuxUsbMonitor {
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }
}

/// Return the username of the first non-root logged-in user found in
/// `/run/user/*/bus`, or `None` if no session is active (headless system).
fn get_logged_in_username() -> Option<String> {
    let entries = std::fs::read_dir("/run/user").ok()?;
    for entry in entries.flatten() {
        let uid_str = entry.file_name().to_string_lossy().to_string();
        // Skip root and system accounts (uid < 1000 on Linux — e.g. gdm uid=120).
        let uid: u32 = match uid_str.parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        if uid < 1000 {
            continue;
        }
        if !entry.path().join("bus").exists() {
            continue; // no active session bus
        }
        let out = std::process::Command::new("id")
            .args(["-un", &uid_str])
            .output()
            .ok()?;
        if out.status.success() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Parse the mount point from `udisksctl mount` stdout.
///
/// Expected line format: `Mounted /dev/sdX at /path/to/mountpoint.\n`
fn parse_udisksctl_output(stdout: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(stdout).ok()?;
    let idx = s.find(" at ")?;
    let rest = s[idx + 4..].trim().trim_end_matches('.');
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// Extract the information about a USB device and its signature from a `udev::Device`.
fn extract_device_info(device: Device) -> Result<(UsbDevice, Option<String>), anyhow::Error> {
    let devnode = device
        .devnode()
        .ok_or_else(|| anyhow!("Devnode not found"))?;

    let vendor = device
        .property_value(OsStr::new("ID_VENDOR"))
        .ok_or_else(|| anyhow!("Vendor not found"))?;
    let model = device
        .property_value(OsStr::new("ID_MODEL"))
        .ok_or_else(|| anyhow!("Model not found"))?;
    let revision = device
        .property_value(OsStr::new("ID_REVISION"))
        .ok_or_else(|| anyhow!("Revision not found"))?;
    let serial = device
        .property_value(OsStr::new("ID_SERIAL_SHORT"))
        .ok_or_else(|| anyhow!("Serial number not found"))?;

    // Walk up the sysfs tree to the parent USB device node.
    let usb_syspath = device
        .parent_with_subsystem_devtype(OsStr::new("usb"), OsStr::new("usb_device"))
        .ok()
        .flatten()
        .map(|p| p.syspath().as_os_str().to_os_string());

    let usb_device = UsbDevice {
        device_id: devnode.as_os_str().to_os_string(),
        mnt_point: None,
        vendor: vendor.to_os_string(),
        model: model.to_os_string(),
        revision: revision.to_os_string(),
        serial: serial.to_os_string(),
        usb_syspath,
    };

    // Signature is at byte offset 512 on the RAW disk (e.g. /dev/sdb).
    // Strip the trailing partition digit to obtain the raw device path.
    let raw_device: std::path::PathBuf = {
        let s = devnode.to_string_lossy();
        let stripped = if s.ends_with(|c: char| c.is_ascii_digit()) {
            &s[..s.len() - 1]
        } else {
            s.as_ref()
        };
        std::path::PathBuf::from(stripped)
    };
    log::info!(
        "Reading signature from raw device {:?} (partition: {:?})",
        raw_device,
        devnode
    );
    let mut f = File::open(&raw_device)?;
    let mut size_buf = [0u8; 4];
    f.seek(SeekFrom::Start(512))?;
    f.read_exact(&mut size_buf)?;
    let sig_size = u32::from_be_bytes(size_buf);
    log::info!("Signature size read at offset 512: {} bytes", sig_size);
    let signature = match sig_size <= 7684 {
        true => {
            let mut sig_buf = vec![0u8; sig_size as usize];
            f.read_exact(&mut sig_buf)?;
            Some(String::from_utf8(sig_buf.to_vec())?)
        }
        false => None,
    };

    Ok((usb_device, signature))
}

/// Extract the information about a USB device and its signature if it exists
///
/// # Argument
///
/// `event` - the udev event associated to the USB device connection
fn extract_usb_info(event: Event) -> Result<(UsbDevice, Option<String>), anyhow::Error> {
    extract_device_info(event.device())
}

/// Scan already-present USB partitions at daemon startup.
///
/// After a system reboot the udev "add" events for plugged-in devices fired
/// before the daemon started.  The udev rule set UDISKS_IGNORE=1 so nothing
/// was auto-mounted, and /run/keysas/certified/ (tmpfs) was cleared.  This
/// function enumerates those pre-existing partitions and processes them
/// exactly like a live plug-in event would.
///
/// Devices already recovered by `recover_mounted_devices()` (sentinel present,
/// device mounted) are skipped via `is_device_tracked()`.
fn scan_existing_usb_partitions(ctrl: &Arc<Mutex<ServiceController>>) {
    let mut enumerator = match udev::Enumerator::new() {
        Ok(e) => e,
        Err(e) => {
            log::warn!("scan_existing_usb_partitions: enumerator init failed: {e}");
            return;
        }
    };
    if enumerator.match_subsystem("block").is_err()
        || enumerator.match_property("DEVTYPE", "partition").is_err()
    {
        log::warn!("scan_existing_usb_partitions: failed to set enumerator filters");
        return;
    }

    let devices = match enumerator.scan_devices() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("scan_existing_usb_partitions: scan failed: {e}");
            return;
        }
    };

    for device in devices {
        // Only process USB-connected partitions (walk parent chain).
        let is_usb = device
            .parent_with_subsystem_devtype(OsStr::new("usb"), OsStr::new("usb_device"))
            .ok()
            .flatten()
            .is_some();
        if !is_usb {
            continue;
        }

        let devnode = match device.devnode() {
            Some(n) => n.as_os_str().to_os_string(),
            None => continue,
        };

        // Skip if already tracked by recover_mounted_devices().
        if ctrl.lock().unwrap().is_device_tracked(&devnode) {
            log::info!("scan_existing_usb_partitions: {:?} already tracked, skipping", devnode);
            continue;
        }

        log::info!("scan_existing_usb_partitions: processing pre-existing partition {:?}", devnode);

        let (mut usb_device, signature) = match extract_device_info(device) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("scan_existing_usb_partitions: info extraction failed for {:?}: {e}", devnode);
                continue;
            }
        };

        let authorized = match ctrl.lock().unwrap().authorize_usb(&usb_device, signature.as_deref()) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("scan_existing_usb_partitions: authorize_usb failed for {:?}: {e}", devnode);
                if let Some(ref syspath) = usb_device.usb_syspath {
                    let auth_path = std::path::Path::new(syspath).join("authorized");
                    let _ = std::fs::write(&auth_path, b"0\n");
                }
                continue;
            }
        };

        if authorized {
            let dev_name = std::path::Path::new(&usb_device.device_id)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "usb".to_string());

            let mnt_result = match mount_certified_via_udisks(&usb_device.device_id, &dev_name) {
                Ok(mnt) => Ok(mnt),
                Err(e) => {
                    log::warn!(
                        "scan_existing_usb_partitions: udisks2 mount failed for {:?}: {e} — falling back",
                        usb_device.device_id
                    );
                    mount_certified_headless(&usb_device.device_id, &dev_name)
                }
            };

            match mnt_result {
                Ok(mnt_point) => {
                    usb_device.mnt_point = Some(OsString::from(&mnt_point));
                    log::info!(
                        "scan_existing_usb_partitions: certified {:?} mounted at {}",
                        usb_device.device_id, mnt_point
                    );
                    if let Err(e) = ctrl.lock().unwrap().update_usb(&usb_device) {
                        log::warn!("scan_existing_usb_partitions: update_usb failed: {e}");
                    }
                }
                Err(e) => {
                    log::warn!(
                        "scan_existing_usb_partitions: all mount attempts failed for {:?}: {e}",
                        usb_device.device_id
                    );
                }
            }
        } else {
            // Blocked: deauthorize at kernel level.
            if let Some(ref syspath) = usb_device.usb_syspath {
                let auth_path = std::path::Path::new(syspath).join("authorized");
                match std::fs::write(&auth_path, b"0\n") {
                    Ok(_) => log::info!(
                        "scan_existing_usb_partitions: {:?} deauthorized via {:?}",
                        usb_device.device_id, auth_path
                    ),
                    Err(e) => log::warn!(
                        "scan_existing_usb_partitions: deauthorize {:?} failed: {e}",
                        usb_device.device_id
                    ),
                }
            }
        }
    }
}

/// Mount a certified USB partition via udisks2 so it appears at the standard
/// desktop path (`/media/<user>/<label>` or `/run/media/<user>/<label>`) with
/// file-manager visibility and graphical-eject support.
///
/// Steps:
///  1. Write sentinel `/run/keysas/certified/<devname>`.
///  2. Fire `udevadm trigger --action=change` so the udev rule can flip
///     `UDISKS_IGNORE` to 0 for udisks2.
///  3. Wait for udevd to flush its queue (`udevadm settle`).
///  4. Call `udisksctl mount` as the logged-in user via `runuser`.
///
/// Returns the mount point string on success.
fn mount_certified_via_udisks(devnode: &OsStr, dev_name: &str) -> Result<String, anyhow::Error> {
    // ── Phase 1: write sentinel and signal udev ──────────────────────────────
    let certified_dir = "/run/keysas/certified";
    let sentinel = format!("{}/{}", certified_dir, dev_name);

    std::fs::create_dir_all(certified_dir)
        .map_err(|e| anyhow!("Cannot create {}: {e}", certified_dir))?;
    std::fs::write(&sentinel, b"")
        .map_err(|e| anyhow!("Cannot write sentinel {}: {e}", sentinel))?;

    let sysfs_path = format!("/sys/class/block/{}", dev_name);
    let _ = std::process::Command::new("udevadm")
        .args(["trigger", "--action=change", &sysfs_path])
        .status();
    // Flush the udevd queue so udisks2 processes the change before we mount
    let _ = std::process::Command::new("udevadm")
        .args(["settle", "--timeout=3"])
        .status();

    // ── Phase 2: mount as logged-in user ─────────────────────────────────────
    let username =
        get_logged_in_username().ok_or_else(|| anyhow!("No active user session found"))?;

    log::info!(
        "Mounting certified USB {:?} via udisks2 as user '{}'",
        devnode,
        username
    );

    let out = std::process::Command::new("runuser")
        .args([
            "-u",
            &username,
            "--",
            "udisksctl",
            "mount",
            "-b",
            &devnode.to_string_lossy(),
            "--no-user-interaction",
            "--options",
            "noexec,nosuid,nodev",
        ])
        .output()
        .map_err(|e| anyhow!("runuser/udisksctl exec failed: {e}"))?;

    if !out.status.success() {
        return Err(anyhow!(
            "udisksctl mount failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    parse_udisksctl_output(&out.stdout)
        .ok_or_else(|| anyhow!("Cannot parse mount point from udisksctl output"))
}

/// Fallback: mount directly at `/run/keysas/media/<devname>` for headless
/// systems where no user session is available.
fn mount_certified_headless(devnode: &OsStr, dev_name: &str) -> Result<String, anyhow::Error> {
    let mnt_point = format!("/run/keysas/media/{}", dev_name);
    std::fs::create_dir_all(&mnt_point).map_err(|e| anyhow!("Cannot create {}: {e}", mnt_point))?;

    let status = std::process::Command::new("mount")
        .args([
            "-o",
            "noexec,nosuid,nodev",
            &devnode.to_string_lossy(),
            &mnt_point,
        ])
        .status()
        .map_err(|e| anyhow!("mount exec failed: {e}"))?;

    if !status.success() {
        return Err(anyhow!(
            "mount failed for {:?} (exit {:?})",
            devnode,
            status.code()
        ));
    }

    Ok(mnt_point)
}

impl UsbMonitor for LinuxUsbMonitor {
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let stop_flag = self.stop_flag.clone();

        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Monitor "block" (partition add/remove) and "usb" (physical unplug
            // of a device that was already kernel-deauthorized, whose block node
            // was already gone so no second "block remove" event fires).
            let monitor = MonitorBuilder::new()?
                .match_subsystem("block")?
                .match_subsystem_devtype("usb", "usb_device")?
                .listen()?;

            // Process USB partitions already present before this daemon instance
            // started (e.g. after a reboot that cleared /run/keysas/certified/).
            // The monitor is listening above so any events that arrive during the
            // scan are buffered and will be processed in the event loop below.
            scan_existing_usb_partitions(&ctrl_hdl);

            let mut fds = vec![pollfd {
                fd: monitor.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            }];

            // 1-second timeout so the stop flag is checked regularly
            let mut timeout = libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                let res = unsafe {
                    ppoll(
                        (&mut fds[..]).as_mut_ptr(),
                        fds.len() as nfds_t,
                        &mut timeout as *mut libc::timespec,
                        ptr::null(),
                    )
                };

                if res < 0 {
                    let err = io::Error::last_os_error();
                    // EINTR (4) is normal when a signal interrupts ppoll
                    if err.raw_os_error() == Some(4) {
                        continue;
                    }
                    return Err(anyhow!("ppoll error: {}", err));
                }

                if res == 0 {
                    // Timeout — loop back to check stop_flag
                    continue;
                }

                let event = match monitor.iter().next() {
                    Some(evt) => evt,
                    None => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };

                let action = event.action();
                let subsystem = event.device().subsystem().map(|s| s.to_os_string());
                let devtype = event
                    .device()
                    .property_value(OsStr::new("DEVTYPE"))
                    .map(|v| v.to_os_string());

                let is_partition = devtype.as_deref() == Some(OsStr::new("partition"));

                // ── Physical unplug of a deauthorized USB device ─────────────
                // When the kernel deauthorizes a device (writes 0 to authorized),
                // the block node (/dev/sdbX) disappears immediately.  The later
                // physical unplug generates a "usb_device remove" event on the
                // "usb" subsystem — not a "block" event — so we must handle it
                // here to remove the kept-blocked entry from the store.
                let is_usb_device = subsystem.as_deref() == Some(OsStr::new("usb"))
                    && devtype.as_deref() == Some(OsStr::new("usb_device"));

                if action == Some(OsStr::new("remove")) && is_usb_device {
                    // Walk the sysfs children of this USB device to find any
                    // block nodes that are still tracked as blocked.
                    let syspath = event.device().syspath().to_path_buf();
                    let mut ctrl = ctrl_hdl.lock().unwrap();
                    // Collect all device IDs under /sys/<usb_syspath>/**/dev
                    // by checking /dev/<sysname> patterns.  The simplest heuristic:
                    // iterate unmounted_usb and remove any whose usb_syspath starts
                    // with this device's syspath.
                    let to_remove: Vec<OsString> = ctrl
                        .unmounted_usb_ids_with_syspath_prefix(&syspath)
                        .into_iter()
                        .collect();
                    for id in to_remove {
                        log::info!(
                            "Physical unplug detected for deauthorized device {:?} \
                             (USB parent: {:?})",
                            id,
                            syspath
                        );
                        ctrl.force_remove_usb(&id);
                    }
                    continue;
                }

                // ── Remove event: clean up sentinel and notify controller ────
                if action == Some(OsStr::new("remove")) && is_partition {
                    let dev_name = event.device().sysname().to_string_lossy().into_owned();

                    // Remove the certification sentinel (if present)
                    let sentinel = format!("/run/keysas/certified/{}", dev_name);
                    if std::path::Path::new(&sentinel).exists() {
                        let _ = std::fs::remove_file(&sentinel);
                        log::info!("Removed certification sentinel for {}", dev_name);
                    }

                    // Notify the controller so it can remove the fanotify mark
                    // and clean up its tracking tables.
                    let device_id = event
                        .device()
                        .devnode()
                        .map(|p| p.as_os_str().to_os_string())
                        .unwrap_or_else(|| OsString::from(format!("/dev/{}", dev_name)));
                    ctrl_hdl.lock().unwrap().remove_usb(&device_id);

                    continue;
                }

                // ── Add event: process new USB partition ─────────────────────
                if action != Some(OsStr::new("add")) || !is_partition {
                    continue;
                }

                let (mut device, signature) = match extract_usb_info(event) {
                    Ok((d, s)) => (d, s),
                    Err(e) => {
                        log::warn!("Error while parsing udev event: {e}");
                        continue;
                    }
                };

                log::info!("USB partition detected: {:?}", device.device_id);

                // Authorize the device (signature check + policy)
                let authorized = match ctrl_hdl
                    .lock()
                    .unwrap()
                    .authorize_usb(&device, signature.as_deref())
                {
                    Ok(auth) => auth,
                    Err(e) => {
                        // Authorization error (e.g. malformed signature): treat as blocked
                        // and deauthorize the device to prevent any kernel-level access.
                        log::warn!("Failed to authorize USB device: {e} — deauthorizing");
                        if let Some(ref syspath) = device.usb_syspath {
                            let auth_path = std::path::Path::new(syspath).join("authorized");
                            let _ = std::fs::write(&auth_path, b"0\n");
                        }
                        continue;
                    }
                };

                log::info!(
                    "USB device {:?}: {}",
                    device.device_id,
                    if authorized { "authorized" } else { "blocked" }
                );

                if !authorized {
                    // Deauthorize the USB device at the kernel level.
                    // Writing 0 to the parent USB device's `authorized` sysfs attribute
                    // causes the kernel to disconnect it entirely — no /dev node remains.
                    // The udev rule (60-keysas-firewall.rules) has already set
                    // UDISKS_IGNORE=1, so no automount can race this write.
                    match &device.usb_syspath {
                        Some(syspath) => {
                            let auth_path = std::path::Path::new(syspath).join("authorized");
                            match std::fs::write(&auth_path, b"0\n") {
                                Ok(_) => log::info!(
                                    "USB device {:?} deauthorized via {:?}",
                                    device.device_id,
                                    auth_path
                                ),
                                Err(e) => log::warn!(
                                    "Failed to deauthorize {:?} via {:?}: {e}",
                                    device.device_id,
                                    auth_path
                                ),
                            }
                        }
                        None => log::warn!(
                            "Cannot deauthorize {:?}: USB parent sysfs path not found",
                            device.device_id
                        ),
                    }
                } else {
                    // Certified device: mount so the desktop can see it.
                    //
                    // Primary path  — user session present: mount via udisks2
                    //   so the device appears at the standard desktop path
                    //   (/media/<user>/<label>) with file-manager and
                    //   graphical-eject support.
                    //
                    // Fallback path — headless system: mount directly at
                    //   /run/keysas/media/<devname> (original behaviour).
                    let dev_name = std::path::Path::new(&device.device_id)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "usb".to_string());

                    let mnt_result = match mount_certified_via_udisks(&device.device_id, &dev_name)
                    {
                        Ok(mnt) => Ok(mnt),
                        Err(e) => {
                            log::warn!(
                                "udisks2 mount failed for {:?}: {e} \
                                     — falling back to direct mount",
                                device.device_id
                            );
                            mount_certified_headless(&device.device_id, &dev_name)
                        }
                    };

                    match mnt_result {
                        Ok(mnt_point) => {
                            device.mnt_point = Some(OsString::from(&mnt_point));
                            log::info!(
                                "Certified USB {:?} mounted at {}",
                                device.device_id,
                                mnt_point
                            );
                            if let Err(e) = ctrl_hdl.lock().unwrap().update_usb(&device) {
                                log::warn!("Failed to update USB mount state: {e}");
                            }
                        }
                        Err(e) => {
                            log::warn!("All mount attempts failed for {:?}: {e}", device.device_id)
                        }
                    }
                }
            }

            Ok(())
        });

        Ok(())
    }

    /// Stop the monitor thread by setting the stop flag.
    fn stop(self: Box<Self>) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}
