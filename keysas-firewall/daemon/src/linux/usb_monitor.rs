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
    fs::{read_to_string, File},
    io::{self, Read, Seek, SeekFrom},
    os::fd::AsRawFd,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use udev::{Event, MonitorBuilder};

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

/// Get the mount point of a device node by scanning /proc/mounts.
///
/// # Argument
///
/// `devnode` - Device node path, e.g "/dev/sda1"
fn get_mount_point(devnode: &OsStr) -> Result<OsString, anyhow::Error> {
    let mnt_points = read_to_string("/proc/mounts")?;

    for line in mnt_points.lines() {
        let mut tokens = line.split_ascii_whitespace();
        if let Some(node) = tokens.next() {
            if node.eq(devnode) {
                let mnt = tokens
                    .next()
                    .ok_or(anyhow!("failed to parse mounts file"))?;
                return Ok(OsString::from(mnt));
            }
        }
    }

    Err(anyhow!("Mount point not found"))
}

/// Poll /proc/mounts until the device is mounted or the timeout expires.
///
/// # Arguments
///
/// `devnode`      - Device node path (e.g. "/dev/sda1")
/// `timeout_secs` - Maximum number of seconds to wait
///
/// # Return value
///
/// The mount point as `OsString` if found within the timeout, `None` otherwise.
fn wait_for_mount(devnode: &OsStr, timeout_secs: u64) -> Option<OsString> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(mnt) = get_mount_point(devnode) {
            return Some(mnt);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Extract the information about a USB device and its signature if it exists
///
/// # Argument
///
/// `event` - the udev event associated to the USB device connection
fn extract_usb_info(event: Event) -> Result<(UsbDevice, Option<String>), anyhow::Error> {
    // Extract Usb device metadata
    let device = event.device();

    let devnode = device
        .devnode()
        .ok_or_else(|| anyhow!("Devnode not found"))?;

    let vendor = device
        .property_value(OsStr::new("ID_VENDOR_ID"))
        .ok_or_else(|| anyhow!("Vendor ID not found"))?;
    let model = device
        .property_value(OsStr::new("ID_MODEL_ID"))
        .ok_or_else(|| anyhow!("Model ID not found"))?;
    let revision = device
        .property_value(OsStr::new("ID_REVISION"))
        .ok_or_else(|| anyhow!("Revision not found"))?;
    let serial = device
        .property_value(OsStr::new("ID_SERIAL"))
        .ok_or_else(|| anyhow!("Serial number not found"))?;

    // Walk up the sysfs tree to the parent USB device node.
    // Its `authorized` attribute is used to deauthorize uncertified devices.
    let usb_syspath = device
        .parent_with_subsystem_devtype(OsStr::new("usb"), OsStr::new("usb_device"))
        .ok()
        .flatten()
        .map(|p| p.syspath().as_os_str().to_os_string());

    let usb_device = UsbDevice {
        device_id: devnode.as_os_str().to_os_string(),
        mnt_point: None, // Partition not mounted yet
        vendor: vendor.to_os_string(),
        model: model.to_os_string(),
        revision: revision.to_os_string(),
        serial: serial.to_os_string(),
        usb_syspath,
    };

    // Try to extract a signature
    let mut f = File::open(devnode)?;
    // First get the signature size
    let mut size_buf = [0u8; 4];
    f.seek(SeekFrom::Start(512))?;
    f.read_exact(&mut size_buf)?;
    let sig_size = u32::from_be_bytes(size_buf);
    // Size must not be greater than 7684 bytes LBA-MBR (8196-512)
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

impl UsbMonitor for LinuxUsbMonitor {
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let stop_flag = self.stop_flag.clone();

        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Look for usb device
            let monitor = MonitorBuilder::new()?.match_subsystem("block")?.listen()?;

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

                // Only process partition add events
                if event.action() == Some(OsStr::new("add"))
                    && event.device().property_value(OsStr::new("DEVTYPE"))
                        == Some(OsStr::new("partition"))
                {
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
                            log::warn!("Failed to authorize USB device: {e}");
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
                                        device.device_id, auth_path
                                    ),
                                    Err(e) => log::warn!(
                                        "Failed to deauthorize {:?} via {:?}: {e}",
                                        device.device_id, auth_path
                                    ),
                                }
                            }
                            None => log::warn!(
                                "Cannot deauthorize {:?}: USB parent sysfs path not found",
                                device.device_id
                            ),
                        }
                    } else {
                        // Certified device: mount explicitly to /run/keysas/media/<devname>/.
                        // This is necessary because the udev rule sets UDISKS_IGNORE=1 for
                        // all USB block devices, preventing udisks2 automounting.
                        let dev_name = std::path::Path::new(&device.device_id)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "usb".to_string());
                        let mnt_point = format!("/run/keysas/media/{}", dev_name);

                        if let Err(e) = std::fs::create_dir_all(&mnt_point) {
                            log::warn!("Failed to create mount point {}: {e}", mnt_point);
                        } else {
                            let status = std::process::Command::new("mount")
                                .args([
                                    "-o", "noexec,nosuid,nodev",
                                    &device.device_id.to_string_lossy().as_ref(),
                                    &mnt_point,
                                ])
                                .status();
                            match status {
                                Ok(s) if s.success() => {
                                    device.mnt_point = Some(OsString::from(&mnt_point));
                                    log::info!(
                                        "Certified USB {:?} mounted at {}",
                                        device.device_id, mnt_point
                                    );
                                    if let Err(e) = ctrl_hdl.lock().unwrap().update_usb(&device) {
                                        log::warn!("Failed to update USB mount state: {e}");
                                    }
                                }
                                Ok(s) => log::warn!(
                                    "mount failed for {:?} (exit {:?})",
                                    device.device_id, s.code()
                                ),
                                Err(e) => log::warn!(
                                    "mount command error for {:?}: {e}",
                                    device.device_id
                                ),
                            }
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
