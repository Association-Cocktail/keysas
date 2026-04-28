// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! USB monitor implementation for Windows
//!
//! Detection strategy: a background thread polls `GetLogicalDrives()` every 500 ms.
//! When a new `DRIVE_REMOVABLE` letter appears the daemon:
//!   1. Maps the volume to its physical disk via `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`.
//!   2. Reads the Keysas signature from the MBR gap of the raw disk at byte offset 512.
//!   3. Reads vendor / model / revision / serial from `IOCTL_STORAGE_QUERY_PROPERTY`.
//!   4. Calls `authorize_usb()` (certificate + policy check).
//!   5. If blocked  → eject the volume (lock + dismount + IOCTL_STORAGE_EJECT_MEDIA).
//!   6. If certified → record the mount point and call `update_usb()`.
//!
//! # Compatibility note
//!
//! The Linux daemon uses udev properties (`ID_VENDOR_ID` = 4-hex-digit USB VID,
//! `ID_MODEL_ID`, `ID_REVISION`, `ID_SERIAL`) when building the signed string.
//! The Windows daemon uses the equivalent SCSI Inquiry strings returned by
//! `IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty`.  The keysas-admin
//! Windows signing tool **must use the same source** so that signature strings
//! match at verification time.

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
use std::{
    collections::HashSet,
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDrives, ReadFile, SetFileAttributesW, SetFilePointerEx,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME,
    IOCTL_STORAGE_EJECT_MEDIA, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_QUERY, VOLUME_DISK_EXTENTS,
};
use windows::Win32::System::IO::DeviceIoControl;

// Raw constants not exposed by windows 0.52 under the expected module paths.
// Values from the Windows SDK headers.
const DRIVE_REMOVABLE: u32 = 2;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

use crate::controller::{ServiceController, UsbDevice};
use crate::usb_monitor::UsbMonitor;

// GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000.
// Using raw u32 values avoids depending on the exact newtype the windows crate
// uses for dwDesiredAccess across versions.
const GENERIC_READ_ACCESS: u32 = 0x8000_0000;
const GENERIC_WRITE_ACCESS: u32 = 0x4000_0000;

/// Walk `root` recursively and apply `FILE_ATTRIBUTE_HIDDEN` to every file
/// whose name matches `^\..+\.krp$` (hidden Keysas report files).
///
/// Called once after a USB device is certified so that report files are
/// invisible in Windows Explorer — consistent with the dot-prefix convention
/// used on Linux.
fn hide_krp_files(root: &str) {
    fn walk(dir: &std::path::Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("hide_krp_files: cannot read {:?}: {e}", dir);
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path);
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_owned(),
                None => continue,
            };
            // Match ".<something>.krp" — at least one char between '.' and '.krp'
            if name.starts_with('.') && name.ends_with(".krp") && name.len() > 5 {
                let wide: Vec<u16> = path
                    .to_string_lossy()
                    .encode_utf16()
                    .chain(std::iter::once(0u16))
                    .collect();
                unsafe {
                    if let Err(e) = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_HIDDEN)
                    {
                        log::warn!("hide_krp_files: SetFileAttributesW({:?}) failed: {e}", path);
                    } else {
                        log::debug!("hide_krp_files: hid {:?}", path);
                    }
                }
            }
        }
    }

    walk(std::path::Path::new(root));
}

#[derive(Debug)]
pub struct WindowsUsbMonitor {
    stop_flag: Arc<AtomicBool>,
}

impl WindowsUsbMonitor {
    pub fn init() -> Result<WindowsUsbMonitor, anyhow::Error> {
        Ok(WindowsUsbMonitor {
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }
}

/// Returns a null-terminated UTF-16 vector suitable for use as a `PCWSTR`.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Returns the set of removable drive letters currently visible to Windows.
fn get_removable_drives() -> HashSet<char> {
    let mut drives = HashSet::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) != 0 {
            let letter = (b'A' + i as u8) as char;
            let path = to_wide(&format!("{letter}:\\"));
            let drive_type = unsafe { GetDriveTypeW(PCWSTR(path.as_ptr())) };
            if drive_type == DRIVE_REMOVABLE {
                drives.insert(letter);
            }
        }
    }
    drives
}

/// Maps a volume drive letter to its underlying physical disk number via
/// `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`.
fn get_physical_drive_number(drive_letter: char) -> Result<u32, anyhow::Error> {
    let path = to_wide(&format!("\\\\.\\{drive_letter}:"));
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0, // No file access — IOCTL only
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?
    };

    let mut vde = VOLUME_DISK_EXTENTS::default();
    let mut bytes_returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(&mut vde as *mut _ as *mut std::ffi::c_void),
            size_of::<VOLUME_DISK_EXTENTS>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result?;

    if vde.NumberOfDiskExtents == 0 {
        return Err(anyhow!("No disk extents for drive {drive_letter}:"));
    }
    Ok(vde.Extents[0].DiskNumber)
}

/// Queries vendor, model, revision and serial from a volume via
/// `IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty`.
///
/// Returns empty strings for fields the device does not expose.
fn get_device_info(drive_letter: char) -> Result<(String, String, String, String), anyhow::Error> {
    let path = to_wide(&format!("\\\\.\\{drive_letter}:"));
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?
    };

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0u8; 1],
    };

    let mut buf = [0u8; 4096];
    let mut bytes_returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const std::ffi::c_void),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result?;

    if (bytes_returned as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
        return Err(anyhow!(
            "STORAGE_DEVICE_DESCRIPTOR too small ({bytes_returned} bytes)"
        ));
    }

    let desc = unsafe { &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
    let valid = bytes_returned as usize;

    // Extract a null-terminated ASCII string at the given byte offset within the buffer.
    let extract = |offset: u32| -> String {
        if offset == 0 || offset as usize >= valid {
            return String::new();
        }
        let s = &buf[offset as usize..valid];
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..end]).trim().to_string()
    };

    Ok((
        extract(desc.VendorIdOffset),
        extract(desc.ProductIdOffset),
        extract(desc.ProductRevisionOffset),
        extract(desc.SerialNumberOffset),
    ))
}

/// Reads the Keysas hybrid signature from the raw physical disk at byte offset 512.
///
/// Layout (same as Linux — written by `keysas-admin`):
///   - bytes 0–3 at disk offset 512: big-endian u32 — signature length (max 7684)
///   - bytes 4–N at disk offset 516: UTF-8 base64 signature string
///
/// The read starts at sector boundary 512 and covers 8 192 bytes (16 sectors),
/// which is sector-aligned as required for physical drive I/O on Windows.
fn read_signature(disk_number: u32) -> Result<Option<String>, anyhow::Error> {
    let path = to_wide(&format!("\\\\.\\PhysicalDrive{disk_number}"));
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            GENERIC_READ_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?
    };

    // 16 sectors = 8 192 bytes, sector-aligned, starting at sector 1 (byte 512).
    const READ_SIZE: usize = 8192;
    let mut buf = [0u8; READ_SIZE];
    let mut bytes_read = 0u32;

    let result = unsafe {
        SetFilePointerEx(handle, 512i64, None, FILE_BEGIN)?;
        ReadFile(handle, Some(&mut buf), Some(&mut bytes_read), None)
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result?;

    if bytes_read < 4 {
        return Err(anyhow!(
            "Read only {bytes_read} bytes from PhysicalDrive{disk_number} (need ≥ 4)"
        ));
    }

    let sig_size = u32::from_be_bytes(buf[0..4].try_into()?);
    log::info!("Signature size read at offset 512 on PhysicalDrive{disk_number}: {sig_size} bytes");

    // Size 0 → unsigned device; > 7684 → corrupt / not a Keysas device.
    if sig_size == 0 || sig_size > 7684 {
        return Ok(None);
    }

    let end = 4 + sig_size as usize;
    if end > bytes_read as usize {
        return Err(anyhow!(
            "Signature extends past read ({end} bytes needed, {bytes_read} read)"
        ));
    }

    Ok(Some(String::from_utf8(buf[4..end].to_vec())?))
}

/// Ejects a removable volume: lock → dismount → eject media.
///
/// Individual IOCTL failures are logged but not propagated — a partial eject
/// still prevents the user from accessing files.
fn eject_volume(drive_letter: char) -> Result<(), anyhow::Error> {
    let path = to_wide(&format!("\\\\.\\{drive_letter}:"));
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            GENERIC_READ_ACCESS | GENERIC_WRITE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?
    };

    let mut returned = 0u32;
    unsafe {
        if let Err(e) = DeviceIoControl(
            handle,
            FSCTL_LOCK_VOLUME,
            None,
            0,
            None,
            0,
            Some(&mut returned),
            None,
        ) {
            log::warn!("FSCTL_LOCK_VOLUME on {drive_letter}: {e} (continuing)");
        }
        if let Err(e) = DeviceIoControl(
            handle,
            FSCTL_DISMOUNT_VOLUME,
            None,
            0,
            None,
            0,
            Some(&mut returned),
            None,
        ) {
            log::warn!("FSCTL_DISMOUNT_VOLUME on {drive_letter}: {e} (continuing)");
        }
        if let Err(e) = DeviceIoControl(
            handle,
            IOCTL_STORAGE_EJECT_MEDIA,
            None,
            0,
            None,
            0,
            Some(&mut returned),
            None,
        ) {
            log::warn!("IOCTL_STORAGE_EJECT_MEDIA on {drive_letter}: {e} (continuing)");
        }
        let _ = CloseHandle(handle);
    }
    Ok(())
}

/// Processes a newly detected removable drive: authorize → eject or accept.
fn handle_new_drive(drive_letter: char, ctrl: &Arc<Mutex<ServiceController>>) {
    log::info!("New removable drive: {drive_letter}:");

    // Map volume → physical disk.
    let disk_number = match get_physical_drive_number(drive_letter) {
        Ok(n) => n,
        Err(e) => {
            log::warn!("Cannot map {drive_letter}: to physical disk: {e} — ejecting");
            let _ = eject_volume(drive_letter);
            return;
        }
    };

    // Device metadata (for signature verification string).
    let (vendor, model, revision, serial) = match get_device_info(drive_letter) {
        Ok(info) => info,
        Err(e) => {
            log::warn!("Cannot get device info for {drive_letter}: {e} — ejecting");
            let _ = eject_volume(drive_letter);
            return;
        }
    };

    // Read Keysas signature from the MBR gap of the physical disk.
    let signature = match read_signature(disk_number) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to read signature from PhysicalDrive{disk_number}: {e} — ejecting");
            let _ = eject_volume(drive_letter);
            return;
        }
    };

    let device = UsbDevice {
        device_id: OsString::from(format!("\\\\.\\PhysicalDrive{disk_number}")),
        // Store the mount point before calling authorize_usb so that it is
        // preserved in unmounted_usb and available for override_blocked_usb()
        // if the user later manually authorizes the device.
        mnt_point: Some(OsString::from(format!("{drive_letter}:\\"))),
        vendor: OsString::from(&vendor),
        model: OsString::from(&model),
        revision: OsString::from(&revision),
        serial: OsString::from(&serial),
        usb_syspath: None, // Windows: no sysfs deauthorization path
    };

    log::info!(
        "USB PhysicalDrive{disk_number} ({drive_letter}:) vendor={vendor:?} \
         model={model:?} revision={revision:?}"
    );

    let authorized = match ctrl
        .lock()
        .unwrap()
        .authorize_usb(&device, signature.as_deref())
    {
        Ok(auth) => auth,
        Err(e) => {
            log::warn!("Failed to authorize USB device: {e} — ejecting");
            let _ = eject_volume(drive_letter);
            return;
        }
    };

    log::info!(
        "USB PhysicalDrive{disk_number} ({drive_letter}:): {}",
        if authorized { "authorized" } else { "blocked" }
    );

    if authorized {
        if let Err(e) = ctrl.lock().unwrap().update_usb(&device) {
            log::warn!("Failed to update USB mount state: {e}");
        } else {
            // Hide all .krp report files on the certified volume so they are
            // invisible in Windows Explorer (FILE_ATTRIBUTE_HIDDEN), consistent
            // with the dot-prefix convention used on Linux.
            hide_krp_files(&format!("{drive_letter}:\\"));
            log::info!("Certified USB PhysicalDrive{disk_number} accessible at {drive_letter}:\\");
        }
    } else {
        // When user override is allowed by policy, keep the drive accessible at
        // the filesystem level: the minifilter will block all file access until
        // the user clicks "Autoriser" in the tray app.  This avoids requiring a
        // physical replug after the override.
        if ctrl.lock().unwrap().is_user_usb_auth_enabled() {
            log::info!(
                "Blocked USB PhysicalDrive{disk_number} ({drive_letter}:): \
                 kept mounted, awaiting user override"
            );
        } else {
            match eject_volume(drive_letter) {
                Ok(()) => log::info!("Blocked drive {drive_letter}: ejected"),
                Err(e) => log::warn!("Failed to eject blocked drive {drive_letter}: {e}"),
            }
        }
    }
}

impl UsbMonitor for WindowsUsbMonitor {
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let stop_flag = self.stop_flag.clone();

        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Snapshot drives present at daemon start — do not inspect pre-existing drives.
            let mut known_drives = get_removable_drives();
            log::info!(
                "USB monitor started. Pre-existing removable drives (skipped): {:?}",
                known_drives
            );

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                thread::sleep(Duration::from_millis(200));

                let current_drives = get_removable_drives();

                let removed_drives: Vec<char> =
                    known_drives.difference(&current_drives).copied().collect();

                for letter in removed_drives {
                    log::info!("Removable drive {letter}: removed");
                    ctrl_hdl.lock().unwrap().remove_usb_by_drive(letter);
                }

                let new_drives: Vec<char> =
                    current_drives.difference(&known_drives).copied().collect();

                for letter in new_drives {
                    // Brief grace period so Windows finishes populating the volume
                    // before we issue IOCTL calls.
                    thread::sleep(Duration::from_millis(200));
                    handle_new_drive(letter, &ctrl_hdl);
                }

                known_drives = current_drives;
            }

            Ok(())
        });

        Ok(())
    }

    fn stop(self: Box<Self>) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}
