// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! File filter interface for Windows
//! It interfaces a minifilter that intercepts IRP_MJ_CREATE (file opent) and
//!  IRP_MJ_WRITE (file modification) requests to the filesystem. The calls
//!  between the minifilter and the interface are the following:
//!
//! - When a new volume is detected and a new minifilter instance is created, the
//!  minifilter requests the default authorization policiy for the volume
//!
//! ```text
//!     Minifilter                      Filter IF                 Controller
//!     ──────────                      ─────────                 ──────────
//!         │      scan_usb(mnt_point)      │                          │
//!         │ ────────────────────────────► │  get_usb_auth(mnt_point) │
//!         │                               │ ───────────────────────► │
//!         │                               │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//!         │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                          │
//! ```
//! The filter asks the controller for the default policy, if the Controller does
//!  not have a policy for the volume it blocks it by default
//!
//! - When a new file is detected on a volume in [AllowRead](crate::controller::UsbAuthorization)
//!  and [AllowRW](crate::controller::UsbAuthorization), the minifilter asks the policy to apply for the file.
//!
//! ```text
//!     Minifilter                      Filter IF                   Controller
//!     ──────────                      ─────────                   ──────────
//!         │   scan_file(path, file_id)  │                             │
//!         │ ──────────────────────────► │ authorize_file(file, write) │
//!         │                             │ ──────────────────────────► │
//!         │                             │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
//!         │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                             │
//! ```
//! The filter asks the controller for the policy to apply, if an error occur the
//!  default policy is set to [Block](crate::controller::FileAuthorization)
//!
//! - When the policy for a file is updated
//!
//! ```text
//!     Controller                      Filter IF                 Minifilter
//!     ──────────                      ─────────                 ──────────
//!         │  update_file_auth(update)  │                            │
//!         │ ─────────────────────────► │   update(file_id, auth)    │
//!         │                            │ ─────────────────────────► │
//!         │                            │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//!         │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                            │
//! ```
//!
//! - When the policy is updated for a volume
//!
//! ```text
//!     Controller                      Filter IF                 Minifilter
//!     ──────────                      ─────────                 ──────────
//!         │  update_usb_auth(update)   │                            │
//!         │ ─────────────────────────► │  update(mnt_point, auth)   │
//!         │                            │ ─────────────────────────► │
//!         │                            │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//!         │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                            │
//! ```

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
use std::ffi::{c_void, OsString};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::thread;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Foundation::{GetLastError, STATUS_SUCCESS};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FilterSendMessage,
    FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER,
};

use crate::controller::{
    FileAuthorization, FilePolicy, FilteredFile, ServiceController, UsbAuthorization,
    UsbDevicePolicy,
};
use crate::file_filter_if::FileFilterInterface;

// C enum values from KEYSAS_FILTER_OPERATION in keysasCommunication.h
const SCAN_FILE: u32 = 0;
const SCAN_USB: u32 = 2;

/// Format of a request from the driver to the service scanner
#[derive(Debug)]
#[repr(C)]
struct DriverRequest {
    /// Header of the request managed by Windows
    header: FILTER_MESSAGE_HEADER,
    /// Operation code: raw u32 matching the C enum KEYSAS_FILTER_OPERATION
    /// (SCAN_FILE=0, USER_ALLOW_FILE=1, SCAN_USB=2, ...)
    operation: u32,
    /// Buffer with the content of the operation
    content: [u16; 1024],
}

/// Format of a reply to the driver
#[derive(Debug)]
#[repr(C)]
struct UserReply {
    /// Header of the message, managed by Windows
    header: FILTER_REPLY_HEADER,
    /// Raw KEYSAS_AUTHORIZATION value for the kernel:
    /// AUTH_PENDING=1, AUTH_BLOCK=2, AUTH_ALLOW_READ=3, AUTH_ALLOW_WARNING=4, AUTH_ALLOW_ALL=5
    result: u8,
}

/// Handle to the driver interface
#[derive(Debug, Copy, Clone)]
pub struct WindowsFileFilterInterface {
    /// Handle to the communication port
    handle: HANDLE,
}

impl WindowsFileFilterInterface {
    /// Initialize the interface to the Windows driver
    /// The connection is made with the name in DRIVER_COM_PORT
    pub fn init() -> Result<WindowsFileFilterInterface, anyhow::Error> {
        // Open communication canal with the driver
        let com_port_name = U16CString::from_str(DRIVER_COM_PORT).unwrap().into_raw();

        let handle = unsafe {
            match FilterConnectCommunicationPort(PCWSTR(com_port_name), 0, None, 0, None) {
                Ok(h) => h,
                Err(e) => {
                    log::error!("Connection to minifilter failed: {e}");
                    return Err(anyhow!("Connection to minifilter failed: {e}"));
                }
            }
        };

        Ok(Self { handle })
    }
}

/// Name of the communication port with the driver
const DRIVER_COM_PORT: &str = "\\KeysasPort";

/// Message type: file authorization update  [0x01 | file_id_32 | auth_u8]
const MSG_FILE_AUTH: u8 = 0x01;
/// Message type: USB volume authorization update  [0x02 | auth_u8 | nt_vol_name_utf16_null]
const MSG_USB_AUTH: u8 = 0x02;

/// Resolve a DOS drive letter (e.g. "D:") to its NT device path (e.g. `\Device\HarddiskVolume3`)
/// using QueryDosDeviceW.
fn query_dos_device(drive: &str) -> Result<String, anyhow::Error> {
    let drive_wide = U16CString::from_str(drive)
        .map_err(|e| anyhow!("Invalid drive name '{}': {}", drive, e))?;
    let mut buf = vec![0u16; 512];

    let len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buf)) };

    if len == 0 {
        let err = unsafe { GetLastError() };
        return Err(anyhow!("QueryDosDeviceW failed for '{}': {:?}", drive, err));
    }

    let end = buf[..len as usize]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(len as usize);
    String::from_utf16(&buf[..end]).map_err(|e| anyhow!("NT path encoding error: {e}"))
}

/// Reverse-resolve a NT device path (e.g. `\Device\HarddiskVolume3`) to the
/// corresponding DOS mount-point path (e.g. `D:\`) by enumerating drive letters.
///
/// Returns `None` if no drive letter resolves to the given NT path.
fn nt_path_to_mnt_point(nt_path: &str) -> Option<OsString> {
    let nt_norm = nt_path.trim_end_matches('\\');
    for byte in b'A'..=b'Z' {
        let drive = format!("{}:", byte as char);
        if let Ok(resolved) = query_dos_device(&drive) {
            let res_norm = resolved.trim_end_matches('\\');
            if nt_norm.eq_ignore_ascii_case(res_norm) {
                return Some(OsString::from(format!("{}\\", drive)));
            }
        }
    }
    None
}

impl FileFilterInterface for WindowsFileFilterInterface {
    /// Start listening to the drivers' requests
    ///
    /// # Arguments
    ///
    /// * `cb` - Callback to handle the driver requests
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let handle = self.handle;
        let ctrl_hdl = ctrl.clone();
        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Pre-compute the request and response sizes.
            // UserReply.result is u8 (1 byte); the filter manager strips the header.
            let request_size = u32::try_from(size_of::<DriverRequest>())?;
            let reply_size =
                u32::try_from(size_of::<FILTER_REPLY_HEADER>())? + u32::try_from(size_of::<u8>())?;

            loop {
                // Wait for a request from the driver.
                let mut request = DriverRequest {
                    header: FILTER_MESSAGE_HEADER::default(),
                    operation: 0u32,
                    content: [0; 1024],
                };

                unsafe {
                    if FilterGetMessage(handle, &mut request.header, request_size, None).is_err() {
                        println!("Failed to get message from driver");
                        continue;
                    }
                }

                // Raw KEYSAS_AUTHORIZATION value to send back to the kernel.
                let auth_kernel: u8 = match request.operation {
                    SCAN_FILE => {
                        // content = [FileID(16×u16 = 32 bytes) | FileName(utf16, null-terminated)]
                        let mut file = FilteredFile {
                            path: None,
                            id: [0; 32],
                        };
                        for i in 0..16 {
                            let bytes = request.content[i].to_le_bytes();
                            file.id[i * 2] = bytes[0];
                            file.id[i * 2 + 1] = bytes[1];
                        }
                        let end = request.content[16..]
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(request.content.len() - 16);
                        file.path = Some(OsString::from(String::from_utf16_lossy(
                            &request.content[16..16 + end],
                        )));

                        let result = {
                            let mut ctrl = ctrl_hdl.lock().unwrap();
                            match ctrl.authorize_file(&file, true) {
                                Ok(true) => FileAuthorization::AllowRead,
                                Ok(false) => FileAuthorization::Block,
                                Err(e) => {
                                    println!("SCAN_FILE authorize_file error: {e}");
                                    FileAuthorization::Block
                                }
                            }
                        };
                        println!(
                            "SCAN_FILE -> {:?} (kernel={})",
                            result,
                            result.to_kernel_u8()
                        );
                        result.to_kernel_u8()
                    }

                    SCAN_USB => {
                        // content = [nt_volume_name (utf16, null-terminated)]
                        // e.g. "\Device\HarddiskVolume3"
                        let end = request
                            .content
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(request.content.len());
                        let nt_vol = String::from_utf16_lossy(&request.content[..end]);
                        println!("SCAN_USB for NT volume: {nt_vol}");

                        // Reverse-resolve NT path → DOS drive letter → lookup auth.
                        let auth = if let Some(mnt_point) = nt_path_to_mnt_point(&nt_vol) {
                            let ctrl = ctrl_hdl.lock().unwrap();
                            ctrl.get_usb_auth_by_mount(&mnt_point)
                                .unwrap_or(UsbAuthorization::Block)
                        } else {
                            println!("SCAN_USB: cannot resolve NT path '{nt_vol}' to drive letter");
                            UsbAuthorization::Block
                        };
                        println!("SCAN_USB -> {:?} (kernel={})", auth, auth.to_kernel_u8());
                        auth.to_kernel_u8()
                    }

                    op => {
                        println!("Unknown minifilter operation {op:#x}, blocking");
                        2u8 // AUTH_BLOCK
                    }
                };

                // Send the reply.
                let reply = UserReply {
                    header: FILTER_REPLY_HEADER {
                        MessageId: request.header.MessageId,
                        Status: STATUS_SUCCESS,
                    },
                    result: auth_kernel,
                };

                unsafe {
                    if FilterReplyMessage(handle, &reply.header, reply_size).is_err() {
                        println!("Failed to send response to driver");
                        continue;
                    }
                }
            }
        });
        Ok(())
    }

    /// Update the control policy on a file
    ///
    /// Sends a MSG_FILE_AUTH message to the minifilter:
    ///   [0x01 | file_id_32 | auth_u8]  = 34 bytes
    ///
    /// # Arguments
    ///
    /// `update` - Information on the file and the new authorization status
    fn update_file_auth(&self, update: &FilePolicy) -> Result<(), anyhow::Error> {
        let mut msg: [u8; 34] = [0; 34];
        msg[0] = MSG_FILE_AUTH;
        msg[1..33].copy_from_slice(&update.file.id);
        msg[33] = update.auth.to_kernel_u8();

        let mut nb_bytes_ret: u32 = 0;
        unsafe {
            if let Err(_) = FilterSendMessage(
                self.handle,
                &msg as *const _ as *const c_void,
                msg.len().try_into()?,
                None,
                0,
                &mut nb_bytes_ret as *mut u32,
            ) {
                let err = GetLastError();
                log::error!("update_file_auth FilterSendMessage failed: {:?}", err);
                return Err(anyhow!("Failed to send file auth update to driver"));
            }
        }

        Ok(())
    }

    /// Update the authorization policy for a USB volume in the minifilter.
    ///
    /// Resolves the DOS drive letter to the NT device path via QueryDosDeviceW,
    /// then sends a MSG_USB_AUTH message:
    ///   [0x02 | auth_u8 | nt_vol_name_utf16_null]
    ///
    /// The minifilter matches the NT path against its attached instances and updates
    /// the instance context authorization accordingly.
    ///
    /// # Arguments
    ///
    /// `update` - USB device policy including mount point and new authorization level
    fn update_usb_auth(&self, update: &UsbDevicePolicy) -> Result<(), anyhow::Error> {
        let mnt_point = match &update.device.mnt_point {
            Some(p) => p,
            None => return Err(anyhow!("USB device has no mount point")),
        };

        // Strip trailing separator to get the drive letter (e.g. "D:\" -> "D:")
        let path_str = mnt_point.to_string_lossy();
        let drive = path_str.trim_end_matches(['\\', '/']);

        // Resolve "D:" -> "\Device\HarddiskVolume3"
        let nt_path = query_dos_device(drive)?;

        log::info!(
            "update_usb_auth: {} -> {} auth={}",
            drive,
            nt_path,
            update.auth.to_kernel_u8()
        );

        // Build message: [0x02 | auth_u8 | nt_path_utf16_null_terminated]
        // auth_byte must use the kernel KEYSAS_AUTHORIZATION values.
        let auth_byte = update.auth.to_kernel_u8();
        let nt_wide: Vec<u16> = nt_path
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

        let mut msg: Vec<u8> = Vec::with_capacity(2 + nt_wide.len() * 2);
        msg.push(MSG_USB_AUTH);
        msg.push(auth_byte);
        for w in &nt_wide {
            msg.extend_from_slice(&w.to_le_bytes());
        }

        let mut nb_bytes_ret: u32 = 0;
        unsafe {
            if let Err(_) = FilterSendMessage(
                self.handle,
                msg.as_ptr() as *const c_void,
                msg.len().try_into()?,
                None,
                0,
                &mut nb_bytes_ret as *mut u32,
            ) {
                let err = GetLastError();
                log::error!("update_usb_auth FilterSendMessage failed: {:?}", err);
                return Err(anyhow!("Failed to send USB auth update to driver"));
            }
        }

        Ok(())
    }

    /// Close the communication with the driver
    fn stop(self: Box<Self>) {
        unsafe {
            let _ = CloseHandle::<HANDLE>(self.handle);
        }
    }
}
