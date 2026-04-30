// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Generic interface to the Keysas daemon/Windows service. It must be specialized
//!  for Linux and Windows
//! 
//! Communications between the daemon and the tray app are:
//! 
//! - Notification of Usb device or File authorization update
//!
//!  ```text
//!           Daemon                        App
//!           ──────                       ─────
//!             │      FileUpdateMessage     │
//!             │ ─────────────────────────► │
//!             │                            │
//!             │      UsbUpdateMessage      │
//!             │ ─────────────────────────► │
//!             │                            │
//! ```
//! 
//! - Request by the user to update the authorization status for a Usb device or a File
//!
//! ```text
//!            App                         Daemon
//!           ─────                        ──────
//!             │      FileUpdateMessage     │
//!             │ ─────────────────────────► │
//!             │                            │
//!             │      UsbUpdateMessage      │
//!             │ ─────────────────────────► │
//!             │                            │
//! ```
//! 
//! Both type of communications are done with UpdateMessage

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![allow(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use cfg_if::cfg_if;

use crate::app_controller::AppController;

#[cfg(target_os = "windows")]
use crate::windows::service_if::WindowsServiceInterface;

#[cfg(target_os = "linux")]
use crate::linux::service_if::LinuxServiceInterface;

/// Authorization states for USB devices
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum UsbAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed with a warning to the user
    AllowRW,
    /// Access is allowed for all operations
    AllowAll,
}

impl UsbAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authorization states for files
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FileAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed in read/write mode
    AllowRW,
}

impl FileAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Convert u8 to FileAuthorization, default value is Block
    pub fn from_u8(auth: u8) -> FileAuthorization {
        match auth {
            0 => FileAuthorization::Pending,
            1 => FileAuthorization::Block,
            2 => FileAuthorization::AllowRead,
            3 => FileAuthorization::AllowRW,
            _ => FileAuthorization::Block
        }
    }
}

/// Message for a file status notification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileUpdateMessage {
    pub device: String,
    pub id: [u16; 16],
    pub path: String,
    pub authorization: FileAuthorization,
}

/// Message code — mirrors the daemon's GuiMessageCode so that JSON
/// round-trips between the tray app and daemon are consistent.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum GuiMessageCode {
    UsbUpdateMessage,
    FileUpdateMessage,
    UsbFileListRequest,
    PolicyUpdate,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UsbUpdateMessage {
    /// Discriminator required by the daemon's deserializer
    pub code: GuiMessageCode,
    pub device: String,
    pub path: String,
    pub name: String,
    pub authorization: UsbAuthorization,
    /// Whether the daemon policy allows the user to elevate to read-write.
    /// Tray-app uses this to show or hide the "Autoriser l'écriture" button.
    #[serde(default)]
    pub allow_user_file_write: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct UsbFileListRequest {
    pub code: GuiMessageCode,
}

impl UsbFileListRequest {
    pub fn new() -> Self {
        UsbFileListRequest { code: GuiMessageCode::UsbFileListRequest }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ServiceInterfaceBuilder {}

impl ServiceInterfaceBuilder {
    pub fn build(_app: &tauri::AppHandle) -> Result<Box<dyn ServiceInterface + Send + Sync>, anyhow::Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let iface: Box<dyn ServiceInterface + Send + Sync> =
                    Box::new(LinuxServiceInterface::init()?);
                return Ok(iface)
            } else if #[cfg(target_os = "windows")] {
                let iface: Box<dyn ServiceInterface + Send + Sync> = Box::new(WindowsServiceInterface::init()?);
                return Ok(iface)
            } else {
                return Err(anyhow::anyhow!("OS not supported"))
            }
        }
    }
}

/// Generic Service Interface
pub trait ServiceInterface {
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error>;

    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error>;

    /// Manually authorize a blocked (non-certified) USB device.
    /// Requires `allow_user_usb_authorization = true` on the daemon side.
    fn allow_usb_override(&self, device_path: &str) -> Result<(), anyhow::Error>;

    /// Elevate a read-only USB device to read-write access.
    /// Requires `allow_user_file_write = true` on the daemon side.
    fn allow_write_usb(&self, device_path: &str) -> Result<(), anyhow::Error>;

    /// Return the list of blocked (non-certified) file paths for a device.
    /// Requires `allow_user_file_read = true` on the daemon side.
    fn get_blocked_files(&self, device_id: &str) -> Result<Vec<String>, anyhow::Error>;

    /// Move a blocked file into the pre-validated cache so the next open succeeds.
    fn authorize_blocked_file(&self, device_id: &str, path: &str) -> Result<(), anyhow::Error>;
}
