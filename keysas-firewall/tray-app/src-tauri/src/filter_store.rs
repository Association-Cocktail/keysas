// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Data store for Keysas filter application

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

use crate::service_if::UsbAuthorization;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FileAuth {
    pub device: String,
    pub id: [u16; 16],
    pub path: String,
    pub authorization: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbDevice {
    /// Unique device identifier (device node path, e.g. `/dev/sdb1`).
    pub id: String,
    pub name: String,
    /// Mount point (e.g. `/media/user/Volta`), empty while unmounted.
    pub path: String,
    /// Serialized as u8 so TypeScript can compare with numeric enum values.
    pub authorization: u8,
    /// Files that were blocked (not pre-certified) and are awaiting user authorization.
    pub blocked_files: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FilterStore {
    pub devices: Vec<UsbDevice>,
    pub files: Vec<FileAuth>,
}

impl FilterStore {
    pub fn init_store() -> FilterStore {
        FilterStore {
            devices: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn add_device(&mut self, device: &UsbDevice) {
        self.devices.push(device.clone());
    }

    /// Replace the entire device list (used after each polling cycle to
    /// reconcile the store with the daemon's current state).
    pub fn replace_devices(&mut self, devices: Vec<UsbDevice>) {
        self.devices = devices;
    }

    pub fn remove_device(&mut self, device_id: &str) -> Result<(), anyhow::Error> {
        self.devices.retain(|d| !d.id.eq(device_id));
        // Also remove all files associated with the device
        self.files.retain(|f| !f.device.eq(device_id));
        Ok(())
    }

    pub fn get_devices(&self) -> &[UsbDevice] {
        &self.devices
    }

    /// Look up a device by its unique device ID.
    pub fn get_device(&self, device_id: &str) -> Option<&UsbDevice> {
        self.devices.iter().find(|d| d.id.eq(device_id))
    }

    /// Look up a device mutably by its unique device ID.
    pub fn get_device_mut(&mut self, device_id: &str) -> Option<&mut UsbDevice> {
        self.devices.iter_mut().find(|d| d.id.eq(device_id))
    }

    /// Set the blocked-files list for a device (replaces previous list).
    pub fn set_device_blocked_files(&mut self, device_id: &str, files: Vec<String>) {
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == device_id) {
            d.blocked_files = files;
        }
    }

    pub fn set_device_auth(
        &mut self,
        device_id: &str,
        auth: UsbAuthorization,
    ) -> Result<(), anyhow::Error> {
        match self.devices.iter_mut().find(|d| d.id.eq(device_id)) {
            Some(d) => {
                d.authorization = auth.as_u8();
                Ok(())
            }
            None => Err(anyhow::anyhow!("Device '{}' not found", device_id)),
        }
    }

    pub fn add_file(&mut self, file: &FileAuth) -> Result<(), anyhow::Error> {
        self.files.push(file.clone());
        Ok(())
    }

    pub fn remove_file(
        &mut self,
        device_id: &str,
        file_path: &str,
    ) -> Result<(), anyhow::Error> {
        self.files
            .retain(|f| !(f.device.eq(device_id) && f.path.eq(file_path)));
        Ok(())
    }

    pub fn get_files(&self, device_id: &str) -> Result<Vec<FileAuth>, anyhow::Error> {
        let files: Vec<FileAuth> = self
            .files
            .iter()
            .filter(|f| f.device.eq(device_id))
            .cloned()
            .collect();
        Ok(files)
    }

    pub fn set_file_auth(
        &mut self,
        device_id: &str,
        file_path: &str,
        auth: u8,
    ) -> Result<(), anyhow::Error> {
        match self
            .files
            .iter_mut()
            .find(|f| f.device.eq(device_id) && f.path.eq(file_path))
        {
            Some(f) => {
                f.authorization = auth;
                Ok(())
            }
            None => Err(anyhow::anyhow!(
                "File '{}' on device '{}' not found",
                file_path,
                device_id
            )),
        }
    }
}
