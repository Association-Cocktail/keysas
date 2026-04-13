// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Controller for the application

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
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

use crate::filter_store::{FileAuth, FilterStore, UsbDevice};
use crate::service_if::{FileUpdateMessage, FileAuthorization, ServiceInterface,
    ServiceInterfaceBuilder, UsbUpdateMessage};

use anyhow::anyhow;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Emitter};

/// Application controller object, it contains handle to the application main services
pub struct AppController {
    pub store: RwLock<FilterStore>,
    view: AppHandle,
    comm: Box<dyn ServiceInterface + Send + Sync>,
}

impl AppController {
    /// Initialize the application controller
    /// It initialize
    ///     - the application data store
    ///     - the communication interface to the Keysas service
    ///     - store an handle to the view
    pub fn init(app_handle: AppHandle) -> Result<Arc<AppController>, anyhow::Error> {
        // Create the application controller
        let ctrl = Arc::new(AppController {
            store: RwLock::new(FilterStore::init_store()),
            view: app_handle.clone(),
            comm: ServiceInterfaceBuilder::build(&app_handle)?,
        });

        // Start the server thread
        if let Err(e) = ctrl.comm.start_server(&ctrl) {
            log::error!("Failed to start communications with service: {e}");
            return Err(anyhow!("Failed to start server thread: {e}"));
        }

        // Create a default USB device for the tests
        // let usb = USBDevice {
        //     name: String::from("Kingston USB"),
        //     path: String::from("D:"),
        //     authorization: UsbAuthorization::AllowRead,
        // };

        // match ctrl.store.write() {
        //     Ok(mut store) => store.add_device(&usb),
        //     Err(e) => log::error!("Failed to get store lock: {e}"),
        // }

        Ok(ctrl)
    }

    /// Called when a file notification has been received from the driver (reserved for future push-based file updates)
    #[allow(dead_code)]
    /// It adds the new file to the data store and notifies the view to update itself
    pub fn notify_file_change(&self, update: &FileUpdateMessage) {
        let mut id: [u16; 16] = Default::default();
        id.copy_from_slice(&update.id);

        // Store the new file
        let file = FileAuth {
            device: String::from(&update.device),
            id,
            path: String::from(&update.path),
            authorization: update.authorization.as_u8(),
        };

        match self.store.write() {
            Ok(mut store) => {
                if let Err(e) = store.add_file(&file) {
                    println!("Failed to add file in store: {e}");
                    return;
                }
            }
            Err(e) => println!("Failed to get store lock: {e}"),
        }

        // Notify the GUI to update the view
        if let Err(e) = self
            .view
            .emit("file_update", String::from(&update.device))
        {
            println!("Failed to notify view of file changed: {e}");
        }
    }

    /// Replace the entire device list with the latest snapshot from the daemon.
    ///
    /// Called each polling cycle so that devices removed since the last poll
    /// disappear from the store automatically.
    pub fn set_usb_list(&self, updates: Vec<UsbUpdateMessage>) {
        let devices: Vec<UsbDevice> = updates
            .into_iter()
            .map(|u| UsbDevice {
                id: u.device,
                name: u.name,
                path: u.path,
                authorization: u.authorization.as_u8(),
            })
            .collect();

        match self.store.write() {
            Ok(mut store) => store.replace_devices(devices),
            Err(e) => log::error!("set_usb_list: failed to acquire store lock: {e}"),
        }

        // Notify the UI to refresh the device list
        if let Err(e) = self.view.emit("usb_update", ()) {
            log::error!("set_usb_list: failed to emit usb_update event: {e}");
        }
    }

    /// Called when a usb notification has been received from the driver (reserved for future push-based updates).
    #[allow(dead_code)]
    ///
    /// Upserts the device in the store (update if already present, add otherwise)
    /// then emits a `usb_update` event so the UI can refresh.
    pub fn notify_usb_change(&self, update: &UsbUpdateMessage) {
        match self.store.write() {
            Ok(mut store) => {
                if let Some(existing) = store.get_device_mut(&update.device) {
                    existing.name.clone_from(&update.name);
                    existing.path.clone_from(&update.path);
                    existing.authorization = update.authorization.as_u8();
                } else {
                    store.add_device(&UsbDevice {
                        id: update.device.clone(),
                        name: update.name.clone(),
                        path: update.path.clone(),
                        authorization: update.authorization.as_u8(),
                    });
                }
            }
            Err(e) => log::error!("notify_usb_change: failed to acquire store lock: {e}"),
        }

        if let Err(e) = self.view.emit("usb_update", &update.device) {
            log::error!("notify_usb_change: failed to emit usb_update event: {e}");
        }
    }

    /// Return a clone of the application handle (used by the polling thread).
    pub fn app_handle(&self) -> AppHandle {
        self.view.clone()
    }

    /// Ask the daemon to manually authorize a blocked USB device.
    pub fn allow_usb(&self, device_path: &str) -> Result<(), anyhow::Error> {
        self.comm.allow_usb_override(device_path)
    }

    /// Return the list of files in the datastore
    pub fn get_file_list(&self, device_path: &str) -> Result<Vec<FileAuth>, anyhow::Error> {
        match self.store.read() {
            Ok(store) => store.get_files(device_path),
            Err(e) => Err(anyhow!("Failed to get store lock: {e}")),
        }
    }

    /// Request a change of file authorization in the driver
    /// If it is successful it then change it in the datastore and updates the view
    pub fn request_file_auth_toggle(
        &self,
        device: &str,
        id: &[u16],
        path: &str,
        new_auth: FileAuthorization,
    ) -> Result<(), anyhow::Error> {
        let mut file_id: [u16; 16] = Default::default();
        file_id.copy_from_slice(id);

        if let Err(e) = self.comm.send_file_update(&FileUpdateMessage {
            device: device.to_string(),
            id: file_id,
            path: path.to_string(),
            authorization: new_auth,
        }) {
            println!("request_file_auth_toggle: File toggle failed: {e}");
            return Err(anyhow!("Failed to send request to Keysas daemon: {e}"));
        }

        Ok(())
    }
}
