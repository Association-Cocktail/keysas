// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Implementation of the Service Interface for Windows

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

use anyhow::anyhow;
use std::sync::{Arc, RwLock};

use crate::app_controller::AppController;
use crate::service_if::{
    FileAuthorization, FileUpdateMessage, GuiMessageCode, ServiceInterface, UsbAuthorization,
    UsbFileListRequest, UsbUpdateMessage,
};

/// Handle to the service interface client and server
pub struct WindowsServiceInterface {
    server: Arc<RwLock<libmailslot::MailSlot>>,
}

/// Name of the communication pipes (named pipes — no SMB, no network).
const SERVICE_PIPE: &str = r"\\.\pipe\keysas-service-to-app";
const TRAY_PIPE: &str = r"\\.\pipe\keysas-app-to-service";

impl WindowsServiceInterface {
    pub fn init() -> Result<WindowsServiceInterface, anyhow::Error> {
        // Initialize the mailslot handles
        let server = match libmailslot::create_mailslot(SERVICE_PIPE) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("Failed to create server: {e}")),
        };

        Ok(WindowsServiceInterface {
            server: RwLock::new(server).into(),
        })
    }
}

fn request_usb_file_list() {
    if let Ok(req) = serde_json::to_string(&UsbFileListRequest::new()) {
        if let Err(e) = libmailslot::write_mailslot(TRAY_PIPE, &req) {
            log::warn!("Windows tray: failed to send UsbFileListRequest: {e}");
        }
    }
}

impl ServiceInterface for WindowsServiceInterface {
    /// Start the server thread to listen for the Keysas service
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error> {
        // Start listening on the server side
        let ctrl_hdl = ctrl.clone();
        let server = self.server.clone();
        std::thread::spawn(move || {
            // Get a mutable lock on the server
            let mut server = match server.write() {
                Ok(s) => s,
                Err(_) => {
                    return;
                }
            };
            log::info!("Windows tray: listening for daemon on {SERVICE_PIPE}");
            loop {
                match libmailslot::read_mailslot(&mut *server) {
                    Ok(Some(msg)) => {
                        if let Ok(update) =
                            serde_json::from_slice::<FileUpdateMessage>(msg.as_bytes())
                        {
                            ctrl_hdl.notify_file_change(&update);
                        } else if let Ok(update) =
                            serde_json::from_slice::<UsbUpdateMessage>(msg.as_bytes())
                        {
                            ctrl_hdl.notify_usb_change(&update);
                        } else {
                            log::warn!("Windows tray: unrecognised message from daemon");
                        }
                    }
                    Ok(None) => {
                        // Client disconnected; ConnectNamedPipe in the next call
                        // will block — no sleep needed with PIPE_WAIT.
                    }
                    Err(e) => {
                        log::error!("Windows tray: read_mailslot error: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        });
        // Request the current device list from the daemon so that USB keys
        // already connected before the tray-app started are shown immediately.
        request_usb_file_list();

        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            request_usb_file_list();
        });

        Ok(())
    }

    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        let json = serde_json::to_string(update)
            .map_err(|e| anyhow!("Failed to serialize FileUpdateMessage: {e}"))?;
        libmailslot::write_mailslot(TRAY_PIPE, &json)
            .map_err(|e| anyhow!("Failed to send FileUpdateMessage to daemon: {e}"))
    }

    /// Send an override request for a blocked (non-certified) USB device to the
    /// daemon via the app-to-service mailslot.  The daemon's mailslot server
    /// deserialises the message as `UsbUpdateMessage` and routes it through
    /// `request_usb_update()` → `override_blocked_usb()`.
    fn allow_usb_override(&self, device_path: &str) -> Result<(), anyhow::Error> {
        let msg = UsbUpdateMessage {
            code: GuiMessageCode::UsbUpdateMessage,
            device: device_path.to_string(),
            path: String::new(),
            name: String::new(),
            authorization: UsbAuthorization::AllowRW,
            allow_user_file_write: false,
            allow_user_file_read: false,
            allow_user_usb_authorization: false,
            blocked_files: Vec::new(),
        };
        let json = serde_json::to_string(&msg)
            .map_err(|e| anyhow!("Failed to serialize USB override message: {e}"))?;
        libmailslot::write_mailslot(TRAY_PIPE, &json)
            .map_err(|e| anyhow!("Failed to send USB override to daemon: {e}"))
    }

    fn allow_write_usb(&self, device_path: &str) -> Result<(), anyhow::Error> {
        let msg = UsbUpdateMessage {
            code: GuiMessageCode::UsbUpdateMessage,
            device: device_path.to_string(),
            path: String::new(),
            name: String::new(),
            authorization: UsbAuthorization::AllowRW,
            allow_user_file_write: false,
            allow_user_file_read: false,
            allow_user_usb_authorization: false,
            blocked_files: Vec::new(),
        };
        let json = serde_json::to_string(&msg)
            .map_err(|e| anyhow!("Failed to serialize USB write elevation message: {e}"))?;
        libmailslot::write_mailslot(TRAY_PIPE, &json)
            .map_err(|e| anyhow!("Failed to send USB write elevation to daemon: {e}"))
    }

    fn get_blocked_files(&self, _device_id: &str) -> Result<Vec<String>, anyhow::Error> {
        Ok(Vec::new())
    }

    fn authorize_blocked_file(&self, device_id: &str, path: &str) -> Result<(), anyhow::Error> {
        let msg = FileUpdateMessage {
            code: GuiMessageCode::FileUpdateMessage,
            device: device_id.to_string(),
            id: [0u16; 16],
            path: path.to_string(),
            authorization: FileAuthorization::AllowRead,
        };
        let json = serde_json::to_string(&msg)
            .map_err(|e| anyhow!("Failed to serialize authorize file message: {e}"))?;
        libmailslot::write_mailslot(TRAY_PIPE, &json)
            .map_err(|e| anyhow!("Failed to send authorize file message to daemon: {e}"))
    }
}
