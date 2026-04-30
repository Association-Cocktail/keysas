// SPDX-License-Identifier: GPL-3.0-only
//! Linux implementation of the Service Interface via D-Bus.
//!
//! Polls `fr.asso_cocktail.keysas.Firewall1` every 5 seconds, feeds updates
//! into the `AppController`, then calls `tray_menu::rebuild_tray_menu` so
//! GNOME Shell refreshes the native tray menu immediately.

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use std::sync::Arc;

use crate::app_controller::AppController;
use crate::service_if::{FileUpdateMessage, ServiceInterface, UsbAuthorization, UsbUpdateMessage};

// ─────────────────────────────────────────────────────────────────────────────
// D-Bus proxy — fr.asso_cocktail.keysas.Firewall1 (system bus, blocking)
// ─────────────────────────────────────────────────────────────────────────────

#[zbus::dbus_proxy(
    interface = "fr.asso_cocktail.keysas.Firewall1",
    default_service = "fr.asso_cocktail.keysas.Firewall1",
    default_path = "/fr/asso_cocktail/keysas/Firewall"
)]
trait Firewall1 {
    fn request_objects_list(&self) -> zbus::Result<()>;
    fn update_usb_authorization(&self, device: &str, auth: u8) -> zbus::Result<()>;
    fn get_usb_list(&self) -> zbus::Result<String>;
    fn override_usb_authorization(&self, device: &str) -> zbus::Result<()>;
    fn get_blocked_files(&self, device: &str) -> zbus::Result<String>;
    fn authorize_blocked_file(&self, device: &str, path: &str) -> zbus::Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxServiceInterface
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Copy, Clone)]
pub struct LinuxServiceInterface {}

impl LinuxServiceInterface {
    pub fn init() -> Result<LinuxServiceInterface, anyhow::Error> {
        Ok(LinuxServiceInterface {})
    }
}

impl ServiceInterface for LinuxServiceInterface {
    /// Spawn a background thread that polls `get_usb_list` every 5 seconds,
    /// reconciles the tray-app store, then rebuilds the native tray menu.
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let app = ctrl.app_handle();

        std::thread::spawn(move || loop {
            match zbus::blocking::Connection::system() {
                Ok(conn) => match Firewall1ProxyBlocking::new(&conn) {
                    Ok(proxy) => match proxy.get_usb_list() {
                        Ok(json) => {
                            match serde_json::from_str::<
                                Vec<(String, String, String, u8, bool, bool, bool)>,
                            >(&json)
                            {
                                Ok(entries) => {
                                    let updates: Vec<UsbUpdateMessage> = entries
                                        .into_iter()
                                        .map(|(device, path, name, auth_u8, allow_write, allow_read, allow_usb)| UsbUpdateMessage {
                                            code: crate::service_if::GuiMessageCode::UsbUpdateMessage,
                                            device,
                                            path,
                                            name,
                                            authorization: match auth_u8 {
                                                0 => UsbAuthorization::Pending,
                                                1 => UsbAuthorization::Block,
                                                2 => UsbAuthorization::AllowRead,
                                                3 => UsbAuthorization::AllowRW,
                                                _ => UsbAuthorization::AllowAll,
                                            },
                                            allow_user_file_write: allow_write,
                                            allow_user_file_read: allow_read,
                                            allow_user_usb_authorization: allow_usb,
                                            blocked_files: Vec::new(),
                                        })
                                        .collect();

                                    // Fetch blocked files for each device and
                                    // store them before rebuilding the tray.
                                    let device_ids: Vec<String> =
                                        updates.iter().map(|u| u.device.clone()).collect();
                                    ctrl_hdl.set_usb_list(updates);
                                    for device_id in &device_ids {
                                        match proxy.get_blocked_files(device_id) {
                                            Ok(json) => {
                                                if let Ok(files) =
                                                    serde_json::from_str::<Vec<String>>(&json)
                                                {
                                                    ctrl_hdl.set_blocked_files(device_id, files);
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("get_blocked_files({device_id}): {e}");
                                            }
                                        }
                                    }
                                    crate::tray_menu::rebuild_tray_menu(&app, &ctrl_hdl);
                                }
                                Err(e) => {
                                    log::warn!("start_server: failed to parse USB list JSON: {e}")
                                }
                            }
                        }
                        Err(e) => log::warn!("get_usb_list failed: {e}"),
                    },
                    Err(e) => log::warn!("Firewall1 proxy error: {e}"),
                },
                Err(e) => log::warn!("System bus connection failed: {e}"),
            }

            std::thread::sleep(std::time::Duration::from_secs(5));
        });

        Ok(())
    }

    fn send_file_update(&self, _update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        log::warn!("send_file_update: not supported on the Linux D-Bus interface");
        Ok(())
    }

    fn allow_usb_override(&self, device_path: &str) -> Result<(), anyhow::Error> {
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| anyhow!("System bus connection failed: {e}"))?;
        let proxy = Firewall1ProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Firewall1 proxy error: {e}"))?;
        proxy
            .override_usb_authorization(device_path)
            .map_err(|e| anyhow!("override_usb_authorization failed: {e}"))?;
        Ok(())
    }

    fn allow_write_usb(&self, device_path: &str) -> Result<(), anyhow::Error> {
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| anyhow!("System bus connection failed: {e}"))?;
        let proxy = Firewall1ProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Firewall1 proxy error: {e}"))?;
        // auth=3 maps to UsbAuthorization::AllowRW in the daemon
        proxy
            .update_usb_authorization(device_path, 3)
            .map_err(|e| anyhow!("update_usb_authorization(AllowRW) failed: {e}"))?;
        Ok(())
    }

    fn get_blocked_files(&self, device_id: &str) -> Result<Vec<String>, anyhow::Error> {
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| anyhow!("System bus connection failed: {e}"))?;
        let proxy = Firewall1ProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Firewall1 proxy error: {e}"))?;
        let json = proxy
            .get_blocked_files(device_id)
            .map_err(|e| anyhow!("get_blocked_files failed: {e}"))?;
        serde_json::from_str::<Vec<String>>(&json)
            .map_err(|e| anyhow!("Failed to parse blocked files JSON: {e}"))
    }

    fn authorize_blocked_file(&self, device_id: &str, path: &str) -> Result<(), anyhow::Error> {
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| anyhow!("System bus connection failed: {e}"))?;
        let proxy = Firewall1ProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Firewall1 proxy error: {e}"))?;
        proxy
            .authorize_blocked_file(device_id, path)
            .map_err(|e| anyhow!("authorize_blocked_file failed: {e}"))
    }
}
