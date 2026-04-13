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
                            match serde_json::from_str::<Vec<(String, String, String, u8)>>(&json) {
                                Ok(entries) => {
                                    let updates: Vec<UsbUpdateMessage> = entries
                                        .into_iter()
                                        .map(|(device, path, name, auth_u8)| UsbUpdateMessage {
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
                                        })
                                        .collect();

                                    ctrl_hdl.set_usb_list(updates);
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
}
