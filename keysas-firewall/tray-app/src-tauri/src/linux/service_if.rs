// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Linux implementation of the Service Interface via D-Bus.
//!
//! The tray-app connects to `fr.asso_cocktail.keysas.Firewall1` on the
//! **system bus** (registered by the root daemon) to:
//!
//! - **`start_server`** — spawns a polling thread that calls `get_usb_list`
//!   every 5 seconds, feeds updates into the `AppController`, then calls
//!   `sni::notify_sni` so GNOME Shell refreshes the tray icon immediately.
//!
//! - **`send_usb_update`** — calls `update_usb_authorization` on the daemon
//!   when the user changes a device's authorization via the UI.
//!
//! - **`send_file_update`** — not yet supported over D-Bus; logs a warning.
//!
//! **D-Bus policy**: the daemon package ships
//! `/etc/dbus-1/system.d/fr.asso-cocktail.keysas.Firewall1.conf` which
//! grants members of the `keysas` group the right to call methods on the
//! service.  The tray-app user must belong to that group.

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
use crate::linux::sni::{notify_sni, SniHandle};
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
    /// Ask the daemon to emit update notifications for all current devices.
    fn request_objects_list(&self) -> zbus::Result<()>;

    /// Change the authorization of a USB device.
    ///
    /// `auth` encodes `UsbAuthorization` (same as daemon):
    ///   1 = Block | 2 = AllowRead | 3 = AllowRW | 4 = AllowAll
    fn update_usb_authorization(&self, device: &str, auth: u8) -> zbus::Result<()>;

    /// Return the current USB device list as a JSON array of
    /// `[device_id, mount_point, name, auth_u8]` tuples.
    fn get_usb_list(&self) -> zbus::Result<String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxServiceInterface
// ─────────────────────────────────────────────────────────────────────────────

/// Handle to the D-Bus service interface.
#[derive(Debug)]
pub struct LinuxServiceInterface {
    /// Handle to the SNI tray icon — used to push NewIcon/NewStatus signals
    /// after each polling cycle.
    sni: Arc<SniHandle>,
}

impl LinuxServiceInterface {
    pub fn init(sni: SniHandle) -> Result<LinuxServiceInterface, anyhow::Error> {
        Ok(LinuxServiceInterface {
            sni: Arc::new(sni),
        })
    }
}

/// Derive the SNI status string from the current device list.
///
/// - No devices        → "Passive"   (dim icon: nothing connected)
/// - Any Pending       → "NeedsAttention" (animated/highlighted icon)
/// - Otherwise         → "Active"    (normal icon)
fn status_from_updates(updates: &[UsbUpdateMessage]) -> &'static str {
    if updates.is_empty() {
        return "Passive";
    }
    if updates
        .iter()
        .any(|u| u.authorization == UsbAuthorization::Pending)
    {
        return "NeedsAttention";
    }
    "Active"
}

impl ServiceInterface for LinuxServiceInterface {
    /// Spawn a background thread that polls `get_usb_list` every 5 seconds,
    /// reconciles the tray-app store, and notifies GNOME Shell via SNI signals.
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let sni_hdl  = self.sni.clone();

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

                                    // Compute SNI status before moving updates.
                                    let new_status = status_from_updates(&updates);

                                    // Update the application store and emit usb_update
                                    // to the Tauri frontend.
                                    ctrl_hdl.set_usb_list(updates);

                                    // Notify GNOME Shell so it refreshes the tray
                                    // icon without waiting for its next property poll.
                                    notify_sni(&sni_hdl, new_status);
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

    /// Send a USB authorization change to the daemon.
    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| anyhow!("System bus connection failed: {e}"))?;
        let proxy = Firewall1ProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Firewall1 proxy error: {e}"))?;
        proxy
            .update_usb_authorization(&update.device, update.authorization.as_u8())
            .map_err(|e| anyhow!("update_usb_authorization failed: {e}"))?;
        Ok(())
    }

    /// File authorization changes are not yet supported over the D-Bus interface.
    fn send_file_update(&self, _update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        log::warn!("send_file_update: not supported on the Linux D-Bus interface");
        Ok(())
    }
}
