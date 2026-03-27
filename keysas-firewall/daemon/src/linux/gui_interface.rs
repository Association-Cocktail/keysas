// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Linux implementation of the GUI interface via D-Bus.
//!
//! Two roles:
//!
//! 1. **Notifications** — sends desktop notifications via
//!    `org.freedesktop.Notifications` on the user's session bus.
//!
//! 2. **D-Bus server** — exposes `fr.asso_cocktail.keysas.Firewall1` on the
//!    system bus so the tray-app can query the device list and request
//!    authorization updates.
//!
//! Session bus discovery: scans `/run/user/*/bus`, skips UID 0 (root).

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
use log::{info, warn};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crate::controller::{ServiceController, UsbAuthorization};
use crate::gui_interface::{
    FileUpdateMessage, GuiInterface, GuiMessageCode, UsbUpdateMessage,
};

// ─────────────────────────────────────────────────────────────────────────────
// D-Bus proxy — org.freedesktop.Notifications (client, session bus)
// ─────────────────────────────────────────────────────────────────────────────

#[zbus::dbus_proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    /// Send a desktop notification. Returns the notification ID.
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, zbus::zvariant::Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    /// Emitted when the user invokes an action on a notification.
    #[dbus_proxy(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;

    /// Emitted when a notification is closed (dismissed or expired).
    #[dbus_proxy(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// D-Bus server interface — fr.asso_cocktail.keysas.Firewall1 (system bus)
// Called by the tray-app to query state and push authorization changes.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct FirewallService {
    ctrl: Arc<Mutex<ServiceController>>,
}

#[zbus::dbus_interface(name = "fr.asso_cocktail.keysas.Firewall1")]
impl FirewallService {
    /// Ask the daemon to emit UsbUpdateMessage / FileUpdateMessage for all
    /// currently registered devices and files.
    fn request_objects_list(&self) -> zbus::fdo::Result<()> {
        if let Err(e) = self.ctrl.lock().unwrap().send_usb_file_list() {
            warn!("request_objects_list: {e}");
        }
        Ok(())
    }

    /// Return the current USB device list as a JSON array of
    /// `[device_id, mount_point, name, auth_u8]` tuples.
    ///
    /// The tray-app calls this periodically to sync its state.
    fn get_usb_list(&self) -> zbus::fdo::Result<String> {
        let entries = self.ctrl.lock().unwrap().list_usb_devices();
        serde_json::to_string(&entries)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Change the authorization of a USB device.
    ///
    /// `auth` encodes UsbAuthorization:
    ///   1 = Block | 2 = AllowRead | 3 = AllowRW | 4 = AllowAll
    fn update_usb_authorization(
        &self,
        device: String,
        auth: u8,
    ) -> zbus::fdo::Result<()> {
        let authorization = match auth {
            1 => UsbAuthorization::Block,
            2 => UsbAuthorization::AllowRead,
            3 => UsbAuthorization::AllowRW,
            4 => UsbAuthorization::AllowAll,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "auth must be 1..4".into(),
                ))
            }
        };
        let msg = UsbUpdateMessage {
            code: GuiMessageCode::UsbUpdateMessage,
            device,
            path: String::default(),
            name: String::default(),
            authorization,
        };
        if let Err(e) = self.ctrl.lock().unwrap().request_usb_update(&msg) {
            warn!("update_usb_authorization: {e}");
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxGuiInterface
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LinuxGuiInterface {
    stop_flag: Arc<AtomicBool>,
}

impl LinuxGuiInterface {
    pub fn init() -> Result<LinuxGuiInterface, anyhow::Error> {
        Ok(LinuxGuiInterface {
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Discover the D-Bus session bus socket of the first non-root user logged
    /// in, by scanning `/run/user/*/bus`.
    fn session_bus_address() -> Result<String, anyhow::Error> {
        let entries = std::fs::read_dir("/run/user")
            .map_err(|e| anyhow!("Cannot scan /run/user: {e}"))?;

        for entry in entries.flatten() {
            let uid = entry.file_name().to_string_lossy().to_string();
            if uid == "0" {
                continue; // skip root
            }
            let bus = entry.path().join("bus");
            if bus.exists() {
                return Ok(format!("unix:path=/run/user/{}/bus", uid));
            }
        }
        Err(anyhow!("No user session bus found in /run/user/*/bus"))
    }

    /// Connect to the session bus of the first logged-in user.
    fn session_conn() -> Result<zbus::blocking::Connection, anyhow::Error> {
        let addr = Self::session_bus_address()?;
        zbus::blocking::ConnectionBuilder::address(addr.as_str())?
            .build()
            .map_err(|e| anyhow!("Session bus connection failed: {e}"))
    }

    /// Fire-and-forget desktop notification.
    fn notify_desktop(summary: &str, body: &str, icon: &str) {
        match Self::session_conn() {
            Ok(conn) => {
                match NotificationsProxyBlocking::new(&conn) {
                    Ok(proxy) => {
                        if let Err(e) = proxy.notify(
                            "Keysas Firewall",
                            0,
                            icon,
                            summary,
                            body,
                            &[],
                            HashMap::new(),
                            5000,
                        ) {
                            warn!("Notification send error: {e}");
                        }
                    }
                    Err(e) => warn!("Notifications proxy error: {e}"),
                }
            }
            Err(e) => warn!("Desktop notification skipped: {e}"),
        }
    }

    /// Send a notification with "Autoriser" / "Refuser" action buttons and
    /// block until the user responds or `timeout_secs` elapses.
    ///
    /// Returns `true` if the user clicked "Autoriser", `false` otherwise
    /// (deny is the safe default on timeout or dismissal).
    fn request_auth_dialog(
        summary: &str,
        body: &str,
        timeout_secs: u64,
    ) -> Result<bool, anyhow::Error> {
        let conn = Self::session_conn()?;
        let proxy = NotificationsProxyBlocking::new(&conn)
            .map_err(|e| anyhow!("Notifications proxy: {e}"))?;

        // Actions are (action-key, display-label) pairs flattened into a slice
        let notif_id = proxy
            .notify(
                "Keysas Firewall",
                0,
                "security-high",
                summary,
                body,
                &["allow", "Autoriser", "deny", "Refuser"],
                HashMap::new(),
                (timeout_secs * 1000) as i32,
            )
            .map_err(|e| anyhow!("Notify call failed: {e}"))?;

        // Channel to collect the first answer from either signal thread
        let (tx, rx) = mpsc::channel::<bool>();

        // Thread 1 — wait for ActionInvoked
        {
            let tx1 = tx.clone();
            let conn1 = conn.clone();
            let id = notif_id;
            thread::spawn(move || {
                let p = match NotificationsProxyBlocking::new(&conn1) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let iter = match p.receive_action_invoked() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                for sig in iter {
                    if let Ok(args) = sig.args() {
                        if args.id() == id {
                            let _ = tx1.send(args.action_key() == "allow");
                            return;
                        }
                    }
                }
            });
        }

        // Thread 2 — wait for NotificationClosed (dismissal / expiry)
        {
            let tx2 = tx;
            let conn2 = conn.clone();
            let id = notif_id;
            thread::spawn(move || {
                let p = match NotificationsProxyBlocking::new(&conn2) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let iter = match p.receive_notification_closed() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                for sig in iter {
                    if let Ok(args) = sig.args() {
                        if args.id() == id {
                            let _ = tx2.send(false); // closed = deny
                            return;
                        }
                    }
                }
            });
        }

        // Block with timeout — deny is the safe default
        match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
            Ok(result) => Ok(result),
            Err(_) => Ok(false),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GuiInterface implementation
// ─────────────────────────────────────────────────────────────────────────────

impl GuiInterface for LinuxGuiInterface {
    /// Start the D-Bus server on the system bus and begin listening for
    /// method calls from the tray-app.
    fn start(
        &mut self,
        ctrl: &Arc<Mutex<ServiceController>>,
    ) -> Result<(), anyhow::Error> {
        let ctrl_hdl = ctrl.clone();
        let stop_flag = self.stop_flag.clone();

        thread::spawn(move || {
            let service = FirewallService { ctrl: ctrl_hdl };

            let conn = match zbus::blocking::ConnectionBuilder::system()
                .and_then(|b| b.name("fr.asso_cocktail.keysas.Firewall1"))
                .and_then(|b| {
                    b.serve_at("/fr/asso_cocktail/keysas/Firewall", service)
                })
                .and_then(|b| b.build())
            {
                Ok(c) => c,
                Err(e) => {
                    warn!("D-Bus server failed to start: {e}");
                    return;
                }
            };

            info!(
                "D-Bus server ready: fr.asso_cocktail.keysas.Firewall1 \
                 at /fr/asso_cocktail/keysas/Firewall"
            );

            // Keep the connection alive until stop() is called
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }

            drop(conn);
            info!("D-Bus server stopped");
        });

        Ok(())
    }

    /// Notify the user of a USB device status change.
    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        let (summary, icon) = match update.authorization {
            UsbAuthorization::Block | UsbAuthorization::Pending => (
                format!("Clé USB bloquée — {}", update.name),
                "security-high",
            ),
            UsbAuthorization::AllowRead => (
                format!("Clé USB autorisée (lecture) — {}", update.name),
                "security-medium",
            ),
            UsbAuthorization::AllowRW | UsbAuthorization::AllowAll => (
                format!("Clé USB autorisée — {}", update.name),
                "security-low",
            ),
        };

        let body = if update.path.is_empty() {
            format!("Périphérique : {}", update.device)
        } else {
            format!("Monté sur : {}", update.path)
        };

        Self::notify_desktop(&summary, &body, icon);
        Ok(())
    }

    /// Notify the user of a file status change (informational).
    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        let summary = format!("Fichier — {}", update.path);
        let body = format!("Autorisation : {:?}", update.authorization);
        Self::notify_desktop(&summary, &body, "dialog-information");
        Ok(())
    }

    /// Ask the user to authorize access to a file.
    ///
    /// Sends a notification with "Autoriser" / "Refuser" buttons and waits
    /// up to 30 seconds. Returns `false` (deny) on timeout or dismissal.
    fn request_file_auth(&self, file: &FileUpdateMessage) -> Result<bool, anyhow::Error> {
        let summary = "Fichier non vérifié — autoriser l'accès ?";
        let body = format!(
            "Le fichier suivant ne possède pas de rapport d'analyse valide :\n{}",
            file.path
        );
        Self::request_auth_dialog(summary, &body, 30)
    }

    /// Ask the user to authorize a USB key.
    ///
    /// Called when `allow_user_usb_authorization = true` and the key has no
    /// valid signature. Sends a notification with action buttons and waits
    /// up to 60 seconds. Returns `false` (deny) on timeout or dismissal.
    fn request_usb_auth(&self, usb: &UsbUpdateMessage) -> Result<bool, anyhow::Error> {
        let summary = "Clé USB non signée — autoriser le montage ?";
        let body = format!(
            "La clé « {} » (périphérique : {}) n'est pas enrôlée dans Keysas.\n\
             Autoriser uniquement si vous faites confiance à cette clé.",
            usb.name, usb.device
        );
        Self::request_auth_dialog(summary, &body, 60)
    }

    /// Stop the D-Bus server thread.
    fn stop(self: Box<Self>) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}
