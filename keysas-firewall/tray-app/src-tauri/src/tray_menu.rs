// SPDX-License-Identifier: GPL-3.0-only
//! Builds and refreshes the system-tray menu from the current USB device list.
//!
//! Menu structure:
//!   ✓ Device name      (AllowRead / AllowRW / AllowAll)
//!   ✗ Device name      (Block / Pending)
//!       Autoriser      (only when blocked/pending)
//!   ────────────────
//!   Quitter

use std::sync::Arc;

use tauri::{AppHandle, Manager};
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, Menu};
use tauri::tray::TrayIcon;

use crate::app_controller::AppController;
use crate::filter_store::UsbDevice;

/// Build a fresh `Menu` from a slice of USB devices.
pub fn build_usb_menu(app: &AppHandle, devices: &[UsbDevice]) -> Result<Menu<tauri::Wry>, anyhow::Error> {
    let mut builder = MenuBuilder::new(app);

    if devices.is_empty() {
        builder = builder.item(
            &MenuItemBuilder::new("Aucun périphérique USB")
                .enabled(false)
                .build(app)?,
        );
    } else {
        for dev in devices {
            let label = if dev.authorization <= 1 {
                format!("✗  {}", dev.name)
            } else {
                format!("✓  {}", dev.name)
            };
            builder = builder.item(
                &MenuItemBuilder::with_id(format!("device:{}", dev.id), label)
                    .build(app)?,
            );
            if dev.authorization <= 1 {
                builder = builder.item(
                    &MenuItemBuilder::with_id(
                        format!("authorize:{}", dev.id),
                        "    Autoriser",
                    )
                    .build(app)?,
                );
            }
        }
    }

    builder = builder
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&MenuItemBuilder::with_id("quit", "Quitter").build(app)?);

    Ok(builder.build()?)
}

/// Rebuild the tray icon's menu from the current store contents.
/// Safe to call from any thread.
pub fn rebuild_tray_menu(app: &AppHandle, ctrl: &Arc<AppController>) {
    let devices = match ctrl.store.read() {
        Ok(store) => store.get_devices().to_vec(),
        Err(e) => {
            log::warn!("rebuild_tray_menu: store lock failed: {e}");
            return;
        }
    };

    let menu = match build_usb_menu(app, &devices) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("rebuild_tray_menu: build failed: {e}");
            return;
        }
    };

    match app.try_state::<TrayIcon<tauri::Wry>>() {
        Some(tray) => {
            if let Err(e) = tray.set_menu(Some(menu)) {
                log::warn!("rebuild_tray_menu: set_menu failed: {e}");
            }
        }
        None => log::warn!("rebuild_tray_menu: TrayIcon not yet in managed state"),
    }
}
