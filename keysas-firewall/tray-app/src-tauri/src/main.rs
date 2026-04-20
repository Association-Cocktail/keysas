// SPDX-License-Identifier: GPL-3.0-only
//! Entry point for the USB Firewall administration panel

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
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_controller;
mod filter_store;
mod service_if;
mod tray_menu;

use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

use crate::app_controller::AppController;
use crate::service_if::FileAuthorization;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

fn main() -> Result<(), anyhow::Error> {
    // Log at INFO for application code; suppress noise from async runtimes.
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .with_module_level("async_io", log::LevelFilter::Warn)
        .with_module_level("polling", log::LevelFilter::Warn)
        .with_module_level("zbus", log::LevelFilter::Warn)
        .init()?;

    init_tauri()?;
    Ok(())
}

/// Initialize the Tauri application as a system-tray app.
fn init_tauri() -> Result<(), anyhow::Error> {
    let app = tauri::Builder::default()
        .setup(|app| {
            // 1. Start the application controller (D-Bus polling thread, store).
            app.manage(AppController::init(app.handle().clone())?);

            // 2. Build the initial (empty) tray menu.
            let initial_menu = tray_menu::build_usb_menu(app.handle(), &[])
                .map_err(|e| format!("Failed to build initial tray menu: {e}"))?;

            // 3. Create the system-tray icon with the native menu.
            //    On Linux this goes through libayatana-appindicator (dbusmenu).
            //    On Windows this uses the Win32 NotifyIcon API.
            use tauri::tray::TrayIconBuilder;
            let tray = TrayIconBuilder::new()
                .icon(tauri::include_image!("icons/logo-keysas-short-32.png"))
                .tooltip("Keysas USB Firewall")
                .menu(&initial_menu)
                .on_menu_event(on_menu_event)
                .build(app)?;
            app.manage(tray);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_file_list,
            get_usb_list,
            toggle_file_auth,
            override_usb
        ])
        .build(tauri::generate_context!())?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            api.prevent_exit();
        }
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tray menu event handler
// ─────────────────────────────────────────────────────────────────────────────

fn on_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref().to_string();

    if id == "quit" {
        app.exit(0);
        return;
    }

    // "authorize:{device_id}" — manually allow a blocked USB key.
    if let Some(device_id) = id.strip_prefix("authorize:") {
        let device_id = device_id.to_string();
        if let Some(ctrl) = app.try_state::<Arc<AppController>>() {
            match ctrl.allow_usb(&device_id) {
                Ok(()) => {
                    // Immediately refresh the menu so "Autoriser" disappears.
                    tray_menu::rebuild_tray_menu(app, &ctrl);
                }
                Err(e) => log::error!("on_menu_event authorize: {e}"),
            }
        }
        return;
    }

    // "allow_write:{device_id}" — elevate AllowRead → AllowRW.
    if let Some(device_id) = id.strip_prefix("allow_write:") {
        let device_id = device_id.to_string();
        if let Some(ctrl) = app.try_state::<Arc<AppController>>() {
            match ctrl.allow_write_usb(&device_id) {
                Ok(()) => {
                    tray_menu::rebuild_tray_menu(app, &ctrl);
                }
                Err(e) => log::error!("on_menu_event allow_write: {e}"),
            }
        }
        return;
    }

    // "authorize_file:{device_id}:{index}" — authorize a blocked (non-certified) file.
    // device_id may contain '/' but not ':', so rfind(':') reliably finds the index.
    if id.starts_with("authorize_file:") {
        if let Some(rest) = id.strip_prefix("authorize_file:") {
            if let Some(colon) = rest.rfind(':') {
                let device_id = &rest[..colon];
                if let Ok(idx) = rest[colon + 1..].parse::<usize>() {
                    if let Some(ctrl) = app.try_state::<Arc<AppController>>() {
                        let path = ctrl
                            .store
                            .read()
                            .ok()
                            .and_then(|s| {
                                s.get_device(device_id)?.blocked_files.get(idx).cloned()
                            });
                        if let Some(path) = path {
                            match ctrl.authorize_blocked_file(device_id, &path) {
                                Ok(()) => tray_menu::rebuild_tray_menu(app, &ctrl),
                                Err(e) => log::error!("on_menu_event authorize_file: {e}"),
                            }
                        }
                    }
                }
            }
        }
        return;
    }

    // "device:{device_id}" — open the file-details window for this device.
    if let Some(device_id) = id.strip_prefix("device:") {
        let device_id = device_id.to_string();
        let app2 = app.clone();
        if let Err(e) = app.run_on_main_thread(move || {
            open_device_view(&app2, &device_id);
        }) {
            log::error!("on_menu_event device: run_on_main_thread failed: {e}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File-details window
// ─────────────────────────────────────────────────────────────────────────────

/// Open (or show) the file-details window for the given device ID and emit
/// a `show_device` event so the Vue frontend navigates to the details view.
fn open_device_view(app: &AppHandle, device_id: &str) {
    // Emit show_device with the full UsbDevice payload so the frontend can
    // display the details without an extra round-trip.
    if let Some(ctrl) = app.try_state::<Arc<AppController>>() {
        if let Ok(store) = ctrl.store.read() {
            if let Some(dev) = store.get_device(device_id) {
                use tauri::Emitter;
                let _ = app.emit("show_device", dev.clone());
            }
        }
    }

    // Show/create the window.
    match app.get_webview_window("main") {
        Some(w) => {
            let _ = w.show();
            let _ = w.set_focus();
        }
        None => {
            if let Ok(w) = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .decorations(false)
            .focused(true)
            .build()
            {
                let _ = w;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri commands (called from the Vue frontend via invoke())
// ─────────────────────────────────────────────────────────────────────────────

/// Return the current USB device list from the store as JSON.
#[tauri::command]
async fn get_usb_list(app_ctrl: State<'_, Arc<AppController>>) -> Result<String, String> {
    match app_ctrl.store.read() {
        Ok(store) => serde_json::to_string(store.get_devices())
            .map_err(|e| format!("Serialization error: {e}")),
        Err(e) => Err(format!("Store lock error: {e}")),
    }
}

/// Return the list of files for a USB device.
#[tauri::command]
async fn get_file_list(
    device_path: String,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<String, String> {
    match app_ctrl.get_file_list(&device_path) {
        Ok(files) => serde_json::to_string(&files)
            .map_err(|e| {
                log::error!("Failed to serialize file list: {e}");
                String::from("Failed to get files")
            }),
        Err(e) => {
            log::error!("Device not found: {e}");
            Err(String::from("Failed to get files"))
        }
    }
}

/// Toggle the authorization for a single file.
#[tauri::command]
async fn toggle_file_auth(
    device: String,
    id: [u16; 16],
    path: String,
    new_auth: u8,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<(), String> {
    let auth = FileAuthorization::from_u8(new_auth);
    app_ctrl
        .request_file_auth_toggle(&device, &id, &path, auth)
        .map_err(|e| {
            log::error!("toggle_file_auth: {e}");
            e.to_string()
        })
}

/// Manually authorize a blocked (non-certified) USB device.
///
/// Requires `allow_user_usb_authorization = true` in the daemon config.
#[tauri::command]
async fn override_usb(
    device_path: String,
    app_ctrl: State<'_, Arc<AppController>>,
    app: AppHandle,
) -> Result<(), String> {
    app_ctrl.allow_usb(&device_path).map_err(|e| {
        log::error!("override_usb: {e}");
        e.to_string()
    })?;
    // Refresh the tray menu immediately.
    tray_menu::rebuild_tray_menu(&app, &app_ctrl);
    Ok(())
}
