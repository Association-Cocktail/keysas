// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

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

use anyhow::anyhow;
use std::sync::Arc;
use tauri::{
    AppHandle, LogicalPosition, LogicalSize, Manager, PhysicalPosition, State, WebviewWindow,
};

use crate::app_controller::AppController;
use crate::service_if::FileAuthorization;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

/// Payload for the init event sent to the usb_details window
#[derive(Clone, serde::Serialize)]
struct InitPayload {
    /// Name of the USB device
    usb_name: String,
}

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    simple_logger::init()?;

    // Launch the tauri application
    init_tauri()?;

    Ok(())
}

/// Initialize the tauri application as a system tray app
fn init_tauri() -> Result<(), anyhow::Error> {
    let app = tauri::Builder::default()
        .setup(|app| {
            app.manage(AppController::init(app.handle().clone())?);

            // On Linux: register the tray icon via the StatusNotifier protocol
            // (pure zbus, no libappindicator dependency).
            // On Windows: use the native Tauri tray icon builder.
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = linux::sni::start_sni(app.handle().clone()) {
                    log::error!("Failed to start StatusNotifierItem: {e}");
                }
            }

            #[cfg(target_os = "windows")]
            {
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                let tray = TrayIconBuilder::new()
                    .icon(tauri::include_image!("icons/logo-keysas-short-32.png"))
                    .tooltip("Keysas USB Firewall")
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            position,
                            ..
                        } = event
                        {
                            let app = tray.app_handle().clone();
                            if let Err(e) = open_usb_view(&app, &position) {
                                log::error!("Failed to open main view: {e}");
                                app.exit(1);
                            }
                        }
                    })
                    .build(app)?;
                app.manage(tray);
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_file_list, get_usb_list, toggle_file_auth])
        .build(tauri::generate_context!())?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            api.prevent_exit();
        }
    });

    Ok(())
}

/// Set the application window just above the tray click position.
fn set_window_over_tray(
    w: &WebviewWindow,
    click: &PhysicalPosition<f64>,
) -> Result<(), anyhow::Error> {
    let screen = w
        .current_monitor()?
        .ok_or_else(|| anyhow!("Not screen detected"))?;
    let scale_factor = screen.scale_factor();

    let click_log = click.to_logical::<f64>(scale_factor);
    let screen_pos_log = screen.position().to_logical::<f64>(scale_factor);
    let screen_size_log = screen.size().to_logical::<f64>(scale_factor);

    let window_size = LogicalSize::<f64>::new(400.0, 300.0);
    w.set_size(window_size)?;

    let x_log = if click_log.x + window_size.width <= screen_pos_log.x + screen_size_log.width {
        click_log.x
    } else {
        screen_pos_log.x + screen_size_log.width - window_size.width
    };
    let window_pos = LogicalPosition::<f64>::new(x_log, click_log.y - window_size.height);
    w.set_position(window_pos)?;

    Ok(())
}

/// Open or toggle the main USB firewall window.
pub(crate) fn open_usb_view(
    app: &AppHandle,
    click: &PhysicalPosition<f64>,
) -> Result<(), anyhow::Error> {
    match app.get_webview_window("main") {
        Some(w) => match w.is_visible()? {
            false => {
                set_window_over_tray(&w, click)?;
                w.set_focus()?;
                w.show()?;
            }
            true => {
                w.hide()?;
            }
        },
        None => {
            let w = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .decorations(false)
            .focused(true)
            .build()?;
            set_window_over_tray(&w, click)?;
        }
    };

    Ok(())
}

/// Command to retrieve the current USB device list from the store.
#[tauri::command]
async fn get_usb_list(
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<String, String> {
    match app_ctrl.store.read() {
        Ok(store) => serde_json::to_string(store.get_devices())
            .map_err(|e| format!("Serialization error: {e}")),
        Err(e) => Err(format!("Store lock error: {e}")),
    }
}

/// Command to retrieve list of all the files in a USB device.
#[tauri::command]
async fn get_file_list(
    device_path: String,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<String, String> {
    match app_ctrl.get_file_list(&device_path) {
        Ok(files) => match serde_json::to_string(&files) {
            Ok(s) => Ok(s),
            Err(e) => {
                log::error!("Failed to serialize result: {e}");
                Err(String::from("Failed to get files"))
            }
        },
        Err(e) => {
            log::error!("Device not found: {e}");
            Err(String::from("Failed to get files"))
        }
    }
}

/// Request to toggle the authorization for a file in a given device.
#[tauri::command]
async fn toggle_file_auth(
    device: String,
    id: [u16; 16],
    path: String,
    new_auth: u8,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<(), String> {
    let auth = FileAuthorization::from_u8(new_auth);
    if let Err(e) = app_ctrl.request_file_auth_toggle(&device, &id, &path, auth) {
        log::error!("toggle_file_auth: {e}");
        return Err(e.to_string());
    }
    Ok(())
}
