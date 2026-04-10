// SPDX-License-Identifier: GPL-3.0-only
//! Pure-zbus StatusNotifierItem implementation.
//!
//! Registers a system-tray icon with GNOME Shell's AppIndicator extension
//! (org.kde.StatusNotifierWatcher) without depending on libappindicator or
//! libayatana-appindicator3.  Uses the session D-Bus directly via zbus.
//!
//! Call `start_sni(app_handle)` once from Tauri's setup().
//! When the user left-clicks the tray icon, GNOME Shell calls `Activate(x,y)`
//! on our D-Bus object; we dispatch `open_usb_view` onto the GTK main thread.
//!
//! The connection and shared state returned by `start_sni` must be stored in
//! Tauri's managed state so that `notify_sni` can emit `NewIcon`/`NewStatus`
//! signals whenever the USB device list changes.

use anyhow::anyhow;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, PhysicalPosition};
use zbus::{dbus_interface, dbus_proxy};

// ─────────────────────────────────────────────────────────────────────────────
// Shared mutable state for the SNI icon
// ─────────────────────────────────────────────────────────────────────────────

/// State shared between the D-Bus object and the polling thread.
/// The polling thread writes here; zbus reads it on every D-Bus property call.
#[derive(Debug, Clone)]
pub struct SniState {
    pub icon_pixmap_data: Vec<(i32, i32, Vec<u8>)>,
    /// SNI status string: "Active" | "NeedsAttention" | "Passive"
    pub status: String,
}

/// Handle returned by `start_sni` and stored in Tauri managed state.
/// Call `notify_sni` with it after each USB list update.
#[derive(Debug, Clone)]
pub struct SniHandle {
    pub state: Arc<Mutex<SniState>>,
    pub conn:  Arc<zbus::blocking::Connection>,
}

// ─────────────────────────────────────────────────────────────────────────────
// StatusNotifierItem server object
// ─────────────────────────────────────────────────────────────────────────────

struct SniItem {
    app:   AppHandle<tauri::Wry>,
    state: Arc<Mutex<SniState>>,
}

#[dbus_interface(name = "org.kde.StatusNotifierItem")]
impl SniItem {
    // ── Required properties ────────────────────────────────────────────────

    #[dbus_interface(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[dbus_interface(property)]
    fn id(&self) -> &str {
        "keysas-usbfilter-trayapp"
    }

    #[dbus_interface(property)]
    fn title(&self) -> &str {
        "Keysas USB Firewall"
    }

    /// Dynamic: reflects the current SniState so GNOME Shell re-reads it
    /// after we emit NewStatus.
    #[dbus_interface(property)]
    fn status(&self) -> String {
        self.state
            .lock()
            .map(|s| s.status.clone())
            .unwrap_or_else(|_| "Active".to_string())
    }

    #[dbus_interface(property)]
    fn window_id(&self) -> u32 {
        0
    }

    // ── Icon ──────────────────────────────────────────────────────────────

    #[dbus_interface(property)]
    fn icon_name(&self) -> &str {
        "keysas-usbfilter-trayapp"
    }

    #[dbus_interface(property)]
    fn icon_theme_path(&self) -> &str {
        "/usr/share/icons/hicolor"
    }

    /// Dynamic: returns whatever pixels the polling thread last wrote.
    #[dbus_interface(property)]
    fn icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        self.state
            .lock()
            .map(|s| s.icon_pixmap_data.clone())
            .unwrap_or_default()
    }

    #[dbus_interface(property)]
    fn overlay_icon_name(&self) -> &str {
        ""
    }

    #[dbus_interface(property)]
    fn overlay_icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        Vec::new()
    }

    #[dbus_interface(property)]
    fn attention_icon_name(&self) -> &str {
        ""
    }

    #[dbus_interface(property)]
    fn attention_icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        Vec::new()
    }

    #[dbus_interface(property)]
    fn attention_movie_name(&self) -> &str {
        ""
    }

    #[dbus_interface(property)]
    fn tool_tip(&self) -> (String, Vec<(i32, i32, Vec<u8>)>, String, String) {
        (
            String::from("keysas-usbfilter-trayapp"),
            Vec::new(),
            String::from("Keysas USB Firewall"),
            String::new(),
        )
    }

    #[dbus_interface(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[dbus_interface(property)]
    fn menu(&self) -> zbus::zvariant::ObjectPath<'_> {
        zbus::zvariant::ObjectPath::from_str_unchecked("/")
    }

    // ── Signals (required by the SNI spec) ────────────────────────────────

    /// Emitted when the icon pixels change.  GNOME Shell re-reads IconPixmap.
    #[dbus_interface(signal)]
    pub async fn new_icon(signal_ctxt: &zbus::SignalContext<'_>) -> zbus::Result<()>;

    /// Emitted when the status string changes.  GNOME Shell re-reads Status.
    #[dbus_interface(signal)]
    pub async fn new_status(
        signal_ctxt: &zbus::SignalContext<'_>,
        status: &str,
    ) -> zbus::Result<()>;

    // ── Methods ────────────────────────────────────────────────────────────

    /// Left-click: open / toggle the main window.
    fn activate(&self, x: i32, y: i32) {
        let app = self.app.clone();
        if let Err(e) = app.clone().run_on_main_thread(move || {
            let pos = PhysicalPosition {
                x: x as f64,
                y: y as f64,
            };
            if let Err(e) = crate::open_usb_view(&app, &pos) {
                log::error!("SNI Activate: {e}");
            }
        }) {
            log::error!("SNI Activate: run_on_main_thread failed: {e}");
        }
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {}

    fn context_menu(&self, _x: i32, _y: i32) {}

    fn scroll(&self, _delta: i32, _orientation: &str) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// StatusNotifierWatcher proxy (to register our item)
// ─────────────────────────────────────────────────────────────────────────────

#[dbus_proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher"
)]
trait StatusNotifierWatcher {
    fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG → SNI ARGB conversion
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a PNG file from bytes and return SNI-format icon pixmap data.
///
/// SNI expects each pixel as a 32-bit big-endian ARGB value:
///   byte 0 = A, byte 1 = R, byte 2 = G, byte 3 = B
fn png_to_sni_argb(png_bytes: &[u8]) -> Result<(i32, i32, Vec<u8>), anyhow::Error> {
    use png::ColorType;

    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = decoder.read_info().map_err(|e| anyhow!("PNG decode: {e}"))?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).map_err(|e| anyhow!("PNG frame: {e}"))?;

    let width = info.width as i32;
    let height = info.height as i32;
    let raw = &buf[..info.buffer_size()];

    let argb: Vec<u8> = match info.color_type {
        ColorType::Rgba => {
            // Input: R G B A per pixel → output: A R G B per pixel
            raw.chunks_exact(4)
                .flat_map(|p| [p[3], p[0], p[1], p[2]])
                .collect()
        }
        ColorType::Rgb => {
            // Input: R G B per pixel → output: 0xFF A R G B per pixel
            raw.chunks_exact(3)
                .flat_map(|p| [0xFFu8, p[0], p[1], p[2]])
                .collect()
        }
        other => return Err(anyhow!("Unsupported PNG color type: {other:?}")),
    };

    Ok((width, height, argb))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Emit `NewIcon` + `NewStatus` on the session bus so GNOME Shell refreshes
/// the tray icon immediately.
///
/// Call this after every USB list update (from the polling thread).
pub fn notify_sni(handle: &SniHandle, new_status: &str) {
    // 1. Write the new status into the shared state so that the D-Bus property
    //    getter returns the updated value when GNOME Shell re-reads it.
    if let Ok(mut state) = handle.state.lock() {
        state.status = new_status.to_string();
    }

    // 2. Obtain a reference to the served SniItem interface and emit signals.
    let iface_ref = match handle
        .conn
        .object_server()
        .interface::<_, SniItem>("/StatusNotifierItem")
    {
        Ok(r)  => r,
        Err(e) => {
            log::warn!("notify_sni: cannot get interface ref: {e}");
            return;
        }
    };

    // zbus blocking signal emission requires building a SignalContext from the
    // interface reference.  We use the async signal fns via block_on.
    let signal_ctx = iface_ref.signal_context().clone();
    if let Err(e) = zbus::block_on(SniItem::new_icon(&signal_ctx)) {
        log::warn!("notify_sni: NewIcon signal failed: {e}");
    }
    if let Err(e) = zbus::block_on(SniItem::new_status(&signal_ctx, new_status)) {
        log::warn!("notify_sni: NewStatus signal failed: {e}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Start the StatusNotifierItem service and register with the watcher.
///
/// Returns an `SniHandle` that must be stored in Tauri managed state so that
/// the polling thread can call `notify_sni` after each USB list refresh.
pub fn start_sni(app: AppHandle<tauri::Wry>) -> Result<SniHandle, anyhow::Error> {
    let pid = std::process::id();
    let svc_name = format!("org.kde.StatusNotifierItem-{pid}-1");

    // Decode the 32×32 PNG icon at startup so we don't need gtk-update-icon-cache.
    let png_bytes = include_bytes!("../../icons/logo-keysas-short-32.png");
    let icon_pixmap_data = match png_to_sni_argb(png_bytes) {
        Ok(entry) => vec![entry],
        Err(e) => {
            log::warn!("Failed to decode tray icon PNG: {e}");
            Vec::new()
        }
    };

    // Shared state: polling thread writes, D-Bus property getters read.
    let sni_state = Arc::new(Mutex::new(SniState {
        icon_pixmap_data,
        status: "Active".to_string(),
    }));

    let item = SniItem {
        app,
        state: sni_state.clone(),
    };

    // Build the session-bus connection, own the well-known name, and serve
    // the interface — zbus runs a background async task internally.
    let conn = Arc::new(
        zbus::blocking::ConnectionBuilder::session()
            .map_err(|e| anyhow!("session bus: {e}"))?
            .name(svc_name.as_str())
            .map_err(|e| anyhow!("request name {svc_name}: {e}"))?
            .serve_at("/StatusNotifierItem", item)
            .map_err(|e| anyhow!("serve_at: {e}"))?
            .build()
            .map_err(|e| anyhow!("build connection: {e}"))?,
    );

    // Register with the watcher so GNOME Shell shows the icon.
    let watcher = StatusNotifierWatcherProxyBlocking::new(&conn)
        .map_err(|e| anyhow!("watcher proxy: {e}"))?;
    watcher
        .register_status_notifier_item(&svc_name)
        .map_err(|e| anyhow!("RegisterStatusNotifierItem: {e}"))?;

    log::info!("SNI registered as {svc_name}");

    // Keep the connection alive in a background thread.
    let conn_keep = conn.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let _ = conn_keep.unique_name();
    });

    Ok(SniHandle {
        state: sni_state,
        conn,
    })
}
