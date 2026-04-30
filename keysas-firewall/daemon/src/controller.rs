// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Service controller
//!
//! It handles communications with the HMI and the kernel filters
//! It contains the security policy and grant the authorizations for the filter
//!
//! The main architecture for the Service Controller is shown below
//!
//! ```text
//!
//!                                       User
//!                                         ▲
//!                                         │
//!                  ┌──────────────────────┼─┐
//!                  │  GUI interface       │ │ Authorization request
//!                  │       ┌──────────────┼─┘
//!                  │       │              │
//!                  │       │  ┌───────────────────────┐
//! ┌─────────────┐  │       │  │                       │
//! │             │  │modif_req │  Service Controller   │
//! │  Tray App   │ ──────────► │                       │
//! │             │  │       │  │ - Security Policy     │
//! │             │ ◄────────── │                       │
//! └─────────────┘  │notif  │  │                       │
//!                  └───────┘  └───────────────────────┘
//!                                ▲  │        ▲     │
//!                  ──────────────┼──┼────────┼─────┼───────────
//!                                │  │    req │     │ modif_req
//!                  kernel        │  ▼        │     ▼
//!                          ┌─────────────┐ ┌─────────────┐
//!                          │ USB monitor │ │ File filter │
//!                          └─────────────┘ └─────────────┘
//! ```
//!
//! USB authorization
//!
//! USB device authorization is based on the security policy setting and the
//! signature of the USB device MBR.
//!
//! ```text
//!                               ///
//!                              /////
//!                               ///
//!                                │
//!                                │
//!  [USB not signed               ▼
//!   or invalid signature] ┌─────────────┐        [USB signature is valid]
//!               ┌─────────│   Pending   │───────────────────────┐
//!               │         └─────────────┘                       │
//!               │                                               │
//!  Block all    │              Allow only read access for valid │
//!  files on     │               and ask user if                 │
//!  the USB key  │               allow_user_file_read = true     │
//!       \       │                                        \      │
//!        \      ▼                                         \     ▼
//!     ┌───────────┐                                       ┌───────────┐
//!     │   Block   │                                       │ Read only │
//!     └───────────┘                                       └───────────┘
//!           │                                                 │
//!           │ [disable_unsigned_usb                           │ [allow_user
//!           │  || (allow_user_usb_authorization               │   _file_write]
//!           │        && user input ok)]                       │
//!           ▼                                                 ▼
//!     ┌───────────┐                                      ┌────────────┐
//!     │ Allow All │                                      │ Read Write │
//!     └───────────┘                                      └────────────┘
//!         /                                                 /
//!        /                                                 /
//!  Allow all file             Allow read to valid file and ask user if
//!  access on USB              allow_user_file_read = true to read invalid file
//!                             and ask user for all write access
//!
//! ```

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signature as SignatureDalek;
use log::*;
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::file_filter_if::{FileFilterInterface, FileFilterInterfaceBuilder};
use crate::gui_interface::{
    FileUpdateMessage, GuiInterface, GuiInterfaceBuilder, GuiMessageCode, PolicyUpdateMessage,
    UsbUpdateMessage,
};
use crate::usb_monitor::{UsbMonitor, UsbMonitorBuilder};
use crate::Config;
use keysas_lib::{
    file_report::parse_report,
    keysas_key::{KeysasHybridPubKeys, KeysasHybridSignature, PublicKeys},
};
use x509_cert::Certificate;

#[cfg(target_os = "windows")]
use crate::windows::service::{load_certificates, load_security_policy, write_policy_settings};

#[cfg(target_os = "linux")]
use crate::linux::service::{load_certificates, load_security_policy};

/// Authorization states for USB devices
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum UsbAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed with a warning to the user
    AllowRW,
    /// Access is allowed for all operations
    AllowAll,
}

impl UsbAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the value expected by the Windows minifilter kernel (KEYSAS_AUTHORIZATION).
    /// KEYSAS_AUTHORIZATION: AUTH_UNKNOWN=0, AUTH_PENDING=1, AUTH_BLOCK=2,
    ///   AUTH_ALLOW_READ=3, AUTH_ALLOW_WARNING=4, AUTH_ALLOW_ALL=5
    /// UsbAuthorization: Pending=0, Block=1, AllowRead=2, AllowRW=3, AllowAll=4
    /// The kernel values are exactly one greater than the daemon values.
    pub fn to_kernel_u8(self) -> u8 {
        self as u8 + 1
    }
}

/// Authorization states for files
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FileAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed in read/write mode
    AllowRW,
}

impl FileAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the value expected by the Windows minifilter kernel (KEYSAS_AUTHORIZATION).
    /// FileAuthorization: Pending=0, Block=1, AllowRead=2, AllowRW=3
    /// KEYSAS_AUTHORIZATION: AUTH_PENDING=1, AUTH_BLOCK=2, AUTH_ALLOW_READ=3, AUTH_ALLOW_WARNING=4
    /// The kernel values are exactly one greater than the daemon values.
    pub fn to_kernel_u8(self) -> u8 {
        self as u8 + 1
    }
}

/// Main firewall security configuration
/// It set on start up by the administrator
#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub struct SecurityPolicy {
    /// If true disable USB signature verification, all USB keys are allowed
    pub disable_unsigned_usb: bool,
    /// If true allow the user to manualy authorize unsigned USB keys
    pub allow_user_usb_authorization: bool,
    /// If true allow the user to grant read access to unverified file
    pub allow_user_file_read: bool,
    /// If true allow the user to grant write access to files
    pub allow_user_file_write: bool,
}

/// Certificates loaded at startup.  `None` when any cert is absent, expired,
/// unreadable or otherwise unusable — in that case the firewall blocks every
/// USB device unconditionally until a daemon restart with valid certificates.
struct CertBundle {
    usb_ca_pub: KeysasHybridPubKeys,
    st_ca_cert_cl: Certificate,
    st_ca_cert_pq: Certificate,
}

/// Service controller object, it contains handles to the service communication interfaces and data
#[allow(missing_debug_implementations)]
pub struct ServiceController {
    usb_monitor: Box<dyn UsbMonitor + Sync + Send>,
    gui: Box<dyn GuiInterface + Sync + Send>,
    file_filter: Box<dyn FileFilterInterface + Sync + Send>,
    policy: SecurityPolicy,
    /// None when certificates could not be loaded — triggers unconditional Block.
    certs: Option<CertBundle>,
    /// Reason for cert load failure, logged on every USB plug-in when certs are None.
    cert_error: Option<String>,
    unmounted_usb: HashMap<OsString, UsbDevicePolicy>,
    mounted_usb: HashMap<OsString, UsbDevicePolicy>,
    /// Cache of files that have been pre-validated before the fanotify mark was
    /// placed on the mount point.  The event handler checks this set first and
    /// returns immediately with `true`, avoiding any file I/O (and therefore any
    /// re-entrant FAN_OPEN_PERM event) from within the handler.
    validated_files: HashSet<PathBuf>,
    /// Files that were denied at open time because they were not pre-certified.
    /// Keyed by device_id.  The tray-app polls this list and can authorize
    /// individual paths, which moves them into `validated_files`.
    blocked_files: HashMap<OsString, Vec<PathBuf>>,
}

/// Representation of USB device in the firewall
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device identifier
    pub device_id: OsString,
    /// Partition identifier
    pub mnt_point: Option<OsString>,
    pub vendor: OsString,
    pub model: OsString,
    pub revision: OsString,
    pub serial: OsString,
    /// Sysfs path of the parent USB device node (e.g. /sys/devices/.../1-1.2/).
    /// Used on Linux to deauthorize uncertified devices by writing 0 to
    /// `{usb_syspath}/authorized`, which makes the kernel disconnect the device.
    pub usb_syspath: Option<OsString>,
}

impl UsbDevice {
    fn get_name(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.vendor.to_string_lossy(),
            self.model.to_string_lossy(),
            self.revision.to_string_lossy(),
            self.serial.to_string_lossy()
        )
    }
}

/// Firewall policy for one USB device
#[derive(Debug)]
pub struct UsbDevicePolicy {
    /// Usb device information
    pub device: UsbDevice,
    /// Authorization status
    pub auth: UsbAuthorization,
}

/// Representation of a file in the firewall
#[derive(Debug, Clone)]
pub struct FilteredFile {
    /// Path to the file
    pub path: Option<OsString>,
    /// Identifier based on SHA-256 of path
    pub id: [u8; 32],
}

/// Firewall policy for one file
#[derive(Debug)]
pub struct FilePolicy {
    pub file: FilteredFile,
    pub auth: FileAuthorization,
}

/// Look up the current mount point of `device` by parsing `/proc/mounts`.
///
/// Returns `None` if the device is not listed as mounted.
#[cfg(target_os = "linux")]
fn find_mount_point(device: &OsString) -> Option<String> {
    use std::io::BufRead;
    let file = std::fs::File::open("/proc/mounts").ok()?;
    let dev_str = device.to_string_lossy();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        // /proc/mounts columns: <device> <mountpoint> <fstype> <options> <dump> <pass>
        let mut cols = line.splitn(3, ' ');
        let dev = match cols.next() {
            Some(d) => d,
            None => continue,
        };
        let mnt = match cols.next() {
            Some(m) => m,
            None => continue,
        };
        if dev == dev_str.as_ref() {
            return Some(mnt.to_string());
        }
    }
    None
}

impl ServiceController {
    /// Initialize the service controller
    pub fn init(config: &Config) -> Result<Arc<Mutex<ServiceController>>, anyhow::Error> {
        let policy = match load_security_policy(config) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!(
                    "ServiceController init: Failed to load security policy {e}"
                ));
            }
        };
        log::info!("Policy loaded");

        // Load certificates — failure is non-fatal: the daemon starts but blocks
        // all USB devices until restarted with valid/unexpired certificates.
        let (certs, cert_error) = match load_certificates(config) {
            Ok((_st_ca_pub, usb_ca_pub, st_ca_cert_cl, st_ca_cert_pq)) => {
                log::info!("ServiceController: certificates loaded and valid");
                (Some(CertBundle { usb_ca_pub, st_ca_cert_cl, st_ca_cert_pq }), None)
            }
            Err(e) => {
                let reason = format!("{e:#}");
                log::warn!(
                    "ServiceController: certificate load failed — \
                     all USB devices will be blocked until a restart with valid certificates. \
                     Reason: {reason}"
                );
                (None, Some(reason))
            }
        };

        let usb_monitor = UsbMonitorBuilder::build()?;

        let gui = GuiInterfaceBuilder::build()?;

        let file_filter = FileFilterInterfaceBuilder::build()?;

        // Initialize the controller
        let ctrl = Arc::new(Mutex::new(ServiceController {
            usb_monitor,
            gui,
            file_filter,
            policy,
            certs,
            cert_error,
            unmounted_usb: HashMap::new(),
            mounted_usb: HashMap::new(),
            validated_files: HashSet::new(),
            blocked_files: HashMap::new(),
        }));

        // Start the interfaces
        {
            let mut ctrl_hdl = ctrl.lock().unwrap();
            ctrl_hdl.gui.start(&ctrl)?;
            ctrl_hdl.usb_monitor.start(&ctrl)?;
            ctrl_hdl.file_filter.start(&ctrl)?;
            // Recover devices that were mounted before this daemon instance started
            #[cfg(target_os = "linux")]
            ctrl_hdl.recover_mounted_devices();
        }

        Ok(ctrl)
    }

    /// Called by the GUI to update a USB key policy in the firewall.
    ///
    /// Two cases:
    /// - Device already mounted (`mounted_usb`): update the file-filter mark.
    /// - Device blocked but not yet mounted (`unmounted_usb`): treat the update
    ///   as a user override and call `override_blocked_usb()` to authorize it.
    ///
    /// # Arguments
    ///
    /// * `update` - Contains the device ID and new authorization status
    pub fn request_usb_update(&mut self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        // Enforce write policy: reject AllowRW if the admin disabled it.
        if matches!(
            update.authorization,
            UsbAuthorization::AllowRW | UsbAuthorization::AllowAll
        ) && !self.policy.allow_user_file_write
        {
            return Err(anyhow!(
                "request_usb_update: elevation to {:?} refused — allow_user_file_write=false",
                update.authorization
            ));
        }

        let device_key = OsString::from(&update.device);

        if let Some(policy) = self.mounted_usb.get(&device_key) {
            // Device is already mounted — just update the file-filter authorization.
            let new_policy = UsbDevicePolicy {
                device: policy.device.clone(),
                auth: update.authorization,
            };
            self.file_filter.update_usb_auth(&new_policy)?;
        } else if self.unmounted_usb.contains_key(&device_key)
            && matches!(
                update.authorization,
                UsbAuthorization::AllowRead
                    | UsbAuthorization::AllowRW
                    | UsbAuthorization::AllowAll
            )
        {
            // Blocked but not yet mounted: this is a user override request.
            self.override_blocked_usb(&update.device)?;
        } else {
            warn!(
                "request_usb_update: device '{}' not found in mounted or unmounted list",
                update.device
            );
        }
        Ok(())
    }

    /// Called by the GUI to update a file policy in the firewall.
    ///
    /// Delegates to `file_filter.update_file_auth()`.  On Linux this is a no-op
    /// because access decisions are taken per mount point via fanotify marks.
    ///
    /// # Arguments
    ///
    /// * `update` - Contains the file path and new authorization status
    pub fn request_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        let file_policy = FilePolicy {
            file: FilteredFile {
                path: Some(OsString::from(&update.path)),
                id: [0u8; 32],
            },
            auth: update.authorization,
        };
        self.file_filter.update_file_auth(&file_policy)
    }

    /// Check a USB device to allow it not
    /// Return Ok(true) or Ok(false) according to the authorization
    ///
    /// # Arguments
    ///
    /// * `device` - Usb device info
    pub fn authorize_usb(
        &mut self,
        device: &UsbDevice,
        signature: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        info!("Received USB device request: {:?}", device);

        // Fail closed: if certificates are not available (absent, expired,
        // unreadable, wrong name, incomplete set, …) block every USB device
        // unconditionally, regardless of policy flags.
        if self.certs.is_none() {
            warn!(
                "authorize_usb: certificates unavailable — blocking {:?} (reason: {})",
                device.device_id,
                self.cert_error.as_deref().unwrap_or("unknown")
            );
            self.unmounted_usb
                .entry(device.device_id.clone())
                .or_insert(UsbDevicePolicy {
                    device: device.clone(),
                    auth: UsbAuthorization::Block,
                });
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: device.device_id.to_string_lossy().into_owned(),
                path: String::default(),
                name: device.get_name(),
                authorization: UsbAuthorization::Block,
            };
            let _ = self.gui.send_usb_update(&update);
            return Ok(false);
        }

        // TODO - Improve list of USB device
        // TODO - If mount point is given insert it in correct list

        // Handle already-tracked devices:
        //   Pending   → being processed, ignore duplicate event
        //   AllowRead/AllowRW/AllowAll → pre-authorized by user override, proceed to mount
        //   Block     → previously blocked and kept for UI; re-evaluate on replug
        if let Some(existing) = self.unmounted_usb.get(&device.device_id) {
            match existing.auth {
                UsbAuthorization::Pending => return Ok(false),
                UsbAuthorization::Block => {
                    self.unmounted_usb.remove(&device.device_id);
                }
                _ => {
                    // Pre-authorized via user override: tell the monitor to mount it.
                    return Ok(true);
                }
            }
        }

        // Insert the new device in the list of unmounted devices
        self.unmounted_usb.insert(
            device.device_id.clone(),
            UsbDevicePolicy {
                device: device.clone(),
                auth: UsbAuthorization::Pending,
            },
        );

        // Evaluate USB key policy
        let auth = match signature {
            Some(sig) => match self.validate_usb_signature(&device, &sig) {
                Ok(true) => match self.policy.allow_user_file_write {
                    true => UsbAuthorization::AllowRW,
                    false => UsbAuthorization::AllowRead,
                },
                Ok(false) => match self.policy.disable_unsigned_usb {
                    true => UsbAuthorization::AllowAll,
                    false => UsbAuthorization::Block,
                },
                Err(e) => {
                    let dev_policy = self.unmounted_usb.get_mut(&device.device_id).unwrap();
                    dev_policy.auth = UsbAuthorization::Block;
                    return Err(e);
                }
            },
            None => match self.policy.disable_unsigned_usb {
                true => UsbAuthorization::AllowAll,
                false => UsbAuthorization::Block,
            },
        };
        let dev_policy = self.unmounted_usb.get_mut(&device.device_id).unwrap();
        dev_policy.auth = auth;

        // Notify GUI immediately for blocked devices.
        // Authorised devices are notified in update_usb() once the mount point is known.
        if matches!(auth, UsbAuthorization::Block) {
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: device.device_id.to_string_lossy().into_owned(),
                path: String::default(),
                name: device.get_name(),
                authorization: auth,
            };
            if let Err(e) = self.gui.send_usb_update(&update) {
                warn!("authorize_usb: GUI notification failed: {e}");
            }
        }

        // Return authorization decision as boolean
        match auth {
            UsbAuthorization::Block | UsbAuthorization::Pending => Ok(false),
            _ => Ok(true),
        }
    }

    /// Manually authorize a blocked (non-certified) USB device.
    ///
    /// Requires `allow_user_usb_authorization = true` in the security policy.
    ///
    /// Platform behaviour:
    ///   Linux — promotes auth then writes `1` to the USB parent's `authorized`
    ///     sysfs attribute so the kernel re-enumerates the device.  The udev
    ///     monitor receives a new "add" event, finds the pre-authorized entry in
    ///     `unmounted_usb`, and proceeds to mount normally.
    ///   Windows — the drive was kept accessible (not ejected) when the policy
    ///     allows user overrides; `update_usb()` is called directly to move the
    ///     device to `mounted_usb` and update the minifilter authorization.
    pub fn override_blocked_usb(&mut self, device_id: &str) -> Result<(), anyhow::Error> {
        if self.certs.is_none() {
            return Err(anyhow!(
                "USB override refused: certificates are not available or have expired"
            ));
        }
        if !self.policy.allow_user_usb_authorization {
            return Err(anyhow!(
                "User USB authorization override is disabled by policy"
            ));
        }

        let key = OsString::from(device_id);

        let new_auth = if self.policy.allow_user_file_write {
            UsbAuthorization::AllowRW
        } else {
            UsbAuthorization::AllowRead
        };

        // Verify the device is tracked and blocked; clone what we need before
        // the mutable borrow below.
        let device = match self.unmounted_usb.get(&key) {
            Some(p) if p.auth == UsbAuthorization::Block => p.device.clone(),
            Some(_) => return Err(anyhow!("Device '{device_id}' is not in a blocked state")),
            None => return Err(anyhow!("Device '{device_id}' not found in blocked list")),
        };

        // Promote auth in unmounted_usb.
        if let Some(policy) = self.unmounted_usb.get_mut(&key) {
            policy.auth = new_auth;
        }

        // Platform-specific: make the newly authorized device accessible.
        #[cfg(target_os = "linux")]
        {
            let syspath = device
                .usb_syspath
                .ok_or_else(|| anyhow!("No sysfs path for device '{device_id}'"))?;
            let auth_path = Path::new(&syspath).join("authorized");
            std::fs::write(&auth_path, b"1\n").map_err(|e| {
                anyhow!("Failed to re-authorize '{device_id}' via {auth_path:?}: {e}")
            })?;
            info!(
                "User override: device '{}' re-authorized at kernel level (auth={:?})",
                device_id, new_auth
            );
        }

        #[cfg(target_os = "windows")]
        {
            // The drive was kept mounted (not ejected) because
            // allow_user_usb_authorization = true.  Its mnt_point was stored in
            // unmounted_usb when it was first detected.
            if device.mnt_point.is_none() {
                return Err(anyhow!(
                    "No mount point stored for device '{device_id}': cannot authorize"
                ));
            }
            // update_usb() removes the entry from unmounted_usb, inserts it into
            // mounted_usb, updates the minifilter, and notifies the GUI.
            self.update_usb(&device)?;
            info!(
                "User override: device '{}' authorized via minifilter (auth={:?})",
                device_id, new_auth
            );
        }

        Ok(())
    }

    /// Return `true` when the security policy allows users to manually
    /// authorize blocked (non-certified) USB devices.
    pub fn is_user_usb_auth_enabled(&self) -> bool {
        self.policy.allow_user_usb_authorization
    }

    /// Return `true` if `device_id` is already tracked (mounted or unmounted).
    /// Used by the Linux initial USB scan to skip devices recovered via sentinels.
    pub fn is_device_tracked(&self, device_id: &OsString) -> bool {
        self.mounted_usb.contains_key(device_id) || self.unmounted_usb.contains_key(device_id)
    }

    /// Walk `mount_point` recursively and validate every regular file using
    /// `validate_file()`.  All files that pass are inserted into
    /// `self.validated_files` so that the fanotify event handler can answer
    /// FAN_OPEN_PERM requests with a simple cache lookup — without performing
    /// any further file I/O from within the handler.
    ///
    /// This must be called **before** `file_filter.update_usb_auth()` places the
    /// fanotify mount mark, otherwise the directory walk would itself generate
    /// FAN_OPEN_PERM events that the (still-single-threaded) event loop could not
    /// process → deadlock.
    fn pre_validate_mount(&mut self, mount_point: &Path) {
        let walker = match std::fs::read_dir(mount_point) {
            Ok(w) => w,
            Err(e) => {
                warn!("pre_validate_mount: cannot read {:?}: {e}", mount_point);
                return;
            }
        };
        self.walk_and_validate(walker);
    }

    fn walk_and_validate(&mut self, dir: std::fs::ReadDir) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    self.walk_and_validate(sub);
                }
                continue;
            }
            // .krp files are always allowed; no need to cache them.
            if path
                .extension()
                .map_or(false, |e| e.eq_ignore_ascii_case("krp"))
            {
                continue;
            }
            match self.validate_file(&path) {
                Ok(true) => {
                    info!("pre_validate_mount: certified {:?}", path);
                    self.validated_files.insert(path);
                }
                Ok(false) => {
                    info!("pre_validate_mount: not certified {:?}", path);
                }
                Err(e) => {
                    info!("pre_validate_mount: error validating {:?}: {e}", path);
                }
            }
        }
    }

    /// Update information about a USB device once it is mounted.
    ///
    /// Moves the device from `unmounted_usb` to `mounted_usb` with the mount point set.
    ///
    /// # Arguments
    ///
    /// * `device` - USB device info with `mnt_point` set to the mounted path
    pub fn update_usb(&mut self, device: &UsbDevice) -> Result<(), anyhow::Error> {
        let mut policy = match self.unmounted_usb.remove(&device.device_id) {
            Some(p) => p,
            None => {
                return Err(anyhow!(
                    "update_usb: device {:?} not found in unmounted list",
                    device.device_id
                ))
            }
        };
        policy.device.mnt_point = device.mnt_point.clone();
        self.mounted_usb.insert(device.device_id.clone(), policy);

        // Pre-validate all files on the mount BEFORE placing the fanotify mark.
        // This avoids any re-entrant FAN_OPEN_PERM events from within validate_file().
        if let Some(mnt) = device.mnt_point.as_ref() {
            self.pre_validate_mount(Path::new(mnt));
        }

        // Notify the file filter — this places the fanotify mount mark.
        // All subsequent file opens will block until the event handler responds.
        if let Some(p) = self.mounted_usb.get(&device.device_id) {
            if let Err(e) = self.file_filter.update_usb_auth(p) {
                warn!("update_usb: file filter mark failed: {e}");
            }
        }

        // Notify GUI that the device is now mounted and accessible.
        if let Some(p) = self.mounted_usb.get(&device.device_id) {
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: device.device_id.to_string_lossy().into_owned(),
                path: p
                    .device
                    .mnt_point
                    .as_ref()
                    .map(|m| m.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                name: p.device.get_name(),
                authorization: p.auth,
            };
            if let Err(e) = self.gui.send_usb_update(&update) {
                warn!("update_usb: GUI notification failed: {e}");
            }
        }

        Ok(())
    }

    /// Remove a USB device from the controller tracking tables and clean up
    /// associated resources (fanotify mark).
    ///
    /// Return the device IDs of all entries in `unmounted_usb` whose
    /// `usb_syspath` starts with `prefix`.  Used to find which tracked blocked
    /// devices belong to a USB parent that is being physically unplugged.
    pub fn unmounted_usb_ids_with_syspath_prefix(&self, prefix: &Path) -> Vec<OsString> {
        self.unmounted_usb
            .iter()
            .filter(|(_, p)| {
                p.device
                    .usb_syspath
                    .as_deref()
                    .map(|sp| Path::new(sp).starts_with(prefix))
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Unconditionally remove a device from `unmounted_usb`.
    /// Used when a physical unplug is detected for a previously deauthorized device.
    pub fn force_remove_usb(&mut self, device_id: &OsString) {
        if self.unmounted_usb.remove(device_id).is_some() {
            info!(
                "force_remove_usb: removed {:?} after physical unplug",
                device_id
            );
        }
    }

    /// Called by the USB monitor when a `remove` udev event is received.
    ///
    /// # Arguments
    ///
    /// * `device_id` - Device node path (e.g. `/dev/sdb1`)
    pub fn remove_usb(&mut self, device_id: &OsString) {
        if let Some(policy) = self.mounted_usb.remove(device_id) {
            // Remove the fanotify mount mark so the now-unmounted filesystem
            // is no longer intercepted.
            let block_policy = UsbDevicePolicy {
                device: policy.device.clone(),
                auth: UsbAuthorization::Block,
            };
            if let Err(e) = self.file_filter.update_usb_auth(&block_policy) {
                warn!(
                    "remove_usb: failed to remove fanotify mark for {:?}: {e}",
                    device_id
                );
            }

            // Evict all pre-validated cache entries and blocked files for this mount.
            if let Some(mnt) = policy.device.mnt_point.as_ref() {
                let prefix = PathBuf::from(mnt);
                self.validated_files.retain(|p| !p.starts_with(&prefix));
                info!("remove_usb: validated_files cache evicted for {:?}", mnt);
            }
            self.blocked_files.remove(&device_id.clone());

            info!(
                "USB device {:?} removed (was mounted at {:?})",
                device_id, policy.device.mnt_point
            );
        } else if let Some(policy) = self.unmounted_usb.get(device_id) {
            if policy.auth == UsbAuthorization::Block {
                // This remove event was triggered by our own kernel-level
                // deauthorization (writing 0 to sysfs/authorized).  Keep the
                // entry in the store so the tray-app polling thread can display
                // "blocked" in the UI.  The entry will be replaced on replug.
                info!(
                    "USB device {:?} kernel-disconnected after block — \
                     keeping entry visible in tray",
                    device_id
                );
            } else {
                self.unmounted_usb.remove(device_id);
                info!("USB device {:?} removed (was pending/unmounted)", device_id);
            }
        }
    }

    /// Called by the Windows USB monitor when a drive letter disappears from the system.
    ///
    /// Cleans up the stale entry from `mounted_usb` or `unmounted_usb` and notifies
    /// the tray-app.  This prevents device-id collisions when a new USB key is plugged
    /// on the same PhysicalDriveN slot as a previously tracked device.
    #[cfg(target_os = "windows")]
    pub fn remove_usb_by_drive(&mut self, drive_letter: char) {
        let prefix = format!("{drive_letter}:\\");

        let found_mounted = self
            .mounted_usb
            .iter()
            .find(|(_, p)| {
                p.device
                    .mnt_point
                    .as_ref()
                    .map(|m| m.to_string_lossy().starts_with(&prefix))
                    .unwrap_or(false)
            })
            .map(|(id, p)| (id.clone(), p.device.get_name()));

        if let Some((id, name)) = found_mounted {
            info!(
                "remove_usb_by_drive: drive {drive_letter}: {:?} unplugged",
                id
            );
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: id.to_string_lossy().into_owned(),
                path: String::default(),
                name,
                authorization: UsbAuthorization::Block,
            };
            if let Err(e) = self.gui.send_usb_update(&update) {
                warn!("remove_usb_by_drive: GUI notification failed: {e}");
            }
            // remove_usb cleans mounted_usb, validated_files and blocked_files caches.
            // FilterSendMessage will fail (drive gone) but the error is non-fatal.
            self.remove_usb(&id);
            return;
        }

        let found_unmounted = self
            .unmounted_usb
            .iter()
            .find(|(_, p)| {
                p.device
                    .mnt_point
                    .as_ref()
                    .map(|m| m.to_string_lossy().starts_with(&prefix))
                    .unwrap_or(false)
            })
            .map(|(id, p)| (id.clone(), p.device.get_name()));

        if let Some((id, name)) = found_unmounted {
            self.unmounted_usb.remove(&id);
            info!(
                "remove_usb_by_drive: drive {drive_letter}: blocked device {:?} unplugged",
                id
            );
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: id.to_string_lossy().into_owned(),
                path: String::default(),
                name,
                authorization: UsbAuthorization::Block,
            };
            if let Err(e) = self.gui.send_usb_update(&update) {
                warn!("remove_usb_by_drive: GUI notification failed: {e}");
            }
        }
    }

    /// Decide to authorize a file
    /// This method is called by the file filter interface
    /// Start by whitelisting file that belongs to Windows and remove directories
    /// Then try to validate it with a station report
    /// Finaly if it fails ask the user to validate it manualy
    ///
    /// USB_op will be used to apply a device wide filter policy
    ///
    /// Returns the authorization decision
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `write` - If write access is requested
    pub fn authorize_file(
        &mut self,
        file: &FilteredFile,
        _write: bool,
    ) -> Result<bool, anyhow::Error> {
        let file_path = match &file.path {
            Some(p) => {
                let mut pb = PathBuf::new();
                pb.push(&p);
                pb
            }
            None => {
                return Err(anyhow!("Invalid file"));
            }
        };

        // Try to get the parent directory
        let mut components = file_path.as_path().components();

        // First component is the Root Directory
        // If the second directory is "System Volume Information" then it is internal to windows, skip it
        loop {
            let c = components.next();
            if c.is_none() || c == Some(Component::RootDir) {
                break;
            }
        }

        if components.next() == Some(Component::Normal(OsStr::new("System Volume Information"))) {
            return Ok(true);
        }

        // Skip the directories
        if file_path.metadata()?.is_dir() {
            return Ok(true);
        }

        // .krp files are internal station-report files: always allow immediately.
        // Calling validate_file() on a .krp would require opening its linked data
        // file, which generates a new FAN_OPEN_PERM event that the single-threaded
        // fanotify event loop cannot process while it is already handling this event
        // → deadlock.  .krp files contain only signatures/digests, not user data.
        if file_path
            .extension()
            .map_or(false, |e| e.eq_ignore_ascii_case("krp"))
        {
            return Ok(true);
        }

        // Cache lookup: was this file certified during the pre-scan that ran
        // BEFORE the fanotify mark was placed?
        //
        // IMPORTANT: do NOT call validate_file() here.  validate_file() calls
        // parse_report() which opens files on the watched mount, generating new
        // FAN_OPEN_PERM events.  The single-threaded fanotify event loop cannot
        // process those events while it is already blocked handling this one →
        // deadlock.  The pre-scan is the only safe validation path.
        if self.validated_files.contains(&file_path) {
            return Ok(true);
        }

        // File was not certified at mount time.
        // Queue for tray-based authorization only when certs are valid AND the
        // policy allows it.  If certs are KO the user cannot bypass cert checks.
        if self.certs.is_some() && self.policy.allow_user_file_read {
            if let Some(device_id) = self.device_id_for_path(&file_path) {
                let is_new = {
                    let list = self.blocked_files.entry(device_id.clone()).or_default();
                    if list.contains(&file_path) {
                        false
                    } else {
                        list.push(file_path.clone());
                        true
                    }
                };
                if is_new {
                    let update = FileUpdateMessage {
                        code: GuiMessageCode::FileUpdateMessage,
                        device: device_id.to_string_lossy().into_owned(),
                        id: [0u16; 16],
                        path: file_path.to_string_lossy().into_owned(),
                        authorization: FileAuthorization::Block,
                    };
                    if let Err(e) = self.gui.send_file_update(&update) {
                        warn!("authorize_file: failed to notify tray of blocked file: {e}");
                    }
                }
            }
        }

        info!("authorize_file: blocking {:?} (not certified)", file_path);
        Ok(false)
    }

    fn validate_usb_signature(
        &self,
        device: &UsbDevice,
        sig_block: &str,
    ) -> Result<bool, anyhow::Error> {
        let mut signatures = sig_block.split('|');

        // Extract ED25519 signature
        let sig_cl = match signatures.next() {
            Some(s) => s,
            None => {
                return Err(anyhow!("Cannot extract ED25519 signature"));
            }
        };

        let sig_cl_dec = match general_purpose::STANDARD.decode(sig_cl) {
            Ok(s) => s,
            Err(_e) => {
                return Err(anyhow!("Failed to parse ED25519 signature"));
            }
        };

        let mut sig_cl_dec_casted: [u8; 64] = [0u8; 64];
        if sig_cl_dec.len() == 64_usize {
            sig_cl_dec_casted.copy_from_slice(&sig_cl_dec);
        } else {
            return Err(anyhow!(
                "ED25519 signature is {} bytes (expected 64); sig_cl base64 length={}",
                sig_cl_dec.len(),
                sig_cl.len()
            ));
        }

        let sig_dalek = SignatureDalek::from_bytes(&sig_cl_dec_casted);

        let sig_pq = match signatures.next() {
            Some(s) => s,
            None => {
                return Err(anyhow!("Cannot extract Dilithium 5 signature"));
            }
        };

        let sig_pq_dec = match general_purpose::STANDARD.decode(sig_pq) {
            Ok(s) => s,
            Err(_e) => {
                return Err(anyhow!("Failed to parse Dilithium 5 signature"));
            }
        };

        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new MlDsa87 algorithm: {e}")),
        };

        let sig_pq = match pq_scheme.signature_from_bytes(&sig_pq_dec) {
            Some(sig) => sig,
            None => return Err(anyhow!("Cannot parse PQ signature from bytes")),
        };

        let hybrid_sig = KeysasHybridSignature {
            classic: sig_dalek,
            pq: sig_pq.to_owned(),
        };

        let data = format!(
            "{}/{}/{}/{}/{}",
            device.vendor.to_string_lossy(),
            device.model.to_string_lossy(),
            device.revision.to_string_lossy(),
            device.serial.to_string_lossy(),
            "out"
        );
        info!("validate_usb_signature: verifying data={:?}", data);

        let usb_ca_pub = &self
            .certs
            .as_ref()
            .ok_or_else(|| anyhow!("validate_usb_signature: no valid certificates"))?
            .usb_ca_pub;

        match KeysasHybridPubKeys::verify_key_signatures(data.as_bytes(), &hybrid_sig, usb_ca_pub) {
            Ok(_) => Ok(true),
            Err(e) => {
                warn!("validate_usb_signature: verification failed: {e}");
                Ok(false)
            }
        }
    }

    /// Check a file
    ///
    /// # Return value
    ///  - If it is a normal file, try to find the corresponding station report
    ///     - If there is none, return False
    ///     - If there is one, validate both
    ///  - If the file is a station report, try to find the corresponding file
    ///     - If there is none, try to validate the report alone. There must be no file digest referenced in it
    ///     - If there is one, validate both
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    fn validate_file(&self, path: &Path) -> Result<bool, anyhow::Error> {
        let certs = match self.certs.as_ref() {
            Some(c) => c,
            None => return Ok(false),
        };

        // Test if the file is itself a station report (.krp)
        if Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("krp"))
        {
            // Derive the data-file path: ".foo.krp" → "foo"
            let mut file_path = path.to_path_buf();
            file_path.set_extension("");
            if let (Some(parent), Some(fname)) = (file_path.parent(), file_path.file_name()) {
                if let Some(stripped) = fname.to_string_lossy().strip_prefix('.') {
                    file_path = parent.join(stripped);
                }
            }

            return if file_path.is_file() {
                // Validate the report and the linked data file together
                match parse_report(
                    path,
                    Some(&file_path),
                    Some(&certs.st_ca_cert_cl),
                    Some(&certs.st_ca_cert_pq),
                ) {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        info!("validate_file: invalid report (with data file): {e}");
                        Ok(false)
                    }
                }
            } else {
                // No linked data file — validate the report alone
                match parse_report(
                    path,
                    None,
                    Some(&certs.st_ca_cert_cl),
                    Some(&certs.st_ca_cert_pq),
                ) {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        info!("validate_file: invalid standalone report: {e}");
                        Ok(false)
                    }
                }
            };
        }

        // Regular file: look for its station report ".<filename>.krp" in the same directory
        let path_report = if let (Some(parent), Some(fname)) = (path.parent(), path.file_name()) {
            parent.join(format!(".{}.krp", fname.to_string_lossy()))
        } else {
            PathBuf::from(path)
        };

        if path_report.is_file() {
            // Validate both the report and the data file (hash check included)
            match parse_report(
                path_report.as_path(),
                Some(path),
                Some(&certs.st_ca_cert_cl),
                Some(&certs.st_ca_cert_pq),
            ) {
                Ok(_) => Ok(true),
                Err(e) => {
                    info!("validate_file: invalid report for {:?}: {e}", path);
                    Ok(false)
                }
            }
        } else {
            info!("validate_file: no report found at {:?}", path_report);
            Ok(false)
        }
    }

    /// Spawn a dialog box to ask the user to validate a file or not
    /// Return Ok(true) or Ok(false) accordingly

    /// Return the device_id of the mounted USB device whose mount point is a
    /// prefix of `path`, or `None` if no such device is found.
    fn device_id_for_path(&self, path: &Path) -> Option<OsString> {
        self.mounted_usb
            .iter()
            .find(|(_, policy)| {
                policy
                    .device
                    .mnt_point
                    .as_ref()
                    .map(|mnt| path.starts_with(Path::new(mnt)))
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
    }

    /// Return the list of blocked (non-certified) file paths for `device_id`.
    /// Used by the D-Bus `get_blocked_files` method so the tray-app can show
    /// per-file authorization buttons.
    pub fn list_blocked_files(&self, device_id: &str) -> Vec<String> {
        let key = OsString::from(device_id);
        self.blocked_files
            .get(&key)
            .map(|paths| {
                paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Move a previously blocked file into `validated_files` so that the next
    /// open attempt succeeds.  Called when the user clicks "Autoriser" in the
    /// tray for a specific file.
    pub fn authorize_blocked_file(
        &mut self,
        device_id: &str,
        path: &str,
    ) -> Result<(), anyhow::Error> {
        let key = OsString::from(device_id);
        let file_path = PathBuf::from(path);
        if let Some(list) = self.blocked_files.get_mut(&key) {
            list.retain(|p| p != &file_path);
        }
        self.validated_files.insert(file_path);
        info!(
            "authorize_blocked_file: authorized {:?} on {:?}",
            path, device_id
        );
        Ok(())
    }

    /// Get the authorization status for a filesystem on a USB device
    ///
    /// # Arguments
    ///
    /// * `mount` - Name of the filesystem partition
    ///
    /// # Return value
    ///
    /// *  if a device with a [mnt_point](UsbDevice) = `mount` => the [auth](UsbDevicePolicy) corresponding to its device policy
    /// * else an error
    pub fn get_usb_auth(&self, mount: &OsString) -> Result<UsbAuthorization, anyhow::Error> {
        match self.mounted_usb.get(mount) {
            Some(dev_policy) => {
                // Return the authorization status for the device
                Ok(dev_policy.auth)
            }
            None => {
                // no mounted device exists, return an error
                Err(anyhow!("No device found"))
            }
        }
    }

    /// Look up USB authorization by DOS mount point path (e.g. `"D:\"`).
    ///
    /// Used on Windows to answer `SCAN_USB` requests from the minifilter,
    /// after the NT volume path has been reverse-resolved to a DOS drive letter.
    pub fn get_usb_auth_by_mount(&self, mnt_point: &OsString) -> Option<UsbAuthorization> {
        self.mounted_usb
            .values()
            .find(|p| p.device.mnt_point.as_ref() == Some(mnt_point))
            .map(|p| p.auth)
    }

    /// Return the list of USB devices currently tracked as a flat tuple list.
    ///
    /// Each tuple is `(device_id, mount_point, name, auth_u8)`.
    /// Used by the D-Bus `get_usb_list` method for tray-app polling.
    pub fn list_usb_devices(&self) -> Vec<(String, String, String, u8)> {
        let mut result = Vec::new();
        for (_, usb) in self.unmounted_usb.iter() {
            result.push((
                usb.device.device_id.to_string_lossy().into_owned(),
                String::new(),
                usb.device.get_name(),
                usb.auth.as_u8(),
            ));
        }
        for (_, usb) in self.mounted_usb.iter() {
            result.push((
                usb.device.device_id.to_string_lossy().into_owned(),
                usb.device
                    .mnt_point
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                usb.device.get_name(),
                usb.auth.as_u8(),
            ));
        }
        result
    }

    /// Re-register USB devices that were certified and mounted before this daemon
    /// instance started (hot-restart recovery).
    ///
    /// For each sentinel in `/run/keysas/certified/`:
    ///   1. If the device node no longer exists, remove the stale sentinel.
    ///   2. If the device is not currently mounted, skip it.
    ///   3. Otherwise, insert it directly into `mounted_usb` with auth derived
    ///      from the current policy (sentinel presence attests prior certification).
    ///   4. Re-apply the fanotify mount mark so file access is filtered immediately.
    ///
    /// Desktop notifications are intentionally skipped; the tray-app will pick
    /// up the restored devices on its next 5-second polling cycle.
    #[cfg(target_os = "linux")]
    fn recover_mounted_devices(&mut self) {
        let certified_dir = Path::new("/run/keysas/certified");
        if !certified_dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(certified_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("recover_mounted_devices: cannot read sentinel dir: {e}");
                return;
            }
        };

        for entry in entries.flatten() {
            let dev_name = entry.file_name().to_string_lossy().into_owned();
            let device_id = OsString::from(format!("/dev/{}", dev_name));

            // Device unplugged while the daemon was stopped — remove stale sentinel.
            if !Path::new(&device_id).exists() {
                let _ = std::fs::remove_file(entry.path());
                info!(
                    "recover_mounted_devices: /dev/{} gone, removed sentinel",
                    dev_name
                );
                continue;
            }

            // Device present but not currently mounted — nothing to re-register.
            let mnt_point = match find_mount_point(&device_id) {
                Some(m) => m,
                None => {
                    info!(
                        "recover_mounted_devices: /dev/{} not mounted, skipping",
                        dev_name
                    );
                    continue;
                }
            };

            // Re-derive auth from the current policy.
            // The sentinel already attests that the device passed certification.
            let auth = if self.policy.allow_user_file_write {
                UsbAuthorization::AllowRW
            } else {
                UsbAuthorization::AllowRead
            };

            let device = UsbDevice {
                device_id: device_id.clone(),
                mnt_point: Some(OsString::from(&mnt_point)),
                vendor: OsString::new(),
                model: OsString::new(),
                revision: OsString::new(),
                serial: OsString::new(),
                usb_syspath: None,
            };
            let policy = UsbDevicePolicy { device, auth };

            // Pre-validate all files before placing the fanotify mark.
            self.pre_validate_mount(Path::new(&mnt_point));

            // Re-apply the fanotify mount mark.
            if let Err(e) = self.file_filter.update_usb_auth(&policy) {
                warn!(
                    "recover_mounted_devices: fanotify mark failed for \
                     /dev/{dev_name}: {e}"
                );
            } else {
                info!(
                    "recover_mounted_devices: restored /dev/{} at {} (auth={:?})",
                    dev_name, mnt_point, auth
                );
            }

            self.mounted_usb.insert(device_id, policy);
        }
    }

    /// Send the list of Usb devices and files currently registered in the firewall
    ///
    /// For now, send the list of USB devices registered
    /// Files are not currently stored in the controller: TO BE FIXED
    ///
    /// # Return value
    ///
    /// * error if needed
    pub fn send_usb_file_list(&self) -> Result<(), anyhow::Error> {
        for (_, usb) in self.unmounted_usb.iter() {
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: String::from(usb.device.device_id.to_string_lossy()),
                path: String::default(),
                name: usb.device.get_name(),
                authorization: usb.auth,
            };

            let _ = self.gui.send_usb_update(&update);
        }

        for (_, usb) in self.mounted_usb.iter() {
            let update = UsbUpdateMessage {
                code: GuiMessageCode::UsbUpdateMessage,
                device: String::from(usb.device.device_id.to_string_lossy()),
                path: String::default(),
                name: usb.device.get_name(),
                authorization: usb.auth,
            };

            let _ = self.gui.send_usb_update(&update);
        }

        Ok(())
    }

    /// Apply new policy settings: update the in-memory policy and persist to
    /// the registry (Windows only — the daemon runs as SYSTEM).
    pub fn update_policy(&mut self, msg: &PolicyUpdateMessage) -> Result<(), anyhow::Error> {
        let new_policy = SecurityPolicy {
            disable_unsigned_usb: msg.disable_unsigned_usb,
            allow_user_usb_authorization: msg.allow_user_usb_authorization,
            allow_user_file_read: msg.allow_user_file_read,
            allow_user_file_write: msg.allow_user_file_write,
        };
        #[cfg(target_os = "windows")]
        write_policy_settings(&new_policy)?;
        self.policy = new_policy;
        Ok(())
    }
}
