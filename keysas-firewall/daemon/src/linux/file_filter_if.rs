// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! FileFilterInterface is a generic interface to send and receive messages
//! to the file filter in kernel space.
//! The interface must be specialized for Linux or Windows

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
use log::*;
use std::ffi::{CString, OsString};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::controller::{FilePolicy, FilteredFile, ServiceController, UsbAuthorization, UsbDevicePolicy};
use crate::file_filter_if::FileFilterInterface;

#[derive(Debug, Clone)]
pub struct LinuxFileFilterInterface {
    fd: Arc<AtomicI32>,
}

impl LinuxFileFilterInterface {
    /// Initialize the fanotify file filter interface.
    ///
    /// Creates a fanotify instance with FAN_CLASS_CONTENT for open-permission events.
    pub fn init() -> Result<LinuxFileFilterInterface, anyhow::Error> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "fanotify_init failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        info!("fanotify initialized (fd={})", fd);
        Ok(LinuxFileFilterInterface {
            fd: Arc::new(AtomicI32::new(fd)),
        })
    }
}

impl Drop for LinuxFileFilterInterface {
    fn drop(&mut self) {
        let fd = self.fd.swap(-1, Ordering::Relaxed);
        if fd >= 0 {
            unsafe { libc::close(fd) };
            info!("fanotify fd={} closed", fd);
        }
    }
}

impl FileFilterInterface for LinuxFileFilterInterface {
    /// Start the fanotify event loop in a background thread.
    ///
    /// For each FAN_OPEN_PERM event the thread:
    ///  1. Resolves the file path via /proc/self/fd/<N>
    ///  2. Calls authorize_file() on the controller
    ///  3. Writes FAN_ALLOW or FAN_DENY back to the fanotify fd
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let fd_arc = Arc::clone(&self.fd);
        let ctrl = Arc::clone(ctrl);
        let daemon_pid = unsafe { libc::getpid() };

        thread::spawn(move || {
            let event_size = mem::size_of::<libc::fanotify_event_metadata>();
            let mut buf = vec![0u8; 4096];

            loop {
                let fan_fd = fd_arc.load(Ordering::Relaxed);
                if fan_fd < 0 {
                    break;
                }

                let ret = unsafe {
                    libc::read(
                        fan_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    // EBADF means the fd was closed (stop() called)
                    debug!("fanotify read returned error: {err}");
                    break;
                }

                let bytes_read = ret as usize;
                let mut offset = 0usize;

                while offset + event_size <= bytes_read {
                    // SAFETY: buffer is large enough and properly aligned via read_unaligned
                    let event: libc::fanotify_event_metadata = unsafe {
                        std::ptr::read_unaligned(
                            buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata,
                        )
                    };

                    if event.event_len < event_size as u32 {
                        error!("fanotify: malformed event (event_len={})", event.event_len);
                        break;
                    }

                    if (event.mask & libc::FAN_OPEN_PERM) != 0 && event.fd >= 0 {
                        // Events from the daemon itself are auto-allowed to prevent deadlocks
                        // when authorize_file() accesses files on the watched mount.
                        let allow = if event.pid == daemon_pid {
                            true
                        } else {
                            // Resolve the path of the file being opened
                            let proc_link = format!("/proc/self/fd/{}", event.fd);
                            let file_path = std::fs::read_link(&proc_link)
                                .ok()
                                .map(OsString::from);

                            let file = FilteredFile {
                                path: file_path,
                                id: [0u8; 32],
                            };

                            ctrl.lock()
                                .map(|mut g| g.authorize_file(&file, false).unwrap_or(false))
                                .unwrap_or(false)
                        };

                        // FAN_DENY on a O_CREAT open leaves an empty inode on the
                        // filesystem (the inode is allocated before file_open fires).
                        // Delete GIO atomic-write temp files to avoid orphans on the key.
                        if !allow {
                            if let Some(ref p) = file.path {
                                let name = Path::new(p)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("");
                                if name.starts_with(".goutputstream-") {
                                    if let Err(e) = std::fs::remove_file(p) {
                                        debug!("fanotify: could not remove orphan {p:?}: {e}");
                                    } else {
                                        debug!("fanotify: removed orphan temp file {p:?}");
                                    }
                                }
                            }
                        }

                        let response = libc::fanotify_response {
                            fd: event.fd,
                            response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY },
                        };

                        let fan_fd_now = fd_arc.load(Ordering::Relaxed);
                        if fan_fd_now >= 0 {
                            unsafe {
                                libc::write(
                                    fan_fd_now,
                                    &response as *const libc::fanotify_response
                                        as *const libc::c_void,
                                    mem::size_of::<libc::fanotify_response>(),
                                );
                            }
                        }
                        unsafe { libc::close(event.fd) };
                    } else if event.fd >= 0 {
                        // Non-permission event or queue overflow: just close the fd
                        unsafe { libc::close(event.fd) };
                    }

                    offset += event.event_len as usize;
                }
            }
        });

        Ok(())
    }

    /// Update the control policy on a file — no-op (per-mount marks cover all files).
    fn update_file_auth(&self, _update: &FilePolicy) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Add or remove a fanotify FAN_OPEN_PERM mark on the USB mount point.
    ///
    /// A mark is added when auth >= AllowRead and removed (blocked) otherwise.
    fn update_usb_auth(&self, update: &UsbDevicePolicy) -> Result<(), anyhow::Error> {
        let mnt_point = match &update.device.mnt_point {
            Some(p) => p,
            None => return Err(anyhow!("USB device has no mount point")),
        };

        let fan_fd = self.fd.load(Ordering::Relaxed);
        if fan_fd < 0 {
            return Err(anyhow!("fanotify fd is not open"));
        }

        let add_mark = matches!(
            update.auth,
            UsbAuthorization::AllowRead
                | UsbAuthorization::AllowRW
                | UsbAuthorization::AllowAll
        );

        let path_cstr = CString::new(mnt_point.as_os_str().as_bytes())
            .map_err(|e| anyhow!("Invalid mount point path: {e}"))?;

        let flags = if add_mark {
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT
        } else {
            libc::FAN_MARK_REMOVE | libc::FAN_MARK_MOUNT
        };

        let ret = unsafe {
            libc::fanotify_mark(
                fan_fd,
                flags as libc::c_uint,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                path_cstr.as_ptr(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // Ignore ENOENT when removing a mark that does not exist
            if add_mark || err.raw_os_error() != Some(libc::ENOENT) {
                return Err(anyhow!(
                    "fanotify_mark {} on {:?}: {err}",
                    if add_mark { "ADD" } else { "REMOVE" },
                    mnt_point
                ));
            }
        }

        info!(
            "fanotify mark {}: mount={:?} auth={:?}",
            if add_mark { "ADD" } else { "REMOVE" },
            mnt_point,
            update.auth
        );

        Ok(())
    }

    /// Stop the file filter — closing the fanotify fd is handled by Drop.
    fn stop(self: Box<Self>) {
        // Drop runs LinuxFileFilterInterface::drop() which closes the fd.
        info!("fanotify file filter stopping");
    }
}
