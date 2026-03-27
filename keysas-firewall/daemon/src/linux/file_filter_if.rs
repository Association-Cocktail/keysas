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
use aya::{include_bytes_aligned, programs::lsm::Lsm, BpfLoader, Btf};
use aya_log::BpfLogger;
use log::*;
use std::ffi::CString;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::{
    boxed::Box,
    fs::create_dir_all,
    path::Path,
    sync::{Arc, Mutex},
    thread,
};
use tokio::runtime::Runtime;

use crate::controller::{ServiceController, FilePolicy, UsbDevicePolicy};
use crate::file_filter_if::FileFilterInterface;

/// Size of the mount point path key in the BPF policy map.
/// Must match KEY_LEN in lsm-file-common.
const BPF_KEY_LEN: usize = 64;

/// Path where the eBPF maps are pinned
const BPF_PIN_PATH: &str = "/sys/fs/bpf/keysas";

/// Path to the policy map pin
const POLICY_MAP_PIN: &str = "/sys/fs/bpf/keysas/POLICY_MAP";

// ─────────────────────────────────────────────────────────────────────────────
// Raw BPF syscall helpers (aya 0.11 does not expose a public pinned-map API)
// ─────────────────────────────────────────────────────────────────────────────

/// Open a pinned BPF object (map or program) and return its file descriptor.
/// Equivalent to `BPF_OBJ_GET`.
fn bpf_obj_get(path: &CString) -> Result<libc::c_int, std::io::Error> {
    // bpf_attr layout for BPF_OBJ_GET / BPF_OBJ_PIN:
    //   offset 0: pathname (__aligned_u64 = u64)
    //   offset 8: bpf_fd  (u32)
    //   offset 12: file_flags (u32)
    #[repr(C)]
    struct BpfAttrObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let mut attr: BpfAttrObjGet = unsafe { mem::zeroed() };
    attr.pathname = path.as_ptr() as u64;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            7i32, // BPF_OBJ_GET
            &mut attr as *mut BpfAttrObjGet as *mut libc::c_void,
            mem::size_of::<BpfAttrObjGet>() as u32,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as libc::c_int)
    }
}

/// Update or insert a key/value pair in a BPF map.
/// Equivalent to `BPF_MAP_UPDATE_ELEM` with `BPF_ANY` flag.
fn bpf_map_update_elem<K, V>(fd: libc::c_int, key: &K, value: &V) -> Result<(), std::io::Error> {
    // bpf_attr layout for BPF_MAP_*_ELEM:
    //   offset 0:  map_fd (u32) + 4 bytes padding
    //   offset 8:  key    (__aligned_u64)
    //   offset 16: value  (__aligned_u64)
    //   offset 24: flags  (u64)
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let mut attr: BpfAttrMapElem = unsafe { mem::zeroed() };
    attr.map_fd = fd as u32;
    attr.key = key as *const K as u64;
    attr.value = value as *const V as u64;
    attr.flags = 0; // BPF_ANY

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2i32, // BPF_MAP_UPDATE_ELEM
            &mut attr as *mut BpfAttrMapElem as *mut libc::c_void,
            mem::size_of::<BpfAttrMapElem>() as u32,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LinuxFileFilterInterface {}

impl LinuxFileFilterInterface {
    /// Initialize the kernel filter interface
    pub fn init() -> Result<LinuxFileFilterInterface, anyhow::Error> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        Ok(LinuxFileFilterInterface {})
    }
}

async fn start_bpf() -> Result<(), anyhow::Error> {
    let lsm_base_path = Path::new(BPF_PIN_PATH);
    create_dir_all(lsm_base_path)?;

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .map_pin_path(lsm_base_path)
        .load(include_bytes_aligned!(
            "../../../ebpfilter/target/bpfel-unknown-none/debug/lsm-file"
        ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .map_pin_path(lsm_base_path)
        .load(include_bytes_aligned!(
            "../../../ebpfilter/target/bpfel-unknown-none/release/lsm-file"
        ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let lsm: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    lsm.load("file_open", &btf)?;
    lsm.attach()?;

    info!("eBPF LSM file_open hook loaded and attached");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

impl FileFilterInterface for LinuxFileFilterInterface {
    /// Start listening for request on the interface
    ///
    /// # Arguments
    ///
    /// `ctrl` - Handle to the service controller
    fn start(&self, _ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        // Create a tokio runtime to handle BPF program loading and events
        // Run it in its own thread
        thread::spawn(|| -> Result<(), anyhow::Error> {
            let rt = Runtime::new()?;
            if let Err(e) = rt.block_on(start_bpf()) {
                error!("BPF thread failed with error: {e}");
            }
            Ok(())
        });

        Ok(())
    }

    /// Update the control policy on a file
    ///
    /// # Arguments
    ///
    /// `update` - Information on the file and the new authorization status
    fn update_file_auth(&self, _update: &FilePolicy) -> Result<(), anyhow::Error> {
        // File-level policy is not enforced via eBPF in this implementation;
        // per-mount-point decisions cover all files on the device.
        Ok(())
    }

    /// Update the control policy on a partition in the POLICY_MAP.
    ///
    /// Opens the pinned BPF map at `/sys/fs/bpf/keysas/POLICY_MAP` and inserts
    /// or updates the entry for `update.device.mnt_point` with the decision
    /// derived from `update.auth`.
    ///
    /// # Arguments
    ///
    /// `update` - USB device policy, must have `mnt_point` set
    fn update_usb_auth(&self, update: &UsbDevicePolicy) -> Result<(), anyhow::Error> {
        let mnt_point = match &update.device.mnt_point {
            Some(p) => p,
            None => return Err(anyhow!("USB device has no mount point")),
        };

        // Build the fixed-size null-padded key from the mount point path
        let mut key = [0u8; BPF_KEY_LEN];
        let mnt_bytes = mnt_point.as_bytes(); // OsStrExt, Unix only
        let copy_len = mnt_bytes.len().min(BPF_KEY_LEN - 1);
        key[..copy_len].copy_from_slice(&mnt_bytes[..copy_len]);
        // Remaining bytes are already 0 (null sentinel)

        let decision: u32 = update.auth.as_u8() as u32;

        // aya 0.11 does not expose a public API for opening pinned maps.
        // Use the raw bpf(2) syscall directly:
        //   BPF_OBJ_GET (cmd=7)  → get fd from pinned path
        //   BPF_MAP_UPDATE_ELEM (cmd=2) → insert/update map entry
        let path_cstr = CString::new(POLICY_MAP_PIN)
            .map_err(|e| anyhow!("Invalid map pin path: {e}"))?;
        let map_fd = bpf_obj_get(&path_cstr)
            .map_err(|e| anyhow!("BPF_OBJ_GET {POLICY_MAP_PIN}: {e}"))?;
        let result = bpf_map_update_elem(map_fd, &key, &decision);
        unsafe { libc::close(map_fd) };
        result.map_err(|e| anyhow!("BPF_MAP_UPDATE_ELEM: {e}"))?;

        info!(
            "BPF policy updated: mount={} decision={}",
            mnt_point.to_string_lossy(),
            decision
        );

        Ok(())
    }

    /// Stop the interface and free resources
    fn stop(self: Box<Self>) {}
}
