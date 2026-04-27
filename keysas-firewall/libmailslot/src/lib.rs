// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Named-pipe IPC wrapper (replaces the Windows mailslot implementation).
//!
//! Named pipes via `\\.\pipe\` are routed through `\Device\NamedPipe\` in the
//! Windows kernel — a flat, session-agnostic namespace.  They work between
//! Session 0 (daemon / SYSTEM) and Session 1+ (interactive tray app) with no
//! SMB stack, no port 445, no firewall rules required.

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
use libc::c_void;
use std::{ffi::OsStr, iter::once, os::windows::ffi::OsStrExt};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, FALSE, HANDLE, INVALID_HANDLE_VALUE,
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED,
};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, NAMED_PIPE_MODE,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

/// Maximum message size in bytes.
const MAX_MSG_SIZE: u32 = 65536;

/// How long `write_mailslot` waits for the pipe server to be ready (milliseconds).
const WRITE_WAIT_MS: u32 = 500;

// Named-pipe mode constants wrapped in the types expected by windows 0.48.
const PIPE_ACCESS_INBOUND: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAGS_AND_ATTRIBUTES(0x0000_0001);
const PIPE_TYPE_MESSAGE: NAMED_PIPE_MODE = NAMED_PIPE_MODE(0x0000_0004);
const PIPE_READMODE_MESSAGE: NAMED_PIPE_MODE = NAMED_PIPE_MODE(0x0000_0002);
const PIPE_NOWAIT: NAMED_PIPE_MODE = NAMED_PIPE_MODE(0x0000_0001);
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

/// Server-side handle for a named pipe channel.
///
/// Not `Copy` or `Clone`: the contained `HANDLE` must not be aliased —
/// it is closed implicitly when the pipe server shuts down.
#[derive(Debug)]
pub struct MailSlot {
    pub handle: HANDLE,
    /// True once a client has connected and we have not yet seen a disconnect.
    connected: bool,
}

/// Create a named pipe server (the reader / server side of the channel).
///
/// Uses message mode and `PIPE_NOWAIT` so that `read_mailslot` can be called
/// in a polling loop without blocking.
///
/// A NULL DACL is set on the pipe so that both Session 0 (SYSTEM) and any
/// interactive-user session can connect, regardless of which side creates it.
pub fn create_mailslot(name: &str) -> Result<MailSlot, anyhow::Error> {
    let slot_name: Vec<u16> = OsStr::new(name).encode_wide().chain(once(0)).collect();
    let pslot_name = PCWSTR::from_raw(slot_name.as_ptr());

    // NULL DACL → any local process may connect (required for cross-session access).
    let mut sec_dec = SECURITY_DESCRIPTOR::default();
    let psec_desc = PSECURITY_DESCRIPTOR(&mut sec_dec as *mut SECURITY_DESCRIPTOR as *mut c_void);

    unsafe {
        if !InitializeSecurityDescriptor(psec_desc, SECURITY_DESCRIPTOR_REVISION).as_bool() {
            let err = GetLastError();
            return Err(anyhow!(
                "create_mailslot: InitializeSecurityDescriptor failed for '{name}' \
                 (Windows error {}: {})",
                err.0,
                err.to_hresult().message().to_string_lossy()
            ));
        }

        if !SetSecurityDescriptorDacl(psec_desc, BOOL::from(true), None, BOOL::from(false))
            .as_bool()
        {
            let err = GetLastError();
            return Err(anyhow!(
                "create_mailslot: SetSecurityDescriptorDacl failed for '{name}' \
                 (Windows error {}: {})",
                err.0,
                err.to_hresult().message().to_string_lossy()
            ));
        }

        if !SetSecurityDescriptorControl(psec_desc, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            .as_bool()
        {
            let err = GetLastError();
            return Err(anyhow!(
                "create_mailslot: SetSecurityDescriptorControl failed for '{name}' \
                 (Windows error {}: {})",
                err.0,
                err.to_hresult().message().to_string_lossy()
            ));
        }
    }

    let sec_attr = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: psec_desc.0,
        bInheritHandle: FALSE,
        ..Default::default()
    };

    let handle = unsafe {
        CreateNamedPipeW(
            pslot_name,
            PIPE_ACCESS_INBOUND,
            // message mode, non-blocking: PIPE_TYPE_MESSAGE(4) | PIPE_READMODE_MESSAGE(2) | PIPE_NOWAIT(1)
            NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_NOWAIT.0),
            PIPE_UNLIMITED_INSTANCES,
            MAX_MSG_SIZE,
            MAX_MSG_SIZE,
            0, // default timeout
            Some(&sec_attr as *const SECURITY_ATTRIBUTES),
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
        let err = unsafe { GetLastError() };
        return Err(anyhow!(
            "create_mailslot: CreateNamedPipeW failed for '{name}' \
             (Windows error {}: {})",
            err.0,
            err.to_hresult().message().to_string_lossy()
        ));
    }

    Ok(MailSlot { handle, connected: false })
}

/// Read one message from a named pipe server (non-blocking).
///
/// Returns `Ok(Some(msg))` when a complete message is available,
/// `Ok(None)` when there is no client or no data yet, and `Err` on
/// unexpected errors.
///
/// Manages the connection lifecycle internally: if a client disconnects the
/// pipe is reset and will accept the next client on the following call.
pub fn read_mailslot(slot: &mut MailSlot) -> Result<Option<String>, anyhow::Error> {
    if !slot.connected {
        // With PIPE_NOWAIT, ConnectNamedPipe always returns FALSE.
        // We only care about GetLastError():
        //   ERROR_PIPE_CONNECTED  → a client connected before we called this
        //   ERROR_PIPE_LISTENING  → no client yet, nothing to read
        unsafe { ConnectNamedPipe(slot.handle, None) };
        let err = unsafe { GetLastError() };
        match err {
            ERROR_PIPE_CONNECTED => {
                slot.connected = true;
            }
            ERROR_PIPE_LISTENING => {
                return Ok(None);
            }
            other => {
                return Err(anyhow!(
                    "read_mailslot: ConnectNamedPipe failed \
                     (Windows error {}: {})",
                    other.0,
                    other.to_hresult().message().to_string_lossy()
                ));
            }
        }
    }

    let mut buffer = vec![0u8; MAX_MSG_SIZE as usize];
    let mut bytes_read: u32 = 0;
    let ok = unsafe {
        ReadFile(
            slot.handle,
            Some(buffer.as_mut_ptr() as *mut c_void),
            MAX_MSG_SIZE,
            Some(&mut bytes_read),
            None,
        )
    };

    if ok.as_bool() {
        let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize])
            .trim_matches(char::from(0))
            .to_owned();
        return Ok(Some(msg));
    }

    let err = unsafe { GetLastError() };
    match err {
        ERROR_NO_DATA => {
            // PIPE_NOWAIT: no message available yet, try again next poll.
            Ok(None)
        }
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => {
            // Client disconnected; reset so the next client can connect.
            unsafe { DisconnectNamedPipe(slot.handle) };
            slot.connected = false;
            // Re-arm immediately so we do not miss a quick reconnect.
            unsafe { ConnectNamedPipe(slot.handle, None) };
            Ok(None)
        }
        other => Err(anyhow!(
            "read_mailslot: ReadFile failed \
             (Windows error {}: {})",
            other.0,
            other.to_hresult().message().to_string_lossy()
        )),
    }
}

/// Write a message to a named pipe server (client / writer side).
///
/// Waits up to `WRITE_WAIT_MS` for the server to be ready, connects,
/// sends the message, and closes the handle.
pub fn write_mailslot(name: &str, message: &str) -> Result<(), anyhow::Error> {
    if message.len() > usize::try_from(MAX_MSG_SIZE).unwrap() {
        log::warn!(
            "write_mailslot: message too long ({} bytes, max {})",
            message.len(),
            MAX_MSG_SIZE
        );
        return Err(anyhow!("write_mailslot: message too long"));
    }

    // Named pipes via \\.\pipe\ are in \Device\NamedPipe\ — a kernel-level
    // global namespace accessible across sessions without SMB.
    let pipe_name: Vec<u16> = OsStr::new(name).encode_wide().chain(once(0)).collect();
    let ppipe_name = PCWSTR::from_raw(pipe_name.as_ptr());

    // Wait for the server instance to become available.
    if !unsafe { WaitNamedPipeW(ppipe_name, WRITE_WAIT_MS) }.as_bool() {
        let err = unsafe { GetLastError() };
        log::warn!(
            "write_mailslot: WaitNamedPipeW timed out for '{}' \
             (Windows error {}: {})",
            name,
            err.0,
            err.to_hresult().message().to_string_lossy()
        );
        return Err(anyhow!(
            "write_mailslot: pipe server not available: '{name}'"
        ));
    }

    let generic_write: u32 = 0x4000_0000; // GENERIC_WRITE
    let handle = unsafe {
        match CreateFileW(
            ppipe_name,
            generic_write,
            FILE_SHARE_MODE(0), // named pipes cannot be shared
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h) => h,
            Err(e) => {
                let os_err = GetLastError();
                log::warn!(
                    "write_mailslot: CreateFileW failed for '{}': {} \
                     (Windows error {}: {})",
                    name,
                    e,
                    os_err.0,
                    os_err.to_hresult().message().to_string_lossy()
                );
                return Err(anyhow!(
                    "write_mailslot: failed to open pipe '{name}': {e}"
                ));
            }
        }
    };

    if handle.is_invalid() {
        let os_err = unsafe { GetLastError() };
        log::warn!(
            "write_mailslot: invalid handle for '{}' \
             (Windows error {}: {})",
            name,
            os_err.0,
            os_err.to_hresult().message().to_string_lossy()
        );
        return Err(anyhow!("write_mailslot: invalid pipe handle for '{name}'"));
    }

    let ok = unsafe { WriteFile(handle, Some(message.as_bytes()), None, None) };
    unsafe { CloseHandle(handle) };

    if !ok.as_bool() {
        let os_err = unsafe { GetLastError() };
        log::warn!(
            "write_mailslot: WriteFile failed for '{}' \
             (Windows error {}: {})",
            name,
            os_err.0,
            os_err.to_hresult().message().to_string_lossy()
        );
        return Err(anyhow!("write_mailslot: WriteFile failed for '{name}'"));
    }

    Ok(())
}
