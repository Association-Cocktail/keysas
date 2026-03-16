// SPDX-License-Identifier: GPL-3.0-only
/*
 * LNK file analysis: binary parsing of Windows Shell Link format.
 * Reference: [MS-SHLLINK] specification.
 */

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

/// Suspicious command-line indicators in LNK targets
const SUSPICIOUS_CMDLINE: &[&str] = &[
    "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "msiexec", "certutil", "bitsadmin", "wmic",
];

/// Suspicious path prefixes for LNK targets
const SUSPICIOUS_PATHS: &[&str] = &[
    "%temp%", "%appdata%", "%localappdata%", "%programdata%",
    "\\temp\\", "\\tmp\\",
];

pub fn analyze(fd: i32, _filename: &str) -> (bool, String) {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        log::warn!("lnk::analyze: dup failed");
        return (true, String::new());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut file = unsafe { File::from_raw_fd(dup_fd) };
    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        log::warn!("lnk::analyze: read error: {e}");
        return (true, String::new());
    }

    // Validate LNK header magic: 4C 00 00 00 (HeaderSize=0x4C)
    if buf.len() < 0x4c || buf[0..4] != [0x4c, 0x00, 0x00, 0x00] {
        return (true, "Not a valid LNK file".to_string());
    }

    // Extract all printable strings from the binary (simple approach)
    let text = extract_strings(&buf);
    let text_lower = text.to_lowercase();

    let mut findings = Vec::new();
    let mut passed = true;

    for cmd in SUSPICIOUS_CMDLINE {
        if text_lower.contains(cmd) {
            findings.push(format!("Suspicious target: {cmd}"));
            passed = false;
        }
    }

    for path in SUSPICIOUS_PATHS {
        if text_lower.contains(path) {
            findings.push(format!("Suspicious path: {path}"));
            passed = false;
        }
    }

    // Check for network share (UNC path \\server\share)
    if text_lower.contains("\\\\") && !text_lower.contains("\\\\localhost") {
        findings.push("Network share target (UNC path)".to_string());
        passed = false;
    }

    let summary = findings.join("; ");
    (passed, summary)
}

/// Extract sequences of printable ASCII characters (min 6 chars)
fn extract_strings(buf: &[u8]) -> String {
    let mut result = String::new();
    let mut current = String::new();
    for &b in buf {
        if b >= 0x20 && b < 0x7f {
            current.push(b as char);
        } else {
            if current.len() >= 6 {
                result.push_str(&current);
                result.push(' ');
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        result.push_str(&current);
    }
    result
}
