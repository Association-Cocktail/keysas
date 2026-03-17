// SPDX-License-Identifier: GPL-3.0-only
/*
 * LNK file analysis: binary parsing of Windows Shell Link format.
 * Reference: [MS-SHLLINK] specification.
 */

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

/// Suspicious executables in LNK targets (blocking)
const SUSPICIOUS_CMDLINE: &[&str] = &[
    "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "msiexec", "certutil", "bitsadmin", "wmic",
];

/// Suspicious temp/user-writable paths (blocking)
const SUSPICIOUS_PATHS: &[&str] = &[
    "%temp%", "%appdata%", "%localappdata%", "%programdata%",
    "\\temp\\", "\\tmp\\",
];

pub fn analyze(fd: i32, _filename: &str) -> (bool, String) {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        log::warn!("lnk::analyze: dup failed");
        return (true, "fd dup failed".to_string());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut file = unsafe { File::from_raw_fd(dup_fd) };
    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        log::warn!("lnk::analyze: read error: {e}");
        return (true, "file read failed".to_string());
    }

    // Validate LNK header magic: 4C 00 00 00 (HeaderSize=0x4C)
    if buf.len() < 0x4c || buf[0..4] != [0x4c, 0x00, 0x00, 0x00] {
        return (true, "not a valid LNK file".to_string());
    }

    let text = extract_strings(&buf);
    let text_lower = text.to_lowercase();

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    for cmd in SUSPICIOUS_CMDLINE {
        if text_lower.contains(cmd) {
            blocking_findings.push(format!("target: {cmd}"));
            passed = false;
        }
    }

    for path in SUSPICIOUS_PATHS {
        if text_lower.contains(path) {
            blocking_findings.push(format!("path: {path}"));
            passed = false;
        }
    }

    // UNC path (network share) — blocking unless localhost
    if text_lower.contains("\\\\") && !text_lower.contains("\\\\localhost") {
        blocking_findings.push("network share target (UNC)".to_string());
        passed = false;
    }

    // Extract the apparent target path for context
    if let Some(target) = extract_target_path(&text) {
        info_findings.push(format!("target: {target}"));
    }

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

/// Try to extract a readable target path from the LNK string blob.
/// Looks for the first path-like string starting with a drive letter or UNC prefix.
fn extract_target_path(text: &str) -> Option<String> {
    for word in text.split_whitespace() {
        // Drive letter path: C:\...
        if word.len() > 3 && word.chars().next()?.is_ascii_alphabetic() && word[1..].starts_with(":\\") {
            return Some(word.chars().take(80).collect());
        }
        // UNC path: \\server\...
        if word.starts_with("\\\\") {
            return Some(word.chars().take(80).collect());
        }
    }
    None
}

fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no suspicious target or path".to_string(),
        (true, false) => format!("info: {}", info.join("; ")),
        (false, true) => format!("ALERT: {}", blocking.join("; ")),
        (false, false) => format!("ALERT: {}; info: {}", blocking.join("; "), info.join("; ")),
    }
}

/// Extract sequences of printable ASCII characters (min 6 chars).
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
