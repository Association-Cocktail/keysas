// SPDX-License-Identifier: GPL-3.0-only
/*
 * PE/executable analysis using diec (Detect-It-Easy) + strings.
 */

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;

/// Packers that make analysis unreliable — blocking
const BLOCKING_PACKERS: &[&str] = &[
    "UPX", "Themida", "VMProtect", "Enigma", "ASPack", "PECompact",
    "Obsidium", "Armadillo", "MPRESS", "NsPack",
];

/// Suspicious API calls or strings — informational, not blocking alone
const SUSPICIOUS_STRINGS: &[&str] = &[
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "URLDownloadToFile",
    "WinExec",
    "RegSetValue",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "ShellExecuteA",
    "ShellExecuteW",
];

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("pe::analyze: failed to write temp file: {e}");
        return (true, "temp file write failed".to_string());
    }

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;
    let mut diec_available = false;
    let mut strings_available = false;

    // Run diec (Detect-It-Easy CLI)
    match Command::new("diec").args(["--json", &tmp_path]).output() {
        Ok(output) => {
            diec_available = true;
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Detect known packers (blocking)
            for packer in BLOCKING_PACKERS {
                if stdout.to_lowercase().contains(&packer.to_lowercase()) {
                    blocking_findings.push(format!("packer: {packer}"));
                    passed = false;
                }
            }

            // Extract compiler/linker info for context (informational)
            if let Some(compiler) = extract_diec_compiler(&stdout) {
                info_findings.push(format!("compiler: {compiler}"));
            }

            // High entropy = likely packed/encrypted (blocking)
            if let Some(entropy) = extract_entropy(&stdout) {
                if entropy > 7.0 {
                    blocking_findings.push(format!("high entropy ({entropy:.2})"));
                    passed = false;
                } else if entropy > 6.5 {
                    info_findings.push(format!("elevated entropy ({entropy:.2})"));
                }
            }
        }
        Err(e) => {
            log::warn!("diec not available: {e}");
        }
    }

    // Run strings
    match Command::new("strings").args(["-n", "6", &tmp_path]).output() {
        Ok(output) => {
            strings_available = true;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut suspicious_found: Vec<String> = Vec::new();
            for s in SUSPICIOUS_STRINGS {
                if stdout.contains(s) {
                    suspicious_found.push((*s).to_string());
                }
            }
            if !suspicious_found.is_empty() {
                // Suspicious strings are informational only (not blocking alone)
                info_findings.push(format!("suspicious strings: {}", suspicious_found.join(", ")));
            }
        }
        Err(e) => {
            log::warn!("strings not available: {e}");
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    let summary = match (diec_available, strings_available) {
        (false, false) => "diec and strings unavailable - analysis skipped".to_string(),
        (false, true) => {
            let mut s = build_summary(&blocking_findings, &info_findings);
            s.push_str(" (diec unavailable)");
            s
        }
        (true, false) => {
            let mut s = build_summary(&blocking_findings, &info_findings);
            s.push_str(" (strings unavailable)");
            s
        }
        (true, true) => build_summary(&blocking_findings, &info_findings),
    };

    (passed, summary)
}

/// Extract compiler/linker name from diec JSON output.
/// diec outputs something like: `"name": "Microsoft Visual C++"`
fn extract_diec_compiler(json: &str) -> Option<String> {
    // Look for compiler/linker type entries
    for keyword in &["compiler", "linker", "tool"] {
        if let Some(pos) = json.to_lowercase().find(&format!("\"type\": \"{keyword}\"")) {
            // Find the nearest "name" field after this position
            if let Some(name_pos) = json[pos..].find("\"name\": \"") {
                let start = pos + name_pos + 9;
                if let Some(end) = json[start..].find('"') {
                    let name = &json[start..start + end];
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract entropy value from diec JSON output.
fn extract_entropy(text: &str) -> Option<f64> {
    let pos = text.find("\"entropy\":")?;
    let rest = text[pos + 10..].trim_start_matches([' ', '\t']);
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
    rest[..end].trim().parse().ok()
}

/// Build a human-readable summary.
fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no packer or suspicious strings".to_string(),
        (true, false) => format!("info: {}", info.join("; ")),
        (false, true) => format!("ALERT: {}", blocking.join("; ")),
        (false, false) => format!("ALERT: {}; info: {}", blocking.join("; "), info.join("; ")),
    }
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' { c } else { '_' })
        .collect()
}

fn write_fd_to_tmp(fd: i32, path: &str) -> std::io::Result<()> {
    use std::os::unix::io::FromRawFd;
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut src = unsafe { File::from_raw_fd(dup_fd) };
    let mut buf = Vec::new();
    src.read_to_end(&mut buf)?;
    let mut dst = File::create(path)?;
    dst.write_all(&buf)?;
    Ok(())
}
