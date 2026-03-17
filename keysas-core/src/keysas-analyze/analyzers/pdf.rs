// SPDX-License-Identifier: GPL-3.0-only
/*
 * PDF analysis using peepdf.
 */

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;

/// Blocking patterns: presence means the PDF can execute code or exfiltrate data
const BLOCKING_PATTERNS: &[&str] = &[
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/Launch",
    "/RichMedia",
    "/XFA",
    "shellcode",
];

/// Informational patterns: suspicious but not blocking alone
const INFO_PATTERNS: &[&str] = &[
    "/AA",
    "/EmbeddedFile",
    "/AcroForm",
    "/Encrypt",
    "/URI",
    "/SubmitForm",
];

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("pdf::analyze: failed to write temp file: {e}");
        return (true, "temp file write failed".to_string());
    }

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;
    let mut tool_available = false;

    match Command::new("peepdf").args(["-j", &tmp_path]).output() {
        Ok(output) => {
            tool_available = true;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if !stderr.is_empty() {
                log::debug!("peepdf stderr: {stderr}");
            }

            for pattern in BLOCKING_PATTERNS {
                if stdout.contains(pattern) {
                    blocking_findings.push((*pattern).to_string());
                    passed = false;
                }
            }
            for pattern in INFO_PATTERNS {
                if stdout.contains(pattern) && !blocking_findings.contains(&pattern.to_string()) {
                    info_findings.push((*pattern).to_string());
                }
            }

            // Report page count and version count if extractable
            if let Some(pages) = extract_pdf_stat(&stdout, "\"pages\"") {
                info_findings.push(format!("{pages} page(s)"));
            }
            if let Some(versions) = extract_pdf_stat(&stdout, "\"versions\"") {
                if versions > 1 {
                    info_findings.push(format!("{versions} PDF version(s)"));
                }
            }
        }
        Err(e) => {
            log::warn!("peepdf not available or failed: {e}");
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    let summary = if !tool_available {
        "peepdf unavailable - analysis skipped".to_string()
    } else {
        build_summary(&blocking_findings, &info_findings)
    };

    (passed, summary)
}

/// Extract a numeric value from a JSON-like key in peepdf output.
/// e.g. `"pages": 3` → Some(3)
fn extract_pdf_stat(text: &str, key: &str) -> Option<u64> {
    let pos = text.find(key)?;
    let after = text[pos + key.len()..].trim_start_matches([' ', ':']);
    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
    after[..end].parse().ok()
}

/// Build a human-readable summary.
fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no suspicious objects".to_string(),
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
