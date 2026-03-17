// SPDX-License-Identifier: GPL-3.0-only
/*
 * Office document analysis using oletools (olevba, oleobj, rtfobj).
 */

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

/// High-risk olevba indicators (blocking)
const HIGH_RISK_INDICATORS: &[&str] = &[
    "AutoExec",
    "Shell",
    "WScript",
    "Dropper",
    "VBA stomping",
    "Auto_Open",
    "AutoOpen",
    "Document_Open",
    "Workbook_Open",
];

/// Informational olevba indicators (non-blocking, worth reporting)
const INFO_INDICATORS: &[&str] = &[
    "Base64 String",
    "Hex String",
    "Dridex",
    "IOC",
    "Suspicious",
    "CreateObject",
    "Chr(",
    "StrReverse",
];

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("office::analyze: failed to write temp file: {e}");
        return (true, "temp file write failed".to_string());
    }

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;
    let mut tools_run: Vec<&str> = Vec::new();

    // Run olevba --json
    match Command::new("olevba").args(["--json", &tmp_path]).output() {
        Ok(output) => {
            tools_run.push("olevba");
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Check macro presence
            let has_macros = stdout.contains("\"macros\"") && !stdout.contains("\"macros\": []");

            if has_macros {
                for indicator in HIGH_RISK_INDICATORS {
                    if stdout.contains(indicator) {
                        blocking_findings.push(indicator.to_string());
                        passed = false;
                    }
                }
                for indicator in INFO_INDICATORS {
                    if stdout.contains(indicator)
                        && !blocking_findings.contains(&indicator.to_string())
                    {
                        info_findings.push(indicator.to_string());
                    }
                }
                if blocking_findings.is_empty() && info_findings.is_empty() {
                    info_findings.push("macros present (no high-risk indicator)".to_string());
                }
            } else {
                info_findings.push("no macros".to_string());
            }
        }
        Err(e) => {
            log::warn!("olevba not available or failed: {e}");
            info_findings.push("olevba unavailable".to_string());
        }
    }

    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Run oleobj on binary OLE formats
    if matches!(ext.as_str(), "doc" | "xls" | "ppt") {
        match Command::new("oleobj").args(["--json", &tmp_path]).output() {
            Ok(output) => {
                tools_run.push("oleobj");
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("executable") || stdout.contains(".exe") || stdout.contains(".dll") {
                    blocking_findings.push("OLE embedded executable".to_string());
                    passed = false;
                } else if stdout.contains("\"objects\"") && !stdout.contains("\"objects\": []") {
                    info_findings.push("OLE embedded objects (non-executable)".to_string());
                }
            }
            Err(e) => {
                log::warn!("oleobj not available: {e}");
                info_findings.push("oleobj unavailable".to_string());
            }
        }
    }

    // Run rtfobj on RTF files
    if ext == "rtf" {
        match Command::new("rtfobj").args(["--json", &tmp_path]).output() {
            Ok(output) => {
                tools_run.push("rtfobj");
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("executable") || stdout.contains(".exe") || stdout.contains(".dll") {
                    blocking_findings.push("RTF embedded executable".to_string());
                    passed = false;
                } else if stdout.contains("\"objects\"") && !stdout.contains("\"objects\": []") {
                    info_findings.push("RTF embedded objects (non-executable)".to_string());
                }
            }
            Err(e) => {
                log::warn!("rtfobj not available: {e}");
                info_findings.push("rtfobj unavailable".to_string());
            }
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    // Build summary: blocking findings first, then informational
    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

/// Build a human-readable summary from blocking and informational findings.
fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no findings".to_string(),
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
