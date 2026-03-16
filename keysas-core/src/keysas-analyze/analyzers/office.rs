// SPDX-License-Identifier: GPL-3.0-only
/*
 * Office document analysis using oletools (olevba, oleobj, rtfobj).
 */

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

/// High-risk olevba indicators
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

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    // Write file to temp path
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("office::analyze: failed to write temp file: {e}");
        return (true, String::new()); // fail-open
    }

    let mut findings = Vec::new();
    let mut passed = true;

    // Run olevba --json
    match Command::new("olevba")
        .args(["--json", &tmp_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                log::debug!("olevba stderr: {stderr}");
            }
            // Parse indicators from JSON output
            let detected = extract_olevba_findings(&stdout);
            for f in &detected {
                if HIGH_RISK_INDICATORS.iter().any(|h| f.contains(h)) {
                    passed = false;
                }
            }
            findings.extend(detected);
        }
        Err(e) => {
            log::warn!("olevba not available or failed: {e}");
        }
    }

    // Also run oleobj if OLE format (not RTF)
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "rtf" {
        match Command::new("rtfobj").args(["--json", &tmp_path]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("executable") || stdout.contains(".exe") || stdout.contains(".dll") {
                    findings.push("RTF embedded executable".to_string());
                    passed = false;
                }
            }
            Err(e) => log::warn!("rtfobj not available: {e}"),
        }
    } else if matches!(ext.as_str(), "doc" | "xls" | "ppt") {
        match Command::new("oleobj").args(["--json", &tmp_path]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("executable") || stdout.contains(".exe") || stdout.contains(".dll") {
                    findings.push("OLE embedded executable".to_string());
                    passed = false;
                }
            }
            Err(e) => log::warn!("oleobj not available: {e}"),
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    let summary = if findings.is_empty() {
        String::new()
    } else {
        findings.join("; ")
    };

    (passed, summary)
}

fn extract_olevba_findings(json: &str) -> Vec<String> {
    let mut findings = Vec::new();
    // olevba JSON contains a "macros" array with "type" and "name" fields
    // Simple string scanning for indicator keywords
    for indicator in HIGH_RISK_INDICATORS {
        if json.contains(indicator) {
            findings.push(indicator.to_string());
        }
    }
    // Additional indicators
    for indicator in &["Base64 String", "Hex String", "Dridex", "IOC", "Suspicious"] {
        if json.contains(indicator) {
            findings.push(indicator.to_string());
        }
    }
    findings
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' { c } else { '_' })
        .collect()
}

fn write_fd_to_tmp(fd: i32, path: &str) -> std::io::Result<()> {
    use std::os::unix::io::FromRawFd;
    // dup so we don't consume the original fd
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
