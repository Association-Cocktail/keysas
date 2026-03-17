// SPDX-License-Identifier: GPL-3.0-only
/*
 * PDF analysis using pdfid (Didier Stevens).
 * pdfid text output: one keyword per line, format: " /Keyword    N"
 */

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;

/// Blocking keywords: if count > 0 the PDF can execute code or exfiltrate data
const BLOCKING_KEYWORDS: &[&str] = &[
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/Launch",
    "/RichMedia",
    "/XFA",
    "/JBIG2Decode",
];

/// Informational keywords: suspicious but not blocking alone
const INFO_KEYWORDS: &[&str] = &[
    "/AA",
    "/EmbeddedFile",
    "/AcroForm",
    "/Encrypt",
    "/ObjStm",
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

    // pdfid text output: lines like " /JavaScript    1"
    match Command::new("pdfid").arg(&tmp_path).output() {
        Ok(output) => {
            tool_available = true;
            let stdout = String::from_utf8_lossy(&output.stdout);

            let counts = parse_pdfid_output(&stdout);

            for kw in BLOCKING_KEYWORDS {
                if counts.get(*kw).copied().unwrap_or(0) > 0 {
                    blocking_findings.push((*kw).to_string());
                    passed = false;
                }
            }
            for kw in INFO_KEYWORDS {
                if counts.get(*kw).copied().unwrap_or(0) > 0 {
                    info_findings.push((*kw).to_string());
                }
            }

            // Report /Page count for context
            if let Some(&pages) = counts.get("/Page") {
                if pages > 0 {
                    info_findings.push(format!("{pages} page(s)"));
                }
            }
        }
        Err(e) => {
            log::warn!("pdfid not available or failed: {e}");
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    let summary = if !tool_available {
        "pdfid unavailable - analysis skipped".to_string()
    } else {
        build_summary(&blocking_findings, &info_findings)
    };

    (passed, summary)
}

/// Parse pdfid text output into a map of keyword → count.
/// Each relevant line looks like: " /JavaScript    1"
fn parse_pdfid_output(text: &str) -> std::collections::HashMap<&str, u64> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(slash_pos) = trimmed.find('/') {
            let rest = &trimmed[slash_pos..];
            // split on whitespace: keyword then count
            let mut parts = rest.split_whitespace();
            if let (Some(kw), Some(count_str)) = (parts.next(), parts.next()) {
                if let Ok(n) = count_str.parse::<u64>() {
                    map.insert(kw, n);
                }
            }
        }
    }
    map
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
