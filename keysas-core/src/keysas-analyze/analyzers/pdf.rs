// SPDX-License-Identifier: GPL-3.0-only
/*
 * PDF analysis using peepdf.
 */

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;

const HIGH_RISK_PATTERNS: &[&str] = &[
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/RichMedia",
    "shellcode",
    "/XFA",
];

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("pdf::analyze: failed to write temp file: {e}");
        return (true, String::new());
    }

    let mut findings = Vec::new();
    let mut passed = true;

    match Command::new("peepdf")
        .args(["-j", &tmp_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for pattern in HIGH_RISK_PATTERNS {
                if stdout.contains(pattern) {
                    findings.push(pattern.to_string());
                    passed = false;
                }
            }
            // Encryption alone is only suspicious
            if stdout.contains("/Encrypt") && findings.is_empty() {
                findings.push("/Encrypt (encrypted PDF)".to_string());
                // Don't set passed=false for encryption alone
            }
        }
        Err(e) => {
            log::warn!("peepdf not available or failed: {e}");
        }
    }

    let _ = std::fs::remove_file(&tmp_path);

    let summary = findings.join("; ");
    (passed, summary)
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
