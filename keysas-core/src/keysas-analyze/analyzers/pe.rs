// SPDX-License-Identifier: GPL-3.0-only
/*
 * PE/executable analysis using diec (Detect-It-Easy) + strings.
 */

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;

const KNOWN_PACKERS: &[&str] = &[
    "UPX", "Themida", "VMProtect", "Enigma", "ASPack", "PECompact",
    "Obsidium", "Armadillo", "MPRESS", "NsPack",
];

const SUSPICIOUS_STRINGS: &[&str] = &[
    "cmd.exe", "powershell", "WScript.Shell", "CreateRemoteThread",
    "VirtualAlloc", "WriteProcessMemory", "ShellExecute", "URLDownloadToFile",
    "WinExec", "CreateProcessA", "RegSetValue", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
];

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/analyze_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("pe::analyze: failed to write temp file: {e}");
        return (true, String::new());
    }

    let mut findings = Vec::new();
    let mut passed = true;

    // Run diec (Detect-It-Easy CLI)
    match Command::new("diec")
        .args(["--json", &tmp_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for packer in KNOWN_PACKERS {
                if stdout.to_lowercase().contains(&packer.to_lowercase()) {
                    findings.push(format!("Packer: {packer}"));
                    passed = false;
                }
            }
            if stdout.contains("\"entropy\"") {
                // High entropy suggests packing/encryption
                if let Some(start) = stdout.find("\"entropy\":") {
                    let rest = &stdout[start + 10..];
                    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
                    if let Ok(entropy) = rest[..end].trim().parse::<f64>() {
                        if entropy > 7.0 {
                            findings.push(format!("High entropy: {entropy:.2}"));
                            passed = false;
                        }
                    }
                }
            }
        }
        Err(e) => {
            log::warn!("diec not available: {e}");
        }
    }

    // Run strings
    match Command::new("strings")
        .args(["-n", "6", &tmp_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for s in SUSPICIOUS_STRINGS {
                if stdout.contains(s) {
                    findings.push(format!("String: {s}"));
                    // Suspicious strings are warnings but not blocking alone
                }
            }
        }
        Err(e) => {
            log::warn!("strings not available: {e}");
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
