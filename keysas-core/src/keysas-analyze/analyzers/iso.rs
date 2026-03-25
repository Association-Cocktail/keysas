// SPDX-License-Identifier: GPL-3.0-only
/*
 * ISO 9660 content scanner — native Rust, no external crate.
 *
 * Walks the directory tree of an ISO image and flags dangerous file types:
 *   - Executables (.exe, .dll, .msi, .com, .scr, .efi)
 *   - Scripts     (.ps1, .bat, .cmd, .vbs, .js, .hta, .wsf)
 *   - Installers  (.inf, .reg)
 *
 * The file data inside the ISO is never read — only directory metadata.
 */

use std::fs::File;
use std::io::Read;

const SECTOR_SIZE: usize = 2048;
const PVD_SECTOR: usize = 16;
const MAX_DEPTH: usize = 8;
const MAX_FILES: usize = 4096;

const EXECUTABLE_EXTS: &[&str] = &[
    "exe", "dll", "msi", "com", "scr", "efi", "sys", "ocx",
];
const SCRIPT_EXTS: &[&str] = &[
    "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "wsf", "wsh",
];
const INSTALLER_EXTS: &[&str] = &["inf", "reg"];

pub fn analyze(fd: i32, _filename: &str, _tmp_dir: &str) -> (bool, String) {
    let buf = match read_fd(fd) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("iso::analyze: cannot read fd: {e}");
            return (true, "read error - analysis skipped".to_string());
        }
    };

    let pvd_offset = PVD_SECTOR * SECTOR_SIZE;
    if buf.len() < pvd_offset + 190 {
        return (true, "too small to be a valid ISO".to_string());
    }

    let pvd = &buf[pvd_offset..];
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        return (true, "not a valid ISO 9660 image".to_string());
    }

    // Root directory record is embedded in the PVD at offset 156 (33 bytes).
    let root_lba = read_u32_le(pvd, 158) as usize; // little-endian at +2 inside the record
    let root_size = read_u32_le(pvd, 166) as usize; // little-endian at +10

    let mut files: Vec<String> = Vec::new();
    walk_dir(&buf, root_lba, root_size, "", &mut files, 0);

    let total = files.len();
    let mut executables: Vec<String> = Vec::new();
    let mut scripts: Vec<String> = Vec::new();
    let mut installers: Vec<String> = Vec::new();

    for f in &files {
        let ext = f.rsplit('.').next().unwrap_or("").to_lowercase();
        if EXECUTABLE_EXTS.contains(&ext.as_str()) {
            executables.push(f.clone());
        } else if SCRIPT_EXTS.contains(&ext.as_str()) {
            scripts.push(f.clone());
        } else if INSTALLER_EXTS.contains(&ext.as_str()) {
            installers.push(f.clone());
        }
    }

    let mut blocking: Vec<String> = Vec::new();
    let mut info: Vec<String> = Vec::new();
    let mut passed = true;

    if !executables.is_empty() {
        blocking.push(format!(
            "{} executable(s): {}",
            executables.len(),
            executables[..executables.len().min(3)].join(", ")
        ));
        passed = false;
    }
    if !scripts.is_empty() {
        blocking.push(format!(
            "{} script(s): {}",
            scripts.len(),
            scripts[..scripts.len().min(3)].join(", ")
        ));
        passed = false;
    }
    if !installers.is_empty() {
        info.push(format!("{} installer file(s)", installers.len()));
    }

    info.push(format!("{total} file(s) in ISO"));

    let summary = build_summary(&blocking, &info);
    (passed, summary)
}

/// Recursively walk an ISO 9660 directory.
fn walk_dir(
    buf: &[u8],
    lba: usize,
    size: usize,
    prefix: &str,
    files: &mut Vec<String>,
    depth: usize,
) {
    if depth > MAX_DEPTH || files.len() >= MAX_FILES {
        return;
    }

    let offset = lba * SECTOR_SIZE;
    if offset >= buf.len() {
        return;
    }
    let end = (offset + size).min(buf.len());
    let dir_data = &buf[offset..end];

    let mut pos = 0;
    while pos < dir_data.len() {
        let record_len = dir_data[pos] as usize;
        if record_len == 0 {
            // Pad to next sector boundary
            let next = ((pos / SECTOR_SIZE) + 1) * SECTOR_SIZE;
            if next >= dir_data.len() {
                break;
            }
            pos = next;
            continue;
        }
        if pos + record_len > dir_data.len() || record_len < 34 {
            break;
        }

        let record = &dir_data[pos..pos + record_len];
        let flags = record[25];
        let is_dir = (flags & 0x02) != 0;
        let name_len = record[32] as usize;

        if 33 + name_len > record_len {
            pos += record_len;
            continue;
        }

        let name_raw = &record[33..33 + name_len];

        // Skip current-dir (0x00) and parent-dir (0x01) entries
        if name_raw == b"\x00" || name_raw == b"\x01" {
            pos += record_len;
            continue;
        }

        // Strip ISO version suffix ";1"
        let name = String::from_utf8_lossy(name_raw)
            .split(';')
            .next()
            .unwrap_or("")
            .to_lowercase();

        let full_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if is_dir {
            let child_lba = read_u32_le(record, 2) as usize;
            let child_size = read_u32_le(record, 10) as usize;
            walk_dir(buf, child_lba, child_size, &full_path, files, depth + 1);
        } else {
            files.push(full_path);
        }

        pos += record_len;
    }
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    if offset + 4 > buf.len() {
        return 0;
    }
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no dangerous content".to_string(),
        (true, false) => format!("info: {}", info.join("; ")),
        (false, true) => format!("ALERT: {}", blocking.join("; ")),
        (false, false) => format!("ALERT: {}; info: {}", blocking.join("; "), info.join("; ")),
    }
}

fn read_fd(fd: i32) -> std::io::Result<Vec<u8>> {
    use std::os::unix::io::FromRawFd;
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut src = unsafe { File::from_raw_fd(dup_fd) };
    let mut buf = Vec::new();
    src.read_to_end(&mut buf)?;
    Ok(buf)
}
