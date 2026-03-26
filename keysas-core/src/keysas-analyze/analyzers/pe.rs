// SPDX-License-Identifier: GPL-3.0-only
/*
 * PE/executable analysis — native Rust using goblin.
 * Detects known packers (section names + high entropy),
 * and suspicious imports from the PE import table.
 */

use std::fs::File;
use std::io::Read;

/// Known packer section name prefixes (case-insensitive).
const PACKER_SECTIONS: &[&str] = &[
    "upx",      // UPX
    ".themida", // Themida / WinLicense
    ".winlicen",
    ".mpress",   // MPRESS
    ".aspack",   // ASPack
    ".nsp",      // NsPack
    ".obsidium", // Obsidium
    "armadillo",
    ".enigma",
];

/// Suspicious imports: present in many malware families, informational only.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "URLDownloadToFile",
    "WinExec",
    "RegSetValueEx",
    "ShellExecuteA",
    "ShellExecuteW",
    "LoadLibraryA",
    "GetProcAddress",
];

pub fn analyze(fd: i32, filename: &str, _tmp_dir: &str) -> (bool, String) {
    let buf = match read_fd(fd) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("pe::analyze: cannot read fd: {e}");
            return (true, "read error - analysis skipped".to_string());
        }
    };

    let pe = match goblin::pe::PE::parse(&buf) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("pe::analyze: goblin parse error for {filename}: {e}");
            return (true, "PE parse error - analysis skipped".to_string());
        }
    };

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    // --- Section analysis ---
    for section in &pe.sections {
        let name_raw = std::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_lowercase();

        // Known packer section names
        for packer in PACKER_SECTIONS {
            if name_raw.starts_with(packer) {
                blocking_findings.push(format!("packer section: {name_raw}"));
                passed = false;
            }
        }

        // Entropy of section raw data
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start < buf.len() {
            let end = (start + size).min(buf.len());
            let section_data = &buf[start..end];
            let ent = entropy(section_data);
            if ent > 7.2 {
                blocking_findings.push(format!("high entropy section '{name_raw}' ({ent:.2})"));
                passed = false;
            } else if ent > 6.5 {
                info_findings.push(format!("elevated entropy '{name_raw}' ({ent:.2})"));
            }
        }
    }

    // --- Import table ---
    let mut suspicious_found: Vec<String> = Vec::new();
    for import in &pe.imports {
        for &api in SUSPICIOUS_IMPORTS {
            if import.name.eq_ignore_ascii_case(api) {
                suspicious_found.push(api.to_string());
            }
        }
    }
    if !suspicious_found.is_empty() {
        info_findings.push(format!(
            "suspicious imports: {}",
            suspicious_found.join(", ")
        ));
    }

    // Architecture / bitness for context
    let arch = if pe.is_64 { "PE64" } else { "PE32" };
    info_findings.push(arch.to_string());

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

/// Shannon entropy of a byte slice (0.0 – 8.0).
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no packer or suspicious imports".to_string(),
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
