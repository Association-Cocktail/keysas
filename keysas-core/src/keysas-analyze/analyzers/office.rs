// SPDX-License-Identifier: GPL-3.0-only
/*
 * Office document analysis — native Rust, no external tools.
 *
 * OOXML (.docx/.xlsx/.pptx): ZIP-based; detect vbaProject.bin, scan XML.
 * OLE  (.doc/.xls/.ppt/.rtf): CFB parser (cfb crate) + byte scan for VBA.
 * RTF: byte scan for \object / \objocx.
 */

use std::fs::File;
use std::io::{Cursor, Read};

/// VBA patterns blocking when found in macro code or stream bytes.
const HIGH_RISK_PATTERNS: &[&[u8]] = &[
    b"AutoExec",
    b"AutoOpen",
    b"Auto_Open",
    b"Document_Open",
    b"Workbook_Open",
    b"Shell",
    b"WScript",
    b"CreateObject",
    b"VBA stomping",
];

/// Informational patterns — suspicious but not blocking alone.
const INFO_PATTERNS: &[&[u8]] = &[
    b"Base64",
    b"StrReverse",
    b"Chr(",
    b"Hex(",
    b"URLDownloadToFile",
    b"WinExec",
    b"CreateRemoteThread",
];

pub fn analyze(fd: i32, filename: &str, _tmp_dir: &str) -> (bool, String) {
    let buf = match read_fd(fd) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("office::analyze: cannot read fd: {e}");
            return (true, "read error - analysis skipped".to_string());
        }
    };

    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "docx" | "xlsx" | "pptx" => analyze_ooxml(&buf),
        "doc" | "xls" | "ppt" => analyze_ole(&buf),
        "rtf" => analyze_rtf(&buf),
        _ => (true, "unsupported office format".to_string()),
    }
}

// ---------------------------------------------------------------------------
// OOXML (.docx / .xlsx / .pptx)
// ---------------------------------------------------------------------------

fn analyze_ooxml(buf: &[u8]) -> (bool, String) {
    let cursor = Cursor::new(buf);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            log::warn!("office::ooxml: ZIP parse error: {e}");
            return (true, "ZIP parse error - analysis skipped".to_string());
        }
    };

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    // Detect VBA project (macros)
    let has_vba = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .ok()
            .map(|f| f.name().to_lowercase().ends_with("vbaproject.bin"))
            .unwrap_or(false)
    });

    if has_vba {
        // Scan the raw vbaProject.bin bytes for high-risk patterns
        // (many VBA strings are stored uncompressed or partially readable)
        for i in 0..archive.len() {
            if let Ok(mut entry) = archive.by_index(i) {
                if entry.name().to_lowercase().ends_with("vbaproject.bin") {
                    let mut vba_bytes = Vec::new();
                    if entry.read_to_end(&mut vba_bytes).is_ok() {
                        let (block, info) = scan_patterns(&vba_bytes);
                        blocking_findings.extend(block);
                        info_findings.extend(info);
                    }
                    break;
                }
            }
        }
        if blocking_findings.is_empty() {
            info_findings.push("VBA macros present (no high-risk pattern detected)".to_string());
        } else {
            passed = false;
        }
    } else {
        info_findings.push("no macros".to_string());
    }

    // Scan relationship files for suspicious external targets
    for i in 0..archive.len() {
        if let Ok(mut entry) = archive.by_index(i) {
            let name = entry.name().to_lowercase();
            if name.ends_with(".rels") {
                let mut xml = String::new();
                if entry.read_to_string(&mut xml).is_ok() {
                    if xml.contains("http://") || xml.contains("https://") || xml.contains("ftp://") {
                        info_findings.push("external relationship target".to_string());
                    }
                    // Embedded OLE objects in OOXML
                    if xml.contains("oleObject") {
                        info_findings.push("embedded OLE object".to_string());
                    }
                }
            }
        }
    }

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

// ---------------------------------------------------------------------------
// OLE/CFB (.doc / .xls / .ppt)
// ---------------------------------------------------------------------------

fn analyze_ole(buf: &[u8]) -> (bool, String) {
    let cursor = Cursor::new(buf);
    let mut cfb = match cfb::CompoundFile::open(cursor) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("office::ole: CFB parse error: {e}");
            return (true, "CFB parse error - analysis skipped".to_string());
        }
    };

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    // Walk all entries and check for VBA storage
    let entries: Vec<String> = cfb
        .walk()
        .map(|e| e.path().to_string_lossy().to_lowercase())
        .collect();

    let has_vba = entries.iter().any(|p| p.contains("vba"));
    let has_macros = entries.iter().any(|p| p.contains("macro") || p.contains("module"));

    if has_vba || has_macros {
        // Try to scan VBA module streams for patterns
        // VBA streams: Module1, Module2, ThisDocument, Sheet1, etc.
        let module_paths: Vec<String> = entries
            .iter()
            .filter(|p| {
                p.contains("/vba/") && !p.ends_with('/') && !p.ends_with("_vba_project")
            })
            .cloned()
            .collect();

        for path in &module_paths {
            let p = std::path::Path::new(path);
            if let Ok(mut stream) = cfb.open_stream(p) {
                let mut bytes = Vec::new();
                if stream.read_to_end(&mut bytes).is_ok() {
                    let (block, info) = scan_patterns(&bytes);
                    blocking_findings.extend(block);
                    info_findings.extend(info);
                }
            }
        }

        if blocking_findings.is_empty() {
            info_findings.push("VBA macros present (no high-risk pattern detected)".to_string());
        } else {
            passed = false;
        }
    } else {
        info_findings.push("no macros".to_string());
    }

    // Check for embedded OLE objects (Equation Editor, OLE links)
    if entries.iter().any(|p| p.contains("equation") || p.contains("olestream")) {
        info_findings.push("embedded OLE object".to_string());
    }

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

// ---------------------------------------------------------------------------
// RTF
// ---------------------------------------------------------------------------

fn analyze_rtf(buf: &[u8]) -> (bool, String) {
    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    // Suspicious RTF constructs
    let rtf_blocking: &[&[u8]] = &[
        b"\\objhtml",
        b"\\objocx",
        b"\\objclass",    // OLE object with class name (exploit delivery)
    ];
    let rtf_info: &[&[u8]] = &[
        b"\\object",       // any embedded object
        b"\\pict",         // picture (can carry shellcode)
        b"\\objdata",      // raw OLE data
    ];

    for &pattern in rtf_blocking {
        if contains(buf, pattern) {
            blocking_findings.push(String::from_utf8_lossy(pattern).to_string());
            passed = false;
        }
    }
    for &pattern in rtf_info {
        if contains(buf, pattern) && !blocking_findings.iter().any(|f| f.contains(&String::from_utf8_lossy(pattern).to_string())) {
            info_findings.push(String::from_utf8_lossy(pattern).to_string());
        }
    }

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scan bytes for HIGH_RISK_PATTERNS and INFO_PATTERNS.
/// Returns (blocking_findings, info_findings).
fn scan_patterns(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut blocking: Vec<String> = Vec::new();
    let mut info: Vec<String> = Vec::new();

    for &pat in HIGH_RISK_PATTERNS {
        if contains(bytes, pat) {
            blocking.push(String::from_utf8_lossy(pat).to_string());
        }
    }
    for &pat in INFO_PATTERNS {
        if contains(bytes, pat) {
            info.push(String::from_utf8_lossy(pat).to_string());
        }
    }
    (blocking, info)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no findings".to_string(),
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
