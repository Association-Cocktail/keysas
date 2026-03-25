// SPDX-License-Identifier: GPL-3.0-only
/*
 * PDF analysis — native Rust keyword scanner.
 * PDF keywords are ASCII tokens embedded in the raw file bytes,
 * so no external tool or crate is needed.
 */

use std::fs::File;
use std::io::Read;

/// Blocking keywords: presence means the PDF can execute code or exfiltrate data.
const BLOCKING_KEYWORDS: &[&[u8]] = &[
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/Launch",
    b"/RichMedia",
    b"/XFA",
    b"/JBIG2Decode",
];

/// Informational keywords: suspicious but not blocking alone.
const INFO_KEYWORDS: &[&[u8]] = &[
    b"/AA",
    b"/EmbeddedFile",
    b"/AcroForm",
    b"/Encrypt",
    b"/ObjStm",
];

pub fn analyze(fd: i32, _filename: &str, _tmp_dir: &str) -> (bool, String) {
    let buf = match read_fd(fd) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("pdf::analyze: cannot read fd: {e}");
            return (true, "read error - analysis skipped".to_string());
        }
    };

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    for &kw in BLOCKING_KEYWORDS {
        if count_occurrences(&buf, kw) > 0 {
            blocking_findings.push(String::from_utf8_lossy(kw).to_string());
            passed = false;
        }
    }
    for &kw in INFO_KEYWORDS {
        if count_occurrences(&buf, kw) > 0 {
            info_findings.push(String::from_utf8_lossy(kw).to_string());
        }
    }

    // Count pages for context
    let pages = count_occurrences(&buf, b"/Page");
    if pages > 0 {
        info_findings.push(format!("~{pages} /Page object(s)"));
    }

    let summary = build_summary(&blocking_findings, &info_findings);
    (passed, summary)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = haystack[start..].windows(needle.len()).position(|w| w == needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

fn build_summary(blocking: &[String], info: &[String]) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => "no suspicious objects".to_string(),
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
