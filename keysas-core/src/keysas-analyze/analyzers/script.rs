// SPDX-License-Identifier: GPL-3.0-only
/*
 * Script analysis using static regex pattern matching (no execution).
 */

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

/// Patterns per script type: (pattern, is_blocking)
const PS1_PATTERNS: &[(&str, bool)] = &[
    ("Invoke-Expression", true),
    ("IEX", true),
    ("DownloadString", true),
    ("-EncodedCommand", true),
    ("Start-Process", false),
    ("bypass", true),
    ("AMSI", true),
    ("FromBase64String", true),
    ("Reflection.Assembly", true),
    ("System.Net.WebClient", false),
];

const JS_HTA_PATTERNS: &[(&str, bool)] = &[
    ("eval(", true),
    ("unescape(", true),
    ("ActiveXObject", true),
    ("WScript.Shell", true),
    ("XMLHttpRequest", false),
    ("document.write(unescape", true),
    ("String.fromCharCode", false),
];

const VBS_PATTERNS: &[(&str, bool)] = &[
    ("CreateObject", false),
    ("Shell", true),
    ("WScript.Shell", true),
    ("Execute", true),
    ("Eval", true),
    ("Chr(", false),
    ("StrReverse", false),
];

const PY_SH_PATTERNS: &[(&str, bool)] = &[
    ("subprocess", false),
    ("os.system", true),
    ("exec(", true),
    ("base64.decode", false),
    ("base64.b64decode", false),
    ("urllib.request", false),
    ("curl ", false),
    ("wget ", false),
    ("__import__", true),
];

const JNLP_PATTERNS: &[(&str, bool)] = &[
    ("<jar ", false),
    ("<extension ", false),
    ("http://", true),   // jar over non-https is high risk
];

pub fn analyze(fd: i32, filename: &str) -> (bool, String) {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        log::warn!("script::analyze: dup failed");
        return (true, String::new());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut file = unsafe { File::from_raw_fd(dup_fd) };
    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        log::warn!("script::analyze: cannot read file: {e}");
        return (true, String::new());
    }

    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let patterns: &[(&str, bool)] = match ext.as_str() {
        "ps1" | "bat" => PS1_PATTERNS,
        "js" | "hta" => JS_HTA_PATTERNS,
        "vbs" | "vbe" => VBS_PATTERNS,
        "py" | "sh" => PY_SH_PATTERNS,
        "jnlp" => JNLP_PATTERNS,
        _ => return (true, String::new()),
    };

    let mut findings = Vec::new();
    let mut passed = true;

    for (pattern, blocking) in patterns {
        if content.contains(pattern) {
            findings.push(pattern.to_string());
            if *blocking {
                passed = false;
            }
        }
    }

    let summary = findings.join("; ");
    (passed, summary)
}
