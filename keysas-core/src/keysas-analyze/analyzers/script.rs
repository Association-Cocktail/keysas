// SPDX-License-Identifier: GPL-3.0-only
/*
 * Script analysis using static regex pattern matching (no execution).
 */

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

/// Patterns per script type: (pattern, is_blocking, description)
const PS1_PATTERNS: &[(&str, bool, &str)] = &[
    ("Invoke-Expression", true,  "dynamic code execution (IEX)"),
    ("IEX",               true,  "dynamic code execution (IEX)"),
    ("DownloadString",    true,  "downloads and executes remote code"),
    ("-EncodedCommand",   true,  "obfuscated encoded command"),
    ("bypass",            true,  "execution policy bypass"),
    ("AMSI",              true,  "AMSI bypass attempt"),
    ("FromBase64String",  true,  "base64 decoding (obfuscation)"),
    ("Reflection.Assembly", true, "in-memory assembly loading"),
    ("Start-Process",     false, "process execution"),
    ("System.Net.WebClient", false, "network download capability"),
];

const JS_HTA_PATTERNS: &[(&str, bool, &str)] = &[
    ("eval(",                   true,  "dynamic code evaluation"),
    ("unescape(",               true,  "string deobfuscation"),
    ("ActiveXObject",           true,  "ActiveX object (system access)"),
    ("WScript.Shell",           true,  "shell execution via WScript"),
    ("document.write(unescape", true,  "obfuscated DOM injection"),
    ("XMLHttpRequest",          false, "HTTP request"),
    ("String.fromCharCode",     false, "character code obfuscation"),
];

const VBS_PATTERNS: &[(&str, bool, &str)] = &[
    ("WScript.Shell", true,  "shell execution via WScript"),
    ("Execute",       true,  "dynamic code execution"),
    ("Eval",          true,  "dynamic code evaluation"),
    ("Shell",         true,  "shell execution"),
    ("CreateObject",  false, "COM object creation"),
    ("Chr(",          false, "character encoding"),
    ("StrReverse",    false, "string obfuscation"),
];

const PY_SH_PATTERNS: &[(&str, bool, &str)] = &[
    ("os.system",        true,  "OS command execution"),
    ("exec(",            true,  "dynamic code execution"),
    ("__import__",       true,  "dynamic module import"),
    ("subprocess",       false, "subprocess execution"),
    ("base64.b64decode", false, "base64 decoding"),
    ("urllib.request",   false, "network download"),
    ("curl ",            false, "curl invocation"),
    ("wget ",            false, "wget invocation"),
];

const JNLP_PATTERNS: &[(&str, bool, &str)] = &[
    ("http://", true,  "insecure HTTP jar loading"),
    ("<jar ",   false, "JAR dependency"),
    ("<extension ", false, "JNLP extension"),
];

pub fn analyze(fd: i32, filename: &str) -> (bool, String) {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        log::warn!("script::analyze: dup failed");
        return (true, "fd dup failed".to_string());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut file = unsafe { File::from_raw_fd(dup_fd) };
    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        log::warn!("script::analyze: cannot read file: {e}");
        return (true, "file read failed".to_string());
    }

    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let patterns: &[(&str, bool, &str)] = match ext.as_str() {
        "ps1" | "bat" => PS1_PATTERNS,
        "js" | "hta"  => JS_HTA_PATTERNS,
        "vbs" | "vbe" => VBS_PATTERNS,
        "py" | "sh"   => PY_SH_PATTERNS,
        "jnlp"        => JNLP_PATTERNS,
        _             => return (true, "unsupported script type".to_string()),
    };

    let mut blocking_findings: Vec<String> = Vec::new();
    let mut info_findings: Vec<String> = Vec::new();
    let mut passed = true;

    for (pattern, blocking, description) in patterns {
        if content.contains(pattern) {
            if *blocking {
                blocking_findings.push(format!("{pattern} ({description})"));
                passed = false;
            } else {
                info_findings.push(format!("{pattern} ({description})"));
            }
        }
    }

    let summary = build_summary(&blocking_findings, &info_findings, &ext);
    (passed, summary)
}

fn build_summary(blocking: &[String], info: &[String], ext: &str) -> String {
    match (blocking.is_empty(), info.is_empty()) {
        (true, true) => format!("no suspicious patterns in .{ext}"),
        (true, false) => format!("info: {}", info.join("; ")),
        (false, true) => format!("ALERT: {}", blocking.join("; ")),
        (false, false) => format!("ALERT: {}; info: {}", blocking.join("; "), info.join("; ")),
    }
}
