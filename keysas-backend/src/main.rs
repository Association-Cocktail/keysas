// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use std::{net::TcpListener, path::Path, thread::spawn};

use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    path_beneath_rules,
};
use nom::IResult;
use nom::bytes::complete::take_until;
use regex::Regex;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tungstenite::{
    Message, accept_hdr,
    handshake::server::{Request, Response},
};

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

extern crate libc;
extern crate regex;

const SAS_IN: &str = "/var/local/in";
const SAS_OUT: &str = "/var/local/out";
const LOCK_IN: &str = "/run/keysas-in";
const LOCK_TRANSIT: &str = "/run/keysas-transit";
const LOCK_OUT: &str = "/run/keysas-out";
const NEVER_SIGNED: &str = "/usr/share/keysas/neversigned";

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalStatus {
    health: Daemons,
    guichetin: GuichetState,
    guichettransit: bool,
    guichetout: GuichetState,
    has_signed_once: bool,
    keypair_generated: bool,
    ip: Vec<String>,
    progress_in: Option<serde_json::Value>,
    progress_transit: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Daemons {
    pub status_in: bool,
    pub status_transit: bool,
    pub status_out: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileStatus {
    pub filename: String,
    pub is_valid: bool,
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// Per-check pass/fail results parsed from the .krp report.
    /// Key = check identifier (hash, size, type, av, yara, specialized, vt).
    /// Absent = check not available (no .krp) or check not performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<std::collections::HashMap<String, bool>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GuichetState {
    pub name: String,
    pub analysing: bool,
    pub files: Vec<FileStatus>,
}

fn landlock_sandbox() -> Result<(), RulesetError> {
    let abi = ABI::V1;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access to /usr, /etc and /dev.
        .add_rules(path_beneath_rules(
            &[
                "/usr", "/etc", "/dev", "/home", "/tmp", "/var", "/run", "/proc",
            ],
            AccessFs::from_read(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => println!("Landlock: Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => println!("Landlock: Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            println!("Landlock: Not sandboxed! Please update your kernel.")
        }
    }
    Ok(())
}

/// Read progress JSON file if it exists
fn read_progress_file(path: &str) -> Option<serde_json::Value> {
    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(value) => Some(value),
            Err(_) => None,
        },
        Err(_) => None,
    }
}

/// List files from the IN directory as FileStatus, handling .ioerror suffix
pub fn list_files_in(directory: &str) -> Result<Vec<FileStatus>> {
    let re = Regex::new(r"^\.")?;
    let mut result = Vec::new();
    for entry in fs::read_dir(directory)?.filter_map(|e| e.ok()) {
        let name = match entry.path().file_name().and_then(|n| n.to_str().map(String::from)) {
            Some(n) => n,
            None => continue,
        };
        if re.is_match(&name) { continue; }
        if name.ends_with(".ioerror") {
            let filename = name[..name.len() - ".ioerror".len()].to_string();
            result.push(FileStatus { filename, is_valid: false, reason: Some("ioerror".to_string()), detail: None, checks: None });
        } else {
            result.push(FileStatus { filename: name, is_valid: true, reason: None, detail: None, checks: None });
        }
    }
    Ok(result)
}

/// List files from the OUT directory as FileStatus, parsing .krp reports for KO files.
///
/// Two cases in OUT:
/// - OK file: data file present, no .krp (KrpMode::FailOnly) or with .krp (KrpMode::Always)
/// - KO file: only a .krp present, no data file (file was blocked, not copied)
pub fn list_files_out(directory: &str) -> Result<Vec<FileStatus>> {
    let re = Regex::new(r"^\.")?;
    let mut data_files: Vec<String> = Vec::new();
    let mut krp_files: Vec<String> = Vec::new();

    for entry in fs::read_dir(directory)?.filter_map(|e| e.ok()) {
        let name = match entry.path().file_name().and_then(|n| n.to_str().map(String::from)) {
            Some(n) => n,
            None => continue,
        };
        if re.is_match(&name) { continue; }
        if name.ends_with(".sha256") { continue; }
        if name.ends_with(".krp") {
            krp_files.push(name);
        } else {
            data_files.push(name);
        }
    }

    let data_set: std::collections::HashSet<&str> = data_files.iter().map(|s| s.as_str()).collect();
    let mut result = Vec::new();

    // Data files: present = passed (look up .krp only if KrpMode::Always wrote one)
    for name in &data_files {
        let krp_path = format!("{}/{}.krp", directory, name);
        let (is_valid, reason, detail, checks) = if std::path::Path::new(&krp_path).exists() {
            parse_krp(&krp_path)
        } else {
            (true, None, None, None)
        };
        result.push(FileStatus { filename: name.clone(), is_valid, reason, detail, checks });
    }

    // .krp-only files: blocked files (data file was not copied to OUT)
    for krp_name in &krp_files {
        let original = krp_name[..krp_name.len() - 4].to_string();
        if data_set.contains(original.as_str()) { continue; } // already handled above
        let krp_path = format!("{}/{}", directory, krp_name);
        let (_, reason, detail, checks) = parse_krp(&krp_path);
        result.push(FileStatus {
            filename: original,
            is_valid: false,
            reason: reason.or(Some("unknown".to_string())),
            detail,
            checks,
        });
    }

    Ok(result)
}

/// Parse a .krp JSON report.
/// Returns `(is_valid, reason_key, detail, checks)` where `checks` maps each
/// check identifier to its pass/fail result (true = passed).
fn parse_krp(krp_path: &str) -> (bool, Option<String>, Option<String>, Option<std::collections::HashMap<String, bool>>) {
    let content = match fs::read_to_string(krp_path) {
        Ok(c) => c,
        Err(_) => return (true, None, None, None),
    };
    let v: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return (true, None, None, None),
    };
    let meta = &v["metadata"];
    let report = &meta["report"];
    let is_valid = meta["is_valid"].as_bool().unwrap_or(true);

    // Build per-check map
    let mut checks = std::collections::HashMap::new();

    let av_ok = report["av"].as_array().map(|a| a.is_empty()).unwrap_or(true);
    checks.insert("av".to_string(), av_ok);

    let yara_ok = report["yara"].as_str().unwrap_or("").is_empty();
    checks.insert("yara".to_string(), yara_ok);

    checks.insert("type".to_string(), report["type_allowed"].as_bool().unwrap_or(true));
    checks.insert("size".to_string(), !report["toobig"].as_bool().unwrap_or(false));

    let digest_ok = report["is_digest_ok"].as_bool().unwrap_or(true);
    let not_corrupted = !report["corrupted"].as_bool().unwrap_or(false);
    checks.insert("hash".to_string(), digest_ok && not_corrupted);

    // Specialized — only if actually performed
    let analyzer = report["specialized_analyzer"].as_str().unwrap_or("");
    if !analyzer.is_empty() || report["specialized_pass"].as_bool() == Some(false) {
        checks.insert("specialized".to_string(), report["specialized_pass"].as_bool().unwrap_or(true));
    }

    // VirusTotal — only if a lookup was actually done (non-empty summary)
    let vt_summary = report["vt_summary"].as_str().unwrap_or("");
    if !vt_summary.is_empty() {
        checks.insert("vt".to_string(), report["vt_pass"].as_bool().unwrap_or(true));
    }

    if is_valid {
        return (true, None, None, Some(checks));
    }

    // Primary failure reason
    if !not_corrupted {
        return (false, Some("corrupted".to_string()), None, Some(checks));
    }
    if report["toobig"].as_bool() == Some(true) {
        return (false, Some("toobig".to_string()), None, Some(checks));
    }
    if !digest_ok {
        return (false, Some("digest".to_string()), None, Some(checks));
    }
    if report["type_allowed"].as_bool() == Some(false) {
        let detail = meta["file_type"].as_str().filter(|s| !s.is_empty()).map(String::from);
        return (false, Some("forbidden".to_string()), detail, Some(checks));
    }
    if !av_ok {
        let detail = report["av"].as_array()
            .and_then(|a| a.first())
            .and_then(|s| s.as_str())
            .map(String::from);
        return (false, Some("antivirus".to_string()), detail, Some(checks));
    }
    if !yara_ok {
        let detail = Some(report["yara"].as_str().unwrap_or("").chars().take(80).collect());
        return (false, Some("yara".to_string()), detail, Some(checks));
    }
    if report["specialized_pass"].as_bool() == Some(false) {
        let detail = report["specialized_summary"].as_str().filter(|s| !s.is_empty()).map(String::from);
        return (false, Some("specialized".to_string()), detail, Some(checks));
    }
    if report["vt_pass"].as_bool() == Some(false) {
        let detail = report["vt_summary"].as_str().filter(|s| !s.is_empty()).map(String::from);
        return (false, Some("virustotal".to_string()), detail, Some(checks));
    }
    (false, Some("digest".to_string()), None, Some(checks))
}

pub fn daemon_status() -> Result<[bool; 3]> {
    let mut state: [bool; 3] = [true, true, true];

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-in.service")
        .output()
        .expect("failed to get status for keysas-in");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    state[0] = re.is_match(&status_in);

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-transit.service")
        .output()
        .expect("failed to get status for keysas-transit");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    state[1] = re.is_match(&status_in);

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-out.service")
        .output()
        .expect("failed to get status for keysas-out");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    state[2] = re.is_match(&status_in);

    Ok(state)
}

fn parse_ip(s: &str) -> IResult<&str, &str> {
    take_until(":")(s)
}

fn get_ip() -> Result<Vec<String>> {
    let mut ips = Vec::new();
    let addrs = nix::ifaddrs::getifaddrs()?;
    // Exclude loopback and virtual/internal interfaces; keep all physical/virtual ethernet
    let exclude = Regex::new(r"^(lo|docker|virbr|veth|tun|tap)")?;
    for ifaddr in addrs {
        if let Some(address) = ifaddr.address {
            let addr = address.to_string();
            let (_, ip) = parse_ip(&addr).unwrap();
            if !exclude.is_match(&ifaddr.interface_name) && ip.parse::<Ipv4Addr>().is_ok() {
                ips.push(ip.to_string());
            }
        }
    }
    Ok(ips)
}

fn main() -> Result<()> {
    landlock_sandbox()?;
    let server = TcpListener::bind("127.0.0.1:3012")?;
    for stream in server.incoming() {
        println!("keysas-backend: Received a new websocket handshake.");
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept client connection: {e}");
                continue;
            }
        };
        spawn(move || -> Result<()> {
            let callback = |_req: &Request, response: Response| {
                log::info!("keysas-backend: Received a new websocket handshake.");
                //let headers = response.headers_mut();
                //headers.append("Sec-WebSocket-Protocol", "websocket".parse().unwrap());
                //println!("Response: {response:?}");
                Ok(response)
            };
            let mut websocket = accept_hdr(stream, callback)?;

            loop {
                let files_in = list_files_in(SAS_IN);
                let files_out = list_files_out(SAS_OUT);

                let mut fs_in = PathBuf::new();
                fs_in.push(SAS_IN);
                let is_empty_fs_in = fs_in.read_dir()?.next().is_none();

                let working_out = Path::new(LOCK_OUT).exists();

                let daemon_states = daemon_status()?;
                let health: Daemons = Daemons {
                    status_in: daemon_states[0],
                    status_transit: daemon_states[1],
                    status_out: daemon_states[2],
                };

                // Read progress files - only send when actively processing
                let progress_in = read_progress_file("/run/keysas-in/progress.json")
                    .filter(|v| v.get("is_processing").and_then(|b| b.as_bool()).unwrap_or(false));
                let progress_transit = read_progress_file("/run/keysas-transit/progress.json")
                    .filter(|v| v.get("is_processing").and_then(|b| b.as_bool()).unwrap_or(false));

                let working_in = progress_in.is_some() || !is_empty_fs_in;
                let working_transit = progress_transit.is_some();

                let guichet_state_in: GuichetState = GuichetState {
                    name: String::from("GUICHET-IN"),
                    analysing: working_in,
                    files: files_in?,
                };
                let guichet_state_out: GuichetState = GuichetState {
                    name: String::from("GUICHET-OUT"),
                    analysing: working_out,
                    files: files_out?,
                };
                let mut has_signed = false;

                if !Path::new(NEVER_SIGNED).exists() {
                    has_signed = true;
                }

                let orders = GlobalStatus {
                    health,
                    guichetin: guichet_state_in,
                    guichettransit: working_transit,
                    guichetout: guichet_state_out,
                    has_signed_once: has_signed,
                    keypair_generated: Path::new("/etc/keysas/file-sign-cl.p8").exists()
                        && Path::new("/etc/keysas/file-sign-pq.p8").exists(),
                    ip: get_ip()?,
                    progress_in,
                    progress_transit,
                };

                let serialized = serde_json::to_string(&orders)?;
                websocket.send(Message::Text(serialized.into()))?;
                thread::sleep(Duration::from_millis(300));
            }
        });
    }
    Ok(())
}
