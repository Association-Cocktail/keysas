// SPDX-License-Identifier: GPL-3.0-only
/*
 * keysas-analyze
 *
 * (C) Copyright 2019-2026 Stephane Neveu, Luc Bonnafoux
 *
 * Specialized file analysis daemon.
 * Receives files from keysas-transit via Unix socket (SCM_RIGHTS + bincode),
 * dispatches to appropriate analyzer based on file type/extension,
 * and returns analysis results (bincode).
 */

#![feature(unix_socket_ancillary_data)]
#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![forbid(trivial_bounds)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use clap::{Arg, ArgAction, Command, crate_version};
use keysas_lib::init_logger;
use log::{error, info, warn};
use std::io::{IoSlice, IoSliceMut};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{AncillaryData, SocketAddr, SocketAncillary, UnixListener};
use std::process;

mod analyzers;
mod sandbox;

const DEFAULT_TMP_DIR: &str = "/run/keysas-analyze";
const DEFAULT_SOCKET: &str = "socket_analyze";

/// Request received from keysas-transit
#[derive(bincode::Decode, Debug)]
struct AnalyzeRequest {
    filename: String,
    file_type: String,
}

/// Response sent back to keysas-transit
#[derive(bincode::Encode, Debug)]
struct AnalyzeResponse {
    performed: bool,
    passed: bool,
    analyzer: String,
    summary: String,
}

struct Config {
    socket_name: String,
    tmp_dir: String,
}

fn parse_args() -> Config {
    let matches = Command::new("keysas-analyze")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-analyze: specialized file analysis daemon.")
        .arg(
            Arg::new("socket_analyze")
                .short('s')
                .long("socket_analyze")
                .value_name("<NAMESPACE>")
                .default_value(DEFAULT_SOCKET)
                .action(ArgAction::Set)
                .help("Abstract Unix socket name to listen on"),
        )
        .arg(
            Arg::new("tmp_dir")
                .short('t')
                .long("tmp_dir")
                .value_name("<PATH>")
                .default_value(DEFAULT_TMP_DIR)
                .action(ArgAction::Set)
                .help("Temporary directory for subprocess file analysis"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
        .get_matches();

    Config {
        socket_name: matches.get_one::<String>("socket_analyze").unwrap().clone(),
        tmp_dir: matches.get_one::<String>("tmp_dir").unwrap().clone(),
    }
}

/// Detect type category from MIME/magic string and filename extension
#[must_use]
fn detect_category(filename: &str, file_type: &str) -> &'static str {
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let ft = file_type.to_lowercase();

    // LNK
    if ext == "lnk" {
        return "lnk";
    }
    // Office
    if matches!(
        ext.as_str(),
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf"
    ) || ft.contains("msoffice")
        || ft.contains("openxmlformats")
        || ft.contains("ms-excel")
        || ft.contains("ms-powerpoint")
        || ft.contains("msword")
        || ft.contains("rtf")
    {
        return "office";
    }
    // PDF
    if ext == "pdf" || ft.contains("pdf") {
        return "pdf";
    }
    // PE executable
    if matches!(ext.as_str(), "exe" | "dll" | "com" | "efi" | "msi")
        || ft.contains("x-dosexec")
        || ft.contains("x-msdos-program")
        || ft.contains("x-msdownload")
        || ft.contains("x-executable")
    {
        return "pe";
    }
    // Script
    if matches!(
        ext.as_str(),
        "ps1" | "vbs" | "vbe" | "bat" | "sh" | "py" | "js" | "hta" | "jnlp"
    ) {
        return "script";
    }
    // Archive
    if matches!(
        ext.as_str(),
        "zip" | "jar" | "war" | "ear" | "tar" | "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz"
    ) || ft.contains("application/zip")
        || ft.contains("application/x-tar")
        || ft.contains("application/gzip")
        || ft.contains("application/x-bzip2")
        || ft.contains("application/x-xz")
        || ft.contains("application/x-gzip")
    {
        return "archive";
    }
    // ISO 9660
    if ext == "iso" || ft.contains("iso9660") || ft.contains("x-iso") {
        return "iso";
    }

    "unknown"
}

/// Dispatch file to the appropriate analyzer
fn dispatch(fd: i32, filename: &str, file_type: &str, tmp_dir: &str) -> AnalyzeResponse {
    let category = detect_category(filename, file_type);

    match category {
        "office" => {
            info!("Dispatching {} to office analyzer", filename);
            let (passed, summary) = analyzers::office::analyze(fd, filename, tmp_dir);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "office-native".to_string(),
                summary,
            }
        }
        "pdf" => {
            info!("Dispatching {} to PDF analyzer", filename);
            let (passed, summary) = analyzers::pdf::analyze(fd, filename, tmp_dir);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "pdfid".to_string(),
                summary,
            }
        }
        "pe" => {
            info!("Dispatching {} to PE analyzer", filename);
            let (passed, summary) = analyzers::pe::analyze(fd, filename, tmp_dir);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "goblin".to_string(),
                summary,
            }
        }
        "script" => {
            info!("Dispatching {} to script analyzer", filename);
            let (passed, summary) = analyzers::script::analyze(fd, filename);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "script-patterns".to_string(),
                summary,
            }
        }
        "lnk" => {
            info!("Dispatching {} to LNK analyzer", filename);
            let (passed, summary) = analyzers::lnk::analyze(fd, filename);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "lnk-parser".to_string(),
                summary,
            }
        }
        "archive" => {
            info!("Dispatching {} to archive analyzer", filename);
            let (passed, summary) = analyzers::archive::analyze(fd, filename, tmp_dir);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "archive-scanner".to_string(),
                summary,
            }
        }
        "iso" => {
            info!("Dispatching {} to ISO analyzer", filename);
            let (passed, summary) = analyzers::iso::analyze(fd, filename, tmp_dir);
            AnalyzeResponse {
                performed: true,
                passed,
                analyzer: "iso-scanner".to_string(),
                summary,
            }
        }
        _ => {
            // No specialized analyzer for this file type
            AnalyzeResponse {
                performed: false,
                passed: true,
                analyzer: String::new(),
                summary: String::new(),
            }
        }
    }
}

fn main() {
    let config = parse_args();
    init_logger();

    // Sandbox
    match sandbox::landlock_sandbox(&config.tmp_dir) {
        Ok(_) => info!("Landlock sandbox activated."),
        Err(e) => warn!("Landlock sandbox cannot be activated: {e}"),
    }
    match sandbox::init() {
        Ok(_) => info!("Seccomp sandbox activated."),
        Err(e) => warn!("Seccomp sandbox cannot be activated: {e}"),
    }

    // Bind abstract socket
    let addr = match SocketAddr::from_abstract_name(&config.socket_name) {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot create socket address: {e}");
            process::exit(1);
        }
    };
    let listener = match UnixListener::bind_addr(&addr) {
        Ok(l) => {
            info!("Listening on abstract socket: {}", config.socket_name);
            l
        }
        Err(e) => {
            error!("Cannot bind socket: {e}");
            process::exit(1);
        }
    };

    // Accept connections from keysas-transit
    loop {
        let (stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                warn!("Accept error: {e}");
                continue;
            }
        };

        // Receive FD + request
        let mut buf = [0u8; 4096];
        let bufs_in = &mut [IoSliceMut::new(&mut buf[..])][..];
        let mut ancillary_buf = [0u8; 128];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buf[..]);

        match stream.recv_vectored_with_ancillary(bufs_in, &mut ancillary) {
            Ok(0) | Err(_) => {
                warn!("Failed to receive from transit");
                continue;
            }
            Ok(n) => {
                info!("Received {n} bytes from transit");
            }
        }

        // Extract FD from SCM_RIGHTS
        let fd = ancillary
            .messages()
            .filter_map(|m| m.ok())
            .filter_map(|ad| match ad {
                AncillaryData::ScmRights(r) => Some(r),
                _ => None,
            })
            .flatten()
            .next();

        let fd = match fd {
            Some(f) => f,
            None => {
                warn!("No FD received from transit");
                // Send fail-open response
                let resp = AnalyzeResponse {
                    performed: false,
                    passed: true,
                    analyzer: String::new(),
                    summary: String::new(),
                };
                send_response(&stream, &resp);
                continue;
            }
        };

        // Decode request
        let config_bc = bincode::config::standard();
        let req = match bincode::decode_from_slice::<AnalyzeRequest, _>(&buf, config_bc) {
            Ok((r, _)) => r,
            Err(e) => {
                warn!("Cannot decode request: {e}");
                let resp = AnalyzeResponse {
                    performed: false,
                    passed: true,
                    analyzer: String::new(),
                    summary: String::new(),
                };
                send_response(&stream, &resp);
                continue;
            }
        };

        info!("Analyzing: {} (type: {})", req.filename, req.file_type);

        // Dispatch
        let resp = dispatch(fd, &req.filename, &req.file_type, &config.tmp_dir);

        // Close the received FD
        unsafe { libc::close(fd) };

        // Send response
        send_response(&stream, &resp);
    }
}

fn send_response(stream: &std::os::unix::net::UnixStream, resp: &AnalyzeResponse) {
    let config = bincode::config::standard();
    let data = match bincode::encode_to_vec(resp, config) {
        Ok(d) => d,
        Err(e) => {
            warn!("Cannot encode response: {e}");
            return;
        }
    };
    let bufs = &[IoSlice::new(&data[..])];
    let mut ancillary_buf = [0u8; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buf[..]);
    if let Err(e) = stream.send_vectored_with_ancillary(bufs, &mut ancillary) {
        warn!("Cannot send response: {e}");
    }
}
