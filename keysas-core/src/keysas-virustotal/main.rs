// SPDX-License-Identifier: GPL-3.0-only
/*
 * keysas-virustotal
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * VirusTotal hash lookup daemon.
 * Receives SHA256 hashes from keysas-transit via Unix abstract socket (bincode),
 * queries the VirusTotal API v3, caches results in memory,
 * and returns verdicts (bincode).
 * Only hash lookups are performed — files are never uploaded.
 */

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
use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::process;

mod sandbox;
mod virustotal;

const DEFAULT_SOCKET: &str = "socket_virustotal";

/// Request received from keysas-transit
#[derive(bincode::Decode, Debug)]
struct VtRequest {
    sha256: String,
}

/// Response sent back to keysas-transit
#[derive(bincode::Encode, Debug)]
struct VtResponse {
    pass: bool,
    detections: u32,
    summary: String,
}

struct Config {
    socket_name: String,
    api_key: String,
    api_url: String,
    fail_open: bool,
    block_threshold: u32,
    timeout_ms: u64,
    cache_ttl_secs: u64,
}

fn parse_args() -> Config {
    let matches = Command::new("keysas-virustotal")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-virustotal: VirusTotal hash lookup daemon.")
        .arg(
            Arg::new("socket_virustotal")
                .short('s')
                .long("socket_virustotal")
                .value_name("<NAMESPACE>")
                .default_value(DEFAULT_SOCKET)
                .action(ArgAction::Set)
                .help("Abstract Unix socket name to listen on"),
        )
        .arg(
            Arg::new("api_key")
                .short('k')
                .long("api_key")
                .value_name("<KEY>")
                .default_value("")
                .action(ArgAction::Set)
                .help("VirusTotal API key"),
        )
        .arg(
            Arg::new("api_url")
                .long("api_url")
                .value_name("<URL>")
                .default_value("https://www.virustotal.com/api/v3/files")
                .action(ArgAction::Set)
                .help("Base URL for the VirusTotal files API"),
        )
        .arg(
            Arg::new("fail_open")
                .long("fail_open")
                .value_name("<true|false>")
                .default_value("true")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(bool))
                .help("Pass file when VirusTotal is unreachable (true=pass, false=block)"),
        )
        .arg(
            Arg::new("block_threshold")
                .long("block_threshold")
                .value_name("<N>")
                .default_value("3")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u32))
                .help("Minimum number of VT detections to block a file"),
        )
        .arg(
            Arg::new("timeout_ms")
                .long("timeout_ms")
                .value_name("<MS>")
                .default_value("3000")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("HTTP timeout for VirusTotal API calls in milliseconds"),
        )
        .arg(
            Arg::new("cache_ttl_secs")
                .long("cache_ttl_secs")
                .value_name("<SECS>")
                .default_value("3600")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("How long (seconds) VT results are cached in memory"),
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
        socket_name: matches
            .get_one::<String>("socket_virustotal")
            .unwrap()
            .to_string(),
        api_key: matches.get_one::<String>("api_key").unwrap().to_string(),
        api_url: matches.get_one::<String>("api_url").unwrap().to_string(),
        fail_open: *matches.get_one::<bool>("fail_open").unwrap(),
        block_threshold: *matches.get_one::<u32>("block_threshold").unwrap(),
        timeout_ms: *matches.get_one::<u64>("timeout_ms").unwrap(),
        cache_ttl_secs: *matches.get_one::<u64>("cache_ttl_secs").unwrap(),
    }
}

fn main() {
    let config = parse_args();
    init_logger();

    if config.api_key.is_empty() {
        error!("No VirusTotal API key provided (--api_key), exiting.");
        process::exit(1);
    }

    // Landlock sandbox
    match sandbox::landlock_sandbox() {
        Ok(_) => info!("Landlock sandbox activated."),
        Err(e) => warn!("Landlock sandbox cannot be activated: {e}"),
    }
    // Seccomp sandbox
    match sandbox::init() {
        Ok(_) => info!("Seccomp sandbox activated."),
        Err(e) => warn!("Seccomp sandbox cannot be activated: {e}"),
    }

    let mut vt = virustotal::VtClient::new(
        config.api_key.clone(),
        config.api_url.clone(),
        config.fail_open,
        config.block_threshold,
        config.timeout_ms,
        config.cache_ttl_secs,
    );
    info!(
        "VirusTotal client ready (url={}, fail_open={}, threshold={})",
        config.api_url, config.fail_open, config.block_threshold
    );

    // Bind abstract Unix socket
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

    let bc_config = bincode::config::standard();

    // Main loop: accept one connection per hash lookup
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                warn!("Accept error: {e}");
                continue;
            }
        };

        // Receive request
        let mut buf = [0u8; 256];
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => {
                warn!("Failed to receive from transit");
                continue;
            }
            Ok(n) => n,
        };

        let req = match bincode::decode_from_slice::<VtRequest, _>(&buf[..n], bc_config) {
            Ok((r, _)) => r,
            Err(e) => {
                warn!("Cannot decode VT request: {e}");
                let resp = VtResponse {
                    pass: true,
                    detections: 0,
                    summary: "decode error".to_string(),
                };
                if let Ok(data) = bincode::encode_to_vec(&resp, bc_config) {
                    let _ = stream.write_all(&data);
                }
                continue;
            }
        };

        info!("VT lookup for: {}", req.sha256);
        let (pass, detections, summary) = vt.lookup(&req.sha256);

        let resp = VtResponse { pass, detections, summary };
        match bincode::encode_to_vec(&resp, bc_config) {
            Ok(data) => {
                if let Err(e) = stream.write_all(&data) {
                    warn!("Cannot send VT response: {e}");
                }
            }
            Err(e) => warn!("Cannot encode VT response: {e}"),
        }
    }
}
