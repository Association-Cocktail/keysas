// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

#![feature(unix_socket_ancillary_data)]
#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(trivial_bounds)]
#![warn(overflowing_literals)]
#![warn(deprecated)]

use anyhow::Result;
use clamav_tcp::scan;
use clamav_tcp::version;
use clap::{Arg, ArgAction, Command, crate_version};
use infer::get;
use keysas_lib::init_logger;
use keysas_lib::sha256_digest;
use keysas_lib::progress::{AnalysisStep, ProgressTracker};
use log::{error, info, warn};
use nix::unistd;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::io::{IoSlice, IoSliceMut};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::os::fd::FromRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{
    AncillaryData, Messages, SocketAddr, SocketAncillary, UnixListener, UnixStream,
};
use std::process;
use std::str;
use std::thread as main_thread;
use std::time::Duration;
use yara::*;
mod sandbox;

/// Request sent to keysas-analyze
#[derive(bincode::Encode, Debug)]
struct AnalyzeRequest {
    filename: String,
    file_type: String,
}

/// Response received from keysas-analyze
#[derive(bincode::Decode, Debug)]
struct AnalyzeResponse {
    performed: bool,
    passed: bool,
    analyzer: String,
    summary: String,
}

/// Request sent to keysas-virustotal
#[derive(bincode::Encode, Debug)]
struct VtRequest {
    sha256: String,
}

/// Response received from keysas-virustotal
#[derive(bincode::Decode, Debug)]
struct VtResponse {
    pass: bool,
    detections: u32,
    summary: String,
}

/// Send a SHA256 hash to keysas-virustotal and get back the verdict.
/// Returns (pass=true, 0, empty) when keysas-virustotal is unreachable (fail-open).
fn call_vt_analyzer(socket_name: &str, sha256: &str) -> (bool, u32, String) {
    let addr = match SocketAddr::from_abstract_name(socket_name) {
        Ok(a) => a,
        Err(e) => {
            warn!("keysas-virustotal: cannot build socket address: {e}");
            return (true, 0, String::new());
        }
    };
    let mut stream = match UnixStream::connect_addr(&addr) {
        Ok(s) => s,
        Err(e) => {
            warn!("keysas-virustotal unavailable: {e}");
            return (true, 0, String::new());
        }
    };
    let req = VtRequest { sha256: sha256.to_string() };
    let config = bincode::config::standard();
    let data = match bincode::encode_to_vec(&req, config) {
        Ok(d) => d,
        Err(e) => {
            warn!("keysas-virustotal: encode error: {e}");
            return (true, 0, String::new());
        }
    };
    if let Err(e) = stream.write_all(&data) {
        warn!("keysas-virustotal: send error: {e}");
        return (true, 0, String::new());
    }
    let mut buf = [0u8; 512];
    let n = match stream.read(&mut buf) {
        Ok(0) | Err(_) => {
            warn!("keysas-virustotal: no response received");
            return (true, 0, String::new());
        }
        Ok(n) => n,
    };
    match bincode::decode_from_slice::<VtResponse, _>(&buf[..n], config) {
        Ok((resp, _)) => {
            info!("VT result for {sha256}: pass={}, detections={}, summary={}", resp.pass, resp.detections, resp.summary);
            (resp.pass, resp.detections, resp.summary)
        }
        Err(e) => {
            warn!("keysas-virustotal: decode error: {e}");
            (true, 0, String::new())
        }
    }
}

/// Send a file descriptor + metadata to keysas-analyze and get back the analysis result.
/// Returns (pass=true, empty) when keysas-analyze is unreachable (fail-open).
fn call_specialized_analyzer(
    socket_name: &str,
    fd: i32,
    filename: &str,
    file_type: &str,
) -> (bool, String, String) {
    let addr = match SocketAddr::from_abstract_name(socket_name) {
        Ok(a) => a,
        Err(e) => {
            warn!("keysas-analyze: cannot build socket address: {e}");
            return (true, String::new(), String::new());
        }
    };

    let stream = match UnixStream::connect_addr(&addr) {
        Ok(s) => s,
        Err(e) => {
            warn!("keysas-analyze unavailable: {e}");
            return (true, String::new(), String::new());
        }
    };

    // Send FD via SCM_RIGHTS + bincode request
    let req = AnalyzeRequest {
        filename: filename.to_string(),
        file_type: file_type.to_string(),
    };
    let config = bincode::config::standard();
    let data = match bincode::encode_to_vec(&req, config) {
        Ok(d) => d,
        Err(e) => {
            warn!("keysas-analyze: encode error: {e}");
            return (true, String::new(), String::new());
        }
    };

    let bufs = &[IoSlice::new(&data[..])];
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[fd][..]);

    if let Err(e) = stream.send_vectored_with_ancillary(bufs, &mut ancillary) {
        warn!("keysas-analyze: send error: {e}");
        return (true, String::new(), String::new());
    }

    // Receive response
    let mut buf = [0u8; 4096];
    let bufs_in = &mut [IoSliceMut::new(&mut buf[..])][..];
    let mut ancillary_buf_in = [0u8; 128];
    let mut ancillary_in = SocketAncillary::new(&mut ancillary_buf_in[..]);

    match stream.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
        Ok(0) | Err(_) => {
            warn!("keysas-analyze: no response received");
            return (true, String::new(), String::new());
        }
        Ok(_) => {}
    }

    match bincode::decode_from_slice::<AnalyzeResponse, _>(&buf, config) {
        Ok((resp, _)) => {
            if resp.performed {
                info!("Specialized analysis by {}: pass={}, summary={}", resp.analyzer, resp.passed, resp.summary);
            }
            (resp.passed, resp.analyzer, resp.summary)
        }
        Err(e) => {
            warn!("keysas-analyze: decode error: {e}");
            (true, String::new(), String::new())
        }
    }
}

const CONFIG_DIRECTORY: &str = "/etc/keysas";

#[derive(bincode::Decode, Debug)]
struct InputMetadata {
    filename: String,
    digest: String,
    timestamp: String,
    is_corrupted: bool,
}

#[derive(bincode::Encode, Debug)]
struct FileMetadata {
    filename: String,
    digest: String,
    is_digest_ok: bool,
    is_toobig: bool,
    size: u64,
    is_type_allowed: bool,
    av_pass: bool,
    av_report: Vec<String>,
    yara_pass: bool,
    yara_report: String,
    timestamp: String,
    is_corrupted: bool,
    file_type: String,
    specialized_pass: bool,
    specialized_analyzer: String,
    specialized_summary: String,
    vt_pass: bool,
    vt_detections: u32,
    vt_summary: String,
}

#[derive(Debug)]
struct FileData {
    fd: i32,
    md: FileMetadata,
}

/// Daemon configuration arguments
struct Configuration {
    socket_in: String,            // path for the socket with keysas-in
    socket_out: String,           // path for the socket with keysas-out
    socket_analyze: Option<String>, // path for the socket with keysas-analyze (optional)
    socket_vt: Option<String>,    // path for the socket with keysas-virustotal (optional)
    max_size: u64,                // Maximum size for files
    magic_list: Vec<String>,      // List of allowed file type
    clamav_ip: String,            // ClamAV IP address
    clamav_port: u16,             // ClamAV port number
    rule_path: String,            // Path to yara rules
    yara_timeout: i32,            // Timeout for yara
    yara_rules: Option<Rules>,    // Yara rules
    type_off: bool,
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-transit")
          .version(crate_version!())
          .author("Stephane N.")
          .about("keysas-transit, perform file sanitization.")
          .arg(
             Arg::new("socket_in")
                 .short('i')
                 .long("socket_in")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_in")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for input files"),
         )
         .arg(
             Arg::new("socket_out")
                 .short('o')
                 .long("socket_out")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_out")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for output files"),
         )
         .arg(
             Arg::new("max_size")
                 .short('s')
                 .long("max_size")
                 .value_name("<SIZE_IN_BYTES>")
                 .default_value("500000000")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u64))
                 .help("Maximum size for files"),
         )
         .arg(
             Arg::new("allowed_formats")
                 .short('a')
                 .long("allowed_formats")
                 .value_name("<LIST>")
                 .default_value("jpg,png,gif,bmp,mp4,m4v,avi,wmv,mpg,flv,mp3,wav,ogg,epub,mobi,doc,docx,xls,xlsx,ppt,pptx")
                 .action(ArgAction::Set)
                 .help("Whitelist (comma separated) of allowed file formats"),
         )
         .arg(
             Arg::new("clamavip")
                 .short('c')
                 .long("clamavip")
                 .value_name("<IP>")
                 .default_value("127.0.0.1")
                 .action(ArgAction::Set)
                 .help("Clamav IP address"),
         )
         .arg(
             Arg::new("clamavport")
                 .short('p')
                 .long("clamavport")
                 .value_name("<PORT>")
                 .default_value("3310")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u16))
                 .help("Clamav port number"),
         )
         .arg(
             Arg::new("rules_path")
                 .short('r')
                 .long("rules_path")
                 .value_name("<PATH>")
                 .default_value("/usr/share/keysas/rules/index.yar")
                 .action(ArgAction::Set)
                 .help("Sets a custom path for Yara rules"),
         )
         .arg(
             Arg::new("yara_timeout")
                 .short('t')
                 .long("yara_timeout")
                 .value_name("<SECONDS>")
                 .default_value("100")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(i32))
                 .help("Sets a custom timeout for libyara scans"),
         )
         .arg(
            Arg::new("type_off")
                .short('m')
                .long("type_off")
                .action(ArgAction::SetTrue)
                .help("Disable the magic number check"),
        )
         .arg(
            Arg::new("socket_analyze")
                .short('A')
                .long("socket_analyze")
                .value_name("<NAMESPACE>")
                .action(ArgAction::Set)
                .help("Abstract socket name for keysas-analyze (leave unset to disable)"),
        )
         .arg(
            Arg::new("socket_vt")
                .long("socket_vt")
                .value_name("<NAMESPACE>")
                .action(ArgAction::Set)
                .help("Abstract socket name for keysas-virustotal (leave unset to disable)"),
        )
         .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
          .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        socket_in: matches.get_one::<String>("socket_in").unwrap().to_string(),
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        socket_analyze: matches
            .get_one::<String>("socket_analyze")
            .and_then(|s| if s.is_empty() { None } else { Some(s.clone()) }),
        socket_vt: matches
            .get_one::<String>("socket_vt")
            .and_then(|s| if s.is_empty() { None } else { Some(s.clone()) }),
        max_size: *matches.get_one::<u64>("max_size").unwrap(),
        magic_list: matches
            .get_one::<String>("allowed_formats")
            .unwrap()
            .split(',')
            .map(String::from)
            .collect(),
        clamav_ip: matches.get_one::<String>("clamavip").unwrap().to_string(),
        clamav_port: *matches.get_one::<u16>("clamavport").unwrap(),
        rule_path: matches.get_one::<String>("rules_path").unwrap().to_string(),
        yara_timeout: *matches.get_one::<i32>("yara_timeout").unwrap(),
        yara_rules: None,
        type_off: matches.get_flag("type_off"),
    }
}

/// This function retrieves the file descriptors and metadata from the messages
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages
        .filter_map(|m| {
            //Desencapsulate Result
            match m {
                Ok(ad) => Some(ad),
                Err(e) => {
                    log::warn!("failed to get ancillary data: {e:?}");
                    None
                }
            }
        })
        .filter_map(|ad| {
            // Filter AncillaryData to keep only ScmRights
            match ad {
                AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                AncillaryData::ScmCredentials(_) => None,
            }
        })
        .flatten()
        .filter_map(|fd| {
            // Deserialize metadata
            let config = bincode::config::standard().with_limit::<4128>();
            match bincode::decode_from_slice::<InputMetadata, _>(buffer, config) {
                Ok(meta) => {
                    // Initialize with failed value by default
                    log::info!("Receiving fd of file: {}", &meta.0.filename);
                    Some(FileData {
                        fd,
                        md: FileMetadata {
                            filename: meta.0.filename,
                            digest: meta.0.digest,
                            is_digest_ok: false,
                            is_toobig: true,
                            size: 0,
                            is_type_allowed: false,
                            av_pass: false,
                            av_report: Vec::new(),
                            yara_pass: false,
                            yara_report: String::new(),
                            timestamp: meta.0.timestamp,
                            is_corrupted: meta.0.is_corrupted,
                            file_type: "Unknown".into(),
                            specialized_pass: true,
                            specialized_analyzer: String::new(),
                            specialized_summary: String::new(),
                            vt_pass: true,
                            vt_detections: 0,
                            vt_summary: String::new(),
                        },
                    })
                }
                Err(e) => {
                    log::warn!("Failed to deserialize message from in: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Returns true if the buffer looks like plain text (no null bytes, valid UTF-8).
/// Used as a fallback when infer cannot identify a magic number: text files (.txt, .py,
/// .csv, .xml, .json, .sh, .ps1, ...) have no binary signature but are legitimate.
/// Executables always contain null bytes or invalid UTF-8 sequences.
fn is_likely_text(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    let sample = &buf[..buf.len().min(8192)];
    !sample.contains(&0u8) && str::from_utf8(sample).is_ok()
}

/// ZIP-based formats: infer returns "zip" for all of them because they share the PK magic.
/// We allow them when the *declared* extension is in the whitelist AND the magic is ZIP.
/// This means a `malware.zip` renamed to `foo.jar` is allowed only if `jar` is whitelisted,
/// but keysas-analyze and ClamAV still scan the content.
const ZIP_BASED_EXTENSIONS: &[&str] = &[
    "jar", "war", "ear",            // Java archives
    "docx", "xlsx", "pptx",         // Office Open XML
    "odt", "ods", "odp",            // LibreOffice
    "epub",                         // eBook
    "apk",                          // Android (not whitelisted by default)
];

/// This function returns true if the file type is in the list provided.
/// For files with a recognisable magic number, the type must be in the whitelist.
/// For ZIP-based formats (jar, war, docx…), infer returns "zip": we cross-check
/// the declared filename extension against the whitelist.
/// For files without a magic number (plain text), is_likely_text() acts as a guard.
fn check_is_extension_allowed(buf: &[u8], filename: &str, conf: &Configuration) -> bool {
    let declared_ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match get(buf) {
        Some(info) => {
            let magic_ext = info.extension().to_string();
            // Direct magic match
            if conf.magic_list.contains(&magic_ext) {
                return true;
            }
            // ZIP magic + ZIP-based format declared extension in whitelist
            if magic_ext == "zip"
                && ZIP_BASED_EXTENSIONS.contains(&declared_ext.as_str())
                && conf.magic_list.contains(&declared_ext)
            {
                return true;
            }
            false
        }
        None => {
            // KeePass database (.kdbx) — binary, not recognised by infer
            if declared_ext == "kdbx"
                && conf.magic_list.contains(&"kdbx".to_string())
                && (buf.starts_with(&[0x03, 0xd9, 0xa2, 0x9a])
                    || buf.starts_with(&[0x03, 0xd9, 0xa2, 0x9b]))
            {
                return true;
            }
            is_likely_text(buf)
        }
    }
}
/// This function returns true if the file type is in the list provided
fn get_extension(buf: Vec<u8>) -> String {
    match get(&buf) {
        Some(info) => info.to_string(),
        None => "".into(),
    }
}
/// This function check each file given in the input vector.
/// Checks are made against the provided configuration.
/// Checks performed are:
///     - File digest is correct
///     - File size is less than maximum size provided in configuration
///     - File type is in the list provided in configuration
///     - Anti-virus check
///     - Yara rules check
/// Checks results are marked in file metadata.
/// This function does not modify the files.
fn check_files(files: &mut Vec<FileData>, conf: &Configuration, clam_addr: String, progress_tracker: &ProgressTracker, socket_analyze: Option<&str>, socket_vt: Option<&str>) {
    for f in files {
        // Start tracking this file
        progress_tracker.start_file(f.md.filename.clone());
        info!("🔍 Analyse de: {}", f.md.filename);

        match unistd::dup2(f.fd, 500) {
            Ok(nfd) => {
                // Safety: We are using a file descriptor that we know is valid
                let mut file = unsafe { File::from_raw_fd(nfd) };
                // Synchronize the file before calculating the SHA256 hash
                match file.sync_all() {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Failed to synchronize file: {e}");
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check digest
                progress_tracker.update_step(AnalysisStep::Hashing);
                match sha256_digest(&file) {
                    Ok(d) => {
                        f.md.is_digest_ok = f.md.digest.eq(&d);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to calculate digest for file {}, error {e}.",
                            f.md.filename
                        );
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }

                // Check size
                progress_tracker.update_step(AnalysisStep::CheckingSize);
                match &file.metadata() {
                    Ok(meta) => {
                        f.md.is_toobig = meta.len().gt(&conf.max_size);
                        f.md.size = meta.len();
                    }
                    Err(e) => {
                        warn!("Failed to get metadata of file {} error {e}", f.md.filename);
                    }
                }

                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check anti-virus
                progress_tracker.update_step(AnalysisStep::AntivirusScan);
                match scan(clam_addr.clone(), &mut file, None) {
                    Ok(result) => {
                        f.md.av_pass = !result.is_infected;
                        f.md.av_report = result.detected_infections;
                    }
                    Err(e) => {
                        error!("Failed to run clam on file {e}");
                        f.md.av_pass = false;
                    }
                }

                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check yara rules
                progress_tracker.update_step(AnalysisStep::YaraScan);
                match &conf.yara_rules {
                    Some(rules) => match rules.scan_fd(&file, conf.yara_timeout) {
                        Ok(results) => match results.is_empty() {
                            true => {
                                f.md.yara_pass = true;
                            }
                            false => {
                                for result in results {
                                    f.md.yara_report.push_str(result.identifier);
                                }
                                f.md.yara_pass = false;
                                warn!("Yara rules matched");
                            }
                        },
                        Err(e) => {
                            error!("Yara cannot scan file {} error {e}", f.md.filename);
                        }
                    },
                    None => {
                        error!("Yara rules not present");
                        f.md.yara_pass = false;
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check the magic number (must happen before specialized analysis
                // so that file_type is populated when dispatching to keysas-analyze)
                progress_tracker.update_step(AnalysisStep::CheckingFileType);
                // Read only 1Mo of the file to be faster and do not read large files
                let reader = BufReader::new(&file);
                let limited_reader = &mut reader.take(1024 * 1024);
                let mut buffer = Vec::new();
                match limited_reader.read_to_end(&mut buffer) {
                    Ok(_) => {
                        if !conf.type_off {
                            f.md.is_type_allowed = check_is_extension_allowed(&buffer, &f.md.filename, conf);
                            f.md.file_type = get_extension(buffer);
                        } else {
                            f.md.is_type_allowed = true;
                            f.md.file_type = get_extension(buffer);
                        }
                    }
                    Err(e) => {
                        error!(
                            "Cannot read limited buffer: {e:?}, file will be marked as not allowed !"
                        );
                        f.md.is_type_allowed = false;
                        f.md.file_type = "Unknown".into();
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Specialized analysis (oletools, peepdf, die, etc.)
                if let Some(sock) = socket_analyze {
                    progress_tracker.update_step(AnalysisStep::SpecializedAnalysis);
                    let (pass, analyzer, summary) = call_specialized_analyzer(
                        sock, nfd, &f.md.filename, &f.md.file_type,
                    );
                    f.md.specialized_pass = pass;
                    f.md.specialized_analyzer = analyzer;
                    f.md.specialized_summary = summary;
                    // Seek back after FD was sent to analyze
                    match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                        Ok(_) => (),
                        Err(e) => {
                            error!("Unable to lseek after specialized analysis: {e:?}, killing myself.");
                            process::exit(1);
                        }
                    }
                }
                // VirusTotal hash lookup via keysas-virustotal socket (optional)
                if let Some(sock) = socket_vt {
                    progress_tracker.update_step(AnalysisStep::VirusTotalScan);
                    let (pass, detections, summary) = call_vt_analyzer(sock, &f.md.digest);
                    f.md.vt_pass = pass;
                    f.md.vt_detections = detections;
                    f.md.vt_summary = summary;
                    if !pass {
                        warn!("VT blocked file {}: {} detection(s)", f.md.filename, detections);
                    }
                }
            }
            Err(e) => {
                error!("Cannot duplicate file descriptor for analysing: {e:?}, killing myself.");
                process::exit(1);
            }
        };

        // Determine if file passed all checks
        let passed = f.md.is_digest_ok
            && !f.md.is_toobig
            && f.md.is_type_allowed
            && f.md.av_pass
            && f.md.yara_pass
            && f.md.specialized_pass
            && f.md.vt_pass;

        // Mark file as completed
        progress_tracker.complete_file(passed);
        progress_tracker.update_step(if passed {
            AnalysisStep::Complete
        } else {
            AnalysisStep::Failed("Vérifications échouées".to_string())
        });

        let status = if passed { "✅" } else { "❌" };
        log::info!(
            "{} Report for {}: digest_ok: {}, type_allowed: {}, yara_pass: {}, av_pass: {}, too_big: {}",
            status,
            f.md.filename,
            f.md.is_digest_ok,
            f.md.is_type_allowed,
            f.md.yara_pass,
            f.md.av_pass,
            f.md.is_toobig
        );
    }
}

/// This functions send the files filedescriptor and metadata to the socket.
/// Returns Err if the connection to keysas-out is broken (e.g. broken pipe).
fn send_files(files: &Vec<FileData>, stream: &UnixStream, _progress_tracker: &ProgressTracker) -> Result<()> {
    let config = bincode::config::standard();
    for file in files {
        // Get metadata
        let data = match bincode::encode_to_vec(&file.md, config) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to serialize: {e}");
                process::exit(1);
            }
        };
        let bufs = &[IoSlice::new(&data[..])];

        // Send them on the socket
        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
        ancillary.add_fds(&[file.fd][..]);
        match stream.send_vectored_with_ancillary(&bufs[..], &mut ancillary) {
            Ok(_) => info!("File {} sent to Keysas-out.", file.md.filename),
            Err(e) => {
                error!("Failed to send file to keysas-out: {e}");
                // Close remaining FD before returning error
                let _ = unistd::close(file.fd);
                return Err(anyhow::anyhow!("Broken pipe to keysas-out: {e}"));
            }
        }
        // Close the file descriptor
        match unistd::close(file.fd) {
            Ok(_) => info!("File descriptor {} closed for file {}.", file.fd, file.md.filename),
            Err(e) => error!("Failed to close file descriptor {} for file {}: {e}", file.fd, file.md.filename),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // Parse command arguments
    let mut config = parse_args();

    // Configure logger
    init_logger();

    // Initialize progress tracker
    let progress_file = std::path::PathBuf::from("/run/keysas-transit/progress.json");
    let progress_tracker = ProgressTracker::new("keysas-transit".to_string(), progress_file);

    // Landlock initialization
    match sandbox::landlock_sandbox(&config.rule_path) {
        Ok(_) => log::info!("Landlock sandbox activated."),
        Err(e) => log::warn!("Landlock sandbox cannot be activated: {e}"),
    }
    // Seccomp initialization
    match sandbox::init() {
        Ok(_) => log::info!("Seccomp sandbox activated."),
        Err(e) => log::warn!("Seccomp sandbox cannot be activated: {e}"),
    }
    // Initilize clamd client
    // Test if ClamAV IP is valid
    match config.clamav_ip.parse::<IpAddr>() {
        Ok(_) => (),
        Err(e) => {
            error!("ClamAV invalid IP address {e}");
            process::exit(1);
        }
    }
    // Test if clamd is responding
    let url = format!("{}{}{}", &config.clamav_ip, ":", config.clamav_port);
    match url.to_socket_addrs() {
        Ok(mut socket_addrs) => match socket_addrs.next() {
            Some(clam_addr) => match version(clam_addr) {
                Ok(v) => info!("Version: {v}"),
                Err(e) => {
                    error!("Clamav not available: {e:?}, killing my self.");
                    process::exit(1);
                }
            },
            None => {
                error!(
                    "Cannot parse any valid SocketAddr for connecting to clamav server, killing my self."
                );
                process::exit(1);
            }
        },
        Err(e) => {
            error!("Cannot parse clamav configuration: {e:?}")
        }
    };

    // Log VirusTotal socket status
    if let Some(ref sock) = config.socket_vt {
        info!("VirusTotal socket configured: {sock}");
    } else {
        info!("VirusTotal integration disabled (no socket configured)");
    }

    // Initialize yara rules
    match Compiler::new() {
        Ok(c) => match c.add_rules_file_with_namespace(&config.rule_path, "keysas") {
            Ok(c) => match c.compile_rules() {
                Ok(r) => {
                    info!("Yara compiler initialized.");
                    config.yara_rules = Some(r);
                }
                Err(e) => {
                    error!("Failed to compile yara rules {e}");
                    process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to add yara rules to compiler {e}");
                process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to initialize yara compiler {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-in
    let addr_in = SocketAddr::from_abstract_name(&config.socket_in)?;
    let sock_in = match UnixStream::connect_addr(&addr_in) {
        Ok(s) => {
            info!("Connected to Keysas-in socket.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-in {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-out
    let addr_out = SocketAddr::from_abstract_name(&config.socket_out)?;
    let sock_out = match UnixListener::bind_addr(&addr_out) {
        Ok(s) => {
            info!("Socket for Keysas-out created.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-out {e}");
            process::exit(1);
        }
    };

    // Outer loop: re-accept keysas-out connection whenever it reconnects
    loop {
        info!("Waiting for keysas-out to connect...");
        let (out_stream, _sck_addr) = match sock_out.accept() {
            Ok(r) => {
                info!("Keysas-out connected.");
                r
            }
            Err(e) => {
                warn!("Failed to accept keysas-out connection: {e}, retrying...");
                main_thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        // Allocate buffers for input messages
        let mut ancillary_buffer_in = [0; 128];
        let mut ancillary_in = SocketAncillary::new(&mut ancillary_buffer_in[..]);

        // Inner loop
        // 1. receive file descriptors from in
        // 2. run check on the file
        // 3. send fd and report to out
        // Break back to outer loop on broken pipe to keysas-out
        loop {
            // 4128 => filename max 4096 bytes and digest 32 bytes
            let mut buf_in = [0; 4128];
            let bufs_in = &mut [IoSliceMut::new(&mut buf_in[..])][..];

            // Listen for message on socket
            match sock_in.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
                Ok(size) => info!("Receiving data from keysas-in, message size: {size}"),
                Err(e) => {
                    warn!("Failed to receive fds from in: {e}");
                    process::exit(1);
                }
            }

            // Parse messages received
            let mut files = parse_messages(ancillary_in.messages(), &buf_in);

            // Add files to progress tracker
            let filenames: Vec<String> = files.iter().map(|f| f.md.filename.clone()).collect();
            progress_tracker.add_files_to_queue(filenames);

            // Run check on message received
            check_files(&mut files, &config, url.clone(), &progress_tracker, config.socket_analyze.as_deref(), config.socket_vt.as_deref());

            // Send fd and report to out; break to re-accept if connection is broken
            if let Err(e) = send_files(&files, &out_stream, &progress_tracker) {
                warn!("Lost keysas-out connection: {e}, waiting for reconnect...");
                break;
            }
            main_thread::sleep(Duration::from_millis(100));
        }
    }
}
