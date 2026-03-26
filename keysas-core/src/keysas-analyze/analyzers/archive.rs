// SPDX-License-Identifier: GPL-3.0-only
/*
 * Archive analysis: detects encrypted archives and executables within archives.
 *
 * Policy:
 *   - Encrypted ZIP entries  → block
 *   - Executable magic bytes inside archive entries  → block
 *   - Executable filename extensions inside archive entries  → block
 *   - All other archives    → pass
 *
 * Supported formats: ZIP (zip/jar/war/ear), TAR, TAR.GZ, TAR.BZ2, TAR.XZ,
 *                    single GZ, single BZ2, single XZ.
 */

use std::fs::File;
use std::io::{Read, Write};

/// Magic bytes that identify executables — block if found inside an archive entry.
const EXEC_MAGIC: &[(&[u8], &str)] = &[
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit BE"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit BE"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE"),
];

/// Filename extensions that denote executables — block if found inside an archive entry.
const EXEC_EXTENSIONS: &[&str] = &[
    "exe", "dll", "com", "efi", "msi", "scr", "pif", "elf", "so", "dylib", "bat", "cmd", "ps1",
    "vbs", "vbe", "hta",
];

fn is_executable_magic(data: &[u8]) -> Option<&'static str> {
    for (magic, desc) in EXEC_MAGIC {
        if data.starts_with(magic) {
            return Some(desc);
        }
    }
    None
}

fn has_exec_extension(name: &str) -> bool {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    EXEC_EXTENSIONS.contains(&ext.as_str())
}

pub fn analyze(fd: i32, filename: &str, tmp_dir: &str) -> (bool, String) {
    let tmp_path = format!("{}/archive_{}", tmp_dir, sanitize_filename(filename));
    if let Err(e) = write_fd_to_tmp(fd, &tmp_path) {
        log::warn!("archive::analyze: failed to write temp file: {e}");
        return (
            true,
            "temp file write failed — analysis skipped".to_string(),
        );
    }

    let result = analyze_path(&tmp_path, filename);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

fn analyze_path(path: &str, filename: &str) -> (bool, String) {
    let name = filename.to_lowercase();

    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        analyze_tar_gz(path)
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        analyze_tar_bz2(path)
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        analyze_tar_xz(path)
    } else if name.ends_with(".tar") {
        analyze_tar(path)
    } else if name.ends_with(".gz") {
        // Single gzip-compressed file (not a TAR)
        analyze_single_gz(path)
    } else if name.ends_with(".bz2") {
        analyze_single_bz2(path)
    } else if name.ends_with(".xz") {
        analyze_single_xz(path)
    } else {
        // Default: try as ZIP (covers .zip, .jar, .war, .ear)
        analyze_zip(path)
    }
}

// --- ZIP -----------------------------------------------------------------------

fn analyze_zip(path: &str) -> (bool, String) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return (true, format!("cannot open archive: {e}")),
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => return (true, format!("cannot parse ZIP: {e}")),
    };

    for i in 0..archive.len() {
        // Step 1: metadata check (no decompression) — detects encryption flag
        {
            let raw = match archive.by_index_raw(i) {
                Ok(e) => e,
                Err(e) => {
                    log::warn!("archive: zip entry {i} raw read error: {e}");
                    continue;
                }
            };
            if raw.is_dir() {
                continue;
            }
            if raw.encrypted() {
                return (false, format!("encrypted entry: {}", raw.name()));
            }
            let entry_name = raw.name().to_string();
            if has_exec_extension(&entry_name) {
                return (false, format!("executable by extension: {entry_name}"));
            }
        } // raw borrow released here

        // Step 2: magic byte check (decompresses first bytes)
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("archive: zip entry {i} decompression error: {e}");
                continue;
            }
        };
        let entry_name = entry.name().to_string();
        let mut header = [0u8; 8];
        if let Ok(n) = entry.read(&mut header) {
            if let Some(desc) = is_executable_magic(&header[..n]) {
                return (false, format!("executable content ({desc}): {entry_name}"));
            }
        }
    }

    (true, "no encrypted or executable content".to_string())
}

// --- TAR variants --------------------------------------------------------------

fn analyze_tar_stream<R: Read>(reader: R) -> (bool, String) {
    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return (true, format!("cannot read TAR entries: {e}")),
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::warn!("archive: tar entry error: {e}");
                continue;
            }
        };

        // Skip directories and symlinks — check only regular files
        use tar::EntryType;
        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous => {}
            _ => continue,
        }

        let path = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if has_exec_extension(&path) {
            return (false, format!("executable by extension: {path}"));
        }

        let mut header = [0u8; 8];
        if let Ok(n) = entry.read(&mut header) {
            if let Some(desc) = is_executable_magic(&header[..n]) {
                return (false, format!("executable content ({desc}): {path}"));
            }
        }
    }

    (true, "no executable content".to_string())
}

fn analyze_tar(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => analyze_tar_stream(f),
        Err(e) => (true, format!("cannot open TAR: {e}")),
    }
}

fn analyze_tar_gz(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => analyze_tar_stream(flate2::read::GzDecoder::new(f)),
        Err(e) => (true, format!("cannot open TAR.GZ: {e}")),
    }
}

fn analyze_tar_bz2(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => analyze_tar_stream(bzip2::read::BzDecoder::new(f)),
        Err(e) => (true, format!("cannot open TAR.BZ2: {e}")),
    }
}

fn analyze_tar_xz(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => analyze_tar_stream(xz2::read::XzDecoder::new(f)),
        Err(e) => (true, format!("cannot open TAR.XZ: {e}")),
    }
}

// --- Single compressed files ---------------------------------------------------

fn check_decompressed_magic<R: Read>(mut reader: R, fmt: &str) -> (bool, String) {
    let mut header = [0u8; 8];
    match reader.read(&mut header) {
        Ok(n) if n >= 2 => {
            if let Some(desc) = is_executable_magic(&header[..n]) {
                return (
                    false,
                    format!("executable after {fmt} decompression ({desc})"),
                );
            }
        }
        _ => {}
    }
    (true, "no executable content".to_string())
}

fn analyze_single_gz(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => check_decompressed_magic(flate2::read::GzDecoder::new(f), "GZ"),
        Err(e) => (true, format!("cannot open GZ: {e}")),
    }
}

fn analyze_single_bz2(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => check_decompressed_magic(bzip2::read::BzDecoder::new(f), "BZ2"),
        Err(e) => (true, format!("cannot open BZ2: {e}")),
    }
}

fn analyze_single_xz(path: &str) -> (bool, String) {
    match File::open(path) {
        Ok(f) => check_decompressed_magic(xz2::read::XzDecoder::new(f), "XZ"),
        Err(e) => (true, format!("cannot open XZ: {e}")),
    }
}

// --- Helpers -------------------------------------------------------------------

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_fd_to_tmp(fd: i32, path: &str) -> std::io::Result<()> {
    use std::os::unix::io::FromRawFd;
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    let mut src = unsafe { File::from_raw_fd(dup_fd) };
    let mut buf = Vec::new();
    src.read_to_end(&mut buf)?;
    let mut dst = File::create(path)?;
    dst.write_all(&buf)?;
    Ok(())
}
