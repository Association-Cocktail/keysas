#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod vmlinux;

use aya_ebpf::{
    bindings::path,
    cty::{c_char, c_long},
    helpers::bpf_d_path,
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray},
    programs::LsmContext,
};
use aya_log_ebpf::info;
use lsm_file_common::{DECISION_ALLOW_READ, DECISION_BLOCK, KEY_LEN};

use vmlinux::file;

/// Maximum length of a file path to inspect (limited by eBPF stack + PATH_BUF map)
const PATH_LENGTH: usize = 64;

/// Linux O_ACCMODE: mask for access mode bits in f_flags
const O_ACCMODE: u32 = 3;

/// Per-CPU scratch buffer for path strings (avoids eBPF stack limits)
#[map]
static mut PATH_BUF: PerCpuArray<[u8; PATH_LENGTH]> = PerCpuArray::with_max_entries(1, 0);

/// Policy map: mount point path (null-padded, KEY_LEN bytes) → UsbAuthorization as u32
///
/// Populated by the daemon after authorize_usb() + mount detection.
/// Decision encoding (matches UsbAuthorization repr):
///   1 = Block      → -EACCES for all accesses
///   2 = AllowRead  → -EACCES for writes, allow reads
///   3+ = AllowRW/AllowAll → allow everything
#[map]
static mut POLICY_MAP: HashMap<[u8; KEY_LEN], u32> = HashMap::with_max_entries(256, 0);

#[inline(always)]
fn get_bpf_d_path(p: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
    let ret = unsafe {
        bpf_d_path(p, buf.as_mut_ptr() as *mut c_char, buf.len() as u32)
    };
    if ret < 0 {
        return Err(ret);
    }
    Ok(ret as usize)
}

/// Translate a policy decision into an LSM return value.
#[inline(always)]
fn apply_decision(decision: u32, is_write: bool) -> i32 {
    match decision {
        DECISION_BLOCK => -13,                    // -EACCES
        DECISION_ALLOW_READ if is_write => -13,   // -EACCES on writes only
        _ => 0,                                   // allow
    }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        match try_file_open(ctx) {
            Ok(ret) => ret,
            Err(_) => 0, // fail open on internal error
        }
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, c_long> {
    // Get per-CPU scratch buffer
    let buf = {
        let buf_ptr = PATH_BUF.get_ptr_mut(0).ok_or(-1i64)?;
        &mut *buf_ptr
    };

    let f: *const file = ctx.arg(0);
    let p = &(*f).f_path as *const _ as *mut path;
    let len = get_bpf_d_path(p, buf)?;
    if len == 0 || len >= PATH_LENGTH {
        return Ok(0);
    }

    // Detect write access: O_WRONLY (1) or O_RDWR (2)
    let is_write = ((*f).f_flags & O_ACCMODE) != 0;

    // Build key one character at a time.
    // At each '/' boundary (after the first), try a POLICY_MAP lookup with
    // the path prefix accumulated so far (= the potential mount point).
    // Example: "/media/usb0/file.txt"
    //   i=6  ('/'): key="/media"     → no match
    //   i=11 ('/'): key="/media/usb0"→ match → apply decision
    let mut key = [0u8; KEY_LEN];

    for i in 0..PATH_LENGTH {
        if i >= len {
            break;
        }
        let c = buf[i];
        if c == b'/' && i > 0 {
            if let Some(&decision) = POLICY_MAP.get(&key) {
                info!(&ctx, "keysas: USB policy hit: decision={}", decision);
                return Ok(apply_decision(decision, is_write));
            }
        }
        // Accumulate into key (KEY_LEN-1 max, last byte stays null as sentinel)
        if i < KEY_LEN - 1 {
            key[i] = c;
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
