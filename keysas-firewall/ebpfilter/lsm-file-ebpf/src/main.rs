#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use lsm_file_common::DECISION_BLOCK;

use vmlinux::{file, inode, super_block};

/// Policy map: superblock device number (u32) → UsbAuthorization as u32
///
/// Populated by the daemon after authorization + mount detection.
/// Decision encoding (matches UsbAuthorization repr):
///   1 = Block      → -EACCES
///   2+ = AllowRead/AllowRW/AllowAll → allow
#[map]
static mut POLICY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(256, 0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        match try_file_open(ctx) {
            Ok(ret) => ret,
            Err(_) => 0, // fail open on internal error
        }
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let f: *const file = ctx.arg(0);

    // Navigate file -> f_inode -> i_sb -> s_dev to identify the filesystem device.
    // Each pointer field is read via a direct BPF load (no helper needed).
    let fi: *mut inode = (*f).f_inode;
    if fi.is_null() {
        return Ok(0);
    }
    let sb: *mut super_block = (*fi).i_sb;
    if sb.is_null() {
        return Ok(0);
    }
    let dev: u32 = (*sb).s_dev;

    // Access POLICY_MAP through a raw pointer to avoid static_mut_refs lint.
    let policy_map = (&raw const POLICY_MAP).as_ref().ok_or(0i32)?;
    if let Some(&decision) = policy_map.get(&dev) {
        info!(&ctx, "keysas: USB policy hit: dev={} decision={}", dev, decision);
        return Ok(if decision == DECISION_BLOCK { -13 } else { 0 });
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
