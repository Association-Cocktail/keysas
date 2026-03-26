// SPDX-License-Identifier: GPL-3.0-only
/*
 * keysas-virustotal
 *
 * (C) Copyright 2019-2026 Stephane Neveu, Luc Bonnafoux
 *
 * Sandbox configuration for keysas-virustotal (Landlock + Seccomp).
 * This process requires network access for HTTPS calls to the VT API,
 * hence a broader syscall whitelist than purely local daemons.
 */

pub use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetError, RulesetStatus, path_beneath_rules,
};

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    // Basic I/O
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::writev)?;
    ctx.allow_syscall(Syscall::readv)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::fsync)?;
    // Sockets — Unix (transit) + TCP (HTTPS to VT API)
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::listen)?;
    ctx.allow_syscall(Syscall::accept4)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::sendto)?;
    ctx.allow_syscall(Syscall::recvfrom)?;
    ctx.allow_syscall(Syscall::sendmmsg)?;
    ctx.allow_syscall(Syscall::recvmmsg)?;
    // Socket options / metadata (needed by ureq/rustls TCP stack)
    ctx.allow_syscall(Syscall::setsockopt)?;
    ctx.allow_syscall(Syscall::getsockopt)?;
    ctx.allow_syscall(Syscall::getsockname)?;
    ctx.allow_syscall(Syscall::getpeername)?;
    ctx.allow_syscall(Syscall::fcntl)?;
    // CPU feature detection by ring (rustls crypto backend)
    ctx.allow_syscall(Syscall::uname)?;
    // Files
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::fstat)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::pread64)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::access)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::faccessat)?;
    // Memory
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::mremap)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::madvise)?;
    ctx.allow_syscall(Syscall::brk)?;
    // Signals / threading
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::rt_sigprocmask)?;
    ctx.allow_syscall(Syscall::sigaltstack)?;
    ctx.allow_syscall(Syscall::futex)?;
    ctx.allow_syscall(Syscall::set_tid_address)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    // Misc
    ctx.allow_syscall(Syscall::prctl)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::arch_prctl)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::prlimit64)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::clock_gettime)?;
    ctx.allow_syscall(Syscall::clock_nanosleep)?;
    ctx.allow_syscall(Syscall::exit_group)?;
    ctx.allow_syscall(Syscall::fstatfs)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::dup2)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::dup3)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::poll)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::ppoll)?;
    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.load()?;
    Ok(())
}

pub fn landlock_sandbox() -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .set_compatibility(CompatLevel::HardRequirement)
        .create()?
        // TLS certificates, DNS resolution config, NSS config
        .add_rules(path_beneath_rules(
            &["/etc"],
            AccessFs::from_read(abi),
        ))?
        // NSS resolver libraries and TLS shared libraries (loaded lazily by glibc)
        .add_rules(path_beneath_rules(
            &["/usr/lib"],
            AccessFs::from_read(abi),
        ))?
        .restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            log::info!("keysas-virustotal is fully sandboxed using Landlock!")
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("keysas-virustotal is only partially sandboxed using Landlock!")
        }
        RulesetStatus::NotEnforced => {
            log::warn!(
                "keysas-virustotal: Not sandboxed with Landlock! Please update your kernel."
            )
        }
    }
    Ok(())
}
