// SPDX-License-Identifier: GPL-3.0-only
/*
 * keysas-analyze
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * Sandbox configuration for keysas-analyze (Landlock + Seccomp)
 */

pub use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetError, RulesetStatus, make_bitflags, path_beneath_rules,
};

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    // Basic I/O
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::fsync)?;
    // Sockets (Unix)
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::listen)?;
    ctx.allow_syscall(Syscall::accept4)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::sendto)?;
    ctx.allow_syscall(Syscall::recvfrom)?;
    // Files
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::fstat)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::pread64)?;
    ctx.allow_syscall(Syscall::getdents64)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::access)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::faccessat)?;
    ctx.allow_syscall(Syscall::unlink)?;
    ctx.allow_syscall(Syscall::unlinkat)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::mkdir)?;
    ctx.allow_syscall(Syscall::mkdirat)?;
    ctx.allow_syscall(Syscall::rmdir)?;
    // Memory
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::mremap)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::madvise)?;
    ctx.allow_syscall(Syscall::brk)?;
    // Subprocess (Python tools, die, strings)
    ctx.allow_syscall(Syscall::execve)?;
    ctx.allow_syscall(Syscall::wait4)?;
    ctx.allow_syscall(Syscall::waitid)?;
    ctx.allow_syscall(Syscall::clone)?;
    ctx.allow_syscall(Syscall::clone3)?;
    ctx.allow_syscall(Syscall::pipe2)?;
    ctx.allow_syscall(Syscall::kill)?;
    ctx.allow_syscall(Syscall::getpid)?;
    ctx.allow_syscall(Syscall::getppid)?;
    ctx.allow_syscall(Syscall::getcwd)?;
    ctx.allow_syscall(Syscall::chdir)?;
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
    // Needed by Python
    ctx.allow_syscall(Syscall::getuid)?;
    ctx.allow_syscall(Syscall::geteuid)?;
    ctx.allow_syscall(Syscall::getgid)?;
    ctx.allow_syscall(Syscall::getegid)?;
    ctx.allow_syscall(Syscall::umask)?;
    ctx.allow_syscall(Syscall::dup)?;
    ctx.load()?;
    Ok(())
}

pub fn landlock_sandbox(tmp_dir: &str) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let allow_write = make_bitflags!(AccessFs::{ReadFile | ReadDir | WriteFile | MakeReg | RemoveFile});
    // External tools (diec, strings, python, olevba, pdfid) need Execute in addition to Read
    let allow_exec = make_bitflags!(AccessFs::{ReadFile | ReadDir | Execute});

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .set_compatibility(CompatLevel::HardRequirement)
        .create()?
        // Read + execute: binaries, shared libraries, Python environments
        .add_rules(path_beneath_rules(
            &["/usr", "/lib", "/lib64", "/opt"],
            allow_exec,
        ))?
        // Read-only: configuration files (no execute needed)
        .add_rules(path_beneath_rules(
            &["/etc"],
            AccessFs::from_read(abi),
        ))?;

    // Read-write: runtime directory for subprocess temp files
    // Directory is created by systemd RuntimeDirectory= before sandbox activation
    if let Ok(path_fd) = PathFd::new(tmp_dir) {
        ruleset = ruleset.add_rule(PathBeneath::new(path_fd, allow_write))?;
    } else {
        log::warn!("Could not add Landlock rule for {tmp_dir}, temp file analysis may not work");
    }

    let status = ruleset.restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            log::info!("keysas-analyze is fully sandboxed using Landlock!")
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("keysas-analyze is only partially sandboxed using Landlock!")
        }
        RulesetStatus::NotEnforced => {
            log::warn!("keysas-analyze: Not sandboxed with Landlock! Please update your kernel.")
        }
    }
    Ok(())
}
