#![no_std]

/// Decision: all access blocked — matches UsbAuthorization::Block (1)
pub const DECISION_BLOCK: u32 = 1;
/// Decision: read-only — matches UsbAuthorization::AllowRead (2)
pub const DECISION_ALLOW_READ: u32 = 2;
/// Decision: read/write — matches UsbAuthorization::AllowRW (3) or AllowAll (4)
pub const DECISION_ALLOW_RW: u32 = 3;
