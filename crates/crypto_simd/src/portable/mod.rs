//! Scalar Fp and G1 arithmetic for MSM and the IFMA decoder's fallback.
#![allow(
    clippy::needless_range_loop,
    reason = "Aeneas translates index loops into Lean, but not iterator adaptors"
)]

pub mod constants;
#[cfg(target_arch = "x86_64")]
pub mod decompress;
pub mod fp;
pub mod g1;
#[cfg(target_arch = "x86_64")]
pub mod g1_pair;
pub(crate) mod msm;
