//! The scalar route where IFMA does not run: an Fp in blst's layout, and the
//! verifier's curve work on it.
#![allow(
    clippy::needless_range_loop,
    reason = "Aeneas translates index loops into Lean, but not iterator adaptors"
)]

pub mod constants;
#[cfg(any(target_arch = "x86_64", test))]
pub mod decompress;
pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp6;
pub mod g1;
#[cfg(any(target_arch = "x86_64", test))]
pub mod g1_pair;
pub(crate) mod msm;
pub mod pairing;
