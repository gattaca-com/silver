//! The non-IFMA route without blst, for the batch-6 experiment: a scalar Fp in
//! blst's layout, and the verifier's curve work on it.
#![allow(
    clippy::needless_range_loop,
    reason = "Aeneas translates index loops into Lean, but not iterator adaptors"
)]

// The products are `#[target_feature]` functions: every one of them is unsafe
// to call for the same single reason, that `portable_available` must have been
// checked on this CPU, so the safety section lives here rather than on each
// function.
pub mod constants;
#[allow(clippy::missing_safety_doc)]
pub mod decompress;
#[allow(clippy::missing_safety_doc)]
pub mod fp;
#[allow(clippy::missing_safety_doc)]
pub mod g1;
#[allow(clippy::missing_safety_doc)]
pub mod g1_pair;
#[allow(clippy::missing_safety_doc)]
pub mod msm;

/// Whether the portable route can run: `Fp`'s product compiles for BMI2 and
/// ADX.
pub fn portable_available() -> bool {
    is_x86_feature_detected!("bmi2") && is_x86_feature_detected!("adx")
}
