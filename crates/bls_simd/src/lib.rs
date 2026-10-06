//! AVX-512 IFMA arithmetic in the BLS12-381 base field, eight elements per
//! step, for batched point kernels.

// The kernels are `#[target_feature]` functions: every one of them is unsafe to
// call for the same single reason, that `simd_available` must have been checked
// on this CPU, so the safety section lives here rather than on each function.
#[cfg(target_arch = "x86_64")]
pub mod constants;
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
pub mod fp8;

#[cfg(target_arch = "x86_64")]
pub fn simd_available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn simd_available() -> bool {
    false
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
