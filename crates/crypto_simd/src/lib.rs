pub mod bls;
pub mod kzg;

/// Built without the `simd` feature, every operation takes its blst path, as
/// on a CPU without the instructions.
#[cfg(target_arch = "x86_64")]
pub fn simd_available() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn simd_available() -> bool {
    false
}
