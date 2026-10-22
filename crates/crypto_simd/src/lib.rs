pub mod bls;
pub mod kzg;
mod sha256;

/// Built without the `simd` feature, every operation takes its blst path, as
/// on a CPU without the instructions. Every CPU with avx512ifma also has the
/// SHA extensions, so one observation serves the whole kernel.
#[cfg(target_arch = "x86_64")]
pub fn simd_available() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma") &&
        is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("sse4.1")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn simd_available() -> bool {
    false
}

/// False where the kernels cannot run, unless `SILVER_REQUIRE_IFMA` asks for
/// them.
#[cfg(test)]
pub(crate) fn kernels_run() -> bool {
    assert!(
        simd_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma or SHA extensions, \
         or no simd feature"
    );
    simd_available()
}
