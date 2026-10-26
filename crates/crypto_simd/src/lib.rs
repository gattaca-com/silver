pub mod bls;
pub mod kzg;
pub(crate) mod portable;
mod sha256;

/// Whether the IFMA kernels run: built with the `simd` feature, on a CPU with
/// AVX-512F and AVX-512 IFMA. Elsewhere every operation takes its portable
/// path, except G2 decoding, which falls back to blst. Tests may turn the
/// kernels off with `SILVER_TEST_NO_IFMA`.
#[cfg(target_arch = "x86_64")]
pub fn ifma_available() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma") &&
        !off_in_tests("SILVER_TEST_NO_IFMA")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn ifma_available() -> bool {
    false
}

/// Whether the challenge hashes on the SHA extensions, which need SSE4.1 too.
/// Tests may turn them off with `SILVER_TEST_NO_SHA`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn sha_available() -> bool {
    is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("sse4.1") &&
        !off_in_tests("SILVER_TEST_NO_SHA")
}

#[cfg(all(test, target_arch = "x86_64"))]
fn off_in_tests(variable: &str) -> bool {
    std::env::var_os(variable).is_some()
}

#[cfg(all(not(test), target_arch = "x86_64"))]
fn off_in_tests(_variable: &str) -> bool {
    false
}

/// Whether the portable route's products can take their twins built for BMI2.
#[cfg(target_arch = "x86_64")]
fn bmi2_available() -> bool {
    is_x86_feature_detected!("bmi2")
}

/// False where the kernels cannot run, unless `SILVER_REQUIRE_IFMA` asks for
/// them.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn ifma_kernels_run() -> bool {
    assert!(
        ifma_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, no simd feature, \
         or SILVER_TEST_NO_IFMA"
    );
    ifma_available()
}

/// False where the SHA extensions cannot run, unless `SILVER_REQUIRE_SHA` asks
/// for them, or `SILVER_REQUIRE_IFMA`: every IFMA CPU has them.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn sha_kernel_runs() -> bool {
    let required = std::env::var_os("SILVER_REQUIRE_SHA").is_some() ||
        std::env::var_os("SILVER_REQUIRE_IFMA").is_some();
    assert!(
        sha_available() || !required,
        "SILVER_REQUIRE_SHA or SILVER_REQUIRE_IFMA is set, but the SHA extensions are off"
    );
    sha_available()
}
