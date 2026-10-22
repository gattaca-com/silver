pub mod bls;
pub mod kzg;
#[cfg(target_arch = "x86_64")]
pub mod portable;
#[cfg(target_arch = "x86_64")]
mod sha256;

#[cfg(target_arch = "x86_64")]
use std::sync::OnceLock;

/// Where the verifier's work runs: on IFMA lanes, on the scalar portable
/// route, or in blst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Ifma,
    Portable,
    Blst,
}

/// IFMA where it runs, else the portable route. `SILVER_ROUTE` set to `ifma`,
/// `portable` or `blst` forces a route, for measurements; forcing one this
/// CPU cannot run panics.
#[cfg(target_arch = "x86_64")]
pub fn route() -> Route {
    static ROUTE: OnceLock<Route> = OnceLock::new();
    *ROUTE.get_or_init(|| {
        let forced = std::env::var("SILVER_ROUTE").ok();
        match forced.as_deref() {
            None | Some("ifma") if ifma_runs() => Route::Ifma,
            None | Some("portable") => Route::Portable,
            Some("blst") => Route::Blst,
            Some(other) => panic!("SILVER_ROUTE={other}: this CPU cannot run that route"),
        }
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn route() -> Route {
    Route::Blst
}

/// Whether the challenge hashes on the SHA extensions, which need SSE4.1 too.
/// Tests may turn them off with `SILVER_TEST_NO_SHA`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn sha_available() -> bool {
    is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("sse4.1") &&
        !off_in_tests("SILVER_TEST_NO_SHA")
}

#[cfg(target_arch = "x86_64")]
fn ifma_runs() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma")
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

/// Off the IFMA route, every operation takes its portable or blst path, as on
/// a CPU without the instructions; so too built without the `simd` feature.
pub fn ifma_available() -> bool {
    route() == Route::Ifma
}

/// False where the kernels cannot run, unless `SILVER_REQUIRE_IFMA` asks for
/// them.
#[cfg(test)]
pub(crate) fn kernels_run() -> bool {
    assert!(
        ifma_available() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
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
