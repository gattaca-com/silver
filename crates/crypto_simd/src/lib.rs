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

/// IFMA where it runs, else the portable route where BMI2 and ADX run, else
/// blst. `SILVER_ROUTE` set to `ifma`, `portable` or `blst` forces a route,
/// for measurements; forcing one this CPU cannot run panics.
#[cfg(target_arch = "x86_64")]
pub fn route() -> Route {
    static ROUTE: OnceLock<Route> = OnceLock::new();
    *ROUTE.get_or_init(|| {
        let forced = std::env::var("SILVER_ROUTE").ok();
        match forced.as_deref() {
            None | Some("ifma") if ifma_runs() => Route::Ifma,
            None | Some("portable") if portable::portable_available() => Route::Portable,
            None | Some("blst") => Route::Blst,
            Some(other) => panic!("SILVER_ROUTE={other}: this CPU cannot run that route"),
        }
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn route() -> Route {
    Route::Blst
}

/// Whether the portable route hashes on the SHA extensions: where they and
/// SSE4.1 run, unless `SILVER_SHA=portable` asks for plain Rust, for
/// measurements.
#[cfg(target_arch = "x86_64")]
pub fn sha_extensions() -> bool {
    static EXTENSIONS: OnceLock<bool> = OnceLock::new();
    *EXTENSIONS.get_or_init(|| {
        is_x86_feature_detected!("sha") &&
            is_x86_feature_detected!("sse4.1") &&
            std::env::var("SILVER_SHA").ok().as_deref() != Some("portable")
    })
}

/// Every CPU with avx512ifma also has the SHA extensions, BMI2 and ADX, so one
/// observation serves the whole kernel.
#[cfg(target_arch = "x86_64")]
fn ifma_runs() -> bool {
    cfg!(feature = "simd") &&
        is_x86_feature_detected!("avx512f") &&
        is_x86_feature_detected!("avx512ifma") &&
        is_x86_feature_detected!("sha") &&
        is_x86_feature_detected!("sse4.1") &&
        portable::portable_available()
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
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma or SHA extensions, \
         or no simd feature"
    );
    ifma_available()
}
