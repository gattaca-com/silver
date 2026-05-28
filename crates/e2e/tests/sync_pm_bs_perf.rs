//! Perf-regression harness over `crates/e2e/data/perf` fixtures.
//! Run: `just perf-local` (see `data/perf/README.md`).

use std::path::PathBuf;

use silver_e2e::perf::{PerfConfig, run_perf_pipeline};

#[test]
#[ignore = "perf harness — run explicitly with `cargo test ... -- --ignored --nocapture`"]
fn sync_pm_bs_perf() {
    // Silence the per-block `tracing::info!` in BS — those skew p99 by
    // formatting on every block-apply.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cfg = PerfConfig {
        fixtures_dir: manifest.join("data/perf"),
        output_dir: manifest.join("../../target"),
    };

    let report = run_perf_pipeline(cfg).expect("perf pipeline");

    if let Err(e) = report.check_thresholds() {
        panic!("perf regression: {e}");
    }
}
