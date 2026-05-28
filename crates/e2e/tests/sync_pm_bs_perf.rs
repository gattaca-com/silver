//! Local + CI perf-regression harness. Reads committed mainnet fixtures
//! from `crates/e2e/data/perf` (finalized state + N following blocks +
//! expected.json, all git-lfs tracked), replays them through
//! `BeaconStateTile` + the `PeerManager`, asserts the head_state_root
//! matches `expected.json`, and reports per-function `#[timed]` cost +
//! workload to stderr / `target/perf-*.{json,folded}`.
//!
//! Pipeline lives under `silver_e2e::perf`:
//! `Fixtures::load → replay → TimingStats::collect → PerfReport`.
//! To refresh fixtures from mainnet, run `just perf-update-fixtures`.
//!
//! Run: `just perf-local`, or:
//! ```text
//! cargo test --release -p silver_e2e --test sync_pm_bs_perf -- --ignored --nocapture
//! ```

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

    run_perf_pipeline(cfg).expect("perf pipeline");
}
