//! Local perf-regression harness. Self-fetches the latest mainnet
//! `finalized` state (anchored back as far as retention allows) + N
//! following blocks, replays them through `BeaconStateTile` + the
//! `PeerManager`, and reports per-function `#[timed]` cost. The anchor
//! moves run-to-run, so the workload printed alongside the timings
//! records what the cost was paid against. The post-replay state root
//! is cross-checked against canonical mainnet when reachable.
//!
//! Pipeline lives under `silver_e2e::perf`:
//! `remote → cache → replay → TimingStats::collect → PerfReport`.
//! This test is just env-knob parsing + one call into the orchestrator.
//!
//! Env knobs (all optional): `SILVER_PERF_BLOCKS` (default 4),
//! `SILVER_PERF_FIXTURES_DIR`, `SILVER_PERF_ANCHOR_LAG_SLOTS`,
//! `SILVER_PERF_STATE_TTL_SECS` (default 7d), `SILVER_PERF_OUTPUT_JSON`.
//!
//! Run: `just perf-local 128`, or:
//! ```text
//! SILVER_PERF_BLOCKS=128 cargo test --release -p silver_e2e \
//!   --test sync_pm_bs_perf -- --ignored --nocapture
//! ```

use std::{path::PathBuf, time::Duration};

use silver_e2e::perf::{MAX_ANCHOR_LAG_SLOTS, PerfConfig, report, run_perf_pipeline};

/// Dedicated cache dir (not the make-managed `example_checkpoints`, which
/// the `sync_pm_bs*` tests read). Relative to the workspace target dir so
/// it's gitignored and the ~300 MB state never lands in the source tree.
const DEFAULT_FIXTURES: &str = "../../target/perf-fixtures";
const FIXTURES_ENV: &str = "SILVER_PERF_FIXTURES_DIR";
const OUTPUT_JSON_ENV: &str = "SILVER_PERF_OUTPUT_JSON";

const BLOCKS_ENV: &str = "SILVER_PERF_BLOCKS";
const TTL_ENV: &str = "SILVER_PERF_STATE_TTL_SECS";
const ANCHOR_LAG_ENV: &str = "SILVER_PERF_ANCHOR_LAG_SLOTS";
const DEFAULT_BLOCKS: usize = 4;
// 7 days: the anchor state bytes are cached locally so upstream retention
// is irrelevant once fetched, and reusing the same anchor all week keeps
// the workload stable across regression runs. A worker refreshes weekly
// (delete cache or let this TTL expire) so only one run/week pays the
// slow rate-limited block fetch.
const DEFAULT_TTL_SECS: u64 = 604_800;

fn fixtures_dir() -> PathBuf {
    match std::env::var(FIXTURES_ENV) {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_FIXTURES),
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

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

    let want_blocks = env_usize(BLOCKS_ENV, DEFAULT_BLOCKS);
    // Probe ~1.5 slots per wanted block so empty slots don't starve us.
    let lookahead = (want_blocks as u64 * 3 / 2).max(8);
    // Anchor back far enough that the requested blocks exist as canonical
    // history. Blocks past `finalized` exist up to head (~2 epochs), so we
    // only need to reach back `want_blocks − ~2 epochs`, clamped to the
    // archive's retention window. Explicit override via env wins.
    let anchor_lag_slots = env_u64(
        ANCHOR_LAG_ENV,
        (want_blocks as u64).saturating_sub(2 * 32).min(MAX_ANCHOR_LAG_SLOTS),
    );

    let output_dir = report::default_output_dir(
        std::env::var(OUTPUT_JSON_ENV).ok().as_deref(),
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
    );

    let cfg = PerfConfig {
        fixtures_dir: fixtures_dir(),
        want_blocks,
        anchor_lag_slots,
        lookahead,
        ttl: Duration::from_secs(env_u64(TTL_ENV, DEFAULT_TTL_SECS)),
        output_dir,
    };

    let _ = run_perf_pipeline(cfg);
}
