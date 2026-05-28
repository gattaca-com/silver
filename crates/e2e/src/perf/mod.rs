//! Self-contained mainnet perf-regression pipeline:
//!
//! ```text
//! [1] remote (if not cached) → [2] local files → [3] replay
//!                                              → [4] timing collect
//!                                              → [5] report
//! ```

pub mod cache;
pub mod remote;
pub mod replay;
pub mod report;
pub mod workload;

use std::{path::PathBuf, time::Duration};

pub use remote::MAX_ANCHOR_LAG_SLOTS;
pub use replay::ReplayOutcome;
pub use report::PerfReport;
pub use workload::BlockWorkload;

pub struct Fixtures {
    pub anchor_slot: u64,
    pub state_ssz: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
}

impl Fixtures {
    /// Stages 1+2 composed: fetch what's missing, then load from disk.
    /// `anchor_lag_slots` (clamped to [`MAX_ANCHOR_LAG_SLOTS`], `0` = at
    /// `finalized`) controls how far back to anchor. Succeeds offline with a
    /// usable cache; `Err` only on unrecoverable fetch/IO failure.
    pub fn ensure(
        dir: &std::path::Path,
        n_blocks: usize,
        anchor_lag_slots: u64,
        lookahead: u64,
        ttl: std::time::Duration,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create_dir_all({}): {e}", dir.display()))?;
        let cache = cache::FixtureCacheDir(dir);
        let state_path = cache.anchor_state_path();

        let refetched = remote::fetch_anchor_state(&state_path, anchor_lag_slots, ttl)?;
        let state_ssz = std::fs::read(&state_path)
            .map_err(|e| format!("read {}: {e}", state_path.display()))?;
        let anchor_slot = cache::read_state_slot(&state_ssz)?;

        // A fresh anchor invalidates previously-cached next-block files —
        // they belong to the prior anchor's chain.
        if refetched {
            cache.clear_next_blocks();
        }

        remote::fetch_following_blocks(dir, anchor_slot, n_blocks, lookahead)?;
        let blocks = cache.load_next_blocks(anchor_slot, n_blocks);

        Ok(Self { anchor_slot, state_ssz, blocks })
    }
}

pub struct PerfConfig {
    pub fixtures_dir: PathBuf,
    pub want_blocks: usize,
    pub anchor_lag_slots: u64,
    pub lookahead: u64,
    pub ttl: Duration,
    /// Where `perf-<label>.{json,folded}` will be written.
    pub output_dir: PathBuf,
}

/// Drive the full perf pipeline. Returns `None` on a clean skip (missing
/// blocks, archive unreachable) so the caller can `eprintln!` and exit
/// the test without failing CI when the network is down.
pub fn run_perf_pipeline(cfg: PerfConfig) -> Option<PerfReport> {
    let fixtures = match Fixtures::ensure(
        &cfg.fixtures_dir,
        cfg.want_blocks,
        cfg.anchor_lag_slots,
        cfg.lookahead,
        cfg.ttl,
    ) {
        Ok(f) if !f.blocks.is_empty() => f,
        Ok(_) => {
            eprintln!("skipping: fetched anchor but no following blocks were available");
            return None;
        }
        Err(e) => {
            eprintln!("skipping: fixture fetch failed ({e}) — offline? archive down?");
            return None;
        }
    };
    eprintln!("perf: anchor slot {}", fixtures.anchor_slot);
    eprintln!("perf: fixtures dir = {}", cfg.fixtures_dir.display());

    let outcome = replay::replay(&fixtures);
    let report = PerfReport::new(outcome, &fixtures, cfg.output_dir);
    report.emit();
    Some(report)
}
