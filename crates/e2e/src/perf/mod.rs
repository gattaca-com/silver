//! Mainnet perf-regression pipeline. Fixtures (finalized state + N following
//! blocks + expected post-state root) live committed under
//! `crates/e2e/data/perf` via git-lfs; `Fixtures::load` reads them, then
//! `replay → timing collect → report` runs hermetically.
//!
//! Refresh the fixtures with the `perf-update-fixtures` bin; the test
//! never touches the network.

pub mod cache;
pub mod replay;
pub mod report;
pub mod workload;

use std::path::{Path, PathBuf};

pub use replay::ReplayOutcome;
pub use report::PerfReport;
pub use workload::BlockWorkload;

pub struct Fixtures {
    pub finalized_slot: u64,
    pub state_ssz: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub expected_head_state_root: [u8; 32],
}

impl Fixtures {
    /// `Err` if a fixture file is missing — usually `git lfs pull` wasn't run.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let fixtures = cache::FixturesDir(dir);
        let (state_ssz, finalized_slot) = fixtures
            .read_finalized_state()
            .map_err(|e| format!("{e} — run `git lfs pull` or `just perf-update-fixtures`"))?;
        let blocks: Vec<_> =
            fixtures.read_sorted_next_blocks().into_iter().map(|(_, b)| b).collect();

        if blocks.is_empty() {
            return Err(format!(
                "no next_block_*.ssz files under {} — run `git lfs pull` or \
                 `just perf-update-fixtures`",
                dir.display()
            ));
        }

        let expected_head_state_root = fixtures.read_expected()?;
        Ok(Self { finalized_slot, state_ssz, blocks, expected_head_state_root })
    }
}

pub struct PerfConfig {
    pub fixtures_dir: PathBuf,
    pub output_dir: PathBuf,
}

/// `Err` on missing fixtures — run `git lfs pull` or `just
/// perf-update-fixtures`.
pub fn run_perf_pipeline(cfg: PerfConfig) -> Result<PerfReport, String> {
    let fixtures = Fixtures::load(&cfg.fixtures_dir)?;
    eprintln!("perf: finalized slot {}", fixtures.finalized_slot);
    eprintln!("perf: fixtures dir = {}", cfg.fixtures_dir.display());

    let outcome = replay::replay(&fixtures);
    let report = PerfReport::new(outcome, &fixtures, cfg.output_dir);
    report.emit();
    Ok(report)
}
