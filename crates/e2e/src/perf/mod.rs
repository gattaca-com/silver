//! Perf-regression pipeline over committed mainnet fixtures
//! (`crates/e2e/data/perf`).

pub mod fixtures_dir;
pub mod replay;
pub mod report;
pub mod thresholds;
pub mod workload;

use std::{fs, path::PathBuf};

pub use fixtures_dir::BlockFixtures;
pub use replay::ReplayOutcome;
pub use report::PerfReport;
pub use workload::BlockWorkload;

use crate::utils::PmBsHarness;

pub struct Fixtures {
    dir: BlockFixtures,
    pub finalized_slot: u64,
    pub blocks: Vec<Vec<u8>>,
    pub expected_head_state_root: [u8; 32],
    pub thresholds: Vec<thresholds::Threshold>,
}

impl Fixtures {
    /// `Err` if a fixture file is missing — usually `git lfs pull` wasn't run.
    pub fn load(fixtures: BlockFixtures) -> Result<Self, String> {
        let finalized_slot = fixtures
            .root()
            .read_finalized_slot()
            .map_err(|e| format!("{e} — run `git lfs pull` or `just perf-update-fixtures`"))?;
        let blocks: Vec<_> =
            fixtures.read_sorted_next_blocks().into_iter().map(|(_, b)| b).collect();

        if blocks.is_empty() {
            return Err(format!(
                "no next_block_*.ssz files under {} — run `git lfs pull` or \
                 `just perf-update-fixtures`",
                fixtures.root().path().display()
            ));
        }

        let expected_head_state_root = fixtures.read_expected()?;
        let thresholds = fixtures.read_thresholds()?;
        Ok(Self { dir: fixtures, finalized_slot, blocks, expected_head_state_root, thresholds })
    }

    /// Reads the finalized state and its pubkey sidecar only for the build,
    /// so neither stays in memory during the replay.
    pub fn harness(&self) -> PmBsHarness {
        let (state_ssz, _) = self.dir.root().read_finalized_state().expect("finalized state");
        // Empty when absent: the harness then decompresses every key.
        let pubkeys = fs::read(self.dir.root().finalized_pubkeys()).unwrap_or_default();
        PmBsHarness::with_pubkeys(&state_ssz, &pubkeys, self.blocks.len())
    }
}

pub fn run_perf_pipeline(output_dir: PathBuf) -> Result<PerfReport, String> {
    let fixtures = Fixtures::load(BlockFixtures::perf())?;
    eprintln!("perf: finalized slot {}", fixtures.finalized_slot);
    eprintln!("perf: fixtures dir = {}", fixtures.dir.root().path().display());

    let outcome = replay::replay(&fixtures);
    let report = PerfReport::new(outcome, &fixtures, output_dir);
    report.emit();
    Ok(report)
}
