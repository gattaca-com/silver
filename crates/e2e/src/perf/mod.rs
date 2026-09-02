//! Perf-regression pipeline over committed mainnet fixtures
//! (`crates/e2e/data/perf`).

pub mod fixtures_dir;
pub mod replay;
pub mod report;
pub mod workload;

use std::path::PathBuf;

pub use fixtures_dir::BlockFixtures;
pub use replay::ReplayOutcome;
pub use report::PerfReport;
pub use workload::BlockWorkload;

pub struct Fixtures {
    pub finalized_slot: u64,
    pub state_ssz: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub expected_head_state_root: [u8; 32],
    pub thresholds: fixtures_dir::Thresholds,
}

impl Fixtures {
    /// `Err` if a fixture file is missing — usually `git lfs pull` wasn't run.
    pub fn load(fixtures: &BlockFixtures) -> Result<Self, String> {
        let (state_ssz, finalized_slot) = fixtures
            .root()
            .read_finalized_state()
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
        Ok(Self { finalized_slot, state_ssz, blocks, expected_head_state_root, thresholds })
    }
}

pub fn run_perf_pipeline(output_dir: PathBuf) -> Result<PerfReport, String> {
    let dir = BlockFixtures::perf();
    let fixtures = Fixtures::load(&dir)?;
    eprintln!("perf: finalized slot {}", fixtures.finalized_slot);
    eprintln!("perf: fixtures dir = {}", dir.root().path().display());

    let outcome = replay::replay(&fixtures);
    let report = PerfReport::new(outcome, &fixtures, output_dir);
    report.emit();
    Ok(report)
}
