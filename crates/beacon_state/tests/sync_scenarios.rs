mod common;

use std::path::PathBuf;

fn cases_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sync_scenarios")
}

#[test]
fn scenario_1_checkpoint_catchup() {
    common::run_scenario(&cases_dir().join("scenario_1_checkpoint_catchup"));
}
