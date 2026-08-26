mod common;

use std::path::PathBuf;

fn cases_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sync_scenarios")
}

#[test]
fn scenario_1_checkpoint_catchup() {
    common::run_scenario(&cases_dir().join("scenario_1_checkpoint_catchup"));
}

#[test]
fn scenario_2_blob_block_awaits_data_columns() {
    common::run_scenario(&cases_dir().join("scenario_2_blob_da"));
}

#[test]
fn scenario_3_blob_gossip_relayed_before_data_columns() {
    common::run_scenario(&cases_dir().join("scenario_3_blob_gossip_relay"));
}

#[test]
fn scenario_4_finalized_target_does_not_gate_on_data_availability() {
    common::run_scenario(&cases_dir().join("scenario_4_blob_da_syncing_finalized"));
}
