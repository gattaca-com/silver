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

#[test]
fn scenario_5_data_columns_before_block_imports_on_arrival() {
    common::run_scenario(&cases_dir().join("scenario_5_blob_da_before_block"));
}

#[test]
fn scenario_6_blob_block_staged_then_applied_on_data_columns() {
    common::run_scenario(&cases_dir().join("scenario_6_blob_staged_then_applied"));
}

#[test]
fn scenario_7_lapped_staged_block_is_refetched() {
    common::run_scenario(&cases_dir().join("scenario_7_blob_staged_lapped_then_refetched"));
}

#[test]
fn scenario_8_gloas_block_skips_new_payload() {
    common::run_scenario(&cases_dir().join("scenario_8_gloas_block_skips_new_payload"));
}

#[test]
fn scenario_9_gloas_empty_child_of_invalid_payload_imports() {
    common::run_scenario(&cases_dir().join("scenario_9_gloas_empty_child_of_invalid_payload"));
}

#[test]
fn scenario_10_gloas_full_child_of_invalid_payload_is_rejected() {
    common::run_scenario(&cases_dir().join("scenario_10_gloas_full_child_of_invalid_payload"));
}

#[test]
fn scenario_11_gloas_fcu_finalized_hash_is_bid_parent() {
    common::run_scenario(&cases_dir().join("scenario_11_gloas_fcu_finalized_hash"));
}
