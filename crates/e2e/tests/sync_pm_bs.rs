//! End-to-end: peer-manager + beacon-state on one spine. The synthetic peer
//! truncates each `BlocksByRange` request to 2 blocks and completes cleanly,
//! so PM needs two rounds to apply the 4 mainnet blocks pulled by
//! `make checkpoint-fixtures` — the path where a clean terminator must not be
//! read as proof that the unserved remainder is empty. Final head state_root
//! is cross-checked against the canonical mainnet value.

use silver_common::ssz_view::StatusView;
use silver_control::sync_engine::BATCH;
use silver_e2e::{
    mainnet_api::fetch_canonical_state_root,
    utils::{PmBsHarness, block_slot, scan_checkpoint_fixtures},
};

const EXPECTED_BLOCKS: usize = 4;

#[test]
#[ignore]
fn truncated_responses_drive_two_batches_against_real_checkpoint() {
    // Skip cleanly when fixtures are missing or the API is unreachable —
    // either makes the test meaningless rather than failing.
    let Some((checkpoint, blocks)) = scan_checkpoint_fixtures(EXPECTED_BLOCKS) else {
        eprintln!("skipping: run `make -C crates/e2e checkpoint-fixtures` first");
        return;
    };
    let final_slot = block_slot(&blocks[3]);
    let Some(expected_root) = fetch_canonical_state_root(final_slot) else {
        eprintln!("skipping: canonical state_root for slot {final_slot} unavailable");
        return;
    };

    // threshold=1 so a 4-slot-ahead peer qualifies for SyncingHead (the
    // default head_lag_threshold is 32).
    let mut h = PmBsHarness::new(&checkpoint, blocks.len());
    let first_batch_start = StatusView::head_slot(h.local_status()) + 1;
    assert_eq!(first_batch_start, block_slot(&blocks[0]));

    h.connect_peer(final_slot);

    h.drive_batch((first_batch_start, BATCH), &blocks[0..2]);
    h.pump_ctl();
    assert!(h.head_state_slot() >= block_slot(&blocks[1]));

    // no pump_ctl() after the final batch — Controller would emit
    // SyncUpdate::Following and let the ticker advance head_state_root past the
    // gold value.
    h.drive_batch((block_slot(&blocks[1]) + 1, BATCH), &blocks[2..4]);

    assert!(h.head_state_slot() >= final_slot);
    assert_eq!(h.head_state_root(), expected_root);
}
