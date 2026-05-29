//! End-to-end: same wiring as `sync_pm_bs`, but a single big batch.
//! PM issues one `BlocksByRange { count = N }` request covering every
//! `next_block_*.ssz` fixture and BS applies them all in a single
//! `loop_body` pass. Stresses sustained STF + parser flow against a
//! ~100-block stretch of canonical mainnet, the regime where slot-N
//! body-offset corruption / proposer-cache bugs surface.
//!
//! Skipped unless at least `MIN_BLOCKS` (= 64) post-anchor blocks are
//! on disk — run `make -C crates/e2e checkpoint-fixtures-large` first.

use silver_common::ssz_view::StatusView;
use silver_e2e::{
    mainnet_api::fetch_canonical_state_root,
    utils::{PmBsHarness, block_slot, scan_checkpoint_fixtures},
};

const FIXTURES: &str = "tests/example_checkpoints";
/// Below this fixture count the test is uninteresting (covered by
/// `sync_pm_bs`'s 4-block setup). 64 blocks already spans 2 epochs and
/// catches body-parse / proposer-cache edge cases.
const MIN_BLOCKS: usize = 64;

#[test]
#[ignore = "ignored by default — run explicitly with `cargo test ... -- --ignored`"]
fn pm_drives_single_big_batch_against_real_checkpoint() {
    // Install a tracing subscriber driven by `RUST_LOG` so the test can
    // print BS/PM intermediate logs when run with `--nocapture`. `try_init`
    // makes this idempotent if another test already set one up.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let Some((checkpoint, blocks)) = scan_checkpoint_fixtures(FIXTURES, MIN_BLOCKS) else {
        eprintln!(
            "skipping: need >= {MIN_BLOCKS} blocks — run \
             `make -C crates/e2e checkpoint-fixtures-large` first"
        );
        return;
    };
    let n_blocks: u64 = blocks.len() as u64;
    let final_slot = block_slot(blocks.last().unwrap());
    let Some(expected_root) = fetch_canonical_state_root(final_slot) else {
        eprintln!("skipping: canonical state_root for slot {final_slot} unavailable");
        return;
    };

    // One batch covers everything.
    let mut h = PmBsHarness::new(&checkpoint, n_blocks, blocks.len());
    let first_block_slot = block_slot(&blocks[0]);
    assert_eq!(StatusView::head_slot(h.local_status()) + 1, first_block_slot);

    h.connect_peer(final_slot);

    h.drive_batch((first_block_slot, n_blocks), &blocks);

    assert!(
        h.head_state_slot() >= final_slot,
        "BS head should reach final block slot {final_slot}; got {}",
        h.head_state_slot(),
    );
    assert_eq!(
        h.head_state_root(),
        expected_root,
        "post-catchup head_state_root must match canonical mainnet"
    );
}
