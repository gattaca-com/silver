//! Drive PmBsHarness through the cached fixtures and collect the #[timed]
//! summary at the tail.

use std::time::{Duration, Instant};

use silver_beacon_state::ssz_hash::{hash_tree_root_block_header, hash_tree_root_state};
use silver_beacon_state_data::{
    BeaconState, BeaconStateOwner, CheckpointChunk, SpecConfig, decode_checkpoint_pubkeys,
};
use silver_common::{profiler::InProcessReader, ssz_view::StatusView};
use silver_control::sync_engine::BATCH;
use silver_metrics::{TimingStats, fold_stats};

use crate::{
    perf::Fixtures,
    utils::{PmBsHarness, SYNTH_PEER_CONN_ID, block_slot, data_columns_available},
};

/// Destination for the FXT trace, from `PERF_FXT` (empty/unset ⇒ no dump).
pub fn fxt_path() -> Option<std::path::PathBuf> {
    std::env::var_os("PERF_FXT").filter(|s| !s.is_empty()).map(Into::into)
}

fn fxt_requested() -> bool {
    fxt_path().is_some()
}

pub struct ReplayOutcome {
    pub stats: TimingStats,
    pub fxt: Option<Vec<u8>>,
    pub validator_count: usize,
    pub wall_elapsed: Duration,
    pub final_slot: u64,
    pub head_state_root: [u8; 32],
}

/// Restart-equivalence gate: stream the finalized base out through the
/// production checkpoint cursor, reload it the way bootstrap does, and require
/// the re-derived `seed_anchor` block root to equal the fork-choice finalized
/// root. Catches a tier persisting its boot-time base while staying
/// live-correct — invisible to the head state-root check.
fn verify_checkpoint_restart(harness: &PmBsHarness) {
    let reader = harness.state_reader();
    let mut cursor = reader.begin_checkpoint().expect("published snapshot");
    let (mut ssz, mut pubkeys_raw, mut buf) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        match reader.checkpoint_chunk(&mut cursor, &mut buf).expect("checkpoint chunk") {
            CheckpointChunk::Ssz => ssz.extend_from_slice(&buf),
            CheckpointChunk::Pubkeys => pubkeys_raw.extend_from_slice(&buf),
            CheckpointChunk::Restarted => {
                ssz.clear();
                pubkeys_raw.clear();
            }
            CheckpointChunk::Done => break,
        }
    }

    let pubkeys = decode_checkpoint_pubkeys(&pubkeys_raw).expect("pubkeys sidecar");
    let state = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), Some(&pubkeys))
        .expect("decompose persisted checkpoint");
    let mut owner = BeaconStateOwner::new(state);
    let anchor = owner.roll_fresh();
    let rv = owner.read_view(anchor);

    let state_root = hash_tree_root_state(&rv);
    let mut header = rv.slot.state().latest_block_header;
    if header.state_root == [0u8; 32] {
        header.state_root = state_root;
    }
    let block_root = hash_tree_root_block_header(&header);
    assert_eq!(
        block_root,
        harness.fork_choice_finalized_root(),
        "restart from the persisted checkpoint (slot {}) would fail the parent precheck",
        cursor.slot(),
    );
    eprintln!("perf: checkpoint restart re-derives the finalized block root ✓");
}

/// Replay `fixtures.blocks` onto a freshly-built `PmBsHarness` anchored
/// at `fixtures.state_ssz`, then drain the in-process timing sink.
///
/// Panics if the harness fails to reach the final block slot — a stuck
/// replay should fail loudly rather than silently report bad timings.
pub fn replay(fixtures: &Fixtures) -> ReplayOutcome {
    let blocks = &fixtures.blocks;
    let n_blocks = blocks.len() as u64;
    let final_slot = block_slot(blocks.last().expect("non-empty blocks"));
    eprintln!("perf: applying {n_blocks} blocks up to slot {final_slot}");

    let da_events: Vec<_> = blocks.iter().filter_map(|b| data_columns_available(b)).collect();

    // Start before harness construction — `new_heap` already runs `#[timed]` STF
    // code.
    let recorder = InProcessReader::start();

    let mut harness = PmBsHarness::new(&fixtures.state_ssz, blocks.len());
    let anchor_finalized_epoch = harness.fork_choice_finalized_epoch();
    let first_block_slot = block_slot(&blocks[0]);
    assert_eq!(StatusView::head_slot(harness.local_status()) + 1, first_block_slot);

    harness.connect_peer(final_slot);

    for event in &da_events {
        harness.emit_data_columns_available(*event);
    }

    let mut injected = 0;

    // Start before injection: `pump_bs` applies each batch inside this loop, so
    // timing only the tail catch-up would exclude most block applies.
    let wall_start = Instant::now();
    while injected < n_blocks {
        let want = BATCH.min(n_blocks - injected);
        let (start, count, peer, request_id) = harness.next_range_request();
        assert_eq!((start, count, peer), (first_block_slot + injected, want, SYNTH_PEER_CONN_ID));

        harness.pump_bs();
        for b in &blocks[injected as usize..(injected + want) as usize] {
            harness.inject_block(start, b);
        }
        harness.inject_response_complete(request_id);
        harness.pump_ctl();
        injected += want;
    }

    // Stay in Syncing (no Controller tick) — Following mode would let
    // `ticker.tick()` advance head_state_root over wall-clock time and
    // diverge from canonical.
    let max_passes = n_blocks * 2 + 8;
    let mut passes = 0;
    loop {
        harness.pump_bs();
        passes += 1;
        if harness.head_state_slot() >= final_slot || passes >= max_passes {
            break;
        }
    }
    let wall_elapsed = wall_start.elapsed();

    assert!(
        harness.head_state_slot() >= final_slot,
        "BS head should reach final block slot {final_slot}; got {}",
        harness.head_state_slot(),
    );

    let head_state_root = harness.head_state_root();
    assert_eq!(
        head_state_root, fixtures.expected_head_state_root,
        "post-catchup head_state_root must match expected.json (regenerate fixtures \
         if STF logic legitimately changed)"
    );
    eprintln!("perf: state_root matches expected ✓");

    // Finalization is representation-only (promote delta window → base), so the
    // state_root check above also proves it stayed behavior-preserving. Assert
    // it actually fired: a fixture set too short to advance finality would make
    // the `finalize` frame a silent no-op and hide its cost.
    let finalized_epoch = harness.fork_choice_finalized_epoch();
    assert!(
        finalized_epoch > anchor_finalized_epoch,
        "replay never finalized: fork-choice finalized epoch stayed at {anchor_finalized_epoch} \
         — need more blocks (≥4 epochs) for finality to advance past the anchor",
    );
    eprintln!(
        "perf: finalized epoch {anchor_finalized_epoch} → {finalized_epoch} \
         ({} promotions) ✓",
        finalized_epoch - anchor_finalized_epoch,
    );

    let drainer = recorder.collect();
    let fxt = fxt_requested().then(|| drainer.fxt_trace());

    // After `collect` so the persist + full re-hash stay out of the timings.
    verify_checkpoint_restart(&harness);

    ReplayOutcome {
        stats: fold_stats(&drainer),
        fxt,
        validator_count: harness.head_validator_count(),
        wall_elapsed,
        final_slot,
        head_state_root,
    }
}
