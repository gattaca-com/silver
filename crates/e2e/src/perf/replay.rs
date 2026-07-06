//! Drive PmBsHarness through the cached fixtures and collect the #[timed]
//! summary at the tail.

use std::time::{Duration, Instant};

use silver_common::{profiler::InProcessReader, ssz_view::StatusView};
use silver_metrics::{TimingStats, fold_stats};

use crate::{
    perf::Fixtures,
    utils::{PmBsHarness, SYNTH_PEER_CONN_ID, block_slot, data_columns_available},
};

pub struct ReplayOutcome {
    pub stats: TimingStats,
    pub validator_count: usize,
    pub wall_elapsed: Duration,
    pub final_slot: u64,
    pub head_state_root: [u8; 32],
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

    let mut harness = PmBsHarness::new(&fixtures.state_ssz, n_blocks, blocks.len());
    let anchor_finalized_epoch = harness.fork_choice_finalized_epoch();
    let first_block_slot = block_slot(&blocks[0]);
    assert_eq!(StatusView::head_slot(harness.local_status()) + 1, first_block_slot);

    harness.connect_peer(final_slot);

    for event in &da_events {
        harness.emit_data_columns_available(*event);
    }

    // Max blocks by range for syncing head is 32
    let mut injected = 0;

    // Start before injection: `pump_bs` applies each batch inside this loop, so
    // timing only the tail catch-up would exclude most block applies.
    let wall_start = Instant::now();
    while injected < n_blocks {
        let (start, count, peer, request_id) = harness.next_range_request();
        assert_eq!((start, count, peer), (first_block_slot + injected, 32, SYNTH_PEER_CONN_ID));

        harness.pump_bs();
        for b in &blocks[injected as usize..injected as usize + 32] {
            harness.inject_block(start, b);
        }
        harness.inject_response_complete(request_id);
        harness.pump_ctl();
        injected += 32;
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

    ReplayOutcome {
        stats: fold_stats(&recorder.collect()),
        validator_count: harness.head_validator_count(),
        wall_elapsed,
        final_slot,
        head_state_root,
    }
}
