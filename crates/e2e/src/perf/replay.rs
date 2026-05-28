//! Drive PmBsHarness through the cached fixtures and collect the #[timed]
//! summary at the tail.

use std::time::{Duration, Instant};

use silver_common::{
    flamegraph_timer::{collect::enable, report::TimingStats},
    ssz_view::StatusView,
};

use crate::{
    mainnet_api::fetch_canonical_state_root,
    perf::Fixtures,
    utils::{PEER, PmBsHarness, block_slot},
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

    // Start collecting #[timed] samples BEFORE any STF code runs —
    // `BeaconStateTile::new_heap` calls `decompose_beacon_state`.
    enable();

    let mut h = PmBsHarness::new(&fixtures.state_ssz, n_blocks, blocks.len());
    let first_block_slot = block_slot(&blocks[0]);
    assert_eq!(StatusView::head_slot(h.local_status()) + 1, first_block_slot);

    h.connect_peer(final_slot);

    let (start, count, peer) = h.next_range_request();
    assert_eq!((start, count, peer), (first_block_slot, n_blocks, PEER));
    for b in blocks {
        h.inject_block(start, b);
    }

    // BS applies one block per `loop_body` (`adapter.consume_one`), so pump
    // until the head reaches the final block. We deliberately do NOT tick the
    // Controller here: an emitted `SyncUpdate::Following` would flip BS to
    // Following mode and let `ticker.tick()` advance state over wall-clock
    // time, diverging the head_state_root from the canonical value. Staying
    // in Syncing keeps the replay deterministic. Cap iterations so a stuck
    // replay fails loudly instead of hanging.
    let wall_start = Instant::now();
    let max_passes = n_blocks * 2 + 8;
    let mut passes = 0;
    loop {
        h.pump_bs();
        passes += 1;
        if h.head_state_slot() >= final_slot || passes >= max_passes {
            break;
        }
    }
    let wall_elapsed = wall_start.elapsed();

    assert!(
        h.head_state_slot() >= final_slot,
        "BS head should reach final block slot {final_slot}; got {}",
        h.head_state_slot(),
    );

    let head_state_root = h.head_state_root();
    // canonical-root assertion lives inside `replay`, not as a separate stage.
    // Canonical state-root check is best-effort: when the slot isn't
    // reachable on a public archive (typical for old fixtures) we still
    // want the perf numbers.
    match fetch_canonical_state_root(final_slot) {
        Some(expected_root) => {
            assert_eq!(
                head_state_root, expected_root,
                "post-catchup head_state_root must match canonical mainnet"
            );
            eprintln!("perf: state_root matches canonical mainnet ✓");
        }
        None => eprintln!(
            "perf: canonical state_root unavailable for slot {final_slot} — skipping correctness check"
        ),
    }

    ReplayOutcome {
        stats: TimingStats::collect(),
        validator_count: h.head_validator_count(),
        wall_elapsed,
        final_slot,
        head_state_root,
    }
}
