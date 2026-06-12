//! Concurrent reader / single writer stress for `BeaconStateOwner` +
//! the fork rings. Exercises the seqlock protecting finalized writes and
//! the publish-state-id protocol for slot-delta visibility, using only
//! the public `StateReadView` surface — no test-only escape
//! hatches.
//!
//! Seqlock test (finalized tier): writer promotes a slot fork carrying two
//! block roots painted with the SAME tag into the slot group's base under one
//! `WriteGuard` (via `SlotStateGroup::finalize`). The base slot is held at 0 so
//! the promote always writes the same two adjacent cells (`FIN_CELL_A/B`).
//! Reader reads both via `finalized_block_roots()` and asserts they match — a
//! tear would surface as `old != new`.
//!
//! Delta-publish test (slot tier): writer rolls a slot-group fork tagged
//! `slot_tag(s)` (slot `s`, `block_roots[0] = slot_tag(s)`), records it on a
//! fresh `StateId` bundle via `slot_idx`, then `publish_state_id`. Reader sees
//! `delta_block_roots()[0] == slot_tag(view.slot())`.

use std::{
    ops::DerefMut,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use silver_beacon_state_data::{B256, BeaconStateOwner, StateId};

// Strictly below the slot-group ring capacity (256), which both the visibility
// forks (one per iteration) and the finalize-winner forks (one per 8) draw
// from. The publish-state-id protocol does NOT guard against wrap-around:
// rolling past N would overwrite a slot the reader may still be inspecting.
const ITERATIONS: u64 = 200;

// Two adjacent cells in the finalized `block_roots` circular buffer. The base
// slot is held at 0, so `promote` always writes the delta's two roots to cells
// 0 and 1 — both painted with the same tag inside one `WriteGuard`. The slot-
// delta path writes the fork's own (separate) `block_roots`, so no collision.
const FIN_CELL_A: usize = 0;
const FIN_CELL_B: usize = 1;

fn slot_tag(slot: u64) -> B256 {
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&slot.to_le_bytes());
    tag
}

#[test]
fn concurrent_reads_observe_consistent_state() {
    let mut control = BeaconStateOwner::pre_bootstrap();

    // Reader and writer rendezvous here so the reader is live and reading while
    // the writer mutates — the writer loop is microsecond-cheap on its own, so
    // without this it can finish before the reader is even scheduled.
    let start = Arc::new(Barrier::new(2));
    let reads = Arc::new(AtomicUsize::new(0));
    let bad = Arc::new(AtomicUsize::new(0));
    let saw_delta = Arc::new(AtomicBool::new(false));
    let saw_finalized_advance = Arc::new(AtomicBool::new(false));

    let reader = {
        let r_control = control.reader();
        let r_start = Arc::clone(&start);
        let r_reads = Arc::clone(&reads);
        let r_bad = Arc::clone(&bad);
        let r_saw_delta = Arc::clone(&saw_delta);
        let r_saw_finalized_advance = Arc::clone(&saw_finalized_advance);
        std::thread::spawn(move || {
            // Pre-publish scenario, deterministic: the writer publishes only
            // after the barrier, so this read must observe "no snapshot yet".
            assert!(
                r_control.read(&|_| ()).is_none(),
                "read returned a view before the first publish"
            );
            r_start.wait();
            // Read until every invariant the assertions check has been observed.
            // This is guaranteed reachable: after the writer's first finalize
            // (s=7) the base cell is non-zero, and every published state carries
            // a head delta — and the final state is stable, so even a slow reader
            // converges. No timing assumptions.
            loop {
                let read = r_control.read(&|v| {
                    let fin_roots = v.slot.finalized_block_roots();
                    let fin_a = fin_roots[FIN_CELL_A];
                    let fin_b = fin_roots[FIN_CELL_B];
                    let merged_slot = v.slot.slot_number();
                    let delta_roots = v.slot.delta_block_roots();
                    let delta_root0 = delta_roots.first().copied();
                    let has_delta = !delta_roots.is_empty();
                    (fin_a, fin_b, merged_slot, delta_root0, has_delta)
                });
                // `None` until the writer's first publish lands.
                let Some((fin_a, fin_b, merged_slot, delta_root0, has_delta)) = read else {
                    continue;
                };

                let mut errs = 0usize;

                // Seqlock invariant: writer paints both cells to the same
                // tag inside one guard. Reader must see them matched.
                if fin_a != fin_b {
                    errs += 1;
                }

                if has_delta {
                    r_saw_delta.store(true, Ordering::Relaxed);
                    // Slot-delta self-consistency: `block_roots[0]` tags
                    // the delta's slot, which is what `view.slot()`
                    // returns when a delta is present.
                    if delta_root0 != Some(slot_tag(merged_slot)) {
                        errs += 1;
                    }
                }
                if fin_a != [0u8; 32] {
                    r_saw_finalized_advance.store(true, Ordering::Relaxed);
                }

                r_bad.fetch_add(errs, Ordering::Relaxed);
                r_reads.fetch_add(1, Ordering::Relaxed);

                if r_saw_delta.load(Ordering::Relaxed) &&
                    r_saw_finalized_advance.load(Ordering::Relaxed)
                {
                    break;
                }
            }
        })
    };

    // Real committed entries for the tiers this test never re-rolls — the
    // bundle is assembled from honest per-tier ids, not defaults.
    let anchor = control.roll_fresh();

    // Writer = main thread. Release the reader so both run concurrently.
    start.wait();
    for s in 0..ITERATIONS {
        // Roll a slot-group fork tagged for slot `s`, then record it on the
        // bundle via `slot_idx` — the index the reader resolves (the other
        // tiers keep their setup-committed entries).
        let slot_idx = {
            let mut g = control.write();
            let mut sv = g.slot_states.roll_fresh();
            sv.state_mut().slot = s;
            sv.push_block_root(slot_tag(s));
            sv.commit()
        };

        // Now visible to readers.
        control.publish_state_id(StateId { slot_idx, ..anchor });

        // Periodically advance the finalized base by promoting a fork carrying
        // two roots painted with the same tag (cells 0,1 — base slot stays 0).
        // Both cells land under one `WriteGuard`; readers must see them matched
        // on every snapshot or the seqlock is broken.
        if s % 8 == 7 {
            let tag = slot_tag(s);
            let winner = {
                let mut g = control.write();
                let mut sv = g.slot_states.roll_fresh();
                sv.push_block_root(tag);
                sv.push_block_root(tag);
                sv.commit()
            };
            let mut g = control.write();
            g.deref_mut().slot_states.finalize(winner, &[winner]);
        }

        // Encourage interleaving.
        std::thread::yield_now();
    }

    // The reader self-terminates once it has observed both invariants; join
    // blocks until then. The final published state is stable and satisfies them
    // (last iter s=199 is a finalize: base cells 0,1 and the head delta all
    // tagged slot_tag(199)), so this converges with no timing assumptions.
    reader.join().expect("reader thread panicked");

    let r = reads.load(Ordering::Relaxed);
    let b = bad.load(Ordering::Relaxed);
    assert!(r > 0, "reader did not get to run");
    assert!(saw_delta.load(Ordering::Relaxed), "reader never observed a published slot delta");
    assert!(
        saw_finalized_advance.load(Ordering::Relaxed),
        "reader never observed finalized advance"
    );
    assert_eq!(b, 0, "{b} of {r} reads observed inconsistent state");
}
