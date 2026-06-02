//! Concurrent reader / single writer stress for `BeaconStateOwner` +
//! `DeltaBuffer`. Exercises the seqlock protecting finalized writes and
//! the publish-offsets protocol for slot-delta visibility, using only
//! the public `StateDeltaReadView` surface — no test-only escape
//! hatches.
//!
//! Seqlock test (finalized tier): writer updates two adjacent cells of
//! `finalized.slot.block_roots` to the SAME slot-tag under one
//! `WriteGuard`. Reader reads both via `finalized_block_roots()` and
//! asserts they match — a tear would surface as `old != new`.
//!
//! Delta-publish test (slot tier): writer plants `slot_tag(s)` at
//! `block_roots[0]` of the slot delta, then `publish_offsets`. Reader
//! sees `delta_block_roots()[0] == slot_tag(view.slot())`.

use std::{
    ops::DerefMut,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use silver_beacon_state_data::{B256, BeaconState, BeaconStateOwner};

// Strictly below the slots `DeltaBuffer` capacity (256). The publish-offset
// protocol does NOT guard against wrap-around: rolling past N would
// overwrite a slot the reader may still be inspecting.
const ITERATIONS: u64 = 200;

// Two adjacent cells in the finalized `block_roots` circular buffer.
// Writer paints them with the same tag inside one `WriteGuard`; reader
// asserts they match. Chosen high enough that the slot-delta path
// (which writes `block_roots[0]`) cannot collide.
const FIN_TAG_A: usize = 4000;
const FIN_TAG_B: usize = 4001;

fn slot_tag(slot: u64) -> B256 {
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&slot.to_le_bytes());
    tag
}

#[test]
fn concurrent_reads_observe_consistent_state() {
    let mut control = BeaconStateOwner::new(BeaconState::empty());

    let done = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let bad = Arc::new(AtomicUsize::new(0));
    let saw_delta = Arc::new(AtomicBool::new(false));
    let saw_finalized_advance = Arc::new(AtomicBool::new(false));

    let reader = {
        let r_control = control.reader();
        let r_done = Arc::clone(&done);
        let r_reads = Arc::clone(&reads);
        let r_bad = Arc::clone(&bad);
        let r_saw_delta = Arc::clone(&saw_delta);
        let r_saw_finalized_advance = Arc::clone(&saw_finalized_advance);
        std::thread::spawn(move || {
            while !r_done.load(Ordering::Relaxed) {
                let (fin_a, fin_b, merged_slot, delta_root0, has_delta) = r_control.read(&|v| {
                    let fin_roots = v.finalized_block_roots();
                    let fin_a = fin_roots[FIN_TAG_A];
                    let fin_b = fin_roots[FIN_TAG_B];
                    let merged_slot = v.slot();
                    let delta_roots = v.delta_block_roots();
                    let delta_root0 = delta_roots.first().copied();
                    let has_delta = !delta_roots.is_empty();
                    (fin_a, fin_b, merged_slot, delta_root0, has_delta)
                });

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
            }
        })
    };

    // Writer = main thread.
    for s in 0..ITERATIONS {
        // Roll forward; mutate the new slot in place.
        let previous = control.slots().head();
        control.slots().roll(previous);
        let head = control.slots().head().expect("just rolled");
        let delta = control.slots().get_mut(head);
        delta.slot.slot.slot = s;
        delta.slot.block_roots.clear();
        delta.slot.block_roots.push(slot_tag(s));

        // Now visible to readers.
        control.publish_offsets(None, Some(head));

        // Periodically advance finalized. Both cells written under the
        // same `WriteGuard`, to the same tag — readers must see them
        // matched on every snapshot or the seqlock is broken.
        if s % 4 == 3 {
            let mut g = control.write();
            let tag = slot_tag(s);
            g.deref_mut().finalized.slot.block_roots[FIN_TAG_A] = tag;
            g.deref_mut().finalized.slot.block_roots[FIN_TAG_B] = tag;
        }

        // Encourage interleaving.
        std::thread::yield_now();
    }

    done.store(true, Ordering::Relaxed);
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
