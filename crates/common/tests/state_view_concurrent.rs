//! Concurrent reader / single writer stress for `ViewControl` +
//! `DeltaBuffer`. Writer mutates the `BeaconState` directly (slot deltas
//! without a lock, finalised state under a write guard). Reader uses
//! `ViewControl::read` and asserts every observed snapshot is internally
//! consistent.

use std::{
    ops::DerefMut,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use silver_common::{B256, BeaconState, BeaconStateOwner};

// Strictly below the slots `DeltaBuffer` capacity (256). The publish-offset
// protocol does NOT guard against wrap-around: rolling past N would
// overwrite a slot the reader may still be inspecting.
const ITERATIONS: u64 = 200;

fn slot_tag(slot: u64) -> B256 {
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&slot.to_le_bytes());
    tag
}

#[test]
fn concurrent_reads_observe_consistent_state() {
    let mut control = BeaconStateOwner::new(BeaconState::default());

    let done = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let bad = Arc::new(AtomicUsize::new(0));
    let saw_delta = Arc::new(AtomicBool::new(false));
    let saw_finalised_advance = Arc::new(AtomicBool::new(false));

    let reader = {
        let r_control = control.reader();
        let r_done = Arc::clone(&done);
        let r_reads = Arc::clone(&reads);
        let r_bad = Arc::clone(&bad);
        let r_saw_delta = Arc::clone(&saw_delta);
        let r_saw_finalised_advance = Arc::clone(&saw_finalised_advance);
        std::thread::spawn(move || {
            while !r_done.load(Ordering::Relaxed) {
                let (f_slot, f_header, delta) =
                    r_control.read(&|finalised, slot_delta, _epoch_delta| {
                        let f_slot = finalised.slot.slot.slot;
                        let f_header = finalised.slot.slot.latest_block_header.slot;
                        let delta = slot_delta
                            .map(|d| (d.slot.slot.slot, d.slot.block_roots.first().copied()));
                        (f_slot, f_header, delta)
                    });

                let mut errs = 0usize;

                // The writer assigns these two finalised fields inside a
                // single write guard. A consistent reader must see them
                // matched.
                if f_slot != f_header {
                    errs += 1;
                }

                if let Some((d_slot, d_root)) = delta {
                    r_saw_delta.store(true, Ordering::Relaxed);
                    // Slot delta is self-consistent: `block_roots[0]` tags
                    // `slot.slot`. The writer publishes the offset only
                    // after both fields are written.
                    if d_root != Some(slot_tag(d_slot)) {
                        errs += 1;
                    }
                    // Writer never publishes a delta whose slot precedes the
                    // finalised slot at publish time.
                    if d_slot < f_slot {
                        errs += 1;
                    }
                }
                if f_slot > 0 {
                    r_saw_finalised_advance.store(true, Ordering::Relaxed);
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

        // Periodically advance finalised. Both fields are set under the
        // same write guard.
        if s % 4 == 3 {
            let mut g = control.write();
            g.deref_mut().finalised.slot.slot.slot = s;
            g.deref_mut().finalised.slot.slot.latest_block_header.slot = s;
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
        saw_finalised_advance.load(Ordering::Relaxed),
        "reader never observed finalised advance"
    );
    assert_eq!(b, 0, "{} of {} reads observed inconsistent state", b, r);
}
