//! One writer races optimistic readers through the production surface, on a
//! seeded random schedule: block rolls via `apply_block_view` (publish-last, no
//! write window), finalize windows via `write()` + `SlotStateGroup::finalize`,
//! and the slot-ring copy-grow that a long non-finality stretch forces. Every
//! block root for slot `s` is `slot_tag(s)`, so the moment a reader accepts a
//! wrong root — from a live fork's pages or from the promoted base's — the
//! test fails. Set `FUZZ_SEED` to reproduce a failure.

use std::{
    ops::DerefMut,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_beacon_state_data::{
    B256, BeaconState, BeaconStateOwner, EpochStateFinalized, SLOTS_PER_HISTORICAL_ROOT,
    SLOTS_RING_N, StateId, ValSeed,
};

// Finalize stays ineligible until the slot ring has been rolled past its
// capacity, so every run copy-grows the ring under a live reader (before
// growable rings this panicked with "would trample head"). The remaining
// iterations finalize at random, keeping windows short and races frequent.
const FORCED_ROLLS: u32 = SLOTS_RING_N as u32 + 8;
const ITERATIONS: u32 = FORCED_ROLLS + 240;

/// Mixed rather than the plain slot number so no tag is zero — a tag can never
/// be confused with the zero-initialised base.
fn slot_tag(slot: u64) -> B256 {
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&(slot.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1).to_le_bytes());
    tag
}

#[test]
fn fuzz_concurrent_reads_observe_consistent_state() {
    let seed: u64 =
        std::env::var("FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as u64
        });
    println!("fuzz_concurrent_reads_observe_consistent_state seed = {seed} (set FUZZ_SEED)");

    // One validator: `apply_block_view` refuses to operate on an empty
    // finalized state.
    let mut control = BeaconStateOwner::new(BeaconState::for_test(
        EpochStateFinalized::default(),
        &[ValSeed::default()],
        0,
    ));

    let start = Arc::new(Barrier::new(3));
    let stop = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let bad = Arc::new(AtomicUsize::new(0));
    let saw_delta = Arc::new(AtomicBool::new(false));
    let saw_promoted = Arc::new(AtomicBool::new(false));

    let readers: Vec<_> = (0..2)
        .map(|_| {
            let reader = control.reader();
            let (start, stop) = (start.clone(), stop.clone());
            let (accepted, bad) = (accepted.clone(), bad.clone());
            let (saw_delta, saw_promoted) = (saw_delta.clone(), saw_promoted.clone());
            std::thread::spawn(move || {
                // Deterministic: the writer publishes only after the barrier.
                assert!(
                    reader.read(&|_| ()).is_none(),
                    "read returned a view before the first publish"
                );
                start.wait();

                // Honouring `stop` alone lets a loaded machine deschedule a
                // reader for the writer's whole run and validate nothing. The
                // last published state is stable and passes every check below,
                // so waiting for one accepted read always converges.
                let mut validated = false;
                while !validated || !stop.load(Ordering::Acquire) {
                    let Some((errs, has_delta, promoted)) = reader.read(&|v| {
                        let fin_slot = v.slot.base_state().slot;
                        let head_slot = v.slot.slot_number();
                        let mut errs = 0usize;

                        // Every slot ever written carries its own tag, whether
                        // the page it lives on came from the fork or from the
                        // promoted base; a torn window surfaces as a root that
                        // isn't its slot's tag. Slot 0 is never written.
                        for s in head_slot.saturating_sub(7)..=head_slot {
                            if s > 0 && v.block_roots.at_slot(s) != slot_tag(s) {
                                errs += 1;
                            }
                        }

                        (errs, head_slot > fin_slot, fin_slot > 0)
                    }) else {
                        continue;
                    };

                    accepted.fetch_add(1, Ordering::Relaxed);
                    bad.fetch_add(errs, Ordering::Relaxed);
                    validated = true;
                    if has_delta {
                        saw_delta.store(true, Ordering::Relaxed);
                    }
                    if promoted {
                        saw_promoted.store(true, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    let mut rng = StdRng::seed_from_u64(seed);
    let mut head = control.roll_fresh();
    let mut rolls_in_window = 0u32;

    // Writer = main thread. Release the readers so both run concurrently.
    start.wait();
    for i in 0..ITERATIONS {
        // The first finalize is forced (so every seed promotes at least once);
        // the last iteration is always a roll, so a reader scheduled only at
        // the very end still observes a delta over a promoted base.
        let finalize = i >= FORCED_ROLLS &&
            i + 1 < ITERATIONS &&
            rolls_in_window > 0 &&
            (i == FORCED_ROLLS || rng.next_u32() % 8 == 0);

        if finalize {
            // Promote the head, reanchor the survivors, and publish the
            // reanchored bundle in the SAME window — readers must never
            // resolve a bundle whose slot id was already re-anchored.
            let mut guard = control.write();
            let bs = guard.deref_mut();
            bs.block_roots.finalize(&head, &[head], |s| s.block_roots_idx);
            let fresh = bs.slot_states.finalize(head.slot_idx, &[head.slot_idx]);
            head = StateId { slot_idx: fresh[0], ..head };
            guard.set_state_id(head);
            rolls_in_window = 0;
        } else {
            // Extend the head, reading its slot through the same public
            // surface the readers use — never recomputed here.
            let slot = control.read_view(head).slot.slot_number() + 1;

            head = {
                let (mut view, _epoch, _longtail) = control.apply_block_view(head);
                view.slot.state_mut().slot = slot;
                view.block_roots
                    .set((slot % SLOTS_PER_HISTORICAL_ROOT as u64) as u32, slot_tag(slot));
                view.commit(head.epoch_idx, head.longtail_idx)
            };
            control.publish_state_id(head);
            rolls_in_window += 1;
        }
    }

    stop.store(true, Ordering::Release);
    for reader in readers {
        reader.join().expect("reader thread panicked");
    }

    let (accepted, bad) = (accepted.load(Ordering::Relaxed), bad.load(Ordering::Relaxed));
    println!("accepted reads: {accepted}, inconsistent: {bad}");
    assert_eq!(bad, 0, "reader accepted an inconsistent view (seed {seed})");
    assert!(accepted > 0, "readers never observed a stable view");
    assert!(saw_delta.load(Ordering::Relaxed), "reader never observed a published slot delta");
    assert!(saw_promoted.load(Ordering::Relaxed), "reader never observed a promoted base");
}
