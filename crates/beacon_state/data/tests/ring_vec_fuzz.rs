//! One writer races optimistic readers through the production protocol:
//! append-only rolls with publish-last, copy-grows with no write window, and
//! odd/even finalize windows. Every cell `i` holds `tag(i)`, so the moment a
//! reader accepts a wrong value the test fails. Run under miri to turn a
//! latent use-after-free into a hard error; set `FUZZ_SEED` to reproduce a
//! failure.

use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering, compiler_fence},
};

use flux::communication::Seqlock;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_beacon_state_data::{Id, Reset, Ring};

enum Payloads {}

const RING_N: usize = 16;
const ITERATIONS: u32 = if cfg!(miri) { 60 } else { 4000 };

/// `vals[k]` is the value at absolute index `start + k`; the base owns
/// `[0, start)`. Heap-backed so every mutation is realloc pressure.
#[derive(Clone, Default)]
struct VecDelta {
    start: u64,
    vals: Vec<u64>,
}

impl Reset for VecDelta {
    fn reset(&mut self) {
        self.start = 0;
        self.vals.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.start = other.start;
        self.vals.clone_from(&other.vals);
    }
}

struct State {
    base: Vec<u64>,
    ring: Ring<Payloads, VecDelta>,
}

/// Mirrors `ControlInner`: `version` odd = finalize window open.
#[derive(Clone, Copy, Default)]
struct Ctrl {
    version: u64,
    published: Option<Id<Payloads>>,
}

// SAFETY: the writer keeps the allocation alive for the readers' lifetime
// and mutates it only per the publish / write-window protocol.
struct SharedState(*const State);
unsafe impl Send for SharedState {}
unsafe impl Sync for SharedState {}

fn tag(i: u64) -> u64 {
    i.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1
}

#[test]
fn fuzz_ring_vec_payloads_concurrent() {
    let seed: u64 =
        std::env::var("FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as u64
        });
    println!("fuzz_ring_vec_payloads_concurrent seed = {seed} (set FUZZ_SEED to reproduce)");

    let mut state = Box::new(State { base: Vec::new(), ring: Ring::new(RING_N) });
    let ctrl = Arc::new(Seqlock::new(Ctrl::default()));
    let shared = Arc::new(SharedState(&*state as *const State));

    let start = Arc::new(Barrier::new(3));
    let stop = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let bad = Arc::new(AtomicUsize::new(0));

    let readers: Vec<_> = (0..2)
        .map(|_| {
            let (shared, ctrl) = (shared.clone(), ctrl.clone());
            let (start, stop) = (start.clone(), stop.clone());
            let (accepted, bad) = (accepted.clone(), bad.clone());
            std::thread::spawn(move || {
                start.wait();
                while !stop.load(Ordering::Acquire) {
                    let (c, _) = ctrl.read_copy().expect("ctrl never empty");
                    compiler_fence(Ordering::Acquire);
                    if c.version & 1 == 1 {
                        std::hint::spin_loop(); // finalize in progress
                        continue;
                    }
                    let Some(id) = c.published else { continue };

                    // Every value must carry its index tag, and the delta
                    // must sit exactly on the base's end.
                    let state = unsafe { &*shared.0 };
                    let delta = state.ring.get(id);
                    let mut ok = delta.start as usize == state.base.len();
                    for (k, &v) in delta.vals.iter().enumerate() {
                        ok &= v == tag(delta.start + k as u64);
                    }
                    for (i, &v) in state.base.iter().enumerate().rev().take(8) {
                        ok &= v == tag(i as u64);
                    }

                    compiler_fence(Ordering::Acquire);
                    let (post, _) = ctrl.read_copy().expect("ctrl never empty");
                    if post.version != c.version {
                        continue; // finalize raced the read — discard
                    }
                    accepted.fetch_add(1, Ordering::Relaxed);
                    if !ok {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    let mut rng = StdRng::seed_from_u64(seed);

    let mut head = state.ring.roll_fresh().commit();
    let publish = |ctrl: &Seqlock<Ctrl>, c: Ctrl| {
        let (_, v) = ctrl.read_copy().expect("ctrl never empty");
        assert!(ctrl.write_at_version(&c, v), "single writer");
    };
    publish(&ctrl, Ctrl { version: 0, published: Some(head) });
    let mut version = 0u64;
    let mut rolls_in_window = 0u32;

    start.wait();
    for _ in 0..ITERATIONS {
        // Finalize is eligible only past the CURRENT capacity (capped so
        // windows stay short and finalize races stay frequent): the first
        // windows deterministically grow 16 -> 32 -> 64 -> 128, with readers
        // racing every swap.
        let forced_rolls = (state.ring.capacity() as u32).min(4 * RING_N as u32);
        if rolls_in_window <= forced_rolls || rng.next_u32() % 8 != 0 {
            head = {
                let mut w = state.ring.roll_from(head);
                let end = w.start + w.vals.len() as u64;
                for k in 0..1 + (rng.next_u32() as u64 % 5) {
                    w.vals.push(tag(end + k));
                }
                w.commit()
            };
            rolls_in_window += 1;
            publish(&ctrl, Ctrl { version, published: Some(head) });
        } else {
            // Finalize window: promote into the base (realloc), reanchor a
            // fresh head, free the rest.
            version += 1;
            publish(&ctrl, Ctrl { version, published: Some(head) });

            let winner = state.ring.get(head).clone();
            assert_eq!(winner.start as usize, state.base.len());
            state.base.extend_from_slice(&winner.vals);
            head = {
                let mut w = state.ring.roll_fresh();
                w.start = state.base.len() as u64;
                w.commit()
            };
            state.ring.free_outdated(&[head]);
            rolls_in_window = 0;

            version += 1;
            publish(&ctrl, Ctrl { version, published: Some(head) });
        }
    }

    stop.store(true, Ordering::Release);
    for r in readers {
        r.join().unwrap();
    }

    let (accepted, bad) = (accepted.load(Ordering::Relaxed), bad.load(Ordering::Relaxed));
    println!("accepted reads: {accepted}, inconsistent: {bad}");
    assert_eq!(bad, 0, "reader accepted an inconsistent view (seed {seed})");
    assert!(accepted > 0, "readers never observed a stable view");
    assert!(state.ring.capacity() > RING_N, "run never exercised a ring grow (seed {seed})");
}
