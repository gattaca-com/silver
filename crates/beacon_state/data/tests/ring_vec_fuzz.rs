//! Fuzz-style single-writer / concurrent-reader stress for the
//! finalized-base + delta-ring design with HEAP-BACKED (`Vec`) payloads — the
//! realloc hazard class (pending / validators / longtail).
//!
//! Miniature of the exact production protocol, isolated from the beacon types:
//! - the writer rolls copy-on-write deltas (`Ring::roll_from`), mutates ONLY
//!   the unpublished head (append-only: a published slot is never written),
//!   then publishes its id through the control seqlock;
//! - finalization promotes the head delta into the base (GROWING the base `Vec`
//!   — a realloc) inside an odd-version write window, reanchors a fresh head on
//!   the new base, and frees everything older;
//! - readers run the optimistic-read protocol (spin on odd version, re-check
//!   the version after reading, retry on change) and assert every ACCEPTED read
//!   is consistent.
//!
//! Cell `i` always holds `tag(i)`, so any torn / stale / dangling read that
//! survives version validation trips the invariant. A plain `cargo test` run
//! catches materialized corruption; run under `cargo +nightly miri test` to
//! turn a latent use-after-free (reader dereferencing a `Vec` buffer freed by
//! a concurrent realloc, even when the value is later discarded by the retry)
//! into a hard error.
//!
//! Seeded like `hash_tree`'s fuzz: set `FUZZ_SEED` to reproduce a failure.

use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering, compiler_fence},
};

use flux::communication::Seqlock;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_beacon_state_data::{Id, Reset, Ring};

/// Ring group marker (the typed-id discipline, same as the beacon tiers).
enum Payloads {}

const RING_N: usize = 16;
/// Force a finalize before the ring can wrap (tail = last finalize anchor).
const MAX_ROLLS_PER_WINDOW: u32 = RING_N as u32 - 2;
const ITERATIONS: u32 = if cfg!(miri) { 60 } else { 4000 };

/// One fork's delta: values appended since finalization, heap-backed so every
/// growth step is realloc pressure. `vals[k]` is the value at absolute index
/// `start + k`; the base owns `[0, start)`.
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

/// Whole shared state: finalized base + the delta ring (mirrors
/// `BeaconState`'s base-groups + rings, one tier, one column).
struct State {
    base: Vec<u64>,
    ring: Ring<Payloads, VecDelta, RING_N>,
}

/// Control word published through the seqlock — mirrors `ControlInner`:
/// `version` odd ⇒ finalize in progress; `published` is the head fork id.
#[derive(Clone, Copy, Default)]
struct Ctrl {
    version: u64,
    published: Option<Id<Payloads>>,
}

/// Reader-side handle: raw pointer + control seqlock, exactly the
/// `BeaconStateReader` shape.
///
/// SAFETY: the writer keeps the `State` allocation alive for the readers'
/// lifetime and mutates it only per the publish / write-window protocol.
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

    let mut state = Box::new(State { base: Vec::new(), ring: Ring::default() });
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

                    // Optimistic read: every value must carry its index tag,
                    // and the delta must sit exactly on the base's end.
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

    // Seed the first head and publish it (version stays even).
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
        if rolls_in_window < MAX_ROLLS_PER_WINDOW && rng.next_u32() % 8 != 0 {
            // Append-only block: COW-roll a child of the published head and
            // grow its heap payload BEFORE publishing the new id. The slot the
            // readers are on is never touched.
            let mut w = state.ring.roll_from(head);
            let end = w.start + w.vals.len() as u64;
            for k in 0..1 + (rng.next_u32() as u64 % 5) {
                w.vals.push(tag(end + k));
            }
            head = w.commit();
            rolls_in_window += 1;
            publish(&ctrl, Ctrl { version, published: Some(head) });
        } else {
            // Finalize: odd version opens the write window, the base Vec
            // grows (realloc), the survivor reanchors on the new base, older
            // slots free. Readers spin or retry across this whole window.
            version += 1;
            publish(&ctrl, Ctrl { version, published: Some(head) });

            let winner = state.ring.get(head).clone();
            assert_eq!(winner.start as usize, state.base.len());
            state.base.extend_from_slice(&winner.vals); // promote (realloc)
            let mut w = state.ring.roll_fresh();
            w.start = state.base.len() as u64;
            head = w.commit();
            state.ring.free_outdated(&[head]); // tail = reanchored head
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
}
