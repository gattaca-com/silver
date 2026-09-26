use std::sync::atomic::Ordering;

use super::{PRODUCER_EMITTER, TCacheCounters, TCacheRef};

const NONE: u64 = u64::MAX;
const UNRESOLVED: u8 = u8::MAX;

/// One party whose reads this consumer receives: the cache's producer, or a
/// forwarding consumer named at `declare`.
struct Emitter {
    name: &'static str,
    slot: u8,
    // Nothing this emitter still holds or will emit lies below it. NONE: no
    // bound, the emitter has not opened or has closed.
    bound: u64,
    // Snapshot of the emitter's published tail, applied once every queue this
    // consumer reads has drained since it was taken.
    pending: u64,
    // A read stamped by this emitter arrived since the last pass, so its
    // in-band floor is at least as new as any snapshot would be.
    heard: bool,
}

/// The emitter bounds of one consumer. The tail never passes the lowest one.
pub(super) struct Bounds {
    own: u8,
    emitters: Vec<Emitter>,
    claims_seen: u64,
}

impl Bounds {
    pub(super) fn new(own: usize, tail: u64) -> Self {
        let producer =
            Emitter { name: "", slot: PRODUCER_EMITTER, bound: tail, pending: NONE, heard: false };
        Self { own: own as u8, emitters: vec![producer], claims_seen: 0 }
    }

    pub(super) fn declare(&mut self, cache: TCacheRef, name: &'static str) {
        let slot = cache.consumer_index(name).map_or(UNRESOLVED, |slot| slot as u8);
        self.emitters.push(Emitter { name, slot, bound: NONE, pending: NONE, heard: false });
        self.claims_seen = cache.head().claims.load(Ordering::Acquire);
    }

    /// In-band floor from a received read. The highest seen holds: a
    /// re-acquired old read carries its old floor, and every emitter's floor
    /// is monotone while its slot lives. A reopened slot is caught by the
    /// claim counter in `pass`. False when `emitter` was not declared; it is
    /// then bounded on a spare entry so production keeps running.
    pub(super) fn note(&mut self, cache: TCacheRef, emitter: u8, floor: u64) -> bool {
        if emitter == self.own {
            return true;
        }
        if !self.emitters.iter().any(|e| e.slot == emitter) {
            // A declared name may have opened since the last pass.
            self.resolve(cache);
        }
        match self.emitters.iter_mut().find(|e| e.slot == emitter) {
            Some(e) => {
                e.bound = if e.bound == NONE { floor } else { e.bound.max(floor) };
                e.heard = true;
                true
            }
            None => {
                TCacheCounters::UndeclaredEmitter.inc();
                self.emitters.push(Emitter {
                    name: "",
                    slot: emitter,
                    bound: floor,
                    pending: NONE,
                    heard: true,
                });
                false
            }
        }
    }

    /// Re-resolves declared names after a slot claim. A name may have moved,
    /// or been reopened on the same slot with a lower tail, so its bound is
    /// dropped until its next snapshot.
    fn resolve(&mut self, cache: TCacheRef) {
        let claims = cache.head().claims.load(Ordering::Acquire);
        if claims == self.claims_seen {
            return;
        }
        self.claims_seen = claims;
        for e in self.emitters.iter_mut().filter(|e| !e.name.is_empty()) {
            e.slot = cache.consumer_index(e.name).map_or(UNRESOLVED, |slot| slot as u8);
            e.bound = NONE;
            e.pending = NONE;
        }
    }

    pub(super) fn limit(&self) -> u64 {
        self.emitters.iter().map(|e| e.bound).min().unwrap_or(NONE)
    }

    /// End of a pass over this consumer's queues. `drained`: every one of
    /// them ran empty at least once since the last pass, which licenses the
    /// pending snapshots. Then take a snapshot of every emitter not heard
    /// from, unless one is already waiting: waiting only makes it older,
    /// and older is only more conservative.
    pub(super) fn pass(&mut self, cache: TCacheRef, drained: bool) {
        self.resolve(cache);
        for e in &mut self.emitters {
            if drained && e.pending != NONE {
                e.bound = if e.bound == NONE { e.pending } else { e.bound.max(e.pending) };
                e.pending = NONE;
            }
            if e.pending == NONE && !e.heard && e.slot != UNRESOLVED {
                let tail = if e.slot == PRODUCER_EMITTER {
                    cache.producer_floor()
                } else {
                    cache.tail_of(e.slot as usize)
                };
                if tail == NONE {
                    e.bound = NONE;
                } else if e.bound == NONE || tail > e.bound {
                    e.pending = tail;
                }
            }
            e.heard = false;
        }
    }
}
