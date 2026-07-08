use std::{
    cmp::Ordering,
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use flux_profiler::timed;

/// Typed handle to a ring slot owned by group `G`. Minted only by [`Ring<G>`],
/// so a slot id for one group can't be passed where another's is expected and
/// can't be forged outside the allocator.
pub struct Id<G> {
    seq: usize,
    _group: PhantomData<fn() -> G>,
}

impl<G> Id<G> {
    // Private to this module: only `Ring<G>` (and `Default`) mint/unwrap ids.
    #[inline]
    fn new(seq: usize) -> Self {
        Self { seq, _group: PhantomData }
    }

    #[inline]
    fn index(self) -> usize {
        self.seq
    }
}

// Manual impls: deriving would spuriously bind `G: Trait`, but the id is a
// plain seq regardless of the zero-sized phantom group marker.
impl<G> Clone for Id<G> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<G> Copy for Id<G> {}
impl<G> PartialEq for Id<G> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}
impl<G> Eq for Id<G> {}
impl<G> PartialOrd for Id<G> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<G> Ord for Id<G> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}
impl<G> Default for Id<G> {
    fn default() -> Self {
        Self::new(0)
    }
}
impl<G> fmt::Debug for Id<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.seq)
    }
}

/// Overlay a fork's append `log` onto a circular `ring`, entry `i` landing at
/// position `(start + i) % ring.len()` (wrapping).
pub(crate) fn write_ring_window<T: Copy>(ring: &mut [T], start: usize, log: &[T]) {
    let cap = ring.len();
    debug_assert!(log.len() <= cap, "delta log exceeds ring cap");
    for (i, x) in log.iter().enumerate() {
        ring[(start + i) % cap] = *x;
    }
}

/// Drop the prefix of a per-fork append log that a promoted winner already
/// folded into the base — the reanchor invariant for log-style deltas.
pub(crate) fn drain_promoted_prefix<T>(log: &mut Vec<T>, promoted_len: usize) {
    let drop = promoted_len.min(log.len());
    log.drain(..drop);
}

/// Reanchor each distinct survivor exactly once: duplicate ids map to the id
/// minted for their first occurrence, fresh ids come from `reanchor`.
#[timed]
pub(crate) fn reanchor_survivors<I: Copy + PartialEq>(
    survivors: &[I],
    mut reanchor: impl FnMut(I) -> I,
) -> Vec<I> {
    let mut fresh = Vec::with_capacity(survivors.len());
    for (i, &s) in survivors.iter().enumerate() {
        let new_id = match survivors[..i].iter().position(|&p| p == s) {
            Some(seen) => fresh[seen],
            None => reanchor(s),
        };
        fresh.push(new_id);
    }
    fresh
}

pub trait Reset {
    /// Resets to defaults ready for reuse.
    fn reset(&mut self);

    /// Resets with values from another instance.
    fn reset_from(&mut self, other: &Self);
}

/// A mutable handle to a ring slot plus its [`Id<G>`]. The id is reachable
/// **only** by [`commit`](Self::commit), which consumes the writer — so a
/// caller can mutate the slot, but can't obtain (or leak) its id without first
/// giving up write access. `Deref`/`DerefMut` expose the slot value.
pub struct Slot<'a, G, T> {
    value: &'a mut T,
    id: Id<G>,
}

impl<G, T> Slot<'_, G, T> {
    /// Consume the writer and surface the slot's id — the only way to get one.
    #[inline]
    pub fn commit(self) -> Id<G> {
        self.id
    }
}

impl<G, T> Deref for Slot<'_, G, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.value
    }
}

impl<G, T> DerefMut for Slot<'_, G, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}

/// Per-group delta ring: N reusable delta slots addressed by typed [`Id<G>`].
/// The ring is the **sole** minter of its ids — every roll hands back a
/// [`Slot`] writer, and the id only falls out of `Slot::commit` — so a caller
/// can never construct or pre-publish one. This is the boundary that makes a
/// published id unforgeable.
pub struct Ring<G, T, const N: usize> {
    /// Next seq to mint (= rolls so far); the live head is `next_seq - 1`.
    next_seq: usize,
    /// Oldest live seq. Starts at 0 — the first seq ever minted — so the
    /// wrap guard is armed from the first roll.
    tail_seq: usize,
    entries: Box<[T]>,
    _owner: PhantomData<fn() -> G>,
}

impl<G, T: Default, const N: usize> Default for Ring<G, T, N> {
    fn default() -> Self {
        assert!(N.is_power_of_two());
        Self {
            next_seq: 0,
            tail_seq: 0,
            // Per-slot default avoids the `T: Clone` bound that `vec![v; N]` would force.
            entries: (0..N).map(|_| T::default()).collect(),
            _owner: PhantomData,
        }
    }
}

impl<G, T: Reset, const N: usize> Ring<G, T, N> {
    /// Ring position of a sequence number.
    #[inline]
    fn pos(seq: usize) -> usize {
        seq & (N - 1)
    }

    /// Next head seq + its ring position, running the wrap guard. Does not
    /// advance the head — the caller fills the slot first.
    fn next_head(&self) -> (usize, usize) {
        let new_head = self.next_seq;
        let new_head_pos = Self::pos(new_head);

        if new_head - self.tail_seq >= N {
            tracing::warn!(new_head, tail_seq = self.tail_seq, N, "buffer is wrapping!!");
            let tail_pos = Self::pos(self.tail_seq);
            assert!(new_head_pos != tail_pos, "would trample head");
        }

        (new_head, new_head_pos)
    }

    #[inline]
    pub fn get(&self, id: Id<G>) -> &T {
        &self.entries[Self::pos(id.index())]
    }

    /// Roll a fresh head reset to defaults.
    pub fn roll_fresh(&mut self) -> Slot<'_, G, T> {
        let (new_head, new_head_pos) = self.next_head();
        self.entries[new_head_pos].reset();
        self.next_seq = new_head + 1;
        Slot { value: &mut self.entries[new_head_pos], id: Id::new(new_head) }
    }

    /// Roll a head COW-copied (`reset_from`) from `parent`.
    pub fn roll_from(&mut self, parent: Id<G>) -> Slot<'_, G, T> {
        let (new_head, new_head_pos) = self.next_head();

        let parent_pos = Self::pos(parent.index());
        let [new, src] = self
            .entries
            .get_disjoint_mut([new_head_pos, parent_pos])
            .expect("fresh slot aliases a source");
        new.reset_from(src);

        self.next_seq = new_head + 1;
        Slot { value: &mut self.entries[new_head_pos], id: Id::new(new_head) }
    }

    /// Roll a fresh head reset to defaults and hand it back as a writer
    /// alongside shared handles to two existing slots `a`, `b` — for filling
    /// the new slot in one pass from those sources without an intermediate
    /// copy. `a` and `b` may be the same slot (both are shared); each must
    /// be distinct from the fresh slot (guaranteed while the ring isn't
    /// overflowing — see [`next_head`](Self::next_head)'s wrap guard).
    pub fn roll_fresh_deriving(&mut self, a: Id<G>, b: Id<G>) -> (Slot<'_, G, T>, &T, &T) {
        let (new_head, new_pos) = self.next_head();
        self.next_seq = new_head + 1;
        let id = Id::new(new_head);

        let (a_pos, b_pos) = (Self::pos(a.index()), Self::pos(b.index()));
        if a_pos == b_pos {
            let [new, src] = self
                .entries
                .get_disjoint_mut([new_pos, a_pos])
                .expect("fresh slot aliases a source");
            new.reset();
            (Slot { value: new, id }, &*src, &*src)
        } else {
            let [new, av, bv] = self
                .entries
                .get_disjoint_mut([new_pos, a_pos, b_pos])
                .expect("fresh slot aliases a source");
            new.reset();
            (Slot { value: new, id }, &*av, &*bv)
        }
    }

    /// Reclaim every fork older than the oldest id in `live`; the ids in
    /// `live` themselves stay allocated (the oldest becomes the new tail).
    pub fn free_outdated(&mut self, live: &[Id<G>]) {
        if let Some(&oldest) = live.iter().min() {
            self.free(oldest);
        }
    }

    /// Advance the tail forward to `to` (the new oldest live slot); entries
    /// older than it are reclaimed and the wrap check relaxes accordingly.
    /// No-op if the tail is already at or past it.
    pub fn free(&mut self, to: Id<G>) {
        self.tail_seq = self.tail_seq.max(to.index());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum G {}

    #[derive(Clone, Default)]
    struct E(u64);

    impl Reset for E {
        fn reset(&mut self) {
            self.0 = 0;
        }

        fn reset_from(&mut self, other: &Self) {
            self.0 = other.0;
        }
    }

    /// Regression: `roll_fresh` used to leave the tail unseeded, disarming
    /// the wrap guard — wrapping onto a live parentless entry silently
    /// overwrote it instead of panicking.
    #[test]
    #[should_panic(expected = "would trample head")]
    fn fresh_roll_arms_wrap_guard() {
        let mut ring: Ring<G, E, 2> = Ring::default();
        ring.roll_fresh();
        ring.roll_fresh();
        ring.roll_fresh(); // seq 2 wraps onto live seq 0
    }

    /// Freeing below the live set relaxes the wrap guard so reanchor rolls
    /// fit; without it the same roll trips the guard.
    #[test]
    fn free_outdated_makes_room_for_reanchor_rolls() {
        let mut ring: Ring<G, E, 2> = Ring::default();
        let a = ring.roll_fresh().commit();
        let b = ring.roll_from(a).commit();
        ring.free_outdated(&[b]); // `a` is outdated; tail moves to `b`
        let c = ring.roll_from(b).commit(); // reuses `a`'s slot
        assert!(c > b);
    }
}
