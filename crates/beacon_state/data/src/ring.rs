use std::{
    cmp::Ordering,
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut, Range},
};

/// Typed handle to a ring slot owned by group `G`. Minted only by
/// [`RingIndex<G>`], so a slot id for one group can't be passed where another's
/// is expected and can't be forged outside the allocator.
pub struct Id<G> {
    seq: usize,
    _group: PhantomData<fn() -> G>,
}

impl<G> Id<G> {
    // Private to this module: only `RingIndex<G>` (and `Default`) mint/unwrap ids.
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

pub struct RingIndex<G, const N: usize> {
    next_seq: usize,
    tail_seq: usize,
    _owner: PhantomData<fn() -> G>,
}

impl<G, const N: usize> Default for RingIndex<G, N> {
    fn default() -> Self {
        assert!(N.is_power_of_two());
        Self { next_seq: 0, tail_seq: 0, _owner: PhantomData }
    }
}

impl<G, const N: usize> RingIndex<G, N> {
    #[inline]
    pub fn slot(&self, seq: usize) -> usize {
        seq & (N - 1)
    }

    #[inline]
    pub fn pos(&self, id: Id<G>) -> usize {
        self.slot(id.index())
    }

    pub fn roll(&mut self) -> (Id<G>, usize) {
        let new_head = self.next_seq;
        let new_head_pos = self.slot(new_head);

        if new_head - self.tail_seq >= N {
            tracing::warn!(new_head, tail_seq = self.tail_seq, N, "buffer is wrapping!!");
            assert!(new_head_pos != self.slot(self.tail_seq), "would trample head");
        }

        self.next_seq = new_head + 1;
        (Id::new(new_head), new_head_pos)
    }

    pub fn free_outdated(&mut self, live: &[Id<G>]) -> Range<usize> {
        let old_tail = self.tail_seq;
        if let Some(&oldest) = live.iter().min() {
            self.tail_seq = self.tail_seq.max(oldest.index());
        }
        old_tail..self.tail_seq
    }
}

pub struct Ring<G, T, const N: usize> {
    index: RingIndex<G, N>,
    entries: Box<[T]>,
}

impl<G, T: Default, const N: usize> Default for Ring<G, T, N> {
    fn default() -> Self {
        Self { index: RingIndex::default(), entries: (0..N).map(|_| T::default()).collect() }
    }
}

impl<G, T: Reset, const N: usize> Ring<G, T, N> {
    #[inline]
    pub fn get(&self, id: Id<G>) -> &T {
        &self.entries[self.index.pos(id)]
    }

    pub fn roll_fresh(&mut self) -> Slot<'_, G, T> {
        let (id, pos) = self.index.roll();
        self.entries[pos].reset();
        Slot { value: &mut self.entries[pos], id }
    }

    pub fn roll_from(&mut self, parent: Id<G>) -> Slot<'_, G, T> {
        let parent_pos = self.index.pos(parent);
        let (id, pos) = self.index.roll();
        let [new, src] =
            self.entries.get_disjoint_mut([pos, parent_pos]).expect("fresh slot aliases a source");
        new.reset_from(src);
        Slot { value: &mut self.entries[pos], id }
    }

    pub fn roll_fresh_deriving(&mut self, a: Id<G>, b: Id<G>) -> (Slot<'_, G, T>, &T, &T) {
        let (a_pos, b_pos) = (self.index.pos(a), self.index.pos(b));
        let (id, pos) = self.index.roll();

        if a_pos == b_pos {
            let [new, src] =
                self.entries.get_disjoint_mut([pos, a_pos]).expect("fresh slot aliases a source");
            new.reset();
            (Slot { value: new, id }, &*src, &*src)
        } else {
            let [new, av, bv] = self
                .entries
                .get_disjoint_mut([pos, a_pos, b_pos])
                .expect("fresh slot aliases a source");
            new.reset();
            (Slot { value: new, id }, &*av, &*bv)
        }
    }

    pub fn free_outdated(&mut self, live: &[Id<G>]) {
        self.index.free_outdated(live);
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
