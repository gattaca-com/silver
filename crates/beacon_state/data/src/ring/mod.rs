mod id;
mod slot;

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicPtr, Ordering as AtomicOrdering},
};

use flux_profiler::timed;
pub use id::Id;
pub use slot::Slot;

pub trait Reset {
    fn reset(&mut self);

    fn reset_from(&mut self, other: &Self);
}

struct RingBuf<T> {
    mask: usize,
    entries: Box<[T]>,
}

impl<T> RingBuf<T> {
    fn filled(capacity: usize, fill: impl FnMut() -> T) -> Box<Self> {
        assert!(capacity.is_power_of_two());
        let entries: Box<[T]> = std::iter::repeat_with(fill).take(capacity).collect();
        Box::new(Self { mask: capacity - 1, entries })
    }
}

/// Ring of slots addressed by ever-growing seq ids; doubles its buffer
/// whenever a roll wouldn't fit. `next_seq - 1` is the live head, and
/// `tail_seq` (the oldest live seq) advances on
/// [`free_outdated`](Self::free_outdated).
pub struct Ring<G, T> {
    next_seq: usize,
    tail_seq: usize,
    /// The live generation. Atomic so the grow swap pairs a `Release` store
    /// with the readers' `Acquire` loads — a reader that observes the new
    /// generation is guaranteed to see its copied contents.
    buf: AtomicPtr<RingBuf<T>>,
    /// Old generations, never freed or touched again until `Ring` drops: a
    /// reader that started before a grow still reads correct data from
    /// whichever one it resolved. All of them together stay smaller than the
    /// live buffer. Raw pointers (not `Box`) because a racing reader may
    /// still hold references into them.
    retired: Vec<*mut RingBuf<T>>,
    _owner: PhantomData<fn() -> G>,
}

// SAFETY: the raw pointers are uniquely owned by this struct (created from
// `Box` and freed only in `Drop`) — same threading rules as owning boxes.
unsafe impl<G, T: Send> Send for Ring<G, T> {}
unsafe impl<G, T: Send + Sync> Sync for Ring<G, T> {}

impl<G, T> Drop for Ring<G, T> {
    fn drop(&mut self) {
        // No reader can outlive the `Ring`: readers hold the state alive
        // through `Arc` (see `StateCell`).
        unsafe {
            drop(Box::from_raw(*self.buf.get_mut()));
            for &ptr in &self.retired {
                drop(Box::from_raw(ptr));
            }
        }
    }
}

impl<G, T: Default> Ring<G, T> {
    pub fn new(capacity: usize) -> Self {
        Self::filled(capacity, T::default)
    }
}

impl<G, T> Ring<G, T> {
    pub(crate) fn filled(capacity: usize, fill: impl FnMut() -> T) -> Self {
        Self {
            next_seq: 0,
            tail_seq: 0,
            buf: AtomicPtr::new(Box::into_raw(RingBuf::filled(capacity.next_power_of_two(), fill))),
            retired: Vec::new(),
            _owner: PhantomData,
        }
    }

    /// The live generation. The `Acquire` pairs with the grow swap's
    /// `Release`, so the generation's contents are visible to whoever loads
    /// the pointer.
    #[inline]
    fn buf(&self) -> &RingBuf<T> {
        // SAFETY: the pointer is always a live allocation — generations are
        // freed only in `Drop`, when no reader exists.
        unsafe { &*self.buf.load(AtomicOrdering::Acquire) }
    }

    /// Writer-side slot access; `&mut self` makes this thread the only
    /// mutator (racing readers only ever look at slots the writer isn't
    /// touching — the optimistic-reader discipline, see `StateCell`).
    #[inline]
    fn buf_mut(&mut self) -> &mut RingBuf<T> {
        // SAFETY: as in `buf`, plus `&mut self` excludes other writers.
        unsafe { &mut *self.buf.load(AtomicOrdering::Relaxed) }
    }

    #[inline]
    fn slot(&self, seq: usize) -> usize {
        seq & self.buf().mask
    }

    #[inline]
    fn pos(&self, id: Id<G>) -> usize {
        self.slot(id.index())
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf().mask + 1
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.next_seq - self.tail_seq > self.buf().mask
    }

    #[inline]
    pub fn get(&self, id: Id<G>) -> &T {
        let buf = self.buf();
        &buf.entries[id.index() & buf.mask]
    }

    /// Allocate the next slot and hand back read access to `parent`'s — for
    /// callers that build content elsewhere and write the slot only at
    /// commit time.
    pub(crate) fn roll_deriving(&mut self, parent: Option<Id<G>>) -> (Id<G>, &mut T, Option<&T>) {
        if let Some(p) = parent {
            let (id, new, src) = self.mint_from(p);
            (id, new, Some(src))
        } else {
            let (id, pos) = self.roll();
            (id, &mut self.buf_mut().entries[pos], None)
        }
    }

    /// Allocate the next slot, with read access to `parent`'s.
    fn mint_from(&mut self, parent: Id<G>) -> (Id<G>, &mut T, &T) {
        let parent_pos = self.pos(parent);
        let (id, pos) = self.roll();
        let [new, src] = self
            .buf_mut()
            .entries
            .get_disjoint_mut([pos, parent_pos])
            .expect("fresh slot aliases a source");
        (id, new, &*src)
    }

    #[inline]
    pub(crate) fn grow_if_full_with(
        &mut self,
        fill: impl FnMut() -> T,
        copy: impl FnMut(&T, &mut T),
    ) {
        if self.is_full() {
            self.grow_with(fill, copy);
        }
    }

    #[cold]
    fn grow_with(&mut self, fill: impl FnMut() -> T, mut copy: impl FnMut(&T, &mut T)) {
        let old = self.buf();
        let mut next = RingBuf::filled(old.entries.len() * 2, fill);
        for seq in self.tail_seq..self.next_seq {
            copy(&old.entries[seq & old.mask], &mut next.entries[seq & next.mask]);
        }
        tracing::warn!(capacity = next.entries.len(), "ring grew (non-finality)");
        // The `Release` store pairs with readers' `Acquire` loads of `buf`:
        // whichever generation a racing reader resolves, it sees complete
        // contents — the old one is retired untouched, the new one was fully
        // copied before the swap.
        let old = self.buf.swap(Box::into_raw(next), AtomicOrdering::Release);
        self.retired.push(old);
    }

    fn roll(&mut self) -> (Id<G>, usize) {
        let new_head = self.next_seq;
        let new_head_pos = self.slot(new_head);

        if self.is_full() {
            tracing::warn!(new_head, self.tail_seq, "buffer is wrapping!!");
            assert!(new_head_pos != self.slot(self.tail_seq), "would trample head");
        }

        self.next_seq = new_head + 1;
        (Id::new(new_head), new_head_pos)
    }

    pub fn free_outdated(&mut self, live: &[Id<G>]) {
        self.free_outdated_with(live.iter().copied(), |_| ());
    }

    /// Advance the tail past everything older than the oldest live id,
    /// handing each freed slot to `release` (for entries that own external
    /// resources).
    pub(crate) fn free_outdated_with(
        &mut self,
        live: impl IntoIterator<Item = Id<G>>,
        mut release: impl FnMut(&mut T),
    ) {
        let old_tail = self.tail_seq;
        if let Some(oldest) = live.into_iter().min() {
            self.tail_seq = self.tail_seq.max(oldest.index());
        }
        for seq in old_tail..self.tail_seq {
            let pos = self.slot(seq);
            release(&mut self.buf_mut().entries[pos]);
        }
    }
}

impl<G, T: Reset + Default> Ring<G, T> {
    fn grow_if_full(&mut self) {
        self.grow_if_full_with(T::default, |src, dst| dst.reset_from(src));
    }

    #[timed]
    pub fn roll_fresh(&mut self) -> Slot<'_, G, T> {
        self.grow_if_full();
        let (id, pos) = self.roll();
        let value = &mut self.buf_mut().entries[pos];
        value.reset();
        Slot::new(value, id)
    }

    #[timed]
    pub fn roll_from(&mut self, parent: Id<G>) -> Slot<'_, G, T> {
        self.grow_if_full();
        let (id, new, src) = self.mint_from(parent);
        new.reset_from(src);
        Slot::new(new, id)
    }

    #[timed]
    pub fn roll_fresh_deriving(&mut self, a: Id<G>, b: Id<G>) -> (Slot<'_, G, T>, &T, &T) {
        self.grow_if_full();
        if a == b {
            let (id, new, src) = self.mint_from(a);
            new.reset();
            return (Slot::new(new, id), src, src);
        }

        let (a_pos, b_pos) = (self.pos(a), self.pos(b));
        let (id, pos) = self.roll();
        let [new, av, bv] = self
            .buf_mut()
            .entries
            .get_disjoint_mut([pos, a_pos, b_pos])
            .expect("fresh slot aliases a source");
        new.reset();
        (Slot::new(new, id), &*av, &*bv)
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

    /// Rolling past capacity grows instead of trampling: every live id keeps
    /// resolving to its exact pre-grow contents.
    #[test]
    fn roll_past_capacity_grows_and_preserves_entries() {
        let mut ring: Ring<G, E> = Ring::new(4);
        let ids: Vec<_> = (0..10u64)
            .map(|v| {
                let mut slot = ring.roll_fresh();
                slot.0 = v + 10;
                slot.commit()
            })
            .collect();

        assert_eq!(ring.capacity(), 16);
        for (v, id) in ids.iter().enumerate() {
            assert_eq!(ring.get(*id).0, v as u64 + 10);
        }
    }

    /// Grow with the tail mid-buffer: live seqs whose old and new positions
    /// differ are copied over; freed seqs below the tail are not.
    #[test]
    fn grow_with_wrapped_tail() {
        let mut ring: Ring<G, E> = Ring::new(4);
        let mut ids = Vec::new();
        for v in 0..4u64 {
            ids.push({
                let mut slot = ring.roll_fresh();
                slot.0 = v;
                slot.commit()
            });
        }
        ring.free_outdated(&ids[2..]); // tail at seq 2
        for v in 4..8u64 {
            // seqs 4,5 wrap; 6 forces a grow
            ids.push({
                let mut slot = ring.roll_fresh();
                slot.0 = v;
                slot.commit()
            });
        }

        assert_eq!(ring.capacity(), 8);
        for (v, id) in ids.iter().enumerate().skip(2) {
            assert_eq!(ring.get(*id).0, v as u64);
        }
    }

    /// Freeing below the live set makes the next roll reuse the freed slot
    /// instead of growing.
    #[test]
    fn free_outdated_makes_room_for_reanchor_rolls() {
        let mut ring: Ring<G, E> = Ring::new(2);
        let a = ring.roll_fresh().commit();
        let b = ring.roll_from(a).commit();
        ring.free_outdated(&[b]); // `a` is outdated; tail moves to `b`
        let c = ring.roll_from(b).commit(); // reuses `a`'s slot
        assert!(c > b);
        assert_eq!(ring.capacity(), 2);
    }
}
