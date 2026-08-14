use std::{cmp::Ordering, fmt, marker::PhantomData};

/// Handle to a ring slot. Only `G`'s [`Ring`] can create one, so ids from
/// different groups can't be mixed up.
pub struct Id<G> {
    seq: usize,
    _group: PhantomData<fn() -> G>,
}

impl<G> Id<G> {
    #[inline]
    pub(super) fn new(seq: usize) -> Self {
        Self { seq, _group: PhantomData }
    }

    #[inline]
    pub(super) fn index(self) -> usize {
        self.seq
    }
}

// Implemented by hand because derive would demand `G` implement each trait,
// even though the id is just a number and `G` is only a marker.
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
