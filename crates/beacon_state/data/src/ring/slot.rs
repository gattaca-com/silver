use std::ops::{Deref, DerefMut};

use super::{Id, RingGroup};

/// Write handle for a fresh slot. The only way to get the slot's id is
/// [`commit`](Self::commit), which consumes the handle — nobody can hold an
/// id to a slot that is still being written.
pub(crate) struct Slot<'a, G: RingGroup> {
    value: &'a mut G::Entry,
    id: Id<G>,
}

impl<'a, G: RingGroup> Slot<'a, G> {
    #[inline]
    pub(super) fn new(value: &'a mut G::Entry, id: Id<G>) -> Self {
        Self { value, id }
    }

    #[inline]
    pub fn commit(self) -> Id<G> {
        self.id
    }
}

impl<G: RingGroup> Deref for Slot<'_, G> {
    type Target = G::Entry;
    #[inline]
    fn deref(&self) -> &G::Entry {
        self.value
    }
}

impl<G: RingGroup> DerefMut for Slot<'_, G> {
    #[inline]
    fn deref_mut(&mut self) -> &mut G::Entry {
        self.value
    }
}
