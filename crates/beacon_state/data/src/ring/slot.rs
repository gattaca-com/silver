use std::ops::{Deref, DerefMut};

use super::Id;

/// Write handle for a fresh slot. The only way to get the slot's id is
/// [`commit`](Self::commit), which consumes the handle — nobody can hold an
/// id to a slot that is still being written.
pub struct Slot<'a, G, T> {
    value: &'a mut T,
    id: Id<G>,
}

impl<'a, G, T> Slot<'a, G, T> {
    #[inline]
    pub(super) fn new(value: &'a mut T, id: Id<G>) -> Self {
        Self { value, id }
    }

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
