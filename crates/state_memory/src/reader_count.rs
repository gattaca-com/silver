use std::{
    marker::PhantomData,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Optimistic reads in progress. `SeqCst` here orders the count against the
/// pointer swap that retires an allocation.
#[derive(Default)]
pub struct ReaderCount(AtomicUsize);

pub struct ReadGuard<'a>(&'a ReaderCount);

/// Proof that no reader holds a slice into an allocation retired before it
/// was taken. The borrow keeps it from outliving the count's owner, so it
/// cannot reach a later retire.
pub struct Quiescent<'a>(PhantomData<&'a ReaderCount>);

impl ReaderCount {
    /// Call before loading any pointer the read follows.
    pub fn enter(&self) -> ReadGuard<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        ReadGuard(self)
    }

    /// # Safety
    /// Every reader of the allocations this token frees holds a [`ReadGuard`]
    /// of this count while it reads them.
    pub unsafe fn quiescent(&self) -> Option<Quiescent<'_>> {
        (self.0.load(Ordering::SeqCst) == 0).then_some(Quiescent(PhantomData))
    }
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiescent_only_with_no_read_in_progress() {
        let readers = ReaderCount::default();
        let reading = readers.enter();
        // SAFETY: nothing is freed.
        assert!(unsafe { readers.quiescent() }.is_none());
        drop(reading);
        assert!(unsafe { readers.quiescent() }.is_some());
    }
}
