use std::{
    fmt,
    hint::spin_loop,
    sync::{Arc, atomic::AtomicU64},
};

use flux::communication::Seqlock;

use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct MultiProducer {
    cache: *const TCache,
    state: Arc<Seqlock<AllocationState>>,
}

unsafe impl Send for MultiProducer {}
unsafe impl Sync for MultiProducer {}

impl MultiProducer {
    pub(in super::super) fn new(producer: Producer) -> Self {
        Self { cache: producer.cache, state: Arc::new(Seqlock::new(producer.state)) }
    }

    #[inline]
    fn claim(&self) -> AllocationGuard<'_> {
        loop {
            if let Some(guard) = self.try_claim() {
                return guard;
            }
            spin_loop();
        }
    }

    #[inline]
    fn try_claim(&self) -> Option<AllocationGuard<'_>> {
        let version = self.state.version.load(Ordering::Relaxed);
        if version & 1 != 0 {
            return None;
        }
        self.state
            .version
            .compare_exchange(version, version.wrapping_add(1), Ordering::AcqRel, Ordering::Relaxed)
            .ok()?;

        Some(AllocationGuard {
            version: &self.state.version,
            next_version: version.wrapping_add(2),
            // SAFETY: Every state access holds this exclusive writer claim,
            // including Debug. No optimistic copies race with these mutations.
            state: unsafe { &mut *self.state.data.get() },
        })
    }
}

impl SealedProducer for MultiProducer {
    fn tcache(&self) -> *const TCache {
        self.cache
    }
}

impl TCacheProducer for MultiProducer {
    fn publish_head(&self) {
        self.claim().state.publish_head(&self.cache_ref());
    }

    /// Contention retries internally; None means the allocation cannot fit.
    #[inline]
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation> {
        self.claim().state.reserve(self.cache_ref(), len, auto_commit)
    }
}

impl fmt::Debug for MultiProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("MultiProducer");
        debug.field("cache", &self.cache);
        if let Some(guard) = self.try_claim() {
            debug.field("state", &guard.state);
        } else {
            debug.field("state", &"<locked>");
        }
        debug.finish()
    }
}

// The claim covers reclamation and header initialization, never payload writes.
// Releasing it publishes the advanced allocation head only after headers exist.
struct AllocationGuard<'a> {
    version: &'a AtomicU64,
    next_version: u64,
    state: &'a mut AllocationState,
}

impl Drop for AllocationGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.version.store(self.next_version, Ordering::Release);
    }
}
