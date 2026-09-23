use std::io::Write;

use super::*;

#[cfg(test)]
mod tests;

#[allow(private_bounds)]
pub trait TCacheProducer: SealedProducer {
    /// May publish skipped wrap padding even when no payload space is
    /// available.
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation>;

    /// Publishes the head and the floor. Once per loop, after every committed
    /// read of this producer has been handed to the spine: a floor published
    /// earlier could pass a read still held by the tile.
    fn publish_head(&self);

    /// Commits `len` bytes filled by `write`; `None` when the cache has no
    /// room for them.
    fn write_with(&mut self, len: usize, write: impl FnOnce(&mut [u8])) -> Option<TCacheRead> {
        let mut reservation = self.reserve(len, true)?;
        write(&mut reservation.buffer().ok()?[..len]);
        reservation.increment_offset(len);
        Some(reservation.read())
    }

    fn cache_ref(&self) -> TCacheRef {
        TCacheRef { cache: self.tcache() as *const c_void }
    }

    /// Unpinned: only for bytes this producer wrote and has not reclaimed.
    #[inline]
    fn read_buffer(&self, read: TCacheRead) -> Result<&[u8], Error> {
        let cache = unsafe { &*self.tcache() };
        if read.id != cache.id() {
            return Err(Error::UnexpectedCacheRef);
        }
        cache.read(read.seq).map(|(bytes, ..)| bytes)
    }

    fn reservation_buffer<'a>(
        &self,
        reservation: &'a mut Reservation,
    ) -> Result<&'a mut [u8], Error> {
        if reservation.cache.cache != (self.tcache() as *const c_void) {
            return Err(Error::UnexpectedCacheRef);
        }
        let buffer = reservation.writable_buffer()?;
        Ok(&mut buffer[reservation.offset..])
    }
}

/// Private trait.
trait SealedProducer {
    fn tcache(&self) -> *const TCache;
}

#[derive(Debug)]
pub struct Producer {
    pub(super) cache: *const TCache,
    state: AllocationState,
}

unsafe impl Send for Producer {}
unsafe impl Sync for Producer {}

impl Producer {
    pub(super) fn new(cache: Box<TCache>) -> Self {
        let state = AllocationState {
            seq: 0,
            min_allocation: 0,
            reclaimed_seq: 0,
            space: cache.len,
            retain_from: u64::MAX,
        };
        Self { cache: Box::into_raw(cache), state }
    }

    pub fn next_seq(&self) -> u64 {
        self.state.seq
    }

    /// Everything below `seq` may be reclaimed once consumers follow the
    /// published floor, and nothing below it is emitted again; the caller's
    /// retention policy, published as this producer's floor. Monotone.
    /// Publishes at once, so the caller must have handed every committed read
    /// to the spine, as `publish_head` requires.
    pub fn retain_from(&mut self, seq: u64) {
        debug_assert!(
            self.state.retain_from == u64::MAX || seq >= self.state.retain_from,
            "retention moved backwards"
        );
        self.state.retain_from = seq;
        // Observe every commit so far, so the published floor is the boundary
        // itself and not a stale `min_allocation` below it.
        let cache = self.cache_ref();
        self.state.reclaim(&cache);
        self.state.publish_head(&cache);
    }

    /// A producer-side claim cannot survive an allocation, even after the view
    /// has been consumed.
    ///
    /// ```compile_fail
    /// use silver_common::{SubLayout, TCache, TCacheId, TCacheProducer};
    /// let mut producer = TCache::producer(TCacheId::ControlSlot, 1 << 16);
    /// let reference = producer.sub_reservation(
    ///     SubLayout { parts: 1, first_len: 4, second_len: 2 }, b"", b""
    /// ).unwrap();
    /// let claim = producer.view_sub_reservation(reference).unwrap().claim(0).unwrap();
    /// let next = producer.reserve(32, false);
    /// claim.write(b"cell", b"pf").unwrap();
    /// ```
    #[inline]
    pub fn view_sub_reservation(
        &self,
        reference: SubReservationRef,
    ) -> Result<SubReservationView<'_>, SubReservationError> {
        SubReservationView::from_producer(self, reference)
    }

    /// The descriptor does not pin storage. Retention boundaries or acquired
    /// owners must protect it across subsequent allocations.
    pub fn sub_reservation(
        &mut self,
        layout: SubLayout,
        prefix: &[u8],
        middle: &[u8],
    ) -> Result<SubReservationRef, SubReservationError> {
        let reference = self.uninitialized_sub_reservation(layout, prefix.len(), middle.len())?;
        self.view_sub_reservation(reference)?.initialize(prefix, middle)?;
        Ok(reference)
    }

    pub fn uninitialized_sub_reservation(
        &mut self,
        layout: SubLayout,
        prefix_len: usize,
        middle_len: usize,
    ) -> Result<SubReservationRef, SubReservationError> {
        let length = layout
            .reservation_bytes(prefix_len, middle_len)
            .ok_or(SubReservationError::InvalidLayout)?;
        let reservation = self.reserve(length, false).ok_or(SubReservationError::CacheFull)?;
        Ok(SubReservationRef::new(reservation, layout, prefix_len, middle_len))
    }
}

impl SealedProducer for Producer {
    fn tcache(&self) -> *const TCache {
        self.cache
    }
}

impl TCacheProducer for Producer {
    fn publish_head(&self) {
        self.state.publish_head(&self.cache_ref());
    }

    /// Return requested buffer space, if available.
    /// If None is returned, caller should retry.
    /// if `auto_commit` the reservation will be commited as soon as it is
    /// filled. otherwise it must ber manually committed by calling `flush`.
    #[inline]
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation> {
        let cache = self.cache_ref();
        self.state.reserve(cache, len, auto_commit)
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocationState {
    seq: u64,
    // Stops reuse at the first reservation not yet observed committed or aborted.
    min_allocation: u64,
    reclaimed_seq: u64,
    space: u32,
    // Retention boundary set by the owner; u64::MAX when none.
    retain_from: u64,
}

impl AllocationState {
    fn publish_head(&self, cache: &TCache) {
        cache.head().seq.store(self.seq, Ordering::Release);
        self.publish_floor(cache);
        cache.record_head(self.seq);
    }

    /// The promise stamped on every read: nothing this producer emits later
    /// lies below it. Uncommitted reservations may still be emitted, and so
    /// may anything retained.
    #[inline]
    fn floor(&self) -> u64 {
        self.min_allocation.min(self.retain_from)
    }

    fn publish_floor(&self, cache: &TCache) {
        cache.head().floor.store(self.floor(), Ordering::Release);
    }

    /// `floor` is sampled here, under the allocator's claim: `min_allocation`
    /// bounds every reservation still uncommitted, this one included, and
    /// `retain_from` everything the owner may emit again.
    #[inline]
    fn reserve(&mut self, cache: TCacheRef, len: usize, auto_commit: bool) -> Option<Reservation> {
        if len > cache.capacity() - size_of::<Slot>() {
            return None;
        }
        let reservation_len = cache.reserve_len(self.seq, len);
        if reservation_len > self.space as usize ||
            self.seq - self.reclaimed_seq > (cache.len >> 4) as u64
        // for 32MB buffer, reclaim every 2MB reserved
        {
            self.reclaim(&cache);
            if reservation_len > cache.capacity() {
                // The payload fits, but cannot share a record with wrap padding.
                let padding = cache.capacity() - cache.index(self.seq);
                let (seq, reserved) =
                    cache.reserve(self.seq, self.space, (padding - size_of::<Slot>()) as u32)?;
                self.seq += reserved as u64;
                self.space -= reserved as u32;
                cache.commit(seq, false);
                self.reclaim(&cache);
            }
        }
        cache.reserve(self.seq, self.space, len as u32).map(|(seq, reservation_len)| {
            self.seq += reservation_len as u64;
            self.space -= reservation_len as u32;
            let floor = self.floor();
            Reservation { cache, seq, offset: 0, committed: false, auto_commit, floor }
        })
    }

    /// Publishes nothing: head and floor move together in `publish_head`,
    /// which the owning tile calls once its committed reads are on the spine.
    /// A floor published here, mid-batch, could pass a read the tile still
    /// holds.
    fn reclaim(&mut self, cache: &TCache) {
        self.reclaimed_seq = self.seq;
        while self.min_allocation < self.seq {
            let slot = cache.slot_at(cache.index(self.min_allocation));
            if slot.seq.load(Ordering::Acquire) != self.min_allocation {
                break;
            }
            debug_assert!(
                slot.reservation_len > 0 &&
                    slot.reservation_len as u64 <= self.seq - self.min_allocation
            );
            self.min_allocation += slot.reservation_len as u64;
        }
        self.space = cache.space(self.seq, self.min_allocation);
    }
}

#[derive(Debug)]
pub struct Reservation {
    pub(super) cache: TCacheRef,
    pub(super) seq: u64,
    offset: usize,
    pub(super) committed: bool,
    auto_commit: bool,
    floor: u64,
}

unsafe impl Send for Reservation {}
unsafe impl Sync for Reservation {}

impl Reservation {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn remaining(&self) -> Result<usize, std::io::Error> {
        let buffer = self.buffer()?;
        Ok(buffer.len() - self.offset)
    }

    pub fn increment_offset(&mut self, len: usize) {
        let Ok(buffer_len) = self.buffer().map(|buffer| buffer.len()) else {
            return;
        };
        self.offset += len;
        if self.auto_commit && self.offset == buffer_len {
            tracing::trace!(seq = self.seq, len = buffer_len, "recv committed");
            self.cache.commit(self.seq, true);
            self.committed = true;
        }
    }

    #[inline]
    fn writable_buffer(&self) -> Result<&mut [u8], Error> {
        if self.committed {
            return Err(Error::Committed);
        }
        self.cache.write(self.seq)
    }

    pub fn buffer(&self) -> Result<&mut [u8], std::io::Error> {
        self.writable_buffer().map_err(std::io::Error::other)
    }

    /// Buffer slice from the current write offset to the end of the
    /// reservation. Use this when successive writes must not overwrite
    /// earlier bytes (e.g. a framed header followed by body chunks).
    pub fn remaining_buffer(&self) -> Result<&mut [u8], std::io::Error> {
        let buf = self.buffer()?;
        Ok(&mut buf[self.offset..])
    }

    pub fn read(&self) -> TCacheRead {
        TCacheRead {
            id: self.cache.id(),
            emitter: PRODUCER_EMITTER,
            seq: self.seq,
            floor: self.floor,
        }
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

impl Write for Reservation {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buffer = self.buffer()?;
        let buffer_len = buffer.len();
        if buf.len() + self.offset > buffer_len {
            tracing::error!(
                reservation_len = buffer.len(),
                offset = self.offset,
                data_len = buf.len(),
                "tried to write > reservation"
            );
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        buffer[self.offset..self.offset + buf.len()].copy_from_slice(buf);
        self.offset += buf.len();

        if self.auto_commit && self.offset == buffer_len {
            self.cache.commit(self.seq, true);
            self.committed = true;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.committed {
            self.cache.commit(self.seq, true);
            self.committed = true;
        }
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            tracing::debug!(
                seq = self.seq,
                offset = self.offset,
                tcache = self.cache.name(),
                "aborting reservation"
            );
            self.cache.commit(self.seq, false);
        }
    }
}
