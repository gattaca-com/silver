use std::io::Write;

use super::*;

#[cfg(test)]
mod tests;

#[allow(private_bounds)]
pub trait TCacheProducer: SealedProducer {
    /// Called by the owning tile first thing in every loop. Reads committed in
    /// earlier loops are on the spine by now, so the floor may cover them;
    /// reads this loop commits stay above it until the next call. Walks the
    /// commit chain, which touches only this producer's slot headers, and
    /// stores to the shared head only when the floor moved `len / 16` or the
    /// producer is short of space.
    fn loop_start(&mut self);

    /// May publish skipped wrap padding even when no payload space is
    /// available.
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation>;

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
            sampled: 0,
            published_floor: 0,
            retention_moved: false,
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
    /// Takes effect at the next `loop_start`, which publishes it whatever
    /// the throttle.
    pub fn retain_from(&mut self, seq: u64) {
        debug_assert!(
            self.state.retain_from == u64::MAX || seq >= self.state.retain_from,
            "retention moved backwards"
        );
        self.state.retain_from = seq;
        self.state.retention_moved = true;
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
    fn loop_start(&mut self) {
        let cache = self.cache_ref();
        self.state.loop_start(&cache);
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
    // `min_allocation` at the last `loop_start`: everything below it was
    // committed in an earlier loop and is on the spine.
    sampled: u64,
    published_floor: u64,
    retention_moved: bool,
    space: u32,
    // Retention boundary set by the owner; u64::MAX when none.
    retain_from: u64,
}

impl AllocationState {
    fn publish(&mut self, cache: &TCache) {
        self.published_floor = self.floor();
        cache.head().seq.store(self.seq, Ordering::Release);
        cache.head().floor.store(self.published_floor, Ordering::Release);
        cache.record_head(self.seq);
    }

    /// The promise stamped on every read and published: nothing this producer
    /// emits later lies below it. Reads committed this loop may still be
    /// held by the tile and lie above `sampled`; uncommitted reservations lie
    /// above `min_allocation >= sampled`; retained reads above `retain_from`.
    #[inline]
    fn floor(&self) -> u64 {
        self.sampled.min(self.retain_from)
    }

    /// `floor` is sampled here, under the allocator's claim, so the stamp does
    /// not depend on when `read()` is called.
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

    /// The only publish site. The stamped floor follows every loop, since
    /// stamps are local; the shared one once it moved `len / 16`, space runs
    /// short, or the owner moved retention.
    fn loop_start(&mut self, cache: &TCache) {
        self.advance_min_allocation(cache);
        self.sampled = self.min_allocation;
        let threshold = (cache.len >> 4) as u64;
        let moved = self.floor().saturating_sub(self.published_floor);
        if moved > 0 &&
            (moved >= threshold || u64::from(self.space) < threshold || self.retention_moved)
        {
            self.retention_moved = false;
            self.publish(cache);
        }
    }

    /// Publishes nothing: `min_allocation` may pass reads committed this loop
    /// that the tile still holds. `loop_start` publishes the advance.
    fn reclaim(&mut self, cache: &TCache) {
        self.reclaimed_seq = self.seq;
        self.advance_min_allocation(cache);
        self.space = cache.space(self.seq, self.min_allocation);
    }

    fn advance_min_allocation(&mut self, cache: &TCache) {
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
