use std::io::Write;

use super::*;

mod multi;
pub use multi::MultiProducer;

#[cfg(test)]
mod tests;

#[allow(private_bounds)]
pub trait TCacheProducer: SealedProducer {
    /// May publish skipped wrap padding even when no payload space is
    /// available.
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation>;

    /// Publish the head sequence for joining consumers.
    fn publish_head(&self);

    fn cache_ref(&self) -> TCacheRef {
        TCacheRef { cache: self.tcache() as *const c_void }
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
        let state =
            AllocationState { seq: 0, min_allocation: 0, published_seq: 0, space: cache.len };
        Self { cache: Box::into_raw(cache), state }
    }

    pub fn next_seq(&self) -> u64 {
        self.state.seq
    }

    #[inline]
    pub fn read_buffer(&self, read: TCacheRead) -> Result<&[u8], Error> {
        if read.tcache.cache != self.cache.cast() {
            return Err(Error::UnexpectedCacheRef);
        }
        let cache = unsafe { &*self.cache };
        cache.read(read.seq).map(|(bytes, _, _)| bytes)
    }

    /// A producer-side claim cannot survive an allocation, even after the view
    /// has been consumed.
    ///
    /// ```compile_fail
    /// use silver_common::{SubLayout, TCache, TCacheProducer};
    /// let mut producer = TCache::producer("", 1 << 16);
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
        let length = layout
            .reservation_bytes(prefix.len(), middle.len())
            .ok_or(SubReservationError::InvalidLayout)?;
        let reservation = self.reserve(length, false).ok_or(SubReservationError::CacheFull)?;
        Ok(SubReservationRef::new(reservation, layout, prefix, middle))
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
    published_seq: u64,
    space: u32,
}

impl AllocationState {
    fn publish_head(&self, cache: &TCache) {
        cache.head().seq.store(self.seq, Ordering::Release);
        cache.record_head(self.seq);
    }

    #[inline]
    fn reserve(&mut self, cache: TCacheRef, len: usize, auto_commit: bool) -> Option<Reservation> {
        if len > cache.capacity() - size_of::<Slot>() {
            return None;
        }
        let reservation_len = cache.reserve_len(self.seq, len);
        if reservation_len > self.space as usize ||
            self.seq - self.published_seq > (cache.len >> 4) as u64
        // for 32MB buffer, publish head for every 2MB reserved
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
            Reservation { cache, seq, offset: 0, committed: false, auto_commit }
        })
    }

    fn reclaim(&mut self, cache: &TCache) {
        self.publish_head(cache);
        self.published_seq = self.seq;
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

    /// Returns a `TCacheRead` reference for this reservation.
    pub fn read(&self) -> TCacheRead {
        TCacheRead { tcache: self.cache, seq: self.seq }
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
                tcache = self.cache.name,
                "aborting reservation"
            );
            self.cache.commit(self.seq, false);
        }
    }
}
