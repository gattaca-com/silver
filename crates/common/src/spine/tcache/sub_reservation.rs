use std::{
    marker::PhantomData,
    ptr, slice,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use super::{
    AcquiredRange, AcquiredRead, Producer, RandomAccessConsumer, Reservation, Slot, TCacheRead,
};

pub(super) const INCOMPLETE: u8 = 2;
const STATE_BITS: u32 = 3;
const STATE_MASK: u64 = (1 << STATE_BITS) - 1;
const WRITING: u64 = 1;
const PENDING: u64 = 2;
const VALIDATING: u64 = 3;
const VERIFIED: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubReservationError {
    InvalidLayout,
    WrongConsumer,
    WrongProducer,
    CacheFull,
    Stale,
    Closed,
    Claimed,
    Published,
    Incomplete,
}

/// Each part owns one element in each array: prefix, first array, middle,
/// second array.
#[derive(Clone, Copy, Debug)]
pub struct SubLayout {
    pub parts: usize,
    pub first_len: usize,
    pub second_len: usize,
}

impl SubLayout {
    fn header_bytes(self) -> usize {
        (size_of::<Header>() + self.parts * size_of::<AtomicU64>()).next_multiple_of(super::ALIGN)
    }

    pub fn reservation_bytes(self, prefix_len: usize, middle_len: usize) -> Option<usize> {
        if self.parts > 128 ||
            self.first_len == 0 ||
            self.second_len == 0 ||
            self.first_len > u32::MAX as usize ||
            self.second_len > u32::MAX as usize
        {
            return None;
        }
        self.first_len
            .checked_add(self.second_len)?
            .checked_mul(self.parts)?
            .checked_add(prefix_len)?
            .checked_add(middle_len)?
            .checked_add(self.header_bytes())
            .filter(|len| *len <= u32::MAX as usize)
    }
}

#[repr(C, align(32))]
struct Header {
    ready: [AtomicU64; 2],
    closed: AtomicBool,
    parts: u32,
    first_offset: u32,
    first_len: u32,
    second_offset: u32,
    second_len: u32,
}

impl Header {
    #[inline]
    fn ready(&self) -> u128 {
        self.ready[0].load(Ordering::Acquire) as u128 |
            ((self.ready[1].load(Ordering::Acquire) as u128) << 64)
    }

    #[inline]
    fn complete(&self) -> bool {
        self.ready() == u128::MAX.checked_shr(128 - self.parts).unwrap_or(0)
    }

    #[inline]
    fn ranges(&self, part: usize) -> [(usize, usize); 2] {
        [
            (self.first_offset as usize + part * self.first_len as usize, self.first_len as usize),
            (
                self.second_offset as usize + part * self.second_len as usize,
                self.second_len as usize,
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SubReservationRef {
    pub(super) read: TCacheRead,
    pub(super) header_bytes: usize,
}

impl SubReservationRef {
    pub(super) fn new(
        mut reservation: Reservation,
        layout: SubLayout,
        prefix: &[u8],
        middle: &[u8],
    ) -> Self {
        let read = reservation.read();
        let cache = read.tcache;
        let slot_ptr = unsafe { cache.data_ptr().add(cache.index(read.seq)).cast::<Slot>() };
        // The sole allocator owns this unpublished record during initialization.
        unsafe {
            let slot = &mut *slot_ptr;
            let payload = cache.data_ptr().add(slot.data_start as usize);
            let first_end = prefix.len() + layout.parts * layout.first_len;
            ptr::write(payload.cast::<Header>(), Header {
                ready: [AtomicU64::new(0), AtomicU64::new(0)],
                closed: AtomicBool::new(false),
                parts: layout.parts as u32,
                first_offset: prefix.len() as u32,
                first_len: layout.first_len as u32,
                second_offset: (first_end + middle.len()) as u32,
                second_len: layout.second_len as u32,
            });
            let states = payload.add(size_of::<Header>()).cast::<AtomicU64>();
            for part in 0..layout.parts {
                ptr::write(states.add(part), AtomicU64::new(0));
            }
            let data = payload.add(layout.header_bytes());
            ptr::copy_nonoverlapping(prefix.as_ptr(), data, prefix.len());
            ptr::copy_nonoverlapping(middle.as_ptr(), data.add(first_end), middle.len());
            slot.data_start += layout.header_bytes() as u32;
            slot.skip.store(INCOMPLETE, Ordering::Relaxed);
            slot.seq.store(read.seq, Ordering::Release);
            cache.record_head(read.seq + slot.reservation_len as u64);
        }
        reservation.committed = true;
        Self { read, header_bytes: layout.header_bytes() }
    }

    pub fn read(self) -> TCacheRead {
        self.read
    }

    // The caller must hold a pin and have validated this part. Closure does
    // not change the layout or revoke previously acquired, verified bytes.
    pub(super) unsafe fn acquired_offset(self, part: usize, second: bool) -> usize {
        let view = SubReservationView { reference: self, _scope: PhantomData };
        view.header().ranges(part)[usize::from(second)].0
    }

    pub fn acquire(
        self,
        consumer: &mut RandomAccessConsumer,
    ) -> Result<AcquiredSubReservation, SubReservationError> {
        if !consumer.strict || consumer.cache.cache != self.read.tcache.cache {
            return Err(SubReservationError::WrongConsumer);
        }
        let pin = consumer.acquire_strict(self.read).ok_or(SubReservationError::Stale)?;
        let acquired = AcquiredSubReservation { pin, reference: self, _local: PhantomData };
        if acquired.view().header().closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        Ok(acquired)
    }
}

/// Owns closure. Remote tiles acquire the descriptor through their own strict
/// consumers.
pub struct SubReservation {
    acquired: AcquiredSubReservation,
}

impl SubReservation {
    #[inline]
    pub fn new(acquired: AcquiredSubReservation) -> Self {
        Self { acquired }
    }

    #[inline]
    pub fn reference(&self) -> SubReservationRef {
        self.acquired.reference
    }

    #[inline]
    pub fn acquired(&self) -> &AcquiredSubReservation {
        &self.acquired
    }

    pub fn finish(&self) -> Result<TCacheRead, SubReservationError> {
        self.acquired.view().finish()
    }

    pub fn close(&self) {
        self.acquired.view().close();
    }
}

impl Drop for SubReservation {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct AcquiredSubReservation {
    pin: AcquiredRead,
    reference: SubReservationRef,
    // Consumer accounting, including writer and validator drops, remains on the acquiring thread.
    _local: PhantomData<*const ()>,
}

impl AcquiredSubReservation {
    #[inline]
    fn view(&self) -> SubReservationView<'_> {
        SubReservationView { reference: self.reference, _scope: PhantomData }
    }

    #[inline]
    pub fn ready(&self) -> u128 {
        self.view().ready()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.view().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn claim(&self, part: usize) -> Result<SubWrite<'_>, SubReservationError> {
        self.view().claim(part)
    }

    pub fn ranges(&self, part: usize) -> Option<[AcquiredRange; 2]> {
        let header = self.view().header();
        if part >= header.parts as usize || header.ready() & (1u128 << part) == 0 {
            return None;
        }
        Some(header.ranges(part).map(|(offset, length)| AcquiredRange {
            read: self.pin.clone(),
            offset,
            length,
        }))
    }
}

/// Borrows either the sole allocator or an acquired owner. Neither can release
/// this record while the view or one of its write claims remains in use.
pub struct SubReservationView<'a> {
    reference: SubReservationRef,
    _scope: PhantomData<&'a *const ()>,
}

impl<'a> SubReservationView<'a> {
    #[inline]
    pub(super) fn from_producer(
        producer: &'a Producer,
        reference: SubReservationRef,
    ) -> Result<Self, SubReservationError> {
        if reference.read.tcache.cache != producer.cache.cast() {
            return Err(SubReservationError::WrongProducer);
        }
        if !reference.read.tcache.check_seq(reference.read.seq) {
            return Err(SubReservationError::Stale);
        }
        Ok(Self { reference, _scope: PhantomData })
    }

    #[inline]
    fn data(&self) -> *mut u8 {
        let read = self.reference.read;
        let slot = read.tcache.slot_at(read.tcache.index(read.seq));
        unsafe { read.tcache.data_ptr().add(slot.data_start as usize) }
    }

    #[inline]
    fn header(&self) -> &'a Header {
        unsafe { &*self.data().sub(self.reference.header_bytes).cast::<Header>() }
    }

    #[inline]
    fn state(&self, part: usize) -> &'a AtomicU64 {
        assert!(part < self.header().parts as usize);
        // Derive this pointer from the allocation, not a reference limited to the fixed
        // header.
        unsafe {
            &*self
                .data()
                .sub(self.reference.header_bytes)
                .add(size_of::<Header>())
                .cast::<AtomicU64>()
                .add(part)
        }
    }

    #[inline]
    pub fn ready(&self) -> u128 {
        self.header().ready()
    }

    #[inline]
    pub fn len(&self) -> usize {
        let header = self.header();
        header.second_offset as usize + header.parts as usize * header.second_len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn claim(self, part: usize) -> Result<SubWrite<'a>, SubReservationError> {
        let header = self.header();
        if part >= header.parts as usize {
            return Err(SubReservationError::InvalidLayout);
        }
        if header.closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        let state = self.state(part);
        let previous = state.load(Ordering::Relaxed);
        if previous & STATE_MASK != 0 {
            return Err(if previous & STATE_MASK == VERIFIED {
                SubReservationError::Published
            } else {
                SubReservationError::Claimed
            });
        }
        // Missing retains its attempt so delayed completions cannot match a retry.
        let attempt = previous.checked_add(1 << STATE_BITS).ok_or(SubReservationError::Closed)?;
        state
            .compare_exchange(previous, attempt | WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| SubReservationError::Claimed)?;
        let write = SubWrite { view: self, part, attempt, staged: false };
        if header.closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        Ok(write)
    }

    pub fn finish(&self) -> Result<TCacheRead, SubReservationError> {
        let header = self.header();
        if header.closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        if !header.complete() {
            return Err(SubReservationError::Incomplete);
        }
        let read = self.reference.read;
        match read.tcache.complete_sub_reservation(read.seq, true) {
            Ok(()) | Err(0) => {}
            Err(_) => return Err(SubReservationError::Closed),
        }
        Ok(read)
    }

    pub fn close(&self) {
        self.header().closed.store(true, Ordering::Release);
        let read = self.reference.read;
        let _ = read.tcache.complete_sub_reservation(read.seq, false);
    }

    pub fn cancel(&self, pending: PendingSubReservation) -> Result<bool, SubReservationError> {
        if pending.reservation.read.tcache.cache != self.reference.read.tcache.cache ||
            pending.reservation.read.seq != self.reference.read.seq ||
            pending.part >= self.header().parts as usize
        {
            return Err(SubReservationError::Stale);
        }
        if self.header().closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        Ok(self
            .state(pending.part)
            .compare_exchange(
                pending.attempt | PENDING,
                pending.attempt,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok())
    }
}

pub struct SubWrite<'a> {
    view: SubReservationView<'a>,
    part: usize,
    attempt: u64,
    staged: bool,
}

impl SubWrite<'_> {
    pub fn write(
        mut self,
        first: &[u8],
        second: &[u8],
    ) -> Result<PendingSubReservation, SubReservationError> {
        let header = self.view.header();
        if first.len() != header.first_len as usize || second.len() != header.second_len as usize {
            return Err(SubReservationError::InvalidLayout);
        }
        let [first_range, second_range] = header.ranges(self.part);
        // Only the claimed ranges are mutable. Shared references never span another
        // writer's ranges.
        unsafe {
            ptr::copy_nonoverlapping(
                first.as_ptr(),
                self.view.data().add(first_range.0),
                first_range.1,
            );
            ptr::copy_nonoverlapping(
                second.as_ptr(),
                self.view.data().add(second_range.0),
                second_range.1,
            );
        }
        if header.closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        self.view.state(self.part).store(self.attempt | PENDING, Ordering::Release);
        self.staged = true;
        Ok(PendingSubReservation {
            reservation: self.view.reference,
            part: self.part,
            attempt: self.attempt,
        })
    }
}

impl Drop for SubWrite<'_> {
    fn drop(&mut self) {
        if !self.staged {
            self.view.state(self.part).store(self.attempt, Ordering::Release);
        }
    }
}

/// Copyable queue descriptor, not a pin. Retention boundaries or acquired
/// owners must protect it until handoff or expiry.
#[derive(Clone, Copy, Debug)]
pub struct PendingSubReservation {
    reservation: SubReservationRef,
    part: usize,
    attempt: u64,
}

impl PendingSubReservation {
    pub fn reservation(self) -> SubReservationRef {
        self.reservation
    }

    pub fn part(self) -> usize {
        self.part
    }

    pub fn acquire(
        self,
        consumer: &mut RandomAccessConsumer,
    ) -> Result<SubValidation, SubReservationError> {
        let acquired = self.reservation.acquire(consumer)?;
        acquired
            .view()
            .state(self.part)
            .compare_exchange(
                self.attempt | PENDING,
                self.attempt | VALIDATING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| SubReservationError::Stale)?;
        Ok(SubValidation { acquired, pending: self, validated: false })
    }

    /// Cancels queued work only; an active validator owns its bytes until it
    /// finishes.
    pub fn cancel(self, consumer: &mut RandomAccessConsumer) -> Result<bool, SubReservationError> {
        let acquired = self.reservation.acquire(consumer)?;
        acquired.view().cancel(self)
    }
}

pub struct SubValidation {
    acquired: AcquiredSubReservation,
    pending: PendingSubReservation,
    validated: bool,
}

impl SubValidation {
    pub fn buffers(&self) -> [&[u8]; 2] {
        let view = self.acquired.view();
        view.header().ranges(self.pending.part).map(|(offset, length)| unsafe {
            slice::from_raw_parts(view.data().add(offset), length)
        })
    }

    pub fn accept(mut self) -> Result<(), SubReservationError> {
        let view = self.acquired.view();
        let header = view.header();
        if header.closed.load(Ordering::Acquire) {
            return Err(SubReservationError::Closed);
        }
        view.state(self.pending.part).store(self.pending.attempt | VERIFIED, Ordering::Release);
        header.ready[self.pending.part / 64]
            .fetch_or(1u64 << (self.pending.part % 64), Ordering::Release);
        self.validated = true;
        Ok(())
    }
}

impl Drop for SubValidation {
    fn drop(&mut self) {
        if !self.validated {
            self.acquired
                .view()
                .state(self.pending.part)
                .store(self.pending.attempt, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
