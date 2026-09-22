use std::{
    mem,
    ops::{Deref, Range},
    ptr::NonNull,
};

use super::{
    AcquiredRange, AcquiredRead, CacheFrameSegment, CacheFrameView, SubReservationRef, TCacheId,
    TCacheRead, TCacheReader,
};
use crate::spine::tcache::RandomAccessConsumer;

pub enum AcquiredCacheSegment {
    Framing(Range<usize>),
    Data(AcquiredRange),
}

#[derive(Debug)]
pub struct AcquiredCacheFrame {
    view: CacheFrameView,
    reader: NonNull<TCacheReader>,
    // Every non-framing descriptor in [next, acquired_end) owns one bucket
    // count. The descriptor stays pinned until those counts are released.
    next: usize,
    acquired_end: usize,
}

// As with AcquiredRead, the reader stays at a stable address and outlives its
// reads. Acquisition, handoff, and drops remain on the reader's tile.
unsafe impl Send for AcquiredCacheFrame {}

impl AcquiredCacheFrame {
    pub(super) fn new(view: CacheFrameView, reader: &mut TCacheReader) -> Option<Self> {
        let mut frame =
            Self { view, reader: NonNull::from(&mut *reader), next: 0, acquired_end: 0 };
        for segment in frame.view.segments() {
            if segment.kind != 0 {
                let range = segment.acquire(reader)?;
                // No fallible work separates forgetting this owner and recording
                // its count in the frame's acquired prefix.
                mem::forget(range);
            }
            frame.acquired_end += 1;
        }
        Some(frame)
    }

    pub fn take_next(&mut self) -> Option<AcquiredCacheSegment> {
        if self.next == self.acquired_end {
            return None;
        }
        let segment = self.view.segment(self.next);
        if let Some(range) = segment.framing_range() {
            self.next += 1;
            return Some(AcquiredCacheSegment::Framing(range));
        }
        let mut range = self.take_range(&segment);
        while self.next < self.acquired_end {
            let next = self.view.segment(self.next);
            if next.kind == 0 ||
                range.read.consumer != self.consumer(&next).as_ptr() ||
                range.read.seq() != next.seq ||
                range.offset + range.length != Self::offset(&next, &range.read)
            {
                break;
            }
            let next = self.take_range(&next);
            assert!(range.extend_contiguous(&next));
        }
        Some(AcquiredCacheSegment::Data(range))
    }

    fn consumer(&self, segment: &CacheFrameSegment) -> NonNull<RandomAccessConsumer> {
        let id = TCacheId::from_index(segment.cache).expect("admitted segment");
        NonNull::from(unsafe { &mut *self.reader.as_ptr() }.consumer(id))
    }

    fn take_read(&mut self, segment: &CacheFrameSegment) -> AcquiredRead {
        let consumer = self.consumer(segment);
        // Each call transfers exactly one existing count. Nothing increments
        // here, and frame cleanup excludes the transferred descriptor.
        let read = AcquiredRead {
            consumer: consumer.as_ptr(),
            read: TCacheRead { id: unsafe { consumer.as_ref() }.id(), seq: segment.seq },
            acquired: self.view.read.acquired,
        };
        self.next += 1;
        read
    }

    fn take_range(&mut self, segment: &CacheFrameSegment) -> AcquiredRange {
        let read = self.take_read(segment);
        let offset = Self::offset(segment, &read);
        AcquiredRange { read, offset, length: segment.length }
    }

    fn offset(segment: &CacheFrameSegment, read: &AcquiredRead) -> usize {
        if segment.kind != 3 {
            return segment.offset;
        }
        let reference =
            SubReservationRef { read: read.read, header_bytes: (segment.metadata >> 32) as usize };
        // Admission validated this part and retains its count. Its immutable
        // layout remains valid even after the reservation is closed.
        let base = unsafe {
            reference.acquired_offset(
                read.cache(),
                ((segment.metadata as u32) >> 1) as usize,
                segment.metadata & 1 != 0,
            )
        };
        base + segment.offset
    }
}

impl Deref for AcquiredCacheFrame {
    type Target = CacheFrameView;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl Drop for AcquiredCacheFrame {
    fn drop(&mut self) {
        while self.next < self.acquired_end {
            let segment = self.view.segment(self.next);
            if segment.kind == 0 {
                self.next += 1;
            } else {
                drop(self.take_read(&segment));
            }
        }
    }
}
