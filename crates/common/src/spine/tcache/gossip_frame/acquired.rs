use std::{
    mem,
    ops::{Deref, Range},
    ptr::NonNull,
};

use super::{
    AcquiredRange, AcquiredRead, GossipFrameSegment, GossipFrameView, RandomAccessConsumer,
    SubReservationRef, TCacheRead,
};

pub enum AcquiredGossipSegment {
    Framing(Range<usize>),
    Data(AcquiredRange),
}

#[derive(Debug)]
pub struct AcquiredGossipFrame {
    view: GossipFrameView,
    gossip: NonNull<RandomAccessConsumer>,
    columns: Option<NonNull<RandomAccessConsumer>>,
    // Every non-framing descriptor in [next, acquired_end) owns one bucket
    // count. The descriptor stays pinned until those counts are released.
    next: usize,
    acquired_end: usize,
}

// As with AcquiredRead, consumers stay at stable addresses and outlive their
// reads. Acquisition, handoff, and drops remain on the consumer's tile.
unsafe impl Send for AcquiredGossipFrame {}

impl AcquiredGossipFrame {
    pub(super) fn new(
        view: GossipFrameView,
        gossip: &mut RandomAccessConsumer,
        mut columns: Option<&mut RandomAccessConsumer>,
    ) -> Option<Self> {
        let mut frame = Self {
            view,
            gossip: NonNull::from(&mut *gossip),
            columns: columns.as_deref_mut().map(NonNull::from),
            next: 0,
            acquired_end: 0,
        };
        for segment in frame.view.segments() {
            if segment.kind != 0 {
                let range = segment.acquire(gossip, columns.as_deref_mut())?;
                // No fallible work separates forgetting this owner and recording
                // its count in the frame's acquired prefix.
                mem::forget(range);
            }
            frame.acquired_end += 1;
        }
        Some(frame)
    }

    pub fn take_next(&mut self) -> Option<AcquiredGossipSegment> {
        if self.next == self.acquired_end {
            return None;
        }
        let segment = self.view.segment(self.next);
        if let Some(range) = segment.framing_range() {
            self.next += 1;
            return Some(AcquiredGossipSegment::Framing(range));
        }
        let mut range = self.take_range(&segment);
        while self.next < self.acquired_end {
            let next = self.view.segment(self.next);
            if next.kind == 0 ||
                range.read.consumer != self.consumer(&next).as_ptr() ||
                range.read.seq() != next.seq ||
                range.offset + range.length != Self::offset(&next, range.read.read)
            {
                break;
            }
            let next = self.take_range(&next);
            assert!(range.extend_contiguous(&next));
        }
        Some(AcquiredGossipSegment::Data(range))
    }

    fn consumer(&self, segment: &GossipFrameSegment) -> NonNull<RandomAccessConsumer> {
        if segment.kind == 1 { self.gossip } else { self.columns.expect("acquired column segment") }
    }

    fn take_read(&mut self, segment: &GossipFrameSegment) -> AcquiredRead {
        let consumer = self.consumer(segment);
        // Each call transfers exactly one existing count. Nothing increments
        // here, and frame cleanup excludes the transferred descriptor.
        let read = AcquiredRead {
            consumer: consumer.as_ptr(),
            read: TCacheRead { tcache: unsafe { consumer.as_ref() }.cache, seq: segment.seq },
            acquired: self.view.read.acquired,
        };
        self.next += 1;
        read
    }

    fn take_range(&mut self, segment: &GossipFrameSegment) -> AcquiredRange {
        let read = self.take_read(segment);
        let offset = Self::offset(segment, read.read);
        AcquiredRange { read, offset, length: segment.length }
    }

    fn offset(segment: &GossipFrameSegment, read: TCacheRead) -> usize {
        if segment.kind != 3 {
            return segment.offset;
        }
        let reference = SubReservationRef { read, header_bytes: (segment.metadata >> 32) as usize };
        // Admission validated this part and retains its count. Its immutable
        // layout remains valid even after the reservation is closed.
        let base = unsafe {
            reference.acquired_offset(
                ((segment.metadata as u32) >> 1) as usize,
                segment.metadata & 1 != 0,
            )
        };
        base + segment.offset
    }
}

impl Deref for AcquiredGossipFrame {
    type Target = GossipFrameView;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl Drop for AcquiredGossipFrame {
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
