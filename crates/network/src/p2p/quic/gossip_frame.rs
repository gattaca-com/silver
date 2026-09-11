use std::{cell::Cell, ptr::NonNull, time::Instant};

use bytes::Bytes;
use silver_common::{
    AcquiredGossipFrame, AcquiredGossipSegment, AcquiredRange, GossipFrameView, TRead,
};

use super::{Leased, leased::OutboundLeaseWheel};
use crate::{NetworkCounters, p2p::Context};

const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETAINED_OWNERS: usize = 8 * 1024;

#[derive(Debug)]
pub(crate) enum OutboundGossip {
    Contiguous(Leased<TRead>),
    Segmented(SegmentedFrame),
}

pub(crate) struct SegmentedGossipLimits {
    frames: Cell<usize>,
    owners: Cell<usize>,
    retained_bytes: Cell<usize>,
    max_frames: usize,
    max_bytes: usize,
    max_owners: usize,
}

impl Default for SegmentedGossipLimits {
    fn default() -> Self {
        Self::new(128)
    }
}

impl SegmentedGossipLimits {
    pub(crate) fn new(max_frames: usize) -> Self {
        Self {
            frames: Cell::new(0),
            owners: Cell::new(0),
            retained_bytes: Cell::new(0),
            max_frames,
            max_bytes: MAX_RETAINED_BYTES,
            max_owners: MAX_RETAINED_OWNERS,
        }
    }

    pub(crate) fn acquire(
        &self,
        view: GossipFrameView,
        context: &mut Context,
        wheel: &OutboundLeaseWheel,
        now: Instant,
    ) -> Option<SegmentedFrame> {
        let bytes = view.descriptor_len().checked_add(view.wire_len())?;
        let owners = view.segment_count() + 1;
        if bytes > self.max_bytes.saturating_sub(self.retained_bytes.get()) ||
            owners > self.max_owners.saturating_sub(self.owners.get()) ||
            self.frames.get() >= self.max_frames
        {
            NetworkCounters::GossipSegmentedCapacity.inc();
            return None;
        }
        self.frames.set(self.frames.get() + 1);
        self.owners.set(self.owners.get() + owners);
        self.retained_bytes.set(self.retained_bytes.get() + bytes);
        let budget = FrameBudget { limits: NonNull::from(self), owners, bytes };
        let frame = view.acquire_segments(
            &mut context.gossip_consumer,
            context.data_columns_consumer.as_deref_mut(),
        )?;
        NetworkCounters::GossipSegmentedAdmitted.inc();
        NetworkCounters::GossipSegmentedSegments.add(frame.segment_count() as u64);
        Some(SegmentedFrame { segments: wheel.leased(frame, now), budget })
    }

    pub(crate) fn publish_gauges(&self) {
        NetworkCounters::GossipSegmentedFrames.set(self.frames.get() as u64);
        NetworkCounters::GossipSegmentedOwners.set(self.owners.get() as u64);
        NetworkCounters::GossipSegmentedRetainedBytes.set(self.retained_bytes.get() as u64);
    }
}

impl Drop for SegmentedGossipLimits {
    fn drop(&mut self) {
        debug_assert_eq!(self.frames.get(), 0, "limits dropped with active frames");
        debug_assert_eq!(self.owners.get(), 0, "limits dropped with active owners");
        debug_assert_eq!(self.retained_bytes.get(), 0, "limits dropped with retained bytes");
    }
}

#[derive(Debug)]
pub(crate) struct SegmentedFrame {
    segments: Leased<AcquiredGossipFrame>,
    budget: FrameBudget,
}

impl SegmentedFrame {
    pub(crate) fn wire_len(&self) -> usize {
        self.segments.wire_len()
    }

    pub(crate) fn into_writer(self) -> SegmentedWriter {
        let remaining = self.wire_len();
        SegmentedWriter { frame: self, current: Bytes::new(), descriptor: Bytes::new(), remaining }
    }
}

#[derive(Debug)]
pub(crate) struct SegmentedWriter {
    frame: SegmentedFrame,
    current: Bytes,
    descriptor: Bytes,
    remaining: usize,
}

impl SegmentedWriter {
    pub(crate) fn chunk(&mut self) -> Option<&mut Bytes> {
        if self.current.is_empty() {
            let SegmentedFrame { segments, budget } = &mut self.frame;
            self.current = match segments.take_next()? {
                AcquiredGossipSegment::Framing(range) => {
                    if self.descriptor.is_empty() {
                        self.descriptor = budget.owner(segments.child(segments.descriptor_range()));
                    }
                    self.descriptor.slice(range)
                }
                AcquiredGossipSegment::Data(range) => budget.owner(segments.child(range)),
            };
        }
        Some(&mut self.current)
    }

    pub(crate) fn written(&mut self, bytes: usize) -> bool {
        assert!(bytes <= self.remaining);
        self.remaining -= bytes;
        self.remaining == 0
    }
}

#[derive(Debug)]
struct FrameBudget {
    limits: NonNull<SegmentedGossipLimits>,
    owners: usize,
    bytes: usize,
}

// Budgets and owners remain on NetworkTile. P2p's boxed limits outlive all
// peer queues, stream state, and Quinn-owned Bytes.
unsafe impl Send for FrameBudget {}

impl FrameBudget {
    fn owner(&mut self, data: Leased<AcquiredRange>) -> Bytes {
        assert!(self.owners > 0 && data.len() <= self.bytes);
        self.owners -= 1;
        self.bytes -= data.len();
        let owner = SegmentOwner { data, limits: self.limits };
        NetworkCounters::GossipSegmentedOwnerAllocations.inc();
        Bytes::from_owner(owner)
    }
}

impl Drop for FrameBudget {
    fn drop(&mut self) {
        let limits = unsafe { self.limits.as_ref() };
        limits.frames.set(limits.frames.get() - 1);
        limits.owners.set(limits.owners.get() - self.owners);
        limits.retained_bytes.set(limits.retained_bytes.get() - self.bytes);
    }
}

struct SegmentOwner {
    data: Leased<AcquiredRange>,
    limits: NonNull<SegmentedGossipLimits>,
}

// Bytes requires Send. Creation and destruction remain on NetworkTile,
// whose boxed limits outlive every peer's Quinn connection.
unsafe impl Send for SegmentOwner {}

impl AsRef<[u8]> for SegmentOwner {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl Drop for SegmentOwner {
    fn drop(&mut self) {
        let limits = unsafe { self.limits.as_ref() };
        limits.owners.set(limits.owners.get() - 1);
        limits.retained_bytes.set(limits.retained_bytes.get() - self.data.len());
    }
}

#[cfg(test)]
mod tests;
