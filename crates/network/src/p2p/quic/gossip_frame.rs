use std::{
    cell::{Cell, RefCell},
    fmt,
    ptr::NonNull,
    time::Instant,
};

use bytes::Bytes;
use silver_common::{AcquiredRange, GossipFrameView, MAX_GOSSIP_SEGMENTS, TRead};

use super::{Leased, leased::OutboundLeaseWheel};
use crate::{NetworkCounters, p2p::Context};

const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETAINED_OWNERS: usize = 8 * 1024;

#[derive(Debug)]
pub(crate) enum OutboundGossip {
    Contiguous(Leased<TRead>),
    Segmented(SegmentedFrame),
}

struct FrameData {
    chunks: Vec<Bytes>,
    descriptor: Option<Bytes>,
    next: usize,
    wire_len: usize,
    remaining: usize,
}

impl FrameData {
    fn new() -> Self {
        Self {
            chunks: Vec::with_capacity(MAX_GOSSIP_SEGMENTS),
            descriptor: None,
            next: 0,
            wire_len: 0,
            remaining: 0,
        }
    }

    fn clear(&mut self) {
        self.chunks.clear();
        self.descriptor = None;
        self.next = 0;
        self.wire_len = 0;
        self.remaining = 0;
    }
}

// Boxes keep queue entries small and preserve each chunk vector's allocation.
#[allow(clippy::vec_box)]
pub(crate) struct SegmentedFramePool {
    idle: RefCell<Vec<Box<FrameData>>>,
    owners: Cell<usize>,
    retained_bytes: Cell<usize>,
    max_bytes: usize,
    max_owners: usize,
}

impl Default for SegmentedFramePool {
    fn default() -> Self {
        Self::new(128)
    }
}

impl SegmentedFramePool {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            idle: RefCell::new((0..capacity).map(|_| Box::new(FrameData::new())).collect()),
            owners: Cell::new(0),
            retained_bytes: Cell::new(0),
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
        if bytes > self.max_bytes.saturating_sub(self.retained_bytes.get()) ||
            view.segment_count() + 1 > self.max_owners.saturating_sub(self.owners.get())
        {
            NetworkCounters::GossipSegmentedCapacity.inc();
            return None;
        }
        let Some(data) = self.idle.borrow_mut().pop() else {
            NetworkCounters::GossipSegmentedCapacity.inc();
            return None;
        };
        let mut frame = SegmentedFrame { data: Some(data), pool: NonNull::from(self) };
        let data = frame.data.as_mut().unwrap();
        let descriptor = self.owner(wheel.leased(view.descriptor_range(), now));
        let mut pending: Option<AcquiredRange> = None;
        for segment in view.segments() {
            if let Some(range) = segment.framing_range() {
                if let Some(range) = pending.take() {
                    data.chunks.push(self.owner(wheel.leased(range, now)));
                }
                data.chunks.push(descriptor.slice(range));
            } else {
                let range = segment.acquire(
                    &mut context.gossip_consumer,
                    context.data_columns_consumer.as_deref_mut(),
                )?;
                if let Some(previous) = &mut pending {
                    if previous.extend_contiguous(&range) {
                        continue;
                    }
                }
                if let Some(previous) = pending.replace(range) {
                    data.chunks.push(self.owner(wheel.leased(previous, now)));
                }
            }
        }
        if let Some(range) = pending {
            data.chunks.push(self.owner(wheel.leased(range, now)));
        }
        data.descriptor = Some(descriptor);
        data.wire_len = view.wire_len();
        data.remaining = data.wire_len;
        NetworkCounters::GossipSegmentedAdmitted.inc();
        NetworkCounters::GossipSegmentedSegments.add(view.segment_count() as u64);
        Some(frame)
    }

    fn owner(&self, data: Leased<AcquiredRange>) -> Bytes {
        self.owners.set(self.owners.get() + 1);
        self.retained_bytes.set(self.retained_bytes.get() + data.len());
        NetworkCounters::GossipSegmentedOwnerAllocations.inc();
        Bytes::from_owner(SegmentOwner { data, pool: NonNull::from(self) })
    }

    pub(crate) fn publish_gauges(&self) {
        NetworkCounters::GossipSegmentedPoolIdle.set(self.idle.borrow().len() as u64);
        NetworkCounters::GossipSegmentedOwners.set(self.owners.get() as u64);
        NetworkCounters::GossipSegmentedRetainedBytes.set(self.retained_bytes.get() as u64);
    }
}

impl Drop for SegmentedFramePool {
    fn drop(&mut self) {
        debug_assert_eq!(self.owners.get(), 0, "frame pool dropped with active owners");
    }
}

pub(crate) struct SegmentedFrame {
    data: Option<Box<FrameData>>,
    pool: NonNull<SegmentedFramePool>,
}

// Pool checkout, writes, and drops stay on NetworkTile. Its boxed pool has a
// stable address and outlives peer queues and Quinn-owned chunks.
unsafe impl Send for SegmentedFrame {}

impl fmt::Debug for SegmentedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentedFrame")
            .field("remaining", &self.data.as_ref().unwrap().remaining)
            .finish()
    }
}

impl SegmentedFrame {
    pub(crate) fn wire_len(&self) -> usize {
        self.data.as_ref().unwrap().wire_len
    }

    pub(crate) fn chunks(&mut self) -> &mut [Bytes] {
        let data = self.data.as_mut().unwrap();
        &mut data.chunks[data.next..]
    }

    pub(crate) fn written(&mut self, bytes: usize) -> bool {
        let data = self.data.as_mut().unwrap();
        assert!(bytes <= data.remaining);
        data.remaining -= bytes;
        while data.next < data.chunks.len() && data.chunks[data.next].is_empty() {
            data.next += 1;
        }
        data.remaining == 0
    }
}

impl Drop for SegmentedFrame {
    fn drop(&mut self) {
        let mut data = self.data.take().unwrap();
        data.clear();
        // The pool is boxed in P2p after all peers, including their stream state.
        unsafe { self.pool.as_ref() }.idle.borrow_mut().push(data);
    }
}

struct SegmentOwner {
    data: Leased<AcquiredRange>,
    pool: NonNull<SegmentedFramePool>,
}

// Bytes requires Send. All owners are created and released on NetworkTile;
// P2p's boxed pool outlives every peer's Quinn connection.
unsafe impl Send for SegmentOwner {}

impl AsRef<[u8]> for SegmentOwner {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl Drop for SegmentOwner {
    fn drop(&mut self) {
        let pool = unsafe { self.pool.as_ref() };
        pool.owners.set(pool.owners.get() - 1);
        pool.retained_bytes.set(pool.retained_bytes.get() - self.data.len());
    }
}

#[cfg(test)]
mod tests;
