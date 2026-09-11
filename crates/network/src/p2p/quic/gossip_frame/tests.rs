use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Write,
    mem,
    net::SocketAddr,
    time::Duration,
};

use quinn_proto::StreamId;
use silver_common::{
    AcquiredWithOffset, GossipFrameRef, GossipSegment, P2pStreamId, StreamProtocol, SubLayout,
    SubReservationRef, TCache, TCacheProducer, TProducer,
};

use super::*;
use crate::p2p::streams::{
    AcquiredRpcOutbound, StreamError, StreamIo, gossip_out::GossipWriteState,
};

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Harness {
    context: Box<Context>,
    limits: Box<SegmentedGossipLimits>,
    wheel: Box<OutboundLeaseWheel>,
    gossip: TProducer,
    columns: TProducer,
    now: Instant,
}

impl Harness {
    fn new() -> Self {
        let gossip = TCache::producer("", 1 << 18);
        let columns = TCache::producer("", 1 << 18);
        let rpc = TCache::producer("", 1 << 16);
        let now = Instant::now();
        Self {
            context: Box::new(Context {
                gossip_consumer: gossip.cache_ref().strict_random_access("", true).unwrap(),
                data_columns_consumer: Some(Box::new(
                    columns.cache_ref().retained_random_access("").unwrap(),
                )),
                gossip_producer: TCache::producer("", 1 << 16),
                rpc_consumer: rpc.cache_ref().random_access("", true).unwrap(),
                rpc_producer: rpc,
                identify: None,
            }),
            limits: Box::new(SegmentedGossipLimits::new(2)),
            wheel: Box::new(OutboundLeaseWheel::new(now)),
            gossip,
            columns,
            now,
        }
    }

    fn assembly(&mut self, accept: bool) -> (GossipFrameRef, SubReservationRef) {
        let reference = self
            .columns
            .sub_reservation(SubLayout { parts: 2, first_len: 64, second_len: 8 }, b"", b"")
            .unwrap();
        let pending = self
            .columns
            .view_sub_reservation(reference)
            .unwrap()
            .claim(0)
            .unwrap()
            .write(&[0xab; 64], &[0xcd; 8])
            .unwrap();
        if accept {
            pending
                .acquire(self.context.data_columns_consumer.as_deref_mut().unwrap())
                .unwrap()
                .accept()
                .unwrap();
        }
        let frame = GossipFrameRef::write(
            &mut self.gossip,
            self.now + Duration::from_secs(1),
            b"head",
            [
                GossipSegment::Framing { offset: 0, length: 4 },
                GossipSegment::Shared {
                    reservation: reference,
                    part: 0,
                    second: false,
                    offset: 0,
                    length: 64,
                },
                GossipSegment::Shared {
                    reservation: reference,
                    part: 0,
                    second: true,
                    offset: 0,
                    length: 8,
                },
            ]
            .into_iter(),
        )
        .unwrap();
        (frame, reference)
    }

    fn acquire(&mut self, frame: GossipFrameRef) -> Option<SegmentedFrame> {
        let view = frame.acquire(&mut self.context.gossip_consumer, self.now).ok()?;
        self.limits.acquire(view, &mut self.context, &self.wheel, self.now)
    }
}

impl SegmentedWriter {
    fn take_chunk(&mut self) -> Bytes {
        let chunk = mem::take(self.chunk().unwrap());
        self.written(chunk.len());
        chunk
    }
}

struct MockIo {
    pending: Option<OutboundGossip>,
    budget: usize,
    retained: Vec<Bytes>,
    written: Vec<u8>,
    fail: bool,
}

impl MockIo {
    fn new(message: OutboundGossip, budget: usize) -> Self {
        Self {
            pending: Some(message),
            budget,
            retained: Vec::with_capacity(256),
            written: Vec::with_capacity(4096),
            fail: false,
        }
    }
}

impl StreamIo for MockIo {
    fn write_to_stream(&mut self, _: StreamId, data: &[u8]) -> Result<usize, StreamError> {
        let n = self.budget.min(data.len());
        self.written.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn write_leased_to_stream(
        &mut self,
        id: StreamId,
        data: Leased<AcquiredWithOffset>,
    ) -> Result<usize, StreamError> {
        self.write_chunks(id, &mut [Bytes::from_owner(data)])
    }
    fn write_chunks(&mut self, _: StreamId, chunks: &mut [Bytes]) -> Result<usize, StreamError> {
        if self.fail {
            return Err(StreamError::StreamClosed);
        }
        let mut remaining = self.budget;
        for chunk in chunks {
            let n = remaining.min(chunk.len());
            if n != 0 {
                let accepted = chunk.split_to(n);
                self.written.extend_from_slice(&accepted);
                self.retained.push(accepted);
                remaining -= n;
            }
        }
        Ok(self.budget - remaining)
    }
    fn read_from_stream(&mut self, _: StreamId, _: &mut [u8]) -> Result<usize, StreamError> {
        unreachable!()
    }
    fn close_write(&mut self, _: StreamId) -> Result<(), StreamError> {
        Ok(())
    }
    fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
        None
    }
    fn gossip_next(&mut self) -> Option<OutboundGossip> {
        self.pending.take()
    }
    fn remote_addr(&self) -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }
}

fn stream() -> P2pStreamId {
    P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false)
}

#[test]
fn admission_is_atomic_and_limits_include_ack_owners() {
    let mut h = Harness::new();
    let (invalid, _) = h.assembly(false);
    assert!(h.acquire(invalid).is_none());
    assert_eq!(h.wheel.active_count(), 0);
    assert_eq!(h.limits.owners.get(), 0);
    assert_eq!(h.limits.retained_bytes.get(), 0);
    assert_eq!(h.limits.frames.get(), 0);

    let (valid, _) = h.assembly(true);
    let mut first = h.acquire(valid).unwrap().into_writer();
    let second = h.acquire(valid).unwrap();
    assert!(h.acquire(valid).is_none());
    drop(first.take_chunk());
    let retained = first.take_chunk();
    drop(first);
    drop(second);
    assert_eq!(h.limits.frames.get(), 0);
    assert_eq!(h.limits.owners.get(), 1);
    assert_eq!(h.limits.retained_bytes.get(), 64);
    assert_eq!(h.wheel.active_count(), 1);
    drop(retained);
    assert_eq!(h.limits.retained_bytes.get(), 0);
    assert_eq!(h.wheel.active_count(), 0);
}

#[test]
fn segments_are_allocated_lazily_and_blocked_retries_survive_expiry() {
    let mut h = Harness::new();
    let (reference, assembly) = h.assembly(true);
    let warm = h.acquire(reference).unwrap();
    drop(warm);
    let before = ALLOCATIONS.with(Cell::get);
    let frame = h.acquire(reference).unwrap();
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    let cell_ptr = assembly
        .acquire(h.context.data_columns_consumer.as_deref_mut().unwrap())
        .unwrap()
        .ranges(0)
        .unwrap()[0]
        .as_ref()
        .as_ptr();
    let mut io = MockIo::new(OutboundGossip::Segmented(frame), 7);
    let before = ALLOCATIONS.with(Cell::get);
    let mut state = GossipWriteState::Idle.spin(&mut io, &stream()).unwrap();
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 2);
    assert!(matches!(state, GossipWriteState::WritingSegments(_)));
    assert_eq!(io.written[0], 76);
    io.budget = 0;
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..100 {
        state = state.spin(&mut io, &stream()).unwrap();
    }
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    h.columns.view_sub_reservation(assembly).unwrap().close();
    h.context.data_columns_consumer.as_deref_mut().unwrap().advance_retention(h.columns.next_seq());
    assert!(h.acquire(reference).is_none());
    let mut filled = 0;
    while let Some(mut reservation) = h.columns.reserve(8192, true) {
        reservation.buffer().unwrap().fill(0xee);
        reservation.increment_offset(8192);
        filled += 1;
        assert!(filled < 32);
    }
    assert!(filled > 0);
    io.budget = 13;
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..20 {
        state = state.spin(&mut io, &stream()).unwrap();
        if matches!(state, GossipWriteState::Idle) {
            break;
        }
    }
    // Only the previously untouched proof creates a new owner.
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 1);
    assert!(matches!(state, GossipWriteState::Idle));
    assert_eq!(&io.written[..5], b"\x4chead");
    assert_eq!(&io.written[5..69], &[0xab; 64]);
    assert_eq!(&io.written[69..], &[0xcd; 8]);
    assert_eq!(io.retained[1].as_ptr(), cell_ptr);
    assert_eq!(h.limits.frames.get(), 0);
    assert!(h.columns.reserve(8192, true).is_none());
    assert!(h.wheel.expire(h.now + Duration::from_secs(11)).is_some());
    io.retained.clear();
    assert_eq!(h.limits.owners.get(), 0);
    assert_eq!(h.wheel.active_count(), 0);
    h.context.data_columns_consumer.as_deref_mut().unwrap().advance_retention(h.columns.next_seq());
    assert!(h.columns.reserve(8192, true).is_some());
}

#[test]
fn mid_frame_error_never_starts_the_next_frame() {
    let mut h = Harness::new();
    let (reference, _) = h.assembly(true);
    let first = h.acquire(reference).unwrap();
    let second = h.acquire(reference).unwrap();
    let mut io = MockIo::new(OutboundGossip::Segmented(first), 5);
    let state = GossipWriteState::Idle.spin(&mut io, &stream()).unwrap();
    assert_eq!(io.written.len(), 10);
    io.pending = Some(OutboundGossip::Segmented(second));
    io.fail = true;
    assert!(state.spin(&mut io, &stream()).is_err());
    assert_eq!(io.written.len(), 10);
    assert!(io.pending.is_some());
    drop(io);
    assert_eq!(h.wheel.active_count(), 0);
    assert_eq!(h.limits.frames.get(), 0);
    assert_eq!(h.limits.owners.get(), 0);
    assert_eq!(h.limits.retained_bytes.get(), 0);
}

#[test]
fn fanout_has_independent_delivery_leases() {
    let mut h = Harness::new();
    let (reference, _) = h.assembly(true);
    let wheel = Box::new(OutboundLeaseWheel::new(h.now));
    let mut first = h.acquire(reference).unwrap().into_writer();
    let view = reference.acquire(&mut h.context.gossip_consumer, h.now).unwrap();
    let mut second = h.limits.acquire(view, &mut h.context, &wheel, h.now).unwrap().into_writer();
    drop(first.take_chunk());
    drop(second.take_chunk());
    let first_cell = first.take_chunk();
    let second_cell = second.take_chunk();
    assert_eq!(first_cell.as_ptr(), second_cell.as_ptr());
    drop(first_cell);
    drop(second_cell);
    drop(first);
    assert_eq!(h.wheel.active_count(), 0);
    assert!(wheel.active_count() > 0);
    assert!(wheel.expire(h.now + Duration::from_secs(11)).is_some());
    drop(second);
    assert_eq!(wheel.active_count(), 0);
}

#[test]
fn byte_and_owner_limits_remain_charged_until_ack() {
    let mut h = Harness::new();
    let (reference, _) = h.assembly(true);
    let view = reference.acquire(&mut h.context.gossip_consumer, h.now).unwrap();
    h.limits.max_bytes = view.descriptor_len() + view.wire_len();
    h.limits.max_owners = view.segment_count() + 1;
    drop(view);
    let mut frame = h.acquire(reference).unwrap().into_writer();
    drop(frame.take_chunk());
    let ack_owner = frame.take_chunk();
    drop(frame);
    assert!(h.acquire(reference).is_none());
    h.limits.max_bytes = MAX_RETAINED_BYTES;
    assert!(h.acquire(reference).is_none());
    drop(ack_owner);
    let frame = h.acquire(reference).unwrap();
    drop(frame);
    assert_eq!(h.limits.owners.get(), 0);
}

#[test]
fn adjacent_ranges_share_one_owner_without_gathering() {
    let mut h = Harness::new();
    let mut reservation = h.gossip.reserve(64, true).unwrap();
    reservation.write_all(&[0xab; 64]).unwrap();
    let read = reservation.read();
    let reference = GossipFrameRef::write(
        &mut h.gossip,
        h.now + Duration::from_secs(1),
        b"",
        [GossipSegment::Gossip { read, offset: 2, length: 4 }, GossipSegment::Gossip {
            read,
            offset: 6,
            length: 8,
        }]
        .into_iter(),
    )
    .unwrap();
    let mut frame = h.acquire(reference).unwrap().into_writer();
    let before = ALLOCATIONS.with(Cell::get);
    let chunk = frame.take_chunk();
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 1);
    assert_eq!(chunk.as_ref(), &[0xab; 12]);
    assert!(frame.chunk().is_none());
    drop(frame);
    assert_eq!(h.limits.owners.get(), 1);
    assert_eq!(h.limits.retained_bytes.get(), 12);
    drop(chunk);
    assert_eq!(h.limits.owners.get(), 0);
}

#[test]
fn framing_fragments_share_one_lazy_owner_until_the_last_ack() {
    let mut h = Harness::new();
    let reference = GossipFrameRef::write(
        &mut h.gossip,
        h.now + Duration::from_secs(1),
        b"abcdef",
        [
            GossipSegment::Framing { offset: 0, length: 2 },
            GossipSegment::Framing { offset: 4, length: 2 },
            GossipSegment::Framing { offset: 2, length: 2 },
        ]
        .into_iter(),
    )
    .unwrap();
    let before = ALLOCATIONS.with(Cell::get);
    let mut writer = h.acquire(reference).unwrap().into_writer();
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    let descriptor_len = writer.frame.segments.descriptor_len();
    let chunks = [writer.take_chunk(), writer.take_chunk(), writer.take_chunk()];
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 1);
    assert!(writer.chunk().is_none());
    drop(writer);
    assert_eq!(h.limits.frames.get(), 0);
    assert_eq!(h.limits.owners.get(), 1);
    assert_eq!(h.limits.retained_bytes.get(), descriptor_len);
    let [first, second, third] = chunks;
    assert_eq!(first.as_ref(), b"ab");
    assert_eq!(second.as_ref(), b"ef");
    assert_eq!(third.as_ref(), b"cd");
    drop(first);
    drop(second);
    assert_eq!(h.wheel.active_count(), 1);
    drop(third);
    assert_eq!(h.limits.owners.get(), 0);
    assert_eq!(h.limits.retained_bytes.get(), 0);
    assert_eq!(h.wheel.active_count(), 0);
}

#[test]
fn dropping_before_the_prefix_allocates_no_owners_and_releases_the_lease() {
    let mut h = Harness::new();
    let (reference, _) = h.assembly(true);
    let frame = h.acquire(reference).unwrap();
    assert_eq!(h.wheel.active_count(), 1);
    let mut io = MockIo::new(OutboundGossip::Segmented(frame), 0);
    let before = ALLOCATIONS.with(Cell::get);
    let state = GossipWriteState::Idle.spin(&mut io, &stream()).unwrap();
    assert!(matches!(state, GossipWriteState::WritingLength { written: 0, .. }));
    assert!(h.wheel.expire(h.now + Duration::from_secs(11)).is_some());
    drop(state);
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    assert_eq!(h.limits.frames.get(), 0);
    assert_eq!(h.limits.owners.get(), 0);
    assert_eq!(h.limits.retained_bytes.get(), 0);
    assert_eq!(h.wheel.active_count(), 0);
}

#[test]
fn partial_length_prefix_and_mixed_frames_preserve_boundaries() {
    let mut h = Harness::new();
    let reference = GossipFrameRef::write(
        &mut h.gossip,
        h.now + Duration::from_secs(1),
        &[0xab; 300],
        [GossipSegment::Framing { offset: 0, length: 300 }].into_iter(),
    )
    .unwrap();
    let frame = h.acquire(reference).unwrap();
    let mut io = MockIo::new(OutboundGossip::Segmented(frame), 1);
    let mut state = GossipWriteState::Idle.spin(&mut io, &stream()).unwrap();
    assert_eq!(io.written, [0xac]);
    assert!(matches!(state, GossipWriteState::WritingLength { written: 1, .. }));
    let mut write = h.gossip.reserve(3, true).unwrap();
    write.write_all(b"end").unwrap();
    let read = h.context.gossip_consumer.acquire_strict(write.read()).unwrap();
    io.pending = Some(OutboundGossip::Contiguous(h.wheel.leased(read, h.now)));
    io.budget = 0;
    state = state.spin(&mut io, &stream()).unwrap();
    assert_eq!(io.written, [0xac]);
    io.budget = 17;
    for _ in 0..30 {
        state = state.spin(&mut io, &stream()).unwrap();
        if matches!(state, GossipWriteState::Idle) {
            break;
        }
    }
    assert!(matches!(state, GossipWriteState::Idle));
    assert_eq!(&io.written[..2], &[0xac, 0x02]);
    assert_eq!(&io.written[2..302], &[0xab; 300]);
    assert_eq!(&io.written[302..], b"\x03end");
}

#[test]
fn contiguous_baseline_uses_one_owner_per_write_attempt() {
    let mut h = Harness::new();
    let mut reservation = h.gossip.reserve(64, true).unwrap();
    reservation.write_all(&[0xab; 64]).unwrap();
    let read = h.context.gossip_consumer.acquire_strict(reservation.read()).unwrap();
    let mut io = MockIo::new(OutboundGossip::Contiguous(h.wheel.leased(read, h.now)), 7);
    let before = ALLOCATIONS.with(Cell::get);
    let mut state = GossipWriteState::Idle.spin(&mut io, &stream()).unwrap();
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 1);
    io.budget = 0;
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..10 {
        state = state.spin(&mut io, &stream()).unwrap();
    }
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 10);
    drop(state);
    drop(io);
    assert_eq!(h.wheel.active_count(), 0);
}
