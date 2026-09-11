use std::{
    alloc::{GlobalAlloc, Layout, System},
    array,
    cell::Cell,
    hint::black_box,
    io::Write,
    time::{Duration, Instant},
};

use silver_common::{AcquiredGossipSegment, GossipFrameRef, GossipSegment, TCache, TCacheProducer};

thread_local! {
    static ALLOCATION_EVENTS: Cell<u64> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn allocation_min_walk_and_out_of_order_completion_allocate_nothing() {
    let mut producer = TCache::producer("", 256);
    let before = ALLOCATION_EVENTS.with(Cell::get);
    for _ in 0..128 {
        let first = producer.reserve(32, false).unwrap();
        for _ in 0..3 {
            producer.reserve(32, true).unwrap().write_all(&[0xab; 32]).unwrap();
        }
        assert!(producer.reserve(32, false).is_none());
        drop(first);
    }
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn multi_producer_allocation_and_reclamation_allocate_nothing() {
    let producer = TCache::multi_producer("", 256);
    let mut writers: [_; 4] = array::from_fn(|_| producer.clone());
    let before = ALLOCATION_EVENTS.with(Cell::get);
    for _ in 0..128 {
        let first = writers[0].reserve(32, false).unwrap();
        for writer in &mut writers[1..] {
            writer.reserve(32, true).unwrap().write_all(&[0xab; 32]).unwrap();
        }
        assert!(writers[0].reserve(32, false).is_none());
        drop(first);
    }
    producer.publish_head();
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn separate_wrap_padding_allocates_nothing() {
    fn check(mut producer: impl TCacheProducer) {
        let before = ALLOCATION_EVENTS.with(Cell::get);
        for _ in 0..128 {
            producer.reserve(96, true).unwrap().write_all(&[1; 96]).unwrap();
            producer.reserve(160, true).unwrap().write_all(&[2; 160]).unwrap();
            producer.reserve(32, true).unwrap().write_all(&[3; 32]).unwrap();
        }
        assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
    }

    check(TCache::producer("", 256));
    check(TCache::multi_producer("", 256));
}

#[test]
fn descriptor_construction_and_acquisition_allocate_nothing() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let now = Instant::now();
    let before = ALLOCATION_EVENTS.with(Cell::get);
    for _ in 0..128 {
        let frame = GossipFrameRef::write(
            &mut producer,
            now + Duration::from_secs(1),
            b"framing",
            [GossipSegment::Framing { offset: 0, length: 3 }, GossipSegment::Framing {
                offset: 3,
                length: 4,
            }]
            .into_iter(),
        )
        .unwrap();
        let view = frame.acquire(&mut consumer, now).unwrap();
        black_box(view.descriptor_range());
        black_box(view.segments().count());
    }
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn frame_acquisition_handoff_and_rollback_allocate_nothing() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let source = {
        let mut reservation = producer.reserve(32, false).unwrap();
        reservation.write_all(&[0xab; 32]).unwrap();
        reservation.flush().unwrap();
        reservation.read()
    };
    let _source_pin = consumer.acquire_strict(source).unwrap();
    let now = Instant::now();
    let before = ALLOCATION_EVENTS.with(Cell::get);
    for _ in 0..32 {
        let reference = GossipFrameRef::write(
            &mut producer,
            now + Duration::from_secs(1),
            b"framing",
            [
                GossipSegment::Gossip { read: source, offset: 0, length: 4 },
                GossipSegment::Gossip { read: source, offset: 4, length: 4 },
                GossipSegment::Framing { offset: 0, length: 7 },
                GossipSegment::Gossip { read: source, offset: 16, length: 4 },
            ]
            .into_iter(),
        )
        .unwrap();
        let mut frame = reference
            .acquire(&mut consumer, now)
            .unwrap()
            .acquire_segments(&mut consumer, None)
            .unwrap();
        while let Some(segment) = frame.take_next() {
            match segment {
                AcquiredGossipSegment::Framing(range) => {
                    black_box(range);
                }
                AcquiredGossipSegment::Data(range) => {
                    black_box(range.as_ref());
                }
            }
        }
        drop(frame);
        let invalid = GossipFrameRef::write(
            &mut producer,
            now + Duration::from_secs(1),
            b"",
            [GossipSegment::Gossip { read: source, offset: 0, length: 4 }, GossipSegment::Gossip {
                read: source,
                offset: 64,
                length: 1,
            }]
            .into_iter(),
        )
        .unwrap();
        assert!(
            invalid
                .acquire(&mut consumer, now)
                .unwrap()
                .acquire_segments(&mut consumer, None)
                .is_none()
        );
    }
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn range_creation_cloning_and_dropping_allocates_nothing() {
    let mut producer = TCache::producer("", 1 << 16);
    let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
    let mut reservation = producer.reserve(2096, true).unwrap();
    reservation.buffer().unwrap().fill(0xab);
    reservation.increment_offset(2096);

    let before = ALLOCATION_EVENTS.with(Cell::get);
    assert!(before > 0);

    let acquired = consumer.acquire_strict(reservation.read()).unwrap();
    let cell = acquired.with_range(0, 2048).unwrap();
    let proof = acquired.with_range(2048, 48).unwrap();
    let clone = cell.clone();
    let suffix = acquired.with_offset(2048).unwrap();
    assert!(acquired.with_range(1, usize::MAX).is_none());

    black_box(cell.as_ref());
    black_box(proof.as_ref());
    black_box(suffix.as_ref());
    drop(acquired);
    drop(cell);
    drop(proof);
    drop(suffix);
    black_box(clone.as_ref());
    drop(clone);

    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn slot_retention_acquisition_and_expiry_allocate_nothing_after_construction() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut readers = array::from_fn::<_, 2, _>(|_| {
        Box::new(producer.cache_ref().retained_random_access("").unwrap())
    });
    let before = ALLOCATION_EVENTS.with(Cell::get);

    for _ in 0..512 {
        let boundary = producer.next_seq();
        for reader in &mut readers {
            reader.advance_retention(boundary);
        }
        let mut reservation = producer.reserve(8192, false).unwrap();
        reservation.buffer().unwrap().fill(0xab);
        reservation.flush().unwrap();
        for reader in &mut readers {
            let acquired = reader.acquire_strict(reservation.read()).unwrap();
            let range = acquired.with_range(7, 31).unwrap();
            let clone = range.clone();
            black_box(clone.as_ref());
        }
    }
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}
