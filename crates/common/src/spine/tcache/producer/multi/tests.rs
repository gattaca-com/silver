use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Barrier, mpsc},
    thread,
    time::{Duration, Instant},
};

use super::*;

#[test]
fn multi_producer_clones_share_the_oldest_unfinished_reservation() {
    let mut producer = TCache::multi_producer("", 256);
    let mut other = producer.clone();
    let mut first = producer.reserve(32, false).unwrap();
    first.write_all(&[0xaa; 16]).unwrap();
    other.reserve(32, true).unwrap().write_all(&[0xbb; 32]).unwrap();
    let third = producer.reserve(32, false).unwrap();
    third.buffer().unwrap().fill(0xcc);
    other.reserve(32, true).unwrap().write_all(&[0xdd; 32]).unwrap();

    assert!(producer.reserve(32, false).is_none());
    assert!(other.reserve(32, false).is_none());
    assert_eq!(producer.claim().state.min_allocation, first.seq());
    first.write_all(&[0xab; 16]).unwrap();
    first.flush().unwrap();

    let next = other.reserve(32, false).unwrap();
    assert_eq!(next.seq(), 256);
    assert_eq!(producer.claim().state.min_allocation, third.seq());
    assert_eq!(third.buffer().unwrap(), &[0xcc; 32]);
    drop(third);
    assert!(producer.reserve(32, false).is_some());
    assert_eq!(other.claim().state.min_allocation, next.seq());
}

#[test]
fn multi_producer_retries_contention_before_reserving_or_publishing() {
    for allocate in [false, true] {
        let producer = TCache::multi_producer("", 256);
        let cache = producer.cache_ref();
        let allocator = producer.claim();
        let reservation = allocator.state.reserve(cache, 32, false).unwrap();
        assert!(producer.try_claim().is_none());
        assert_eq!(cache.head().seq.load(Ordering::Acquire), 0);
        let mut other = producer.clone();
        let (started, ready) = mpsc::channel();
        let (send, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            let next = if allocate { other.reserve(32, false) } else { None };
            other.publish_head();
            send.send(next).unwrap();
        });

        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let early = receive.recv_timeout(Duration::from_millis(50));
        let early_head = cache.head().seq.load(Ordering::Acquire);
        drop(allocator);
        assert!(matches!(early, Err(mpsc::RecvTimeoutError::Timeout)));
        assert_eq!(early_head, 0);
        let next = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();

        if allocate {
            assert_eq!(next.as_ref().unwrap().seq(), 64);
        } else {
            assert!(next.is_none());
        }
        let slot = cache.slot_at(cache.index(reservation.seq()));
        assert_eq!(slot.magic, MAGIC);
        assert_eq!(slot.seq.load(Ordering::Acquire), u64::MAX);
        assert_eq!(slot.reservation_len, 64);
        assert_eq!(cache.head().seq.load(Ordering::Acquire), if allocate { 128 } else { 64 });
    }
}

#[test]
fn multi_producer_releases_claim_when_reservation_cannot_fit() {
    let mut producer = TCache::multi_producer("", 256);
    for len in [225, 256, usize::MAX] {
        assert!(producer.reserve(len, false).is_none());
        assert_eq!(producer.try_claim().unwrap().state.seq, 0);
    }
    let full = producer.reserve(224, false).unwrap();
    assert!(producer.reserve(0, false).is_none());
    assert_eq!(producer.try_claim().unwrap().state.seq, 256);
    drop(full);
    assert_eq!(producer.reserve(224, false).unwrap().seq(), 256);
}

#[test]
fn multi_producer_releases_claim_after_unwind() {
    let mut producer = TCache::multi_producer("", 256);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let allocator = producer.claim();
        let _reservation = allocator.state.reserve(producer.cache_ref(), 224, false).unwrap();
        panic!("unwind with an allocation claim");
    }));
    assert!(result.is_err());
    assert_eq!(producer.try_claim().unwrap().state.seq, 256);
    assert_eq!(producer.reserve(224, false).unwrap().seq(), 256);
}

#[test]
fn multi_producer_debug_does_not_read_claimed_state() {
    let producer = TCache::multi_producer("", 256);
    let allocator = producer.claim();
    assert!(format!("{producer:?}").contains("<locked>"));
    drop(allocator);
    assert!(format!("{producer:?}").contains("min_allocation: 0"));
}

#[test]
fn multi_producer_walks_and_header_initialization_survive_concurrent_wraps() {
    const CAPACITY: usize = 4096;
    const WORKERS: usize = 4;
    let producer = TCache::multi_producer("", CAPACITY);
    let start = Barrier::new(WORKERS);

    thread::scope(|scope| {
        for id in 0..WORKERS {
            let mut producer = producer.clone();
            let start = &start;
            scope.spawn(move || {
                let pattern = [id as u8 + 1; 544];
                let cache = producer.cache_ref();
                start.wait();
                let deadline = Instant::now() + Duration::from_secs(20);
                for index in 0..1024 {
                    let len = 32 + (index * 131 + id * 17) % 513;
                    let mut reservation = loop {
                        if let Some(reservation) = producer.reserve(len, index % 3 == 2) {
                            break reservation;
                        }
                        assert!(Instant::now() < deadline, "allocator stopped making progress");
                        thread::yield_now();
                    };

                    let allocator = producer.claim();
                    let mut seq = allocator.state.min_allocation;
                    while seq < allocator.state.seq {
                        let slot = cache.slot_at(cache.index(seq));
                        let actual = slot.seq.load(Ordering::Acquire);
                        assert!(actual == seq || actual == u64::MAX);
                        assert_eq!(slot.magic, MAGIC);
                        assert!(slot.reservation_len > 0);
                        assert!(slot.data_start <= slot.data_end);
                        assert!(slot.data_end <= CAPACITY as u32);
                        seq += slot.reservation_len as u64;
                        assert!(seq <= allocator.state.seq);
                    }
                    drop(allocator);

                    let middle = len / 2;
                    reservation.write_all(&pattern[..middle]).unwrap();
                    thread::yield_now();
                    assert_eq!(&reservation.buffer().unwrap()[..middle], &pattern[..middle]);
                    reservation.write_all(&pattern[middle..len]).unwrap();
                    if index % 3 == 1 {
                        reservation.flush().unwrap();
                    }
                }
            });
        }
    });

    producer.publish_head();
    assert!(producer.cache_ref().head().seq.load(Ordering::Acquire) > 100 * CAPACITY as u64);
}

#[test]
fn multi_producer_consumer_tail_still_limits_reuse() {
    let mut producer = TCache::multi_producer("", 256);
    let mut consumer = producer.cache_ref().consumer("").unwrap();
    for _ in 0..4 {
        producer.reserve(32, true).unwrap().write_all(&[0xab; 32]).unwrap();
    }
    assert!(producer.reserve(32, false).is_none());
    assert_eq!(producer.claim().state.min_allocation, 256);
    assert_eq!(consumer.read().unwrap().0, &[0xab; 32]);
    consumer.free();
    assert_eq!(producer.clone().reserve(32, false).unwrap().seq(), 256);
    assert!(producer.reserve(32, false).is_none());
}
