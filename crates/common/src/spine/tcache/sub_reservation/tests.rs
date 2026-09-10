use std::sync::{Arc, Barrier};

use super::{
    super::{Producer, TCacheProducer},
    *,
};
use crate::TCache;

struct Harness {
    owner: Option<SubReservation>,
    consumer: Box<RandomAccessConsumer>,
    producer: Producer,
}

impl Harness {
    fn new(parts: usize) -> Self {
        let mut producer = TCache::producer("", 1 << 17);
        let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
        let reference = producer
            .sub_reservation(SubLayout { parts, first_len: 4, second_len: 2 }, b"prefix", b"middle")
            .unwrap();
        let owner = SubReservation::new(reference.acquire(&mut consumer).unwrap());
        Self { owner: Some(owner), consumer, producer }
    }

    fn owner(&self) -> &SubReservation {
        self.owner.as_ref().unwrap()
    }

    fn stage(&self, part: usize) -> PendingSubReservation {
        self.owner()
            .acquired()
            .claim(part)
            .unwrap()
            .write(&[part as u8; 4], &[part as u8; 2])
            .unwrap()
    }

    fn accept(&mut self, pending: PendingSubReservation) {
        pending.acquire(&mut self.consumer).unwrap().accept().unwrap();
    }
}

#[test]
fn producer_returns_an_unpinned_descriptor() {
    let mut producer = TCache::producer("", 1 << 17);
    let reference = producer
        .sub_reservation(SubLayout { parts: 1, first_len: 4, second_len: 2 }, b"prefix", b"middle")
        .unwrap();
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    drop(reference.acquire(&mut consumer).unwrap());
    drop(reference.acquire(&mut consumer).unwrap());

    for _ in 0..64 {
        let mut reservation = producer.reserve(4096, true).unwrap();
        reservation.buffer().unwrap().fill(0xcc);
        reservation.increment_offset(4096);
        drop(consumer.acquire_strict(reservation.read()).unwrap());
    }
    assert!(matches!(reference.acquire(&mut consumer), Err(SubReservationError::Stale)));
}

#[test]
fn writing_does_not_publish_and_completion_excludes_the_sub_header() {
    let mut h = Harness::new(2);
    let read = h.owner().reference().read();
    assert!(matches!(read.len(), Err(super::super::Error::Incomplete)));
    let pending = h.stage(1);
    assert!(h.owner().acquired().ranges(1).is_none());
    assert_eq!(h.owner().acquired().ready(), 0);
    h.accept(pending);
    let [cell, proof] = h.owner().acquired().ranges(1).unwrap();
    let bytes = cell.as_ref();
    let pending = h.stage(0);
    h.accept(pending);
    assert_eq!(bytes, &[1; 4]);
    assert_eq!(proof.as_ref(), &[1; 2]);
    let full = h.owner().finish().unwrap();
    let full = h.consumer.acquire_strict(full).unwrap();
    assert_eq!(full.buffer().unwrap().0, b"prefix\0\0\0\0\x01\x01\x01\x01middle\0\0\x01\x01");
}

#[test]
fn failed_validation_allows_retry_but_old_notifications_cannot_touch_it() {
    let mut h = Harness::new(1);
    let old = h.stage(0);
    assert!(matches!(h.owner().acquired().claim(0), Err(SubReservationError::Claimed)));
    let validating = old.acquire(&mut h.consumer).unwrap();
    assert_eq!(validating.buffers(), [&[0; 4][..], &[0; 2][..]]);
    assert!(!old.cancel(&mut h.consumer).unwrap());
    assert!(matches!(old.acquire(&mut h.consumer), Err(SubReservationError::Stale)));
    drop(validating);
    let retry = h.stage(0);
    assert!(!old.cancel(&mut h.consumer).unwrap());
    assert!(matches!(old.acquire(&mut h.consumer), Err(SubReservationError::Stale)));
    h.accept(retry);
    assert!(matches!(h.owner().acquired().claim(0), Err(SubReservationError::Published)));
    assert_eq!(h.owner().acquired().ready(), 1);
}

#[test]
fn aborted_writes_and_cancelled_queue_entries_release_their_claims() {
    let mut h = Harness::new(1);
    drop(h.owner().acquired().claim(0).unwrap());
    assert_eq!(
        h.owner().acquired().claim(0).unwrap().write(&[], &[]).unwrap_err(),
        SubReservationError::InvalidLayout
    );
    let pending = h.stage(0);
    assert!(pending.cancel(&mut h.consumer).unwrap());
    assert!(!pending.cancel(&mut h.consumer).unwrap());
    let retry = h.stage(0);
    h.accept(retry);
}

#[test]
fn closure_preserves_existing_ranges_and_prevents_new_work() {
    let mut h = Harness::new(2);
    let reference = h.owner().reference();
    let pending = h.stage(0);
    h.accept(pending);
    let ranges = h.owner().acquired().ranges(0).unwrap();
    let pending = h.stage(1);
    let validation = pending.acquire(&mut h.consumer).unwrap();
    h.owner.take();
    assert_eq!(validation.buffers()[0], &[1; 4]);
    assert_eq!(validation.accept(), Err(SubReservationError::Closed));
    assert!(matches!(reference.acquire(&mut h.consumer), Err(SubReservationError::Closed)));
    assert_eq!(ranges[0].as_ref(), &[0; 4]);
}

#[test]
fn cross_thread_writers_claim_once_and_validator_reads_published_input() {
    let mut h = Harness::new(64);
    let reference = h.owner().reference();
    let cache = h.producer.cache_ref();
    let barrier = Arc::new(Barrier::new(4));
    let results = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..4 {
            let barrier = barrier.clone();
            threads.push(scope.spawn(move || {
                let mut consumer = Box::new(cache.strict_random_access("", true).unwrap());
                let acquired = reference.acquire(&mut consumer).unwrap();
                barrier.wait();
                let mut pending = Vec::new();
                for part in 0..64 {
                    if let Ok(write) = acquired.claim(part) {
                        pending.push(write.write(&[part as u8; 4], &[part as u8; 2]).unwrap());
                    }
                }
                pending
            }));
        }
        threads.into_iter().flat_map(|thread| thread.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.len(), 64);
    assert_eq!(h.owner().acquired().ready(), 0);
    for pending in results {
        let validation = pending.acquire(&mut h.consumer).unwrap();
        assert_eq!(validation.buffers()[0], &[pending.part() as u8; 4]);
        validation.accept().unwrap();
    }
    assert_eq!(h.owner().acquired().ready(), u64::MAX as u128);
    h.owner().finish().unwrap();
}

#[test]
fn zero_and_128_parts_finish_without_shifting_overflow() {
    let h = Harness::new(0);
    assert_eq!(h.owner().finish().unwrap().len().unwrap(), 12);
    let mut h = Harness::new(128);
    for part in 0..128 {
        let pending = h.stage(part);
        h.accept(pending);
    }
    assert_eq!(h.owner().acquired().ready(), u128::MAX);
    h.owner().finish().unwrap();
    assert!(matches!(h.owner().acquired().claim(128), Err(SubReservationError::InvalidLayout)));
}

#[test]
fn wrong_cache_and_non_strict_consumers_are_rejected() {
    let h = Harness::new(1);
    let reference = h.owner().reference();
    let mut non_strict = h.producer.cache_ref().random_access("", true).unwrap();
    assert!(matches!(reference.acquire(&mut non_strict), Err(SubReservationError::WrongConsumer)));
    let other = TCache::producer("", 1 << 16);
    let mut foreign = other.cache_ref().strict_random_access("", true).unwrap();
    assert!(matches!(reference.acquire(&mut foreign), Err(SubReservationError::WrongConsumer)));
    assert_eq!(size_of::<super::super::Slot>(), 32);
}

#[test]
fn invalid_layouts_do_not_allocate() {
    let mut producer = TCache::producer("", 1 << 17);
    let seq = producer.seq;
    for layout in [
        SubLayout { parts: 129, first_len: 1, second_len: 1 },
        SubLayout { parts: 1, first_len: usize::MAX, second_len: 1 },
        SubLayout { parts: 1, first_len: 0, second_len: 1 },
    ] {
        assert!(layout.reservation_bytes(1, 1).is_none());
        assert!(matches!(
            producer.sub_reservation(layout, b"a", b"b"),
            Err(SubReservationError::InvalidLayout)
        ));
        assert_eq!(producer.seq, seq);
    }
}

#[test]
fn writers_validators_and_ranges_pin_expired_storage_until_their_last_drop() {
    let mut h = Harness::new(3);
    let reference = h.owner().reference();
    let pending = h.stage(0);
    h.accept(pending);
    let ranges = h.owner().acquired().ranges(0).unwrap();
    let pending = h.stage(1);
    let validation = pending.acquire(&mut h.consumer).unwrap();
    let writer = reference.acquire(&mut h.consumer).unwrap();
    let writing = writer.claim(2).unwrap();
    h.owner.take();
    let mut blocked = false;
    for _ in 0..64 {
        let Some(mut reservation) = h.producer.reserve(4096, true) else {
            blocked = true;
            break;
        };
        reservation.buffer().unwrap().fill(0xcc);
        reservation.increment_offset(4096);
        drop(h.consumer.acquire_strict(reservation.read()).unwrap());
    }
    assert!(blocked);
    assert_eq!(validation.buffers()[0], &[1; 4]);
    assert_eq!(ranges[0].as_ref(), &[0; 4]);
    drop(writing);
    drop(writer);
    assert!(h.producer.reserve(4096, false).is_none());
    drop(validation);
    assert!(h.producer.reserve(4096, false).is_none());
    drop(ranges);
    h.consumer.free();
    for _ in 0..64 {
        let mut reservation = h.producer.reserve(4096, true).unwrap();
        reservation.buffer().unwrap().fill(0xcc);
        reservation.increment_offset(4096);
        drop(h.consumer.acquire_strict(reservation.read()).unwrap());
    }
    assert!(matches!(reference.acquire(&mut h.consumer), Err(SubReservationError::Stale)));
    assert!(matches!(pending.cancel(&mut h.consumer), Err(SubReservationError::Stale)));
}
