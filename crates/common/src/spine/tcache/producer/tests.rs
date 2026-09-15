use super::*;

#[test]
fn unfinished_reservations_stop_reuse_despite_out_of_order_commits() {
    let mut producer = TCache::producer("", 256);
    let mut first = producer.reserve(32, false).unwrap();
    first.write_all(&[0xaa; 16]).unwrap();
    let mut second = producer.reserve(32, true).unwrap();
    second.write_all(&[0xbb; 32]).unwrap();
    let mut third = producer.reserve(32, false).unwrap();
    third.buffer().unwrap().fill(0xcc);
    let mut fourth = producer.reserve(32, true).unwrap();
    fourth.write_all(&[0xdd; 32]).unwrap();

    assert!(producer.reserve(32, false).is_none());
    assert_eq!(producer.state.min_allocation, first.seq());
    assert_eq!(&first.buffer().unwrap()[..16], &[0xaa; 16]);

    first.write_all(&[0xab; 16]).unwrap();
    first.flush().unwrap();
    let next = producer.reserve(32, false).unwrap();
    assert_eq!(next.seq(), 256);
    assert_eq!(producer.state.min_allocation, third.seq());
    assert_eq!(third.buffer().unwrap(), &[0xcc; 32]);

    third.flush().unwrap();
    assert!(producer.reserve(32, false).is_some());
    assert_eq!(producer.state.min_allocation, next.seq());
}

#[test]
fn allocation_min_passes_manual_auto_and_aborted_commits() {
    let mut producer = TCache::producer("", 256);
    let mut manual = producer.reserve(32, false).unwrap();
    let mut automatic_write = producer.reserve(32, true).unwrap();
    let mut automatic_offset = producer.reserve(32, true).unwrap();
    let aborted = producer.reserve(32, false).unwrap();

    automatic_write.write_all(&[1; 32]).unwrap();
    automatic_offset.buffer().unwrap().fill(2);
    automatic_offset.increment_offset(32);
    drop(aborted);
    assert!(producer.reserve(32, false).is_none());

    manual.write_all(&[3; 32]).unwrap();
    manual.flush().unwrap();
    let head = producer.next_seq();
    let full = producer.reserve(256 - size_of::<Slot>(), false).unwrap();
    assert_eq!(full.seq(), head);
    assert_eq!(producer.state.min_allocation, head);
    assert_eq!(producer.state.space, 0);
}

#[test]
fn allocation_min_walks_wrap_padding_on_commit_or_abort() {
    for abort in [false, true] {
        let mut producer = TCache::producer("", 256);
        producer.reserve(160, false).unwrap().flush().unwrap();
        let mut wrapped = producer.reserve(96, false).unwrap();
        assert_eq!(wrapped.seq(), 192);
        assert_eq!(producer.next_seq(), 384);
        wrapped.buffer().unwrap().fill(0xab);

        producer.reserve(32, false).unwrap().flush().unwrap();
        assert!(producer.reserve(32, false).is_none());
        assert_eq!(producer.state.min_allocation, wrapped.seq());
        assert_eq!(wrapped.buffer().unwrap(), &[0xab; 96]);

        if !abort {
            wrapped.flush().unwrap();
        }
        drop(wrapped);
        let head = producer.next_seq();
        assert_eq!(head, 448);
        assert_eq!(producer.reserve(32, false).unwrap().seq(), head);
        assert_eq!(producer.state.min_allocation, head);
    }
}

#[test]
fn consumer_tail_still_limits_reuse_after_all_writes_finish() {
    let mut producer = TCache::producer("", 256);
    let mut consumer = producer.cache_ref().consumer("").unwrap();
    for _ in 0..4 {
        producer.reserve(32, true).unwrap().write_all(&[0xab; 32]).unwrap();
    }
    assert!(producer.reserve(32, false).is_none());
    assert_eq!(producer.state.min_allocation, producer.next_seq());

    assert_eq!(consumer.read().unwrap().0, &[0xab; 32]);
    consumer.free();
    assert_eq!(producer.reserve(32, false).unwrap().seq(), 256);
    assert!(producer.reserve(32, false).is_none());
}

#[test]
fn committed_reservation_cannot_modify_a_reused_slot() {
    let mut producer = TCache::producer("", 256);
    let mut old = producer.reserve(224, false).unwrap();
    old.write_all(&[0xaa; 32]).unwrap();
    old.flush().unwrap();
    let mut replacement = producer.reserve(224, false).unwrap();
    replacement.buffer().unwrap().fill(0xbb);
    assert_eq!(replacement.seq(), 256);

    assert!(old.buffer().is_err());
    assert!(old.remaining_buffer().is_err());
    assert!(old.remaining().is_err());
    assert!(old.write(b"x").is_err());
    assert!(matches!(producer.reservation_buffer(&mut old), Err(Error::Committed)));
    old.increment_offset(1);
    assert_eq!(old.offset, 32);
    old.flush().unwrap();
    drop(old);

    assert_eq!(replacement.buffer().unwrap(), &[0xbb; 224]);
    replacement.flush().unwrap();
    assert_eq!(producer.read_buffer(replacement.read()).unwrap(), &[0xbb; 224]);
}

#[test]
fn oversized_reservations_do_not_advance_the_allocator() {
    let mut producer = TCache::producer("", 256);
    for length in [225, 256, usize::MAX] {
        assert!(producer.reserve(length, false).is_none());
        assert_eq!(producer.next_seq(), 0);
        assert_eq!(producer.state.min_allocation, 0);
        assert_eq!(producer.state.space, 256);
    }
    assert!(producer.reserve(224, false).is_some());
}

#[test]
fn every_valid_payload_size_fits_at_every_empty_cache_offset() {
    fn check(mut producer: impl TCacheProducer, offset: usize, len: usize) {
        if offset != 0 {
            producer.reserve(offset - size_of::<Slot>(), false).unwrap().flush().unwrap();
        }
        let mut reservation = producer.reserve(len, false).expect("empty cache must fit payload");
        reservation.write_all(&[0xab; 224][..len]).unwrap();
        reservation.flush().unwrap();
        assert_eq!(reservation.read().len().unwrap(), len);
    }

    for offset in (0..256).step_by(ALIGN) {
        for len in 0..=224 {
            check(TCache::producer("", 256), offset, len);
            check(TCache::multi_producer("", 256), offset, len);
        }
    }
}

#[test]
fn padding_waits_for_pending_writes_and_linear_consumer_release() {
    fn check(mut producer: impl TCacheProducer) {
        let cache = producer.cache_ref();
        let mut consumer = cache.consumer("").unwrap();
        let mut pending = producer.reserve(96, false).unwrap();
        pending.buffer().unwrap().fill(0xab);
        assert!(producer.reserve(160, false).is_none());
        assert_eq!(cache.head().seq.load(Ordering::Acquire), 256);
        let padding = cache.slot_at(128);
        assert_eq!(padding.seq.load(Ordering::Acquire), 128);
        assert_eq!(padding.reservation_len, 128);
        assert_eq!(padding.skip.load(Ordering::Acquire), 1);
        assert_eq!(pending.buffer().unwrap(), &[0xab; 96]);

        pending.flush().unwrap();
        assert!(producer.reserve(160, false).is_none());
        assert_eq!(consumer.read().unwrap().0, &[0xab; 96]);
        consumer.free();
        assert!(consumer.read().is_err());
        consumer.free();
        let mut large = producer.reserve(160, true).unwrap();
        assert_eq!(large.seq(), 256);
        large.write_all(&[0xcd; 160]).unwrap();
        assert_eq!(consumer.read().unwrap().0, &[0xcd; 160]);
    }

    check(TCache::producer("", 256));
    check(TCache::multi_producer("", 256));
}

#[test]
fn padding_itself_must_fit_without_overwriting_consumer_data() {
    fn check(mut producer: impl TCacheProducer) {
        let mut consumer = producer.cache_ref().consumer("").unwrap();
        producer.reserve(96, true).unwrap().write_all(&[1; 96]).unwrap();
        assert_eq!(consumer.read().unwrap().0, &[1; 96]);
        consumer.free();
        for value in [2, 3] {
            producer.reserve(96, true).unwrap().write_all(&[value; 96]).unwrap();
        }
        assert!(producer.reserve(160, false).is_none());
        assert_eq!(producer.cache_ref().head().seq.load(Ordering::Acquire), 384);
        assert_eq!(consumer.read().unwrap().0, &[2; 96]);
        consumer.free();
        assert!(producer.reserve(160, false).is_none());
        assert_eq!(producer.cache_ref().head().seq.load(Ordering::Acquire), 512);
        assert_eq!(consumer.read().unwrap().0, &[3; 96]);
        consumer.free();
        assert!(consumer.read().is_err());
        consumer.free();
        assert_eq!(producer.reserve(160, false).unwrap().seq(), 512);
    }

    check(TCache::producer("", 256));
    check(TCache::multi_producer("", 256));
}

#[test]
fn sub_reservations_use_separate_padding_when_needed() {
    let mut producer = TCache::producer("", 512);
    producer.reserve(224, false).unwrap().flush().unwrap();
    let reference = producer
        .sub_reservation(SubLayout { parts: 0, first_len: 4, second_len: 2 }, &[0xab; 300], b"")
        .unwrap();
    assert_eq!(reference.read().seq(), 512);
    let read = producer.view_sub_reservation(reference).unwrap().finish().unwrap();
    assert_eq!(producer.read_buffer(read).unwrap(), &[0xab; 300]);
}
