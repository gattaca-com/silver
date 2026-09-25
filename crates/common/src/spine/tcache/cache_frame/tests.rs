use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use super::*;
use crate::{
    P2pSend, SubLayout, TCache, TCacheId, TCacheTable, TReadMode, test_util::follow_producer_floor,
};

/// Strict on the gossip cache; retained on `columns` when given.
fn frame_reader(gossip: &Producer, columns: Option<&Producer>) -> TCacheReader {
    let caches = std::iter::once(gossip.cache_ref()).chain(columns.map(TCacheProducer::cache_ref));
    let mut reader = TCacheReader::new(TCacheTable::from_iter(caches));
    reader.open(TCacheId::ControlGossip, "", TReadMode::Strict).unwrap();
    if columns.is_some() {
        reader.open(TCacheId::ControlSlot, "", TReadMode::Strict).unwrap();
    }
    reader
}

fn write(producer: &mut Producer, bytes: &[u8]) -> TCacheRead {
    let mut reservation = producer.reserve(bytes.len(), false).unwrap();
    reservation.write_all(bytes).unwrap();
    reservation.flush().unwrap();
    reservation.read()
}

#[test]
fn copy_handle_round_trips_framing_and_source_ranges() {
    fn is_copy<T: Copy>() {}
    is_copy::<P2pSend>();
    is_copy::<CacheFrameRef>();
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut reader = frame_reader(&producer, None);
    let source = write(&mut producer, b"0123456789");
    let now = Instant::now();
    let frame = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"ab--cd",
        [
            CacheSegment::Framing { offset: 0, length: 2 },
            CacheSegment::Gossip { read: source, offset: 3, length: 4 },
            CacheSegment::Framing { offset: 4, length: 2 },
        ]
        .into_iter(),
    )
    .unwrap();
    let view = frame.acquire(&mut reader, now).unwrap();
    let restored = view.reference();
    assert_eq!(restored.read().seq(), frame.read().seq());
    assert_eq!(restored.read().id(), frame.read().id());
    assert_eq!(restored.expires, frame.expires);
    assert_eq!(view.wire_len(), 8);
    assert_eq!(view.segment_count(), 3);
    let descriptor = view.descriptor_range();
    let mut wire = Vec::new();
    for segment in view.segments() {
        if let Some(range) = segment.framing_range() {
            wire.extend_from_slice(&descriptor.as_ref()[range]);
        } else {
            wire.extend_from_slice(segment.acquire(&mut reader).unwrap().as_ref());
        }
    }
    assert_eq!(wire, b"ab3456cd");
    assert!(matches!(
        frame.acquire(&mut reader, now + Duration::from_secs(1)),
        Err(CacheFrameError::Expired)
    ));
}

#[test]
fn shared_segments_expose_only_verified_subranges() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut columns = TCache::producer(TCacheId::ControlSlot, 1 << 18);
    let mut reader = frame_reader(&producer, Some(&columns));
    let reference = columns
        .sub_reservation(SubLayout { parts: 2, first_len: 4, second_len: 2 }, b"", b"")
        .unwrap();
    let pending = columns
        .view_sub_reservation(reference)
        .unwrap()
        .claim(0)
        .unwrap()
        .write(b"cell", b"pf")
        .unwrap();
    let now = Instant::now();
    let frame = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"",
        [
            CacheSegment::Shared {
                reservation: reference,
                part: 0,
                second: false,
                offset: 1,
                length: 2,
            },
            CacheSegment::Shared {
                reservation: reference,
                part: 0,
                second: true,
                offset: 0,
                length: 2,
            },
        ]
        .into_iter(),
    )
    .unwrap();
    let view = frame.acquire(&mut reader, now).unwrap();
    assert!(view.segments().next().unwrap().acquire(&mut reader).is_none());
    pending.acquire(&mut reader).unwrap().accept().unwrap();
    let ranges: Vec<_> =
        view.segments().map(|segment| segment.acquire(&mut reader).unwrap()).collect();
    assert_eq!(ranges[0].as_ref(), b"el");
    assert_eq!(ranges[1].as_ref(), b"pf");
    columns.view_sub_reservation(reference).unwrap().close();
    columns.retain_from(columns.next_seq());
    columns.loop_start();
    follow_producer_floor(&mut reader);
    assert!(view.segments().next().unwrap().acquire(&mut reader).is_none());
    assert_eq!(ranges[0].as_ref(), b"el");
}

#[test]
fn descriptor_bounds_and_sources_are_checked() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut other = TCache::producer(TCacheId::ControlProcessing, 1 << 18);
    let mut reader =
        TCacheReader::new(TCacheTable::from_iter([producer.cache_ref(), other.cache_ref()]));
    reader.open(TCacheId::ControlGossip, "", TReadMode::Strict).unwrap();
    let other_read = write(&mut other, b"data");
    let expires = Instant::now() + Duration::from_secs(1);
    for segment in [
        CacheSegment::Framing { offset: usize::MAX, length: 1 },
        CacheSegment::Framing { offset: 0, length: 0 },
        CacheSegment::Framing { offset: 1, length: 4 },
        CacheSegment::Gossip { read: other_read, offset: 0, length: 4 },
    ] {
        assert!(
            CacheFrameRef::write(&mut producer, expires, b"data", [segment].into_iter()).is_err()
        );
    }
    assert!(CacheFrameRef::write(&mut producer, expires, b"", [].into_iter()).is_err());
    assert!(
        CacheFrameRef::write(
            &mut producer,
            expires,
            b"x",
            std::iter::repeat_n(
                CacheSegment::Framing { offset: 0, length: 1 },
                MAX_CACHE_SEGMENTS + 1,
            )
        )
        .is_err()
    );
    let frame = CacheFrameRef::write(
        &mut producer,
        expires,
        b"",
        [CacheSegment::DataColumns { read: other_read, offset: 2, length: 4 }].into_iter(),
    )
    .unwrap();
    let view = frame.acquire(&mut reader, Instant::now()).unwrap();
    let segment = view.segments().next().unwrap();
    assert!(segment.acquire(&mut reader).is_none(), "source cache not open");
    reader.open(TCacheId::ControlProcessing, "", TReadMode::Strict).unwrap();
    assert!(segment.acquire(&mut reader).is_none(), "range past the source bytes");

    for bytes in [&b"not a descriptor"[..], &b"SGFRAME1\xff\xff\xff\xff\x01\x00\x00\x00"[..]] {
        let malformed = CacheFrameRef { descriptor: write(&mut producer, bytes), expires };
        assert!(matches!(
            malformed.acquire(&mut reader, Instant::now()),
            Err(CacheFrameError::InvalidDescriptor)
        ));
    }
}

#[test]
fn owned_range_slices_check_bounds() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 16);
    let mut reader = frame_reader(&producer, None);
    let read = write(&mut producer, b"0123456789");
    let acquired = reader.acquire_strict(read).unwrap();
    let range = acquired.with_range(2, 6).unwrap();
    assert_eq!(range.clone().slice(2, 3).unwrap().as_ref(), b"456");
    assert!(range.clone().slice(6, 0).unwrap().is_empty());
    assert!(range.clone().slice(6, 1).is_none());
    assert!(range.clone().slice(usize::MAX, 1).is_none());
    assert!(range.slice(1, usize::MAX).is_none());
    let mut first = acquired.with_range(0, 3).unwrap();
    let next = acquired.with_range(3, 4).unwrap();
    let gap = acquired.with_range(8, 1).unwrap();
    assert!(!first.extend_contiguous(&gap));
    assert!(first.extend_contiguous(&next));
    drop(next);
    assert_eq!(first.as_ref(), b"0123456");
}

#[test]
fn failed_acquisition_releases_every_successful_prefix_without_touching_other_reads() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut columns = TCache::producer(TCacheId::ControlSlot, 1 << 18);
    let mut reader = frame_reader(&producer, Some(&columns));
    let gossip = write(&mut producer, b"gossip");
    let column = write(&mut columns, b"column");
    let gossip_guard = reader.acquire_strict(gossip).unwrap();
    let column_guard = reader.acquire_strict(column).unwrap();
    let shared = columns
        .sub_reservation(SubLayout { parts: 2, first_len: 4, second_len: 2 }, b"", b"")
        .unwrap();
    columns
        .view_sub_reservation(shared)
        .unwrap()
        .claim(0)
        .unwrap()
        .write(b"cell", b"pf")
        .unwrap()
        .acquire(&mut reader)
        .unwrap()
        .accept()
        .unwrap();
    let now = Instant::now();
    let segments = [
        CacheSegment::Framing { offset: 0, length: 1 },
        CacheSegment::Gossip { read: gossip, offset: 1, length: 3 },
        CacheSegment::DataColumns { read: column, offset: 0, length: 4 },
        CacheSegment::Shared { reservation: shared, part: 0, second: false, offset: 0, length: 4 },
        CacheSegment::Shared { reservation: shared, part: 0, second: true, offset: 0, length: 2 },
        CacheSegment::Gossip { read: gossip, offset: 1, length: 3 },
        CacheSegment::Framing { offset: 0, length: 1 },
    ];
    for failed in 0..segments.len() {
        let mut descriptors = segments;
        descriptors[failed] = CacheSegment::DataColumns { read: column, offset: 100, length: 1 };
        let frame = CacheFrameRef::write(
            &mut producer,
            now + Duration::from_secs(1),
            b"f",
            descriptors.into_iter(),
        )
        .unwrap();
        assert!(frame.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).is_none());
        assert_eq!(reader.active_count(TCacheId::ControlGossip), 1, "failed descriptor {failed}");
        assert_eq!(reader.active_count(TCacheId::ControlSlot), 1, "failed descriptor {failed}");
        assert_eq!(gossip_guard.buffer().unwrap().0, b"gossip");
        assert_eq!(column_guard.buffer().unwrap().0, b"column");
    }
    drop(gossip_guard);
    drop(column_guard);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 0);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 0);
}

#[test]
fn handoff_transfers_counts_and_frame_drop_releases_only_the_remainder() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut columns = TCache::producer(TCacheId::ControlSlot, 1 << 18);
    let mut reader = frame_reader(&producer, Some(&columns));
    let gossip = write(&mut producer, b"gossip");
    let column = write(&mut columns, b"column");
    let now = Instant::now();
    let reference = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"f",
        [
            CacheSegment::Framing { offset: 0, length: 1 },
            CacheSegment::Gossip { read: gossip, offset: 0, length: 6 },
            CacheSegment::DataColumns { read: column, offset: 0, length: 6 },
            CacheSegment::DataColumns { read: column, offset: 0, length: 6 },
            CacheSegment::Framing { offset: 0, length: 1 },
        ]
        .into_iter(),
    )
    .unwrap();
    let mut frame =
        reference.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).unwrap();
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 2);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 2);
    assert!(matches!(frame.take_next(), Some(AcquiredCacheSegment::Framing(_))));
    let Some(AcquiredCacheSegment::Data(gossip_range)) = frame.take_next() else { panic!() };
    let Some(AcquiredCacheSegment::Data(column_range)) = frame.take_next() else { panic!() };
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 2);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 2);
    columns.retain_from(columns.next_seq());
    columns.loop_start();
    follow_producer_floor(&mut reader);
    drop(frame);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 1);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 1);
    assert_eq!(gossip_range.as_ref(), b"gossip");
    assert_eq!(column_range.as_ref(), b"column");
    drop(gossip_range);
    drop(column_range);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 0);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 0);
}

#[test]
fn shared_handoff_survives_closure_without_exposing_unverified_gaps() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut columns = TCache::producer(TCacheId::ControlSlot, 1 << 18);
    let mut reader = frame_reader(&producer, Some(&columns));
    let shared = columns
        .sub_reservation(SubLayout { parts: 3, first_len: 4, second_len: 2 }, b"hdr", b"mid")
        .unwrap();
    for part in [0, 2] {
        columns
            .view_sub_reservation(shared)
            .unwrap()
            .claim(part)
            .unwrap()
            .write(&[part as u8; 4], &[part as u8 + 10; 2])
            .unwrap()
            .acquire(&mut reader)
            .unwrap()
            .accept()
            .unwrap();
    }
    let now = Instant::now();
    let reference = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"",
        [
            CacheSegment::Shared {
                reservation: shared,
                part: 0,
                second: false,
                offset: 1,
                length: 3,
            },
            CacheSegment::Shared {
                reservation: shared,
                part: 2,
                second: false,
                offset: 0,
                length: 4,
            },
            CacheSegment::Shared {
                reservation: shared,
                part: 0,
                second: true,
                offset: 0,
                length: 2,
            },
            CacheSegment::Shared {
                reservation: shared,
                part: 2,
                second: true,
                offset: 1,
                length: 1,
            },
        ]
        .into_iter(),
    )
    .unwrap();
    let mut frame =
        reference.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).unwrap();
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 4);
    columns.view_sub_reservation(shared).unwrap().close();
    columns.retain_from(columns.next_seq());
    columns.loop_start();
    follow_producer_floor(&mut reader);
    assert!(reference.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).is_none());
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 4);
    for (index, expected) in [&[0; 3][..], &[2; 4], &[10; 2], &[12; 1]].into_iter().enumerate() {
        let Some(AcquiredCacheSegment::Data(range)) = frame.take_next() else { panic!() };
        assert_eq!(reader.active_count(TCacheId::ControlSlot), 4 - index);
        assert_eq!(range.as_ref(), expected);
        drop(range);
        assert_eq!(reader.active_count(TCacheId::ControlSlot), 3 - index);
    }
    assert!(frame.take_next().is_none());
    drop(frame);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 0);
    assert_eq!(reader.active_count(TCacheId::ControlSlot), 0);
}

#[test]
fn coalescing_transfers_one_pin_and_releases_redundant_pins() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut reader = frame_reader(&producer, None);
    let source = write(&mut producer, b"0123456789");
    let now = Instant::now();
    let reference = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"",
        [
            CacheSegment::Gossip { read: source, offset: 1, length: 3 },
            CacheSegment::Gossip { read: source, offset: 4, length: 3 },
            CacheSegment::Gossip { read: source, offset: 7, length: 2 },
        ]
        .into_iter(),
    )
    .unwrap();
    let mut frame =
        reference.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).unwrap();
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 4);
    let Some(AcquiredCacheSegment::Data(range)) = frame.take_next() else { panic!() };
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 2);
    assert!(frame.take_next().is_none());
    drop(frame);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 1);
    assert_eq!(range.as_ref(), b"12345678");
    drop(range);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 0);
}

#[test]
fn unwinding_releases_untransferred_pins_but_not_the_handed_off_read() {
    let mut producer = TCache::producer(TCacheId::ControlGossip, 1 << 18);
    let mut reader = frame_reader(&producer, None);
    let source = write(&mut producer, b"data");
    let now = Instant::now();
    let reference = CacheFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"",
        [CacheSegment::Gossip { read: source, offset: 0, length: 4 }; 3].into_iter(),
    )
    .unwrap();
    let mut handed_off = None;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut frame =
            reference.acquire(&mut reader, now).unwrap().acquire_segments(&mut reader).unwrap();
        let Some(AcquiredCacheSegment::Data(range)) = frame.take_next() else { panic!() };
        handed_off = Some(range);
        panic!("abort a partially handed-off frame");
    }));
    assert!(result.is_err());
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 1);
    assert_eq!(handed_off.as_ref().unwrap().as_ref(), b"data");
    drop(handed_off);
    assert_eq!(reader.active_count(TCacheId::ControlGossip), 0);
}
