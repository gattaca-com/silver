use std::time::Duration;

use super::*;
use crate::{P2pSend, SubLayout, TCache};

fn write(producer: &mut Producer, bytes: &[u8]) -> TCacheRead {
    let mut reservation = producer.reserve_scoped(bytes.len()).unwrap();
    reservation.write_all(bytes).unwrap();
    reservation.flush().unwrap();
    reservation.read()
}

#[test]
fn copy_handle_round_trips_framing_and_source_ranges() {
    fn is_copy<T: Copy>() {}
    is_copy::<P2pSend>();
    is_copy::<GossipFrameRef>();
    let mut producer = TCache::producer("", 1 << 18);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let source = write(&mut producer, b"0123456789");
    let now = Instant::now();
    let frame = GossipFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"ab--cd",
        [
            GossipSegment::Framing { offset: 0, length: 2 },
            GossipSegment::Gossip { read: source, offset: 3, length: 4 },
            GossipSegment::Framing { offset: 4, length: 2 },
        ]
        .into_iter(),
    )
    .unwrap();
    let view = frame.acquire(&mut consumer, now).unwrap();
    assert_eq!(view.wire_len(), 8);
    assert_eq!(view.segment_count(), 3);
    let descriptor = view.descriptor_range();
    let mut wire = Vec::new();
    for segment in view.segments() {
        if let Some(range) = segment.framing_range() {
            wire.extend_from_slice(&descriptor.as_ref()[range]);
        } else {
            wire.extend_from_slice(segment.acquire(&mut consumer, None).unwrap().as_ref());
        }
    }
    assert_eq!(wire, b"ab3456cd");
    assert!(matches!(
        frame.acquire(&mut consumer, now + Duration::from_secs(1)),
        Err(GossipFrameError::Expired)
    ));
}

#[test]
fn shared_segments_expose_only_verified_subranges() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let mut columns = TCache::producer("", 1 << 18);
    let mut reader = Box::new(columns.cache_ref().retained_random_access("").unwrap());
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
    let frame = GossipFrameRef::write(
        &mut producer,
        now + Duration::from_secs(1),
        b"",
        [
            GossipSegment::Shared {
                reservation: reference,
                part: 0,
                second: false,
                offset: 1,
                length: 2,
            },
            GossipSegment::Shared {
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
    let view = frame.acquire(&mut consumer, now).unwrap();
    assert!(view.segments().next().unwrap().acquire(&mut consumer, Some(&mut reader)).is_none());
    pending.acquire(&mut reader).unwrap().accept().unwrap();
    let ranges: Vec<_> = view
        .segments()
        .map(|segment| segment.acquire(&mut consumer, Some(&mut reader)).unwrap())
        .collect();
    assert_eq!(ranges[0].as_ref(), b"el");
    assert_eq!(ranges[1].as_ref(), b"pf");
    columns.view_sub_reservation(reference).unwrap().close();
    reader.advance_retention(columns.next_seq());
    assert!(view.segments().next().unwrap().acquire(&mut consumer, Some(&mut reader)).is_none());
    assert_eq!(ranges[0].as_ref(), b"el");
}

#[test]
fn descriptor_bounds_and_sources_are_checked() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let mut other = TCache::producer("", 1 << 18);
    let mut other_reader = Box::new(other.cache_ref().retained_random_access("").unwrap());
    let other_read = write(&mut other, b"data");
    let expires = Instant::now() + Duration::from_secs(1);
    for segment in [
        GossipSegment::Framing { offset: usize::MAX, length: 1 },
        GossipSegment::Framing { offset: 0, length: 0 },
        GossipSegment::Framing { offset: 1, length: 4 },
        GossipSegment::Gossip { read: other_read, offset: 0, length: 4 },
    ] {
        assert!(
            GossipFrameRef::write(&mut producer, expires, b"data", [segment].into_iter()).is_err()
        );
    }
    assert!(GossipFrameRef::write(&mut producer, expires, b"", [].into_iter()).is_err());
    assert!(
        GossipFrameRef::write(
            &mut producer,
            expires,
            b"x",
            std::iter::repeat_n(
                GossipSegment::Framing { offset: 0, length: 1 },
                MAX_GOSSIP_SEGMENTS + 1,
            )
        )
        .is_err()
    );
    let frame = GossipFrameRef::write(
        &mut producer,
        expires,
        b"",
        [GossipSegment::DataColumns { read: other_read, offset: 2, length: 4 }].into_iter(),
    )
    .unwrap();
    let view = frame.acquire(&mut consumer, Instant::now()).unwrap();
    let segment = view.segments().next().unwrap();
    assert!(segment.acquire(&mut consumer, None).is_none());
    assert!(segment.acquire(&mut consumer, Some(&mut other_reader)).is_none());

    for bytes in [&b"not a descriptor"[..], &b"SGFRAME1\xff\xff\xff\xff\x01\x00\x00\x00"[..]] {
        let malformed = GossipFrameRef { descriptor: write(&mut producer, bytes), expires };
        assert!(matches!(
            malformed.acquire(&mut consumer, Instant::now()),
            Err(GossipFrameError::InvalidDescriptor)
        ));
    }
}

#[test]
fn owned_range_slices_check_bounds() {
    let mut producer = TCache::producer("", 1 << 16);
    let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
    let read = write(&mut producer, b"0123456789");
    let acquired = consumer.acquire_strict(read).unwrap();
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
