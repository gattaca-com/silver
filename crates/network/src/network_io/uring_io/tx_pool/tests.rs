use std::{
    mem::align_of,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
};

use quinn_proto::EcnCodepoint;

use super::*;

const MORE: u32 = 1 << 1;
const NOTIF: u32 = 1 << 3;

fn transmit(buffer: &mut Vec<u8>) -> Option<Transmit> {
    buffer.extend_from_slice(b"original");
    Some(Transmit {
        destination: SocketAddr::from(([127, 0, 0, 1], 9000)),
        ecn: None,
        size: buffer.len(),
        segment_size: None,
        src_ip: None,
    })
}

fn submitted(zero_copy: bool) -> TxPool {
    let mut pool = TxPool::new(SocketId::Quic, 1, if zero_copy { 0 } else { usize::MAX });
    assert!(pool.enqueue(transmit).unwrap());
    // Inject completions without a kernel so rare error/notification orders are
    // deterministic.
    pool.queued.clear();
    pool.slots[0].state = State::InFlight { result: None, more: false, notified: false };
    pool.in_flight = 1;
    pool
}

#[test]
fn zero_copy_slot_waits_for_both_completions_in_either_order() {
    for notification_first in [false, true] {
        let mut pool = submitted(true);
        let tag = pool.slots[0].tag;
        let pointer = pool.slots[0].buffer.as_ptr();
        let completions = if notification_first {
            [(i32::MIN, NOTIF), (8, MORE)]
        } else {
            [(8, MORE), (i32::MIN, NOTIF)]
        };
        pool.complete(tag, completions[0].0, completions[0].1).unwrap();
        assert!(pool.is_blocked());
        assert!(!pool.enqueue(|_| panic!("producer called while buffer was in flight")).unwrap());
        assert_eq!(pool.slots[0].buffer, b"original");
        pool.complete(tag, completions[1].0, completions[1].1).unwrap();
        assert!(!pool.has_in_flight());
        assert!(pool.enqueue(transmit).unwrap());
        assert_eq!(pool.slots[0].buffer.as_ptr(), pointer);
    }
}

#[test]
fn failed_and_cancelled_sends_still_wait_for_promised_notifications() {
    for error in [libc::EIO, libc::ECANCELED] {
        let mut pool = submitted(true);
        let tag = pool.slots[0].tag;
        assert_eq!(pool.complete(tag, -error, MORE).unwrap_err().raw_os_error(), Some(error));
        assert!(pool.is_blocked());
        assert!(pool.has_in_flight());
        pool.stop();
        pool.complete(tag, 0, NOTIF).unwrap();
        assert!(!pool.has_in_flight());
        assert_eq!(pool.free.len(), 1);
    }
}

#[test]
fn terminal_errors_and_short_datagrams_do_not_retry_partial_data() {
    for result in [-libc::EINVAL, 4] {
        let mut pool = submitted(true);
        let tag = pool.slots[0].tag;
        assert!(pool.complete(tag, result, 0).is_err());
        assert!(!pool.has_in_flight());
        assert!(!pool.is_blocked());
        assert!(pool.queued.is_empty());
    }
}

#[test]
fn retry_keeps_the_original_bytes_and_waits_for_the_notification() {
    for error in [libc::EAGAIN, libc::EINTR] {
        let mut pool = submitted(true);
        let tag = pool.slots[0].tag;
        pool.complete(tag, -error, MORE).unwrap();
        assert!(pool.queued.is_empty());
        assert!(pool.has_in_flight());
        pool.complete(tag, 0, NOTIF).unwrap();
        assert_eq!(pool.queued.front(), Some(&0));
        assert!(pool.is_blocked());
        assert!(!pool.has_in_flight());
        assert_eq!(pool.slots[0].buffer, b"original");
        pool.stop();
        assert!(pool.queued.is_empty());
        assert_eq!(pool.free.len(), 1);
    }
}

#[test]
fn copying_sends_need_one_completion_and_reject_notifications() {
    let mut pool = submitted(false);
    let tag = pool.slots[0].tag;
    assert_eq!(pool.complete(tag, 0, NOTIF).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(pool.has_in_flight());
    pool.complete(tag, 8, 0).unwrap();
    assert!(!pool.is_blocked());
    assert!(!pool.has_in_flight());
}

#[test]
fn stale_duplicate_and_wrong_socket_completions_cannot_release_a_slot() {
    let mut pool = submitted(true);
    let old_tag = pool.slots[0].tag;
    pool.complete(old_tag, 8, 0).unwrap();
    assert!(pool.complete(old_tag, 8, 0).is_err());
    assert!(pool.enqueue(transmit).unwrap());
    pool.queued.clear();
    pool.slots[0].tag += 1 << GENERATION_SHIFT;
    pool.slots[0].state = State::InFlight { result: None, more: false, notified: false };
    pool.in_flight = 1;
    let tag = pool.slots[0].tag;
    for invalid_tag in [old_tag, tag | 1, tag | (17 << 1)] {
        assert!(pool.complete(invalid_tag, 0, NOTIF).is_err());
        assert!(pool.is_blocked());
        assert!(pool.has_in_flight());
    }
    pool.complete(tag, 8, MORE).unwrap();
    assert!(pool.complete(tag, 8, MORE).is_err());
    assert!(pool.is_blocked());
    pool.complete(tag, 0, NOTIF).unwrap();
    assert!(!pool.is_blocked());
}

#[test]
fn invalid_transmits_and_producer_unwind_leave_the_slot_available() {
    let mut pool = TxPool::new(SocketId::Quic, 1, 0);
    for (size, segment_size) in [(9, None), (8, Some(0)), (8, Some(65536))] {
        let error = pool
            .enqueue(|buffer| {
                let mut tx = transmit(buffer).unwrap();
                tx.size = size;
                tx.segment_size = segment_size;
                Some(tx)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!pool.is_blocked());
    }
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = pool.enqueue(|buffer| {
            buffer.extend_from_slice(b"unfinished");
            panic!("producer panic");
        });
    }));
    assert!(panic.is_err());
    assert!(!pool.is_blocked());
    assert!(pool.enqueue(transmit).unwrap());
}

#[test]
fn ancillary_headers_are_aligned_and_cleared_between_transmits() {
    let mut message = Box::new(TxMessage::new());
    let mut buffer = Vec::new();
    let mut tx = transmit(&mut buffer).unwrap();
    tx.segment_size = Some(4);
    tx.ecn = Some(EcnCodepoint::Ect0);
    tx.src_ip = Some(tx.destination.ip());
    message.prepare(&buffer, &tx).unwrap();
    // SAFETY: preparation initialized all headers and payloads in this live
    // message's control buffer.
    unsafe {
        let segment = libc::CMSG_FIRSTHDR(&message.header);
        assert!(!segment.is_null());
        assert_eq!(segment as usize % align_of::<libc::cmsghdr>(), 0);
        assert_eq!((*segment).cmsg_level, libc::SOL_UDP);
        assert_eq!((*segment).cmsg_type, libc::UDP_SEGMENT);
        assert_eq!(libc::CMSG_DATA(segment).cast::<u16>().read_unaligned(), 4);
        let ecn = libc::CMSG_NXTHDR(&message.header, segment);
        assert!(!ecn.is_null());
        assert_eq!((*ecn).cmsg_level, libc::IPPROTO_IP);
        assert_eq!((*ecn).cmsg_type, libc::IP_TOS);
        assert_eq!(libc::CMSG_DATA(ecn).cast::<i32>().read_unaligned(), EcnCodepoint::Ect0 as i32);
        let source = libc::CMSG_NXTHDR(&message.header, ecn);
        assert!(!source.is_null());
        assert_eq!((*source).cmsg_level, libc::IPPROTO_IP);
        assert_eq!((*source).cmsg_type, libc::IP_PKTINFO);
        let source_ip = libc::CMSG_DATA(source).cast::<libc::in_pktinfo>().read_unaligned();
        assert_eq!(source_ip.ipi_spec_dst.s_addr.to_ne_bytes(), [127, 0, 0, 1]);
        assert!(libc::CMSG_NXTHDR(&message.header, source).is_null());
    }
    tx.segment_size = None;
    tx.ecn = None;
    tx.src_ip = None;
    message.prepare(&buffer, &tx).unwrap();
    assert_eq!(message.header.msg_controllen, 0);
    // SAFETY: the live header has no control messages after preparation.
    assert!(unsafe { libc::CMSG_FIRSTHDR(&message.header) }.is_null());
}
