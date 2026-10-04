use super::*;

#[test]
fn descriptor_tail_wraps_without_overwriting_reserved_bytes() {
    let mut pool = ProvidedBuffers::new(SocketId::Quic, 1).unwrap();
    pool.provide(0);
    pool.publish();
    // SAFETY: no kernel uses this unregistered ring; zero lengths are valid here.
    let header = unsafe { std::mem::zeroed() };
    for _ in 0..u32::from(u16::MAX) + 5 {
        assert!(pool.take(0, -libc::ECANCELED, &header).unwrap().is_none());
        pool.recycle();
    }
    // SAFETY: this initialized descriptor and its aligned tail remain mapped and
    // have no kernel users.
    let (descriptor, tail) = unsafe {
        (
            &*pool.descriptors.as_ptr(),
            &*BufRingEntry::tail(pool.descriptors.as_ptr()).cast::<AtomicU16>(),
        )
    };
    assert_eq!(tail.load(Ordering::Acquire), 5);
    assert_eq!(descriptor.bid(), 0);
    assert_eq!(descriptor.len() as usize, BUFFER_SIZE);
    assert_eq!(descriptor.addr(), pool.buffers[0].as_ptr() as u64);
}

#[test]
fn malformed_completion_releases_its_slot_and_rejects_invalid_ids() {
    let mut pool = ProvidedBuffers::new(SocketId::Quic, 2).unwrap();
    pool.provide(0);
    pool.provide(1);
    pool.publish();
    // SAFETY: null pointers and zero lengths are valid for this layout-only header.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_namelen = NAME_SPACE as _;
    assert!(pool.take(2, 0, &header).is_err());
    assert!(pool.take(0, 0, &header).is_err());
    assert!(pool.take(0, 0, &header).is_err());
    assert!(pool.take(1, BUFFER_SIZE as i32 + 1, &header).is_err());
    assert!(!pool.has_buffers());
    pool.recycle();
    assert!(pool.has_buffers());
    assert_eq!(pool.retired.len(), 0);
}

#[test]
fn exhausted_pool_replaces_pinned_buffers_and_packets_keep_their_storage() {
    let mut pool = ProvidedBuffers::new(SocketId::Quic, 2).unwrap();
    pool.provide(0);
    pool.provide(1);
    pool.publish();
    // SAFETY: null pointers and zero lengths are valid for this layout-only header.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_namelen = NAME_SPACE as _;
    let name = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as _,
        sin6_port: 9000u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: Ipv6Addr::LOCALHOST.octets() },
        sin6_scope_id: 0,
    };
    let mut packets = Vec::new();
    for id in 0..2u16 {
        let buffer = &mut pool.buffers[usize::from(id)];
        let fields = [size_of_val(&name) as u32, 0, 4, 0];
        for (index, field) in fields.iter().enumerate() {
            buffer[index * 4..index * 4 + 4].copy_from_slice(&field.to_ne_bytes());
        }
        // SAFETY: the name region lies within the buffer.
        unsafe {
            ptr::copy_nonoverlapping(
                (&name as *const libc::sockaddr_in6).cast::<u8>(),
                buffer.as_mut_ptr().add(16),
                size_of_val(&name),
            );
        }
        buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].copy_from_slice(b"held");
        let (packet, _) = pool.take(id, PAYLOAD_OFFSET as i32 + 4, &header).unwrap().unwrap();
        assert_eq!(packet.as_ptr() as usize % 16, 0);
        packets.push(packet);
    }
    pool.recycle();
    pool.replace_if_exhausted();
    assert_eq!(pool.retired.len(), 0);
    for (id, packet) in packets.iter().enumerate() {
        assert_ne!(pool.buffers[id].as_ptr(), packet.as_ptr().wrapping_sub(PAYLOAD_OFFSET));
        assert_eq!(&packet[..], b"held");
    }
    pool.replace_if_exhausted();
    assert_eq!(pool.tail, 4);
}

#[test]
fn source_address_parser_checks_lengths_before_reading() {
    assert!(ProvidedBuffers::remote_address(&[]).is_err());
    assert!(ProvidedBuffers::remote_address(&(libc::AF_INET as u16).to_ne_bytes()).is_err());
    assert!(ProvidedBuffers::remote_address(&(libc::AF_INET6 as u16).to_ne_bytes()).is_err());
    assert!(ProvidedBuffers::remote_address(&[0; 128]).is_err());
}
