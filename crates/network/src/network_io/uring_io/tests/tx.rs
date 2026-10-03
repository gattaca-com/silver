use std::iter::repeat_n;

use quinn_proto::EcnCodepoint;

use super::*;

fn config() -> UringConfig {
    UringConfig {
        sq_entries: 8,
        cq_entries: 16,
        quic_rx_buffers: 4,
        discovery_rx_buffers: 4,
        quic_tx_buffers: 1,
        discovery_tx_buffers: 1,
        ..Default::default()
    }
}

fn peer(ipv6: bool) -> UdpSocket {
    let peer = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer
}

fn send(io: &mut UringIo, socket: SocketId, destination: SocketAddr, payload: &[u8]) {
    assert!(
        io.send(socket, |buffer| {
            buffer.extend_from_slice(payload);
            Some(Transmit {
                destination,
                size: payload.len(),
                segment_size: None,
                ecn: None,
                src_ip: None,
            })
        })
        .unwrap()
    );
}

fn drain(io: &mut UringIo) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "send completion deadline");
        io.poll(Duration::from_millis(10), |_, _, _| panic!("unexpected receive")).unwrap();
        if !io.tx.iter().any(TxPool::has_in_flight) {
            break;
        }
    }
}

#[test]
fn zero_copy_and_copy_sends_cover_both_sockets_address_families_and_empty_datagrams() {
    for (sqpoll_cpu, threshold) in
        sqpoll_cpus().into_iter().flat_map(|cpu| [0, usize::MAX].map(|threshold| (cpu, threshold)))
    {
        let Some(mut io) = receiver_with_config(&UringConfig {
            sqpoll_cpu,
            send_zc_min_size: threshold,
            ..config()
        }) else {
            return
        };
        for ipv6 in [false, true] {
            let peer = peer(ipv6);
            for socket in SOCKETS {
                for payload in [b"first".as_slice(), b"replacement".as_slice(), b"".as_slice()] {
                    send(&mut io, socket, peer.local_addr().unwrap(), payload);
                    assert!(io.is_blocked(socket));
                    assert!(
                        !io.send(socket, |_| panic!("consumed producer before a slot was free"))
                            .unwrap()
                    );
                    io.flush().unwrap();
                    drain(&mut io);
                    assert!(!io.is_blocked(socket));
                    let mut bytes = [0; 64];
                    let (len, remote) = peer.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..len], payload);
                    assert_eq!(remote.port(), io.local_addr(socket).unwrap().port());
                    assert_eq!(remote.ip(), peer.local_addr().unwrap().ip());
                }
            }
        }
        io.shutdown().unwrap();
    }
}

#[test]
fn transmit_pools_are_independent_and_headers_survive_moving_the_owner() {
    let Some(mut io) = receiver_with_config(&config()) else { return };
    let peer = peer(false);
    send(&mut io, SocketId::Quic, peer.local_addr().unwrap(), b"quic");
    assert!(io.is_blocked(SocketId::Quic));
    assert!(!io.is_blocked(SocketId::Discovery));
    send(&mut io, SocketId::Discovery, peer.local_addr().unwrap(), b"discovery");
    io.flush().unwrap();
    let io = thread::spawn(move || {
        drain(&mut io);
        io
    })
    .join()
    .unwrap();
    let mut packets = Vec::new();
    for _ in 0..2 {
        let mut bytes = [0; 64];
        let (len, remote) = peer.recv_from(&mut bytes).unwrap();
        packets.push((bytes[..len].to_vec(), remote.port()));
    }
    assert!(packets.contains(&(b"quic".to_vec(), io.local_addr(SocketId::Quic).unwrap().port())));
    assert!(
        packets
            .contains(&(b"discovery".to_vec(), io.local_addr(SocketId::Discovery).unwrap().port()))
    );
}

#[test]
fn one_ring_dispatches_receives_send_results_and_notifications_together() {
    let Some(mut io) = receiver_with_config(&config()) else { return };
    let peer = peer(false);
    for socket in SOCKETS {
        peer.send_to(b"incoming", destination(&io, socket, false)).unwrap();
        send(&mut io, socket, peer.local_addr().unwrap(), b"outgoing");
    }
    let packets = receive(&mut io, 2);
    for socket in SOCKETS {
        assert!(packets.iter().any(|(id, data, remote)| *id == socket &&
            &data[..] == b"incoming" &&
            *remote == peer.local_addr().unwrap()));
    }
    drain(&mut io);
    for _ in 0..2 {
        let mut bytes = [0; 16];
        let (len, _) = peer.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"outgoing");
    }
}

#[test]
fn zero_copy_gso_preserves_segments_and_accepts_ecn_and_source_addresses() {
    let Some(mut io) = receiver_with_config(&config()) else { return };
    for ipv6 in [false, true] {
        let peer = peer(ipv6);
        let address = peer.local_addr().unwrap();
        assert!(
            io.send(SocketId::Quic, |buffer| {
                for index in 0..10u8 {
                    buffer.extend(repeat_n(index, if index == 9 { 117 } else { 1200 }));
                }
                Some(Transmit {
                    destination: address,
                    size: buffer.len(),
                    segment_size: Some(1200),
                    ecn: Some(EcnCodepoint::Ect0),
                    src_ip: Some(address.ip()),
                })
            })
            .unwrap()
        );
        io.flush().unwrap();
        drain(&mut io);
        for index in 0..10u8 {
            let mut bytes = [0; 1500];
            let (len, remote) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(len, if index == 9 { 117 } else { 1200 });
            assert!(bytes[..len].iter().all(|byte| *byte == index));
            assert_eq!(remote.ip(), address.ip());
        }
    }
}

#[test]
fn full_submission_and_completion_queues_preserve_transmits() {
    let config = UringConfig {
        sq_entries: 2,
        cq_entries: 2,
        quic_tx_buffers: 8,
        discovery_tx_buffers: 8,
        ..config()
    };
    let Some(mut io) = receiver_with_config(&config) else { return };
    let peer = peer(false);
    for number in 0..8u8 {
        for socket in SOCKETS {
            send(&mut io, socket, peer.local_addr().unwrap(), &[socket as u8, number]);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !io.ring.submission().cq_overflow() {
        assert!(Instant::now() < deadline, "CQ did not overflow");
        io.flush().unwrap();
        thread::yield_now();
    }
    drain(&mut io);
    let mut packets = Vec::new();
    for _ in 0..16 {
        let mut bytes = [0; 16];
        let (len, _) = peer.recv_from(&mut bytes).unwrap();
        assert_eq!(len, 2);
        packets.push((bytes[0], bytes[1]));
    }
    packets.sort_unstable();
    assert_eq!(
        packets,
        (0..2u8)
            .flat_map(|socket| (0..8u8).map(move |number| (socket, number)))
            .collect::<Vec<_>>()
    );
    assert!(!io.is_blocked(SocketId::Quic));
    assert!(!io.is_blocked(SocketId::Discovery));
    io.shutdown().unwrap();
}

#[test]
fn failed_send_releases_its_slot_after_any_notification_and_allows_reuse() {
    let Some(mut io) = receiver_with_config(&config()) else { return };
    send(&mut io, SocketId::Quic, SocketAddr::from(([127, 0, 0, 1], 0)), b"invalid port");
    let deadline = Instant::now() + Duration::from_secs(2);
    let error = loop {
        assert!(Instant::now() < deadline, "failed send completion deadline");
        if let Err(error) = io.poll(Duration::from_millis(10), |_, _, _| {}) {
            break error;
        }
    };
    assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    drain(&mut io);
    let peer = peer(false);
    send(&mut io, SocketId::Quic, peer.local_addr().unwrap(), b"valid");
    drain(&mut io);
    let mut bytes = [0; 16];
    let (len, _) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], b"valid");
}

#[test]
fn shutdown_cancels_submitted_sends_and_discards_only_unsubmitted_sends() {
    let config = UringConfig {
        sq_entries: 2,
        cq_entries: 2,
        quic_tx_buffers: 16,
        discovery_tx_buffers: 16,
        ..config()
    };
    let Some(mut io) = receiver_with_config(&config) else { return };
    io.flush().unwrap();
    let addresses = SOCKETS.map(|socket| io.local_addr(socket).unwrap());
    let peer = peer(false);
    for number in 0..16u8 {
        for socket in SOCKETS {
            send(&mut io, socket, peer.local_addr().unwrap(), &[number; 1200]);
        }
    }
    io.flush().unwrap();
    io.shutdown().unwrap();
    assert!(!io.tx.iter().any(TxPool::has_in_flight));
    assert!(io.send(SocketId::Quic, |_| panic!("producer called after shutdown")).is_err());
    drop(io);
    for address in addresses {
        UdpSocket::bind(address).expect("send still holds the socket after shutdown");
    }
}
