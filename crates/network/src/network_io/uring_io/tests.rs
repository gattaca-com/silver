mod tx;
#[cfg(feature = "thread_park")]
mod wake;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    panic::{AssertUnwindSafe, catch_unwind},
    thread,
};

use super::*;
use crate::socket::RX_BUF_SIZE;

fn receiver(quic_rx_buffers: u16, discovery_rx_buffers: u16) -> Option<UringIo> {
    let config = UringConfig {
        sq_entries: 8,
        cq_entries: 16,
        quic_rx_buffers,
        discovery_rx_buffers,
        ..Default::default()
    };
    receiver_with_config(&config)
}

fn receiver_with_config(config: &UringConfig) -> Option<UringIo> {
    match UringIo::new(config, "[::]:0".parse().unwrap(), "[::]:0".parse().unwrap()) {
        Ok(receiver) => Some(receiver),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            eprintln!("SKIP io_uring receive test: {error}");
            None
        }
        Err(error) => panic!("create io_uring receiver: {error}"),
    }
}

#[test]
fn completion_queue_pressure_does_not_lose_packets_or_stop_receiving() {
    let config = UringConfig {
        sq_entries: 2,
        cq_entries: 2,
        quic_rx_buffers: 32,
        discovery_rx_buffers: 32,
        ..Default::default()
    };
    let Some(mut receiver) = receiver_with_config(&config) else { return };
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for number in 0..8u8 {
        for socket in SOCKETS {
            peer.send_to(&[number], destination(&receiver, socket, false)).unwrap();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.ring.submission().cq_overflow() {
        assert!(Instant::now() < deadline, "CQ did not overflow");
        thread::yield_now();
    }
    let packets = receive(&mut receiver, 16);
    for socket in SOCKETS {
        let mut numbers: Vec<_> =
            packets.iter().filter(|(id, _, _)| *id == socket).map(|(_, data, _)| data[0]).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (0..8).collect::<Vec<_>>());
        peer.send_to(b"rearmed", destination(&receiver, socket, false)).unwrap();
    }
    for (_, data, _) in receive(&mut receiver, 2) {
        assert_eq!(&data[..], b"rearmed");
    }
    receiver.shutdown().unwrap();
}

fn destination(receiver: &UringIo, socket: SocketId, ipv6: bool) -> SocketAddr {
    let port = receiver.local_addr(socket).unwrap().port();
    if ipv6 { (Ipv6Addr::LOCALHOST, port).into() } else { (Ipv4Addr::LOCALHOST, port).into() }
}

fn receive(receiver: &mut UringIo, count: usize) -> Vec<(SocketId, BytesMut, SocketAddr)> {
    let mut packets = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while packets.len() < count {
        assert!(Instant::now() < deadline, "received {} of {count} packets", packets.len());
        receiver
            .poll(Duration::from_millis(10), |socket, data, remote| {
                packets.push((socket, data, remote));
            })
            .unwrap();
    }
    assert_eq!(packets.len(), count);
    packets
}

#[test]
fn multishot_receives_both_sockets_and_address_families_on_the_tile_thread() {
    let Some(mut receiver) = receiver(8, 4) else { return };
    let peer4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer6 = UdpSocket::bind("[::1]:0").unwrap();
    for socket in SOCKETS {
        peer4.send_to(b"ipv4", destination(&receiver, socket, false)).unwrap();
        peer6.send_to(b"ipv6", destination(&receiver, socket, true)).unwrap();
        peer4.send_to(&[], destination(&receiver, socket, false)).unwrap();
    }
    thread::spawn(move || {
        let packets = receive(&mut receiver, 6);
        for socket in SOCKETS {
            let packets: Vec<_> = packets.iter().filter(|(id, _, _)| *id == socket).collect();
            assert_eq!(packets.len(), 3);
            assert!(
                packets.iter().any(|(_, data, remote)| &data[..] == b"ipv4" &&
                    *remote == peer4.local_addr().unwrap())
            );
            assert!(
                packets.iter().any(|(_, data, remote)| &data[..] == b"ipv6" &&
                    *remote == peer6.local_addr().unwrap())
            );
            assert!(
                packets
                    .iter()
                    .any(|(_, data, remote)| data.is_empty() &&
                        *remote == peer4.local_addr().unwrap())
            );
        }
        receiver.shutdown().unwrap();
        assert_eq!(receiver.active, [false; 2]);
    })
    .join()
    .unwrap();
}

#[test]
fn exhausted_quic_pool_keeps_discovery_live_and_recovers_after_packet_release() {
    let Some(mut receiver) = receiver(1, 2) else { return };
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let quic = destination(&receiver, SocketId::Quic, false);
    let discovery = destination(&receiver, SocketId::Discovery, false);
    peer.send_to(b"retained", quic).unwrap();
    let mut packets = receive(&mut receiver, 1);
    let (_, retained, _) = packets.pop().unwrap();
    let retained_ptr = retained.as_ptr();
    peer.send_to(b"queued", quic).unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    while receiver.active[SocketId::Quic as usize] {
        assert!(Instant::now() < deadline, "receive did not terminate on buffer exhaustion");
        receiver
            .poll(Duration::from_millis(10), |_, _, _| panic!("reused a retained buffer"))
            .unwrap();
    }
    for _ in 0..16 {
        peer.send_to(b"discovery", discovery).unwrap();
        let packets = receive(&mut receiver, 1);
        assert_eq!(packets[0].0, SocketId::Discovery);
        assert_eq!(&packets[0].1[..], b"discovery");
        assert_eq!(&retained[..], b"retained");
    }
    drop(retained);
    let packets = receive(&mut receiver, 1);
    assert_eq!(packets[0].0, SocketId::Quic);
    assert_eq!(&packets[0].1[..], b"queued");
    assert_eq!(packets[0].1.as_ptr(), retained_ptr, "pool allocated a replacement buffer");
    receiver.shutdown().unwrap();
    drop(receiver);
    assert_eq!(&packets[0].1[..], b"queued", "packet did not outlive the receiver");
}

#[test]
fn truncated_datagrams_are_dropped_and_buffers_remain_reusable() {
    let Some(mut receiver) = receiver(2, 2) else { return };
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = destination(&receiver, SocketId::Quic, false);
    peer.send_to(&vec![9; RX_BUF_SIZE + 1], destination).unwrap();
    peer.send_to(&vec![7; RX_BUF_SIZE], destination).unwrap();
    let packets = receive(&mut receiver, 1);
    assert_eq!(&packets[0].1[..], &vec![7; RX_BUF_SIZE]);
    drop(packets);
    peer.send_to(b"after truncation", destination).unwrap();
    assert_eq!(&receive(&mut receiver, 1)[0].1[..], b"after truncation");
}

#[test]
fn shutdown_drains_busy_receives_and_releases_socket_ports() {
    let Some(mut receiver) = receiver(4, 4) else { return };
    let addresses = SOCKETS.map(|socket| receiver.local_addr(socket).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..32 {
        for socket in SOCKETS {
            peer.send_to(b"pending during shutdown", destination(&receiver, socket, false))
                .unwrap();
        }
    }
    receiver.shutdown().unwrap();
    receiver.shutdown().unwrap();
    assert_eq!(receiver.active, [false; 2]);
    assert_eq!(
        receiver.poll(Duration::ZERO, |_, _, _| {}).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    drop(receiver);
    for address in addresses {
        UdpSocket::bind(address).expect("receive still holds a socket after shutdown");
    }
}

#[test]
fn callback_unwind_cancels_receives_before_freeing_their_buffers() {
    let Some(receiver) = receiver(2, 2) else { return };
    let addresses = SOCKETS.map(|socket| receiver.local_addr(socket).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(b"panic", destination(&receiver, SocketId::Quic, false)).unwrap();
    let result = catch_unwind(AssertUnwindSafe(move || {
        let mut receiver = receiver;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < deadline, "receive deadline");
            receiver.poll(Duration::from_millis(10), |_, _, _| panic!("receive callback")).unwrap();
        }
    }));
    let panic = result.expect_err("callback did not panic");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"receive callback"));
    for address in addresses {
        UdpSocket::bind(address).expect("unwinding left an active receive");
    }
}

#[test]
fn bans_filter_both_socket_pools_and_unbanning_restores_receives() {
    let Some(mut io) = receiver(8, 8) else { return };
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ip = peer.local_addr().unwrap().ip();
    io.ban(ip);
    for socket in SOCKETS {
        peer.send_to(b"banned", destination(&io, socket, false)).unwrap();
    }
    let deadline = Instant::now() + Duration::from_millis(20);
    while Instant::now() < deadline {
        assert_eq!(
            io.poll(Duration::from_millis(2), |_, _, _| panic!("banned packet")).unwrap(),
            0
        );
    }
    io.unban(ip);
    for socket in SOCKETS {
        peer.send_to(b"allowed", destination(&io, socket, false)).unwrap();
    }
    for (_, data, _) in receive(&mut io, 2) {
        assert_eq!(&data[..], b"allowed");
    }
    io.shutdown().unwrap();
}
