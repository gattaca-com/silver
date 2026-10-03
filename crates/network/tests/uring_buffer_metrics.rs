#![cfg(all(target_os = "linux", feature = "io-uring"))]

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use silver_network::{NetworkCounters, SocketId, UringConfig, UringIo};

fn receive(io: &mut UringIo) -> (SocketId, BytesMut) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut packet = None;
    while packet.is_none() {
        assert!(Instant::now() < deadline, "receive deadline");
        io.poll(Duration::from_millis(10), |socket, data, _| {
            assert!(packet.is_none(), "unexpected extra packet");
            packet = Some((socket, data));
        })
        .unwrap();
    }
    packet.unwrap()
}

fn gauges(socket: SocketId) -> [u64; 4] {
    match socket {
        SocketId::Quic => [
            NetworkCounters::UringQuicRxBuffersCapacity,
            NetworkCounters::UringQuicRxBuffersProvided,
            NetworkCounters::UringQuicRxBuffersInUse,
            NetworkCounters::UringQuicRxBuffersHighWater,
        ],
        SocketId::Discovery => [
            NetworkCounters::UringDiscoveryRxBuffersCapacity,
            NetworkCounters::UringDiscoveryRxBuffersProvided,
            NetworkCounters::UringDiscoveryRxBuffersInUse,
            NetworkCounters::UringDiscoveryRxBuffersHighWater,
        ],
    }
    .map(NetworkCounters::get)
}

#[test]
fn provided_pool_metrics_track_retention_exhaustion_recycling_and_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    NetworkCounters::init_with_base(directory.path(), "uring-buffer-metrics").unwrap();
    let config = UringConfig {
        sq_entries: 8,
        cq_entries: 16,
        quic_rx_buffers: 1,
        discovery_rx_buffers: 2,
        ..Default::default()
    };
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut io = UringIo::new(&config, addr, addr).unwrap();
    let [quic, discovery] = [SocketId::Quic, SocketId::Discovery].map(|socket| {
        SocketAddr::from((Ipv4Addr::LOCALHOST, io.local_addr(socket).unwrap().port()))
    });
    let peer = UdpSocket::bind(addr).unwrap();
    assert_eq!(gauges(SocketId::Quic), [1, 1, 0, 0]);
    assert_eq!(gauges(SocketId::Discovery), [2, 2, 0, 0]);

    peer.send_to(b"held", quic).unwrap();
    let (socket, held) = receive(&mut io);
    assert_eq!(socket, SocketId::Quic);
    assert_eq!(gauges(SocketId::Quic), [1, 0, 1, 1]);
    assert_eq!(NetworkCounters::UringQuicRxBuffersConsumed.get(), 1);
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 0);

    peer.send_to(b"queued", quic).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while NetworkCounters::UringQuicRxNoBuffers.get() == 0 {
        assert!(Instant::now() < deadline, "buffer exhaustion deadline");
        io.poll(Duration::from_millis(10), |_, _, _| panic!("reused a retained buffer")).unwrap();
    }
    for _ in 0..4 {
        io.poll(Duration::ZERO, |_, _, _| panic!("reused a retained buffer")).unwrap();
    }
    assert_eq!(NetworkCounters::UringQuicRxNoBuffers.get(), 1);

    peer.send_to(b"discovery", discovery).unwrap();
    let (socket, data) = receive(&mut io);
    assert_eq!(socket, SocketId::Discovery);
    assert_eq!(gauges(SocketId::Discovery), [2, 1, 1, 1]);
    drop(data);
    io.poll(Duration::ZERO, |_, _, _| panic!("unexpected packet")).unwrap();
    assert_eq!(gauges(SocketId::Discovery), [2, 2, 0, 1]);
    assert_eq!(NetworkCounters::UringDiscoveryRxBuffersConsumed.get(), 1);
    assert_eq!(NetworkCounters::UringDiscoveryRxBuffersRecycled.get(), 1);
    assert_eq!(NetworkCounters::UringDiscoveryRxNoBuffers.get(), 0);
    assert_eq!(gauges(SocketId::Quic), [1, 0, 1, 1]);

    drop(held);
    let (_, queued) = receive(&mut io);
    assert_eq!(&queued[..], b"queued");
    assert_eq!(NetworkCounters::UringQuicRxBuffersConsumed.get(), 2);
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 1);
    drop(queued);
    io.poll(Duration::ZERO, |_, _, _| panic!("unexpected packet")).unwrap();
    assert_eq!(gauges(SocketId::Quic), [1, 1, 0, 1]);
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 2);

    peer.send_to(&[0; 4096], quic).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while NetworkCounters::UringQuicRxBuffersConsumed.get() < 3 {
        assert!(Instant::now() < deadline, "truncated packet deadline");
        io.poll(Duration::from_millis(10), |_, _, _| panic!("truncated packet delivered")).unwrap();
    }
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 3);
    assert_eq!(gauges(SocketId::Quic), [1, 1, 0, 1]);

    peer.send_to(b"outlives pool", quic).unwrap();
    let (_, retained) = receive(&mut io);
    io.shutdown().unwrap();
    io.shutdown().unwrap();
    assert_eq!(gauges(SocketId::Quic), [0; 4]);
    assert_eq!(gauges(SocketId::Discovery), [0; 4]);
    assert_eq!(NetworkCounters::UringQuicRxBuffersConsumed.get(), 4);
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 3);
    drop(io);
    assert_eq!(&retained[..], b"outlives pool");

    let mut io = UringIo::new(&config, addr, addr).unwrap();
    assert_eq!(gauges(SocketId::Quic), [1, 1, 0, 0]);
    assert_eq!(gauges(SocketId::Discovery), [2, 2, 0, 0]);
    assert_eq!(NetworkCounters::UringQuicRxBuffersConsumed.get(), 4);
    assert_eq!(NetworkCounters::UringQuicRxBuffersRecycled.get(), 3);
    io.shutdown().unwrap();
}
