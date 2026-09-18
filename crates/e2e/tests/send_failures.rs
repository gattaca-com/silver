use std::{
    io::Write,
    mem::discriminant,
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    CacheFrameRef, CacheSegment, GossipMsgOut, P2pSend, P2pStreamId, PeerEvent, RpcOutbound,
    RpcRequest, RpcRequestOutbound, RpcResponse, RpcResponseOutbound, StreamProtocol,
    TCacheProducer, test_util::ShmemDir,
};
use silver_e2e::{PublisherStack, keypair_from_seed};

#[test]
fn unknown_peer_reports_every_send_variant_as_dropped() {
    let dir = ShmemDir::new().expect("create test shared-memory directory");
    let addr = "127.0.0.1:0".parse().expect("test address is valid");
    let mut stack =
        PublisherStack::new(dir.path(), "send_failures", addr, addr, keypair_from_seed(1))
            .expect("create test publisher stack");
    stack.network.loop_body(&mut stack.network_adapter);
    stack.injector_adapter.consume(|_: PeerEvent, _| {});

    let mut reservation = stack.mcache_producer.reserve(1, true).expect("reserve gossip payload");
    reservation.write_all(&[0]).expect("write gossip payload");
    let read = reservation.read();
    let frame = CacheFrameRef::write(
        &mut stack.mcache_producer,
        Instant::now() + Duration::from_secs(1),
        &[0],
        [CacheSegment::Framing { offset: 0, length: 1 }].into_iter(),
    )
    .expect("write segmented gossip frame");
    let peer = 123;
    for attempted in [
        P2pSend::Gossip(GossipMsgOut { peer_id: peer, tcache: read }),
        P2pSend::SegmentedGossip { peer_id: peer, frame, partial_cells: Some(0) },
        P2pSend::Identify(peer),
        P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
            peer,
            application_id: 7,
            request: RpcRequest::Ping([1; 8]),
        })),
        P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            stream_id: P2pStreamId::new(peer, 3, StreamProtocol::Ping, true),
            response: RpcResponse::Ping([2; 8]),
        })),
    ] {
        stack.injector_adapter.produce(attempted);
        stack.network.loop_body(&mut stack.network_adapter);
        let mut dropped = None;
        stack.injector_adapter.consume(|event: PeerEvent, _| {
            if let PeerEvent::P2pOutboundMessageDropped { p2p_peer, protocol, msg } = event {
                assert_eq!(p2p_peer, peer);
                assert_eq!(protocol, attempted.protocol());
                assert!(dropped.replace(msg).is_none(), "one event per failed send");
            }
        });
        let dropped = dropped.expect("every rejected send must be reported");
        assert_eq!(discriminant(&dropped), discriminant(&attempted));
        assert_eq!(dropped.peer_id(), peer);
        if let (P2pSend::Rpc(dropped), P2pSend::Rpc(attempted)) = (dropped, attempted) {
            assert_eq!(discriminant(&dropped), discriminant(&attempted));
        }
    }
}
