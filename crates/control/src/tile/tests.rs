use std::{io::Write, sync::Arc};

use silver_chain_spec::SpecConfig;
use silver_common::{
    GossipBlock, GossipDataColumn, GossipMsgIn, GossipMsgOut, IpBytes, Keypair, MessageId,
    P2pStreamId, PeerId, StreamProtocol, TCache, TCacheProducer, TCacheRead, TProducer,
    test_util::ShmemDir,
};
use silver_peer::SyncingConfig;

use super::*;

struct GossipPublications {
    controller: Controller,
    adapter: SpineAdapter<SilverSpine>,
    observer: SpineAdapter<SilverSpine>,
    incoming: TProducer,
    rpc: TProducer,
    payload: TCacheRead,
    outbound: TRandomAccess,
    _spine: Box<SilverSpine>,
    _dir: ShmemDir,
}

struct Observer;
impl Tile<SilverSpine> for Observer {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

impl GossipPublications {
    fn new(topic: GossipTopic, bytes: &[u8]) -> Self {
        let incoming = TCache::producer("publication_in", 1 << 16);
        let rpc = TCache::producer("publication_rpc", 1 << 16);
        let mut protobuf = TCache::producer("publication_out", 1 << 16);
        let payload = write_bytes(&mut protobuf, bytes);
        let outbound = protobuf.cache_ref().random_access("publication_observer", true).unwrap();
        let controller = Controller::new(
            PeerManager::new(
                PeerId::default(),
                vec![],
                vec![topic],
                Default::default(),
                SyncingConfig::default(),
                [0; 4],
                [0; METADATA_SIZE],
                0,
            ),
            GossipHandler::new(
                incoming.cache_ref().random_access("publication_in", true).unwrap(),
                TCache::producer("publication_ssz", 1 << 16),
                protobuf,
                "00000000".to_owned(),
            )
            .unwrap(),
            TCache::multi_producer("publication_rpc_out", 1 << 16),
            rpc.cache_ref().random_access("publication_rpc", true).unwrap(),
            SyncEngine::new(SyncingConfig::default(), false, 0, Arc::new(SpecConfig::mainnet())),
        );
        let dir = ShmemDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
        let adapter = SpineAdapter::connect_tile(&controller, &mut spine);
        let mut observer = SpineAdapter::connect_tile(&Observer, &mut spine);
        observer.consume(|_: P2pSend, _| {});
        let mut capture = Self {
            controller,
            adapter,
            observer,
            incoming,
            rpc,
            payload,
            outbound,
            _spine: spine,
            _dir: dir,
        };
        capture.crank();
        for peer in 1..=2u8 {
            capture.observer.produce(PeerEvent::P2pNewConnection {
                p2p_peer_id: peer as usize,
                peer_id_full: Keypair::from_secret(&[peer; 32]).unwrap().peer_id(),
                ip: IpBytes::V4([10, 0, 0, peer]),
                port: 4000 + peer as u16,
                local_dial: false,
            });
            capture
                .observer
                .produce(PeerEvent::P2pGossipTopicSubscribe { p2p_peer: peer as usize, topic });
        }
        capture.crank();
        capture.sent();
        capture
    }

    fn crank(&mut self) {
        self.controller.loop_body(&mut self.adapter);
    }

    fn sent(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut frames = Vec::new();
        self.observer.consume(|event: P2pSend, _| {
            if let P2pSend::Gossip(GossipMsgOut { peer_id, tcache }) = event {
                let read = self.outbound.acquire(tcache);
                frames.push((peer_id, read.buffer().unwrap().0.to_vec()));
            }
        });
        frames
    }

    fn iwant(&mut self, peer: usize, hash: MessageId) {
        let stream = P2pStreamId::new(peer, 0, StreamProtocol::GossipSub, true);
        let mut bytes = stream.as_ref().to_vec();
        // RPC.control → ControlMessage.iwant → ControlIWant.message_ids, each
        // length-delimited.
        bytes.extend_from_slice(&[0x1a, 24, 0x12, 22, 0x0a, 20]);
        bytes.extend_from_slice(&hash.id);
        let tcache = write_bytes(&mut self.incoming, &bytes);
        self.observer.produce(GossipMsgIn { p2p_id: stream, tcache });
        self.crank();
    }
}

fn write_bytes(producer: &mut TProducer, bytes: &[u8]) -> TCacheRead {
    let mut reservation = producer.reserve(bytes.len(), false).unwrap();
    reservation.write_all(bytes).unwrap();
    reservation.flush().unwrap();
    reservation.read()
}

#[test]
fn relay_metadata_preserves_routing_and_iwant_service() {
    // Forwarding and IWANT service treat the payload as opaque bytes.
    let bytes = b"relay payload";
    let hash = MessageId { id: [0xCD; 20] };
    for (topic, metadata) in [
        (GossipTopic::BeaconBlock, None),
        (
            GossipTopic::BeaconBlock,
            Some(GossipMetadata::Block(GossipBlock { slot: 37, block_root: [0xAB; 32] })),
        ),
        (
            GossipTopic::DataColumnSidecar(5),
            Some(GossipMetadata::DataColumn(GossipDataColumn {
                slot: 38,
                block_root: [0xCD; 32],
                column_index: 5,
            })),
        ),
    ] {
        let mut capture = GossipPublications::new(topic, bytes);
        capture.observer.produce(PeerEvent::SendGossip {
            originator_stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
            topic,
            msg_hash: hash,
            recv_ts: Nanos::now(),
            protobuf: capture.payload,
            metadata,
        });
        capture.crank();
        assert_eq!(capture.sent(), [(2, bytes.to_vec())], "the sender is excluded");

        capture.iwant(1, hash);
        assert_eq!(
            capture.sent(),
            [(1, bytes.to_vec())],
            "the relay request populated the message cache"
        );
    }
}

#[test]
fn column_publication_encodes_and_routes_without_another_spine_request() {
    let topic = GossipTopic::DataColumnSidecar(5);
    let column = GossipDataColumn { slot: 38, block_root: [0xCD; 32], column_index: 5 };
    // Transport decoding checks payload size; consensus validation is outside this
    // fixture.
    let bytes = vec![0x42; topic.min_uncompressed_size()];
    let mut capture = GossipPublications::new(topic, &[]);
    capture.observer.consume(|_: PeerEvent, _| {});
    let ssz = write_bytes(&mut capture.rpc, &bytes);
    capture.observer.produce(PeerEvent::PublishDataColumn {
        originator: P2pStreamId::new(1, 0, StreamProtocol::DataColumnSidecarsByRoot, true),
        topic,
        ssz,
        column,
    });
    capture.crank();
    let sent = capture.sent();
    let [(peer, encoded)] = sent.as_slice() else { panic!("expected one gossip publication") };
    assert_eq!(*peer, 2, "the sender is excluded");

    let decoded = TCache::producer("publication_decoded", 1 << 16);
    let mut decoded_reader =
        decoded.cache_ref().random_access("publication_decoded", true).unwrap();
    let mut receiver = GossipHandler::new(
        capture.incoming.cache_ref().random_access("publication_receiver", true).unwrap(),
        decoded,
        TCache::producer("publication_received_protobuf", 1 << 16),
        "00000000".to_owned(),
    )
    .unwrap();
    let mut receiver_adapter = SpineAdapter::connect_tile(&Observer, &mut capture._spine);
    receiver.spin(&mut receiver_adapter);
    let stream = P2pStreamId::new(2, 0, StreamProtocol::GossipSub, true);
    let mut packet = stream.as_ref().to_vec();
    packet.extend_from_slice(encoded);
    let tcache = write_bytes(&mut capture.incoming, &packet);
    capture.observer.produce(GossipMsgIn { p2p_id: stream, tcache });
    receiver.spin(&mut receiver_adapter);
    let Some(GossipHandlerEvent::NewGossip(message)) = receiver.pop_event() else {
        panic!("publication must decode as a gossip message")
    };
    assert_eq!(message.topic, topic);
    assert_eq!(decoded_reader.acquire(message.ssz).buffer().unwrap().0, bytes);

    capture.iwant(1, message.msg_hash);
    assert_eq!(capture.sent(), [(1, encoded.clone())]);
    let mut publications = 0;
    capture.observer.consume(|event: PeerEvent, _| match event {
        PeerEvent::PublishDataColumn { .. } => publications += 1,
        PeerEvent::SendGossip { .. } => panic!("column conversion must stay local"),
        _ => {}
    });
    assert_eq!(publications, 1);
}
