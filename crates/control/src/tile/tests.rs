use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use silver_chain_spec::SpecConfig;
use silver_common::{
    GossipBlock, GossipMsgIn, GossipMsgOut, IpBytes, Keypair, MessageId, P2pStreamId, PeerId,
    StreamProtocol, TCache, TCacheProducer, TCacheRead, TProducer,
};
use silver_peer::SyncingConfig;

use super::*;

struct GossipPublications {
    controller: Controller,
    adapter: SpineAdapter<SilverSpine>,
    observer: SpineAdapter<SilverSpine>,
    incoming: TProducer,
    payload: TCacheRead,
    outbound: TRandomAccess,
    _spine: Box<SilverSpine>,
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
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "silver-publications-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&base).unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));
        let adapter = SpineAdapter::connect_tile(&controller, &mut spine);
        let mut observer = SpineAdapter::connect_tile(&Observer, &mut spine);
        observer.consume(|_: P2pSend, _| {});
        let mut capture =
            Self { controller, adapter, observer, incoming, payload, outbound, _spine: spine };
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
    for block in [None, Some(GossipBlock { slot: 37, block_root: [0xAB; 32] })] {
        let mut capture = GossipPublications::new(GossipTopic::BeaconBlock, bytes);
        capture.observer.produce(PeerEvent::SendGossip {
            originator_stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
            topic: GossipTopic::BeaconBlock,
            msg_hash: hash,
            recv_ts: Nanos::now(),
            protobuf: capture.payload,
            block,
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
