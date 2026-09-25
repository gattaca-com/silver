use std::{io::Write, sync::Arc, time::Duration};

use silver_chain_spec::SpecConfig;
use silver_common::{
    ColumnOrigin, ForkName, GossipMsgIn, GossipMsgOut, HeadChange, HeadRoots, IpBytes, Keypair,
    MessageId, Nanos, P2pStreamId, PayloadResolution, PeerId, SszCache, StreamProtocol,
    SyncCommitteeSubnets, TCache, TCacheId, TCacheProducer, TCacheRead, TCacheReader, TCacheTable,
    TProducer, TReadMode, test_util::ShmemDir,
};
use silver_peer::SyncingConfig;

fn test_domain() -> silver_common::GossipDomain {
    silver_common::GossipDomain::new([0; 4], silver_common::ForkName::Fulu)
}

use super::*;

mod partial;

struct GossipPublications {
    controller: Controller,
    adapter: SpineAdapter<SilverSpine>,
    observer: SpineAdapter<SilverSpine>,
    incoming: TProducer,
    rpc: TProducer,
    payload: TCacheRead,
    outbound: TCacheReader,
    _spine: Box<SilverSpine>,
    _dir: ShmemDir,
}

struct Observer;
impl Tile<SilverSpine> for Observer {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

impl GossipPublications {
    fn new(topic: GossipTopic, bytes: &[u8]) -> Self {
        let incoming = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
        let cluster_in = TCache::producer(TCacheId::ClusterInbound, 1 << 16);
        let rpc = TCache::producer(TCacheId::NetworkProcessing, 1 << 16);
        let mut protobuf = TCache::producer(TCacheId::ControlGossip, 1 << 16);
        let payload = write_bytes(&mut protobuf, bytes);
        let mut outbound =
            TCacheReader::single(protobuf.cache_ref(), "publication_observer", TReadMode::Sliding)
                .unwrap();
        let boundary = TCache::producer(TCacheId::BoundaryProcessing, 1 << 12);
        // Plays the network: the handler's mcache pins forward to it.
        outbound.declare(TCacheId::ControlGossip, &[TileId::Control]);
        let tcaches = TCacheTable::from_iter(
            [&incoming, &cluster_in, &rpc, &protobuf, &boundary].map(|p| p.cache_ref()),
        );
        let mut controller = Controller::new(
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
                tcaches,
                TCache::producer(TCacheId::ControlProcessing, 1 << 16),
                protobuf,
                Some(test_domain()),
            )
            .unwrap(),
            TCache::producer(TCacheId::ControlRpc, 1 << 16),
            tcaches,
            TCache::producer(TCacheId::ClusterOutbound, 1 << 16),
            None,
            SyncEngine::new(SyncingConfig::default(), false, 0, Arc::new(SpecConfig::mainnet())),
            Arc::new(SpecConfig::mainnet()),
            [0; 8],
            SyncCommitteeSubnets::OnDemand,
        )
        .unwrap();
        controller.open_tcaches().unwrap();
        let dir = ShmemDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
        let adapter = SpineAdapter::connect_tile(&controller, &mut *spine);
        let mut observer = SpineAdapter::connect_tile(&Observer, &mut *spine);
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
            capture.observer.produce(PeerEvent::P2pGossipTopicSubscribe {
                p2p_peer: peer as usize,
                topic,
                digest: [0; 4],
            });
        }
        capture.crank();
        capture.sent();
        capture
    }

    fn crank(&mut self) {
        self.controller.loop_body(&mut self.adapter);
    }

    fn persist_column(&mut self, origin: ColumnOrigin, bytes: &[u8]) {
        let (ssz, ssz_cache, domain) = match origin {
            ColumnOrigin::Rpc => {
                (write_bytes(&mut self.rpc, bytes), SszCache::Rpc, Some(test_domain()))
            }
            ColumnOrigin::El | ColumnOrigin::Assembly => {
                let config =
                    CellStoreConfig::new(self.controller.spec.clone(), 1 << 5, Duration::ZERO)
                        .unwrap();
                let producer = TCache::producer(TCacheId::ControlSlot, config.cache_capacity());
                let ingress = self
                    .controller
                    .cell_ingress
                    .insert(CellIngress::new(config, producer, 9, Instant::now()).unwrap());
                (
                    write_bytes(ingress.producer_mut(), bytes),
                    SszCache::DataColumns,
                    (origin != ColumnOrigin::El).then_some(test_domain()),
                )
            }
            ColumnOrigin::Gossip => unreachable!(),
        };
        self.observer.produce(DataColumnsEvent::Persist {
            ssz,
            origin,
            ssz_cache,
            domain,
            block_root: [0x51; 32],
            column_index: 5,
            slot: 9,
        });
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
fn gossip_cutover_uses_clock_despite_delayed_status_and_keeps_old_routing_until_retirement() {
    let topic = GossipTopic::DataColumnSidecar(5);
    let bytes = b"validated gossip frame";
    let mut capture = GossipPublications::new(topic, bytes);
    capture.observer.consume(|_: PeerControl, _| {});
    let mut spec = SpecConfig::mainnet();
    spec.fulu_fork_epoch = 0;
    spec.gloas_fork_epoch = 10;
    spec.blob_schedule.clear();
    let old = GossipDomain::new(spec.fork_digest_at(9, &[0; 32]), ForkName::Fulu);
    let new = GossipDomain::new(spec.fork_digest_at(10, &[0; 32]), ForkName::Gloas);
    capture.controller.spec = Arc::new(spec);
    let mut ticker = SlotTicker::new(0, Duration::from_secs(12), Duration::from_secs(3));
    ticker.set_current_slot(9 * SLOTS_PER_EPOCH);
    capture.controller.set_gossip_clock(ticker, &[0; 32]);
    capture.crank();
    assert_eq!(capture.controller.gossip_handler.current_domain(), Some(old));
    let mut subscriptions = Vec::new();
    capture.observer.consume(|event: PeerControl, _| {
        if let PeerControl::P2pGossipSubscribe { digest, .. } = event {
            subscriptions.push(digest);
        }
    });
    assert_eq!(subscriptions.iter().filter(|digest| **digest == old.digest()).count(), 2);
    assert_eq!(subscriptions.iter().filter(|digest| **digest == new.digest()).count(), 2);
    for peer in [1, 2] {
        for domain in [old, new] {
            capture.observer.produce(PeerEvent::P2pGossipTopicSubscribe {
                p2p_peer: peer,
                topic,
                digest: domain.digest(),
            });
        }
    }
    capture.crank();
    capture.sent();

    capture
        .controller
        .gossip_schedule
        .as_mut()
        .unwrap()
        .ticker
        .set_current_slot(10 * SLOTS_PER_EPOCH);
    let mut old_status = [0; STATUS_V2_SIZE];
    old_status[..4].copy_from_slice(&old.digest());
    capture.observer.produce(BeaconStateEvent::Status {
        ssz: old_status,
        latest_block_slot: 0,
        wall_slot: 9 * SLOTS_PER_EPOCH,
        head_optimistic: false,
        enr_fork_id: [0; 16],
        head_roots: HeadRoots::default(),
        head_payload: PayloadResolution::Full,
        head_change: HeadChange::None,
        epoch_transition: false,
    });
    capture.crank();
    assert_eq!(capture.controller.gossip_handler.current_domain(), Some(new));
    assert_eq!(capture.controller.peer_manager.our_fork_digest(), Some(new.digest()));
    assert_eq!(
        StatusView::fork_digest(capture.controller.peer_manager.status().unwrap()),
        &new.digest()
    );
    let mut cutover_enr = false;
    capture.observer.consume(|event: PeerControl, _| {
        if let PeerControl::UpdateEnrForkId { epoch: 10, enr_fork_id } = event {
            assert_eq!(&enr_fork_id[..4], &new.digest());
            cutover_enr = true;
        }
    });
    assert!(cutover_enr);
    capture.sent();

    let ssz = write_bytes(&mut capture.rpc, b"validated sidecar");
    for (index, domain) in [old, new].into_iter().enumerate() {
        capture.observer.produce(PeerEvent::SendGossip {
            originator_stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
            topic,
            domain,
            ssz_cache: SszCache::Gossip,
            msg_hash: MessageId { id: [0xCD + index as u8; 20] },
            recv_ts: Nanos::now(),
            protobuf: capture.payload,
            ssz,
        });
        capture.crank();
        assert_eq!(capture.sent(), [(2, bytes.to_vec())]);
    }

    capture
        .controller
        .gossip_schedule
        .as_mut()
        .unwrap()
        .ticker
        .set_current_slot(12 * SLOTS_PER_EPOCH);
    capture.crank();
    let mut retired = Vec::new();
    capture.observer.consume(|event: PeerControl, _| {
        if let PeerControl::P2pGossipUnsubscribe { digest, .. } = event {
            retired.push(digest);
        }
    });
    assert_eq!(retired, [old.digest(); 2]);
    assert_eq!(capture.controller.gossip_handler.current_domain(), Some(new));
}

#[test]
fn relay_requests_preserve_routing_and_iwant_service() {
    // Distinct payloads expose confusion between the encoded and decompressed
    // handles.
    let bytes = b"relay payload";
    let hash = MessageId { id: [0xCD; 20] };
    for topic in [GossipTopic::BeaconBlock, GossipTopic::DataColumnSidecar(5)] {
        let mut capture = GossipPublications::new(topic, bytes);
        let ssz = write_bytes(&mut capture.rpc, b"decompressed object");
        capture.observer.produce(PeerEvent::SendGossip {
            originator_stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
            topic,
            domain: test_domain(),
            ssz_cache: silver_common::SszCache::Gossip,
            msg_hash: hash,
            recv_ts: Nanos::now(),
            protobuf: capture.payload,
            ssz,
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
    for origin in [ColumnOrigin::Rpc, ColumnOrigin::El, ColumnOrigin::Assembly] {
        assert_column_publication(origin);
    }
}

fn assert_column_publication(origin: ColumnOrigin) {
    let topic = GossipTopic::DataColumnSidecar(5);
    // Transport decoding checks payload size; consensus validation is outside this
    // fixture.
    let bytes = vec![0x42; topic.min_uncompressed_size()];
    let mut capture = GossipPublications::new(topic, &[]);
    capture.observer.consume(|_: PeerEvent, _| {});
    capture.controller.peer_manager.set_sync_target(SyncUpdate::Following);
    if origin != ColumnOrigin::El {
        // These columns were validated before the fork domain changed.
        capture
            .controller
            .gossip_handler
            .set_domains(GossipDomain::new([1; 4], ForkName::Gloas), None);
    }
    capture.persist_column(origin, &bytes);
    capture.crank();
    let sent = capture.sent();
    let frames_to = |peer: usize| {
        let mut frames: Vec<_> =
            sent.iter().filter(|(to, _)| *to == peer).map(|(_, frame)| frame.clone()).collect();
        frames.sort();
        frames
    };
    assert_eq!(frames_to(1), frames_to(2), "a local origin excludes no mesh peer");
    assert_eq!(frames_to(2).len(), 2, "the message and one control frame: {sent:?}");

    // Decode what peer 2 received as peer 2 would.
    let decoded = TCache::producer(TCacheId::ControlProcessing, 1 << 16);
    let mut decoded_reader =
        TCacheReader::single(decoded.cache_ref(), "publication_decoded", TReadMode::Sliding)
            .unwrap();
    let protobuf = TCache::producer(TCacheId::ControlGossip, 1 << 16);
    let mut receiver = GossipHandler::new(
        TCacheTable::from_iter([capture.incoming.cache_ref(), protobuf.cache_ref()]),
        decoded,
        protobuf,
        Some(test_domain()),
    )
    .unwrap();
    receiver.open_tcaches().unwrap();
    let mut receiver_adapter = SpineAdapter::connect_tile(&Observer, &mut capture._spine);
    receiver.spin(&mut receiver_adapter, None);
    let stream = P2pStreamId::new(2, 0, StreamProtocol::GossipSub, true);
    let mut message = None;
    let mut dontwant = None;
    let mut encoded = Vec::new();
    for frame in frames_to(2) {
        let mut packet = stream.as_ref().to_vec();
        packet.extend_from_slice(&frame);
        let tcache = write_bytes(&mut capture.incoming, &packet);
        capture.observer.produce(GossipMsgIn { p2p_id: stream, tcache });
        receiver.spin(&mut receiver_adapter, None);
        while let Some(event) = receiver.pop_event() {
            match event {
                GossipHandlerEvent::NewGossip(received) => {
                    encoded = frame.clone();
                    message = Some(received);
                }
                GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipDontWant { hash, .. }) => {
                    dontwant = Some(hash);
                }
                // The first RPC on a peer stream reports its (absent) extension
                // state; a decoded message also notifies the peer manager.
                GossipHandlerEvent::PeerEvent(
                    PeerEvent::P2pGossipExtensions { .. } | PeerEvent::NewGossip { .. },
                ) => {}
                _ => panic!("unexpected event from the receiver"),
            }
        }
    }
    let message = message.expect("publication must decode as a gossip message");
    assert_eq!(message.topic, topic);
    assert_eq!(decoded_reader.acquire(message.ssz).buffer().unwrap().0, bytes);
    assert_eq!(dontwant, Some(message.msg_hash), "the mesh is told not to send it back");

    capture.iwant(1, message.msg_hash);
    assert_eq!(capture.sent(), [(1, encoded)], "the publication populated the message cache");
    capture.observer.consume(|event: PeerEvent, _| {
        if let PeerEvent::SendGossip { .. } = event {
            panic!("column conversion must stay local");
        }
    });
}

#[test]
fn a_syncing_node_republishes_no_columns() {
    for origin in [ColumnOrigin::Rpc, ColumnOrigin::El, ColumnOrigin::Assembly] {
        assert_no_syncing_publication(origin);
    }
}

fn assert_no_syncing_publication(origin: ColumnOrigin) {
    let topic = GossipTopic::DataColumnSidecar(5);
    let bytes = vec![0x42; topic.min_uncompressed_size()];
    let mut capture = GossipPublications::new(topic, &[]);
    capture
        .controller
        .peer_manager
        .set_sync_target(SyncUpdate::SyncingHead { head_root: [0x33; 32], head_slot: 900 });
    capture.persist_column(origin, &bytes);
    capture.crank();
    assert!(capture.sent().is_empty(), "peers ahead of us already hold the column");
}
