use std::{io::Write, net::IpAddr, sync::Arc};

use buffa::MessageView;
use silver_chain_spec::SpecConfig;
use silver_columns::cell_store::CellStore;
use silver_common::{
    CacheFrameRef, GossipDomain, Keypair, P2pStreamId, PeerId, StreamProtocol, TCache,
    TCacheProducer, TRandomAccess,
    cell_store::{AssemblyRequest, CommitmentContext, ContextData, FuluContextSource},
    column_util::{columns_of, push_data_column_sidecar_prefix},
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF, METADATA_SIZE,
        partial_column::{
            PartialDataColumnPartsMetadataView, PartialDataColumnSidecarFuluView,
            PartialDataColumnSidecarGloasView,
        },
    },
};
use silver_peer::SyncingConfig;

use super::*;

#[path = "../../../gossip/src/generated/protobuf.gossipsub.rs"]
#[allow(dead_code, clippy::all)]
#[rustfmt::skip]
mod protobuf;

mod acquisition;
mod allocations;

const ROOT: [u8; 32] = [7; 32];
const ROWS: usize = 4;

struct Rig {
    config: CellStoreConfig,
    request: AssemblyRequest,
    columns: Box<TRandomAccess>,
    network: Box<TRandomAccess>,
    outbound: Box<TRandomAccess>,
    store: CellStore,
    ingress: CellIngress,
    output: TProducer,
    exchange: PartialExchange,
    peers: PeerManager,
    domain: GossipDomain,
    now: Instant,
}

impl Rig {
    fn new(format: ForkName) -> Self {
        Self::with_columns(format, 3)
    }

    fn with_columns(format: ForkName, column_mask: u128) -> Self {
        let now = Instant::now();
        let spec = Arc::new(SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { 1 },
            max_blobs_per_block_electra: ROWS as u64,
            blob_schedule: Vec::new(),
            ..SpecConfig::mainnet()
        });
        let config = CellStoreConfig::new(spec, column_mask, Duration::from_secs(11)).unwrap();
        let producer = TCache::producer("", config.cache_capacity());
        let columns = Box::new(producer.cache_ref().retained_random_access("").unwrap());
        let network = Box::new(producer.cache_ref().retained_random_access("").unwrap());
        let output = TCache::producer("", 1 << 20);
        let outbound = Box::new(output.cache_ref().strict_random_access("", true).unwrap());
        let exchange = PartialExchange::new(&config, 0, now, PartialColumnsMode::SendOnly);
        let mut ingress = CellIngress::new(config.clone(), producer, 0, now).unwrap();
        let mut store = CellStore::new(config.clone(), 0, now).unwrap();
        let domain = GossipDomain::new([0; 4], format);
        let header = [0; 208];
        let proof = [0x33; 128];
        let commitments = [0x44; ROWS * 48];
        let context_data = if format == ForkName::Fulu {
            ContextData::Fulu {
                signed_header: &header,
                inclusion_proof: &proof,
                commitments: &commitments,
            }
        } else {
            ContextData::Gloas { commitments: &commitments }
        };
        let source = if format == ForkName::Fulu {
            let mut reservation =
                ingress.producer_mut().reserve(context_data.encoded_len(), false).unwrap();
            context_data.write(reservation.buffer().unwrap());
            reservation.flush().unwrap();
            Some(FuluContextSource::Header(reservation.read()))
        } else {
            None
        };
        let context = CommitmentContext { block_root: ROOT, slot: 0, format, blob_count: ROWS };
        store.admit_context(context, domain, context_data, source).unwrap();
        let request = store.request_assemblies(&ROOT).unwrap();
        let set = ingress.allocator_mut().allocate(request).unwrap();
        let mut columns = columns;
        store.install(set, &mut columns).unwrap();
        let mut full = Vec::new();
        if format == ForkName::Fulu {
            push_data_column_sidecar_prefix(&mut full, 0, ROWS, &header, &proof);
        } else {
            full.extend_from_slice(&0u64.to_le_bytes());
            full.extend_from_slice(&56u32.to_le_bytes());
            full.extend_from_slice(&((56 + ROWS * BYTES_PER_CELL) as u32).to_le_bytes());
            full.extend_from_slice(&0u64.to_le_bytes());
            full.extend_from_slice(&ROOT);
        }
        for row in 0..ROWS {
            full.extend_from_slice(&[row as u8; BYTES_PER_CELL]);
        }
        if format == ForkName::Fulu {
            full.extend_from_slice(&commitments);
        }
        for row in 0..ROWS {
            full.extend_from_slice(&[0x10 + row as u8; BYTES_PER_KZG_PROOF]);
        }
        let mut reservation = ingress.producer_mut().reserve(full.len(), false).unwrap();
        reservation.write_all(&full).unwrap();
        reservation.flush().unwrap();
        // These tests start at the verified availability handoff; Columns owns
        // cryptographic validation.
        store.retain_full(&ROOT, 0, reservation.read(), &mut columns).unwrap();
        let peers = PeerManager::new(
            PeerId::default(),
            vec![],
            columns_of(column_mask).map(GossipTopic::DataColumnSidecar).collect(),
            Default::default(),
            SyncingConfig::default(),
            [0; 4],
            [0; METADATA_SIZE],
            column_mask,
        );
        Self {
            config,
            request,
            columns,
            network,
            outbound,
            store,
            ingress,
            output,
            exchange,
            peers,
            domain,
            now,
        }
    }

    fn connect(&mut self, peer: usize, requests: bool, mesh: bool) {
        let peer_id = Keypair::from_secret(&[peer as u8; 32]).unwrap().peer_id();
        let events = [
            PeerEvent::P2pNewConnection {
                p2p_peer_id: peer,
                peer_id_full: peer_id,
                ip: "127.0.0.1".parse::<IpAddr>().unwrap().into(),
                port: 9000,
                local_dial: false,
            },
            PeerEvent::P2pGossipExtensions { p2p_peer: peer, partial_messages: true },
        ];
        for event in events {
            self.peers.handle_event(event, self.now, &mut |_| {});
        }
        for column in columns_of(self.config.columns()) {
            self.peers.handle_event(
                PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: peer,
                    topic: GossipTopic::DataColumnSidecar(column),
                    digest: [0; 4],
                },
                self.now,
                &mut |_| {},
            );
            self.peers.handle_event(
                PeerEvent::P2pGossipPartialCaps {
                    p2p_peer: peer,
                    digest: [0; 4],
                    subnet: column,
                    requests,
                    supports_sending: true,
                },
                self.now,
                &mut |_| {},
            );
            if !mesh {
                self.peers.handle_event(
                    PeerEvent::P2pGossipTopicPrune {
                        p2p_peer: peer,
                        topic: GossipTopic::DataColumnSidecar(column),
                        digest: [0; 4],
                        backoff_seconds: Some(60),
                    },
                    self.now,
                    &mut |_| {},
                );
            }
        }
    }

    fn publish(&mut self, column: usize) {
        let column = self.store.availability(&ROOT, column).unwrap();
        self.ingress.update_availability(column, self.now);
        self.exchange.available(column, &self.peers, self.now, false);
    }

    fn request(&mut self, peer: usize, available: u128, requests: u128) {
        let message = self.message(peer, available, requests);
        self.exchange.metadata(message, &self.ingress, &self.peers, self.now);
    }

    fn message(&self, peer: usize, available: u128, requests: u128) -> PartialMetadataReceived {
        PartialMetadataReceived {
            stream_id: P2pStreamId::new(peer, 3, StreamProtocol::GossipSubV13, true),
            group: ColumnGroupKey { domain: self.domain, block_root: ROOT, column: 0 },
            slot: (self.domain.format() == ForkName::Gloas).then_some(0),
            metadata: PartsMetadata { available, requests, n_rows: ROWS },
        }
    }

    fn spin(&mut self) -> Vec<(usize, CacheFrameRef)> {
        let mut frames = Vec::new();
        let mut emit = |event| {
            let P2pSend::SegmentedGossip { peer_id, frame, .. } = event else {
                panic!("unexpected send")
            };
            frames.push((peer_id, frame));
        };
        self.exchange.advance(
            &self.ingress,
            &self.peers,
            &mut self.output,
            self.now,
            &mut emit,
            &mut |_| panic!("unexpected full recovery"),
        );
        self.exchange.spin(
            &self.ingress,
            &self.peers,
            &mut self.output,
            self.now,
            &mut emit,
            &mut |_| panic!("unexpected full recovery"),
        );
        frames
    }

    fn wire(&mut self, frame: CacheFrameRef) -> Vec<u8> {
        let view = frame.acquire(&mut self.outbound, self.now).unwrap();
        let descriptor = view.descriptor_range();
        let mut wire = Vec::new();
        for segment in view.segments() {
            if let Some(range) = segment.framing_range() {
                wire.extend_from_slice(&descriptor.as_ref()[range]);
            } else {
                let range = segment.acquire(&mut self.outbound, Some(&mut self.network)).unwrap();
                wire.extend_from_slice(range.as_ref());
            }
        }
        assert_eq!(wire.len(), view.wire_len());
        wire
    }

    fn dropped(&mut self, peer: usize, frame: CacheFrameRef) {
        self.exchange.peer_event(
            &PeerEvent::P2pOutboundMessageDropped {
                p2p_peer: peer,
                protocol: StreamProtocol::GossipSub,
                msg: P2pSend::SegmentedGossip { peer_id: peer, frame, partial_cells: Some(0) },
            },
            self.now,
        );
    }
}

#[test]
fn missing_scheduled_exchange_is_discarded_without_sending() {
    let mut rig = Rig::new(ForkName::Gloas);
    assert!(rig.spin().is_empty());
    let key = ExchangeKey { peer: 1, group: rig.message(1, 0, 1).group };
    rig.exchange.ready.push_back(key);
    let seq = rig.output.next_seq();

    assert!(rig.spin().is_empty());
    assert!(rig.exchange.ready.is_empty());
    assert_eq!(rig.output.next_seq(), seq);
}

#[test]
fn missing_peer_budget_prevents_sends_and_withdrawals() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    assert_eq!(rig.spin().len(), 1);
    rig.request(1, 0, 2);
    rig.exchange.peer_exchanges.remove(&1);
    let seq = rig.output.next_seq();

    assert!(rig.spin().is_empty());
    let key = ExchangeKey { peer: 1, group: rig.message(1, 0, 2).group };
    assert_eq!(rig.exchange.exchanges[&key].sent, 0);
    rig.exchange.expire(1, &rig.peers, &mut rig.output, rig.now, &mut |_| {
        panic!("missing budget must not permit a withdrawal")
    });
    assert!(rig.exchange.exchanges.is_empty());
    assert!(rig.exchange.ready.is_empty());
    assert_eq!(rig.output.next_seq(), seq);
}

#[test]
fn removing_exchange_without_peer_budget_clears_queued_work() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    assert!(!rig.exchange.exchanges.is_empty());
    rig.exchange.peer_exchanges.remove(&1);

    rig.exchange.remove_peer(1);
    assert!(rig.exchange.exchanges.is_empty());
    assert!(rig.exchange.ready.is_empty());
}

#[test]
fn retained_full_columns_serve_requested_rows_for_both_forks_and_non_mesh_peers() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.connect(1, true, false);
        rig.request(1, 0b0101, 0b1111);
        assert!(rig.spin().is_empty());
        rig.publish(0);
        let frames = rig.spin();
        assert_eq!(frames.len(), 1);
        let wire = rig.wire(frames[0].1);
        let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
        let partial = rpc.partial.as_option().unwrap();
        assert_eq!(partial.group_id.unwrap().len(), if format == ForkName::Fulu { 33 } else { 41 });
        let payload = partial.partial_message.unwrap();
        let (cells, proofs) = if format == ForkName::Fulu {
            assert_eq!(PartialDataColumnSidecarFuluView::check_size(payload, ROWS), Some(0b1010));
            assert!(PartialDataColumnSidecarFuluView::header(payload).is_empty());
            (
                PartialDataColumnSidecarFuluView::cells(payload),
                PartialDataColumnSidecarFuluView::proofs(payload),
            )
        } else {
            assert_eq!(PartialDataColumnSidecarGloasView::check_size(payload, ROWS), Some(0b1010));
            (
                PartialDataColumnSidecarGloasView::cells(payload),
                PartialDataColumnSidecarGloasView::proofs(payload),
            )
        };
        assert_eq!(&cells[..BYTES_PER_CELL], &[1; BYTES_PER_CELL]);
        assert_eq!(&cells[BYTES_PER_CELL..], &[3; BYTES_PER_CELL]);
        assert_eq!(&proofs[..BYTES_PER_KZG_PROOF], &[0x11; BYTES_PER_KZG_PROOF]);
        assert_eq!(&proofs[BYTES_PER_KZG_PROOF..], &[0x13; BYTES_PER_KZG_PROOF]);
        rig.request(1, 0b0101, 0b1111);
        assert!(rig.spin().is_empty(), "repeated request must not resend submitted rows");
    }
}

#[test]
fn snapshots_replace_and_available_request_bits_do_not_request_data() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 0b1100);
    rig.request(1, 0, 0b0010);
    let frames = rig.spin();
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    assert_eq!(
        PartialDataColumnSidecarGloasView::check_size(
            rpc.partial.as_option().unwrap().partial_message.unwrap(),
            ROWS
        ),
        Some(0b0010)
    );
    rig.request(1, 0b0100, 0b0100);
    assert!(rig.spin().is_empty());
}

#[test]
fn send_only_peers_receive_metadata_but_never_partial_payloads() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, false, false);
    rig.publish(0);
    rig.request(1, 0, 0b1111);
    let frames = rig.spin();
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    let partial = rpc.partial.as_option().unwrap();
    assert!(partial.partial_message.is_none());
    assert_eq!(
        PartialDataColumnPartsMetadataView::check_size(partial.parts_metadata.unwrap(), ROWS),
        Some((15, 0))
    );
}

#[test]
fn fulu_header_is_shared_across_topics_and_failed_send_is_retried() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, true);
    rig.publish(0);
    rig.publish(1);
    let frames = rig.spin();
    assert_eq!(frames.len(), 2);
    let mut headers = 0;
    for (peer, frame) in frames {
        let wire = rig.wire(frame);
        let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
        let has_header = rpc.partial.as_option().unwrap().partial_message.is_some();
        headers += usize::from(has_header);
        if has_header {
            rig.dropped(peer, frame);
        }
    }
    assert_eq!(headers, 1);
    rig.now += RETRY;
    let frames = rig.spin();
    assert_eq!(frames.len(), 2, "a drop resets all optimistic state for this peer");
    let headers = frames
        .into_iter()
        .filter(|(_, frame)| {
            let wire = rig.wire(*frame);
            protobuf::RPCView::decode_view(&wire)
                .unwrap()
                .partial
                .as_option()
                .unwrap()
                .partial_message
                .is_some()
        })
        .count();
    assert_eq!(headers, 1);
    rig.publish(0);
    rig.publish(1);
    assert!(rig.spin().is_empty());
}

#[test]
fn malformed_context_metadata_and_floods_do_not_allocate_cell_storage() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    let mut message = rig.message(1, 0, 1);
    message.metadata.n_rows = 3;
    rig.exchange.metadata(message, &rig.ingress, &rig.peers, rig.now);
    assert!(rig.exchange.exchanges.is_empty());
    message.metadata.n_rows = ROWS;
    message.slot = Some(1);
    rig.exchange.metadata(message, &rig.ingress, &rig.peers, rig.now);
    assert!(rig.exchange.exchanges.is_empty());
    let seq = rig.ingress.producer_mut().next_seq();
    message.slot = Some(0);
    for i in 0..100u8 {
        message.group.block_root = [i; 32];
        rig.exchange.metadata(message, &rig.ingress, &rig.peers, rig.now);
    }
    assert_eq!(rig.exchange.exchanges.len(), rig.exchange.peer_capacity);
    assert_eq!(rig.ingress.producer_mut().next_seq(), seq);
    assert!(rig.exchange.ready.len() <= rig.exchange.peer_capacity);
}

#[test]
fn expiry_withdraws_without_reading_expired_payloads() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    assert_eq!(rig.spin().len(), 1);
    rig.now += Duration::from_secs(12);
    let event = rig.ingress.allocator_mut().advance(rig.now, 0).unwrap();
    rig.network.advance_retention(event.retain_from);
    rig.columns.advance_retention(event.retain_from);
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    let partial = rpc.partial.as_option().unwrap();
    assert!(partial.partial_message.is_none());
    assert_eq!(
        PartialDataColumnPartsMetadataView::check_size(partial.parts_metadata.unwrap(), ROWS),
        Some((0, 0))
    );
    assert!(rig.exchange.exchanges.is_empty());
    assert!(rig.exchange.ready.is_empty());
}

#[test]
fn disconnect_clears_state_and_late_drops_do_not_restore_it() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, true);
    rig.publish(0);
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let group = rig.message(1, 0, 0).group;
    assert!(!rig.exchange.headers.needed(1, group));
    rig.exchange
        .peer_event(&PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: PeerId::default() }, rig.now);
    assert!(rig.exchange.exchanges.is_empty());
    assert!(rig.exchange.peer_exchanges.is_empty());
    rig.dropped(1, frames[0].1);
    assert!(rig.exchange.headers.needed(1, group));
}

#[test]
fn withdrawn_capabilities_discard_sent_headers_and_late_drops() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, true);
    rig.publish(0);
    let frames = rig.spin();
    let event = PeerEvent::P2pGossipPartialCaps {
        p2p_peer: 1,
        subnet: 0,
        digest: rig.domain.digest(),
        requests: false,
        supports_sending: false,
    };
    rig.exchange.peer_event(&event, rig.now);
    rig.peers.handle_event(event, rig.now, &mut |_| {});
    rig.dropped(1, frames[0].1);
    assert!(rig.exchange.headers.needed(1, rig.message(1, 0, 0).group));
    rig.request(1, 0, 1);
    assert!(rig.spin().is_empty());
    assert!(rig.exchange.exchanges.is_empty());
}

#[test]
fn stale_requests_after_an_ignored_withdrawal_never_revive_expired_cells() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.connect(1, true, false);
        rig.publish(0);
        rig.request(1, 0, 1);
        assert_eq!(rig.spin().len(), 1);
        rig.now += Duration::from_secs(12);
        rig.ingress.allocator_mut().advance(rig.now, 0).unwrap();
        assert_eq!(rig.spin().len(), 1);
        let seq = rig.ingress.producer_mut().next_seq();
        // An additive metadata implementation can keep requesting old cells
        // after receiving the all-zero withdrawal.
        for _ in 0..100 {
            rig.request(1, 0, 15);
            assert!(rig.spin().is_empty());
        }
        assert_eq!(rig.ingress.producer_mut().next_seq(), seq);
        assert!(rig.exchange.ready.is_empty());
    }
}

#[test]
fn queued_frames_keep_their_original_domain_across_fork_and_digest_changes() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    let frames = rig.spin();
    for next in
        [GossipDomain::new([1; 4], ForkName::Fulu), GossipDomain::new([2; 4], ForkName::Gloas)]
    {
        rig.peers.set_active_domains(next.digest(), Some(rig.domain.digest()), &mut |_| {});
        let wire = rig.wire(frames[0].1);
        let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
        let partial = rpc.partial.as_option().unwrap();
        assert_eq!(partial.topic_id, Some(&b"/eth2/00000000/data_column_sidecar_0/ssz_snappy"[..]));
        assert_eq!(partial.group_id.unwrap().len(), 33);
        assert_eq!(
            PartialDataColumnSidecarFuluView::check_size(partial.partial_message.unwrap(), ROWS),
            Some(1)
        );
    }
    rig.peers.set_active_domains([2; 4], None, &mut |_| {});
    rig.now += HEARTBEAT;
    assert!(rig.spin().is_empty());
    assert!(rig.exchange.exchanges.is_empty());
}

#[test]
fn drops_retry_latest_requests_only_and_coalesce_without_disturbing_other_peers() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, false);
    rig.connect(2, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    rig.request(2, 0, 1);
    let first = rig.spin();
    assert_eq!(first.len(), 2);
    let dropped = first.iter().find(|(peer, _)| *peer == 1).unwrap().1;
    rig.request(1, 0, 2);
    let second = rig.spin();
    assert_eq!(second.len(), 1);

    rig.dropped(1, dropped);
    assert!(rig.spin().is_empty(), "retry waits for its backoff");
    rig.now += RETRY;
    let retried = rig.spin();
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].0, 1);
    let wire = rig.wire(retried[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    let payload = rpc.partial.as_option().unwrap().partial_message.unwrap();
    assert_eq!(PartialDataColumnSidecarFuluView::check_size(payload, ROWS), Some(2));
    assert!(
        PartialDataColumnSidecarFuluView::header(payload).is_empty(),
        "known headers survive retries"
    );

    rig.dropped(1, second[0].1);
    rig.now += RETRY;
    assert!(
        rig.spin().is_empty(),
        "another drop from the old batch must not reset its replacement"
    );
    rig.request(2, 0, 1);
    assert!(rig.spin().is_empty());

    rig.dropped(1, retried[0].1);
    rig.now += RETRY;
    assert_eq!(rig.spin().len(), 1, "a dropped replacement still triggers recovery");
}

#[test]
fn stream_closure_preserves_requests_for_the_replacement_stream() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 3);
    let first = rig.spin();
    assert_eq!(first.len(), 1);
    rig.exchange.peer_event(
        &PeerEvent::P2pStreamClosed {
            stream_id: P2pStreamId::new(1, 4, StreamProtocol::GossipSubV13, false),
        },
        rig.now,
    );
    rig.now += RETRY;
    let retried = rig.spin();
    assert_eq!(retried.len(), 1);
    assert_eq!(rig.wire(first[0].1), rig.wire(retried[0].1));
    rig.dropped(1, first[0].1);
    rig.now += RETRY;
    assert!(rig.spin().is_empty());
}

#[test]
fn heartbeat_frame_quota_is_per_peer_and_drops_do_not_refund_it() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    let mut last = None;
    for attempt in 0..16 {
        rig.request(1, 0, 1 << (attempt % ROWS));
        let frames = rig.spin();
        assert_eq!(frames.len(), 1);
        last = Some(frames[0].1);
    }
    rig.request(1, 0, 1);
    let seq = rig.output.next_seq();
    assert!(rig.spin().is_empty());
    assert_eq!(
        rig.output.next_seq(),
        seq,
        "rate limiting must happen before reserving a descriptor"
    );

    rig.connect(2, true, false);
    rig.request(2, 0, 1);
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, 2);

    rig.dropped(1, last.unwrap());
    rig.now += RETRY;
    assert!(rig.spin().is_empty());
    rig.now += HEARTBEAT - RETRY;
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, 1);
}

#[test]
fn heartbeat_byte_quota_checks_the_entire_frame_before_writing() {
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.connect(1, true, false);
        rig.publish(0);
        rig.request(1, 0, 1);
        let frame = rig.spin()[0].1;
        let wire_len = rig.wire(frame).len();
        let budget = rig.exchange.peer_exchanges.get_mut(&1).unwrap();
        budget.record(frame.read().seq(), budget.remaining_bytes() - wire_len + 1);
        rig.request(1, 0, 2);
        let seq = rig.output.next_seq();
        assert!(rig.spin().is_empty());
        assert_eq!(rig.output.next_seq(), seq);
        let key = ExchangeKey { peer: 1, group: rig.message(1, 0, 0).group };
        assert_eq!(rig.exchange.exchanges[&key].sent, 0);

        rig.now += HEARTBEAT;
        let frames = rig.spin();
        assert_eq!(frames.len(), 1);
        assert_eq!(rig.wire(frames[0].1).len(), wire_len);
    }
}

#[test]
fn subscription_changes_and_slot_expiry_cannot_reset_the_heartbeat_budget() {
    let mut rig = Rig::new(ForkName::Gloas);
    rig.connect(1, true, false);
    rig.publish(0);
    rig.request(1, 0, 1);
    let frame = rig.spin()[0].1;
    let budget = rig.exchange.peer_exchanges.get_mut(&1).unwrap();
    budget.record(frame.read().seq(), budget.remaining_bytes());
    for event in [
        PeerEvent::P2pGossipTopicUnsubscribe {
            p2p_peer: 1,
            topic: GossipTopic::DataColumnSidecar(0),
            digest: rig.domain.digest(),
        },
        PeerEvent::P2pGossipExtensions { p2p_peer: 1, partial_messages: true },
    ] {
        rig.exchange.peer_event(&event, rig.now);
        rig.request(1, 0, 1);
        assert!(rig.spin().is_empty());
        assert_eq!(rig.exchange.peer_exchanges[&1].remaining_bytes(), 0);
    }
    rig.exchange
        .expire(1, &rig.peers, &mut rig.output, rig.now, &mut |_| panic!("no remaining quota"));
    assert_eq!(rig.exchange.peer_exchanges[&1].remaining_bytes(), 0);
    // Old-slot drops must not reset new exchange state or schedule a retry.
    let key = ExchangeKey { peer: 1, group: rig.message(1, 0, 0).group };
    assert!(rig.exchange.admit(key, 1, ROWS, rig.now + Duration::from_secs(12), rig.now).is_some());
    rig.dropped(1, frame);
    assert_eq!(rig.exchange.exchanges[&key].retry_at, rig.now);
    assert!(rig.exchange.ready.is_empty());
}
