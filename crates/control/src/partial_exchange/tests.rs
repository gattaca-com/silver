use std::{io::Write, net::IpAddr, sync::Arc};

use buffa::MessageView;
use silver_chain_spec::SpecConfig;
use silver_columns::cell_store::CellStore;
use silver_common::{
    CacheFrameRef, GossipDomain, Keypair, P2pStreamId, PeerId, StreamProtocol, TCache,
    TCacheProducer, TRandomAccess,
    cell_store::{CommitmentContext, ContextData, FuluContextSource},
    column_util::push_data_column_sidecar_prefix,
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

mod allocations;

const ROOT: [u8; 32] = [7; 32];
const ROWS: usize = 4;

struct Rig {
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
        let now = Instant::now();
        let spec = Arc::new(SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { u64::MAX },
            max_blobs_per_block_electra: ROWS as u64,
            blob_schedule: Vec::new(),
            ..SpecConfig::mainnet()
        });
        let config = CellStoreConfig::new(spec, 3, Duration::from_secs(11)).unwrap();
        let producer = TCache::producer("", config.cache_capacity());
        let columns = Box::new(producer.cache_ref().retained_random_access("").unwrap());
        let network = Box::new(producer.cache_ref().retained_random_access("").unwrap());
        let output = TCache::producer("", 1 << 20);
        let outbound = Box::new(output.cache_ref().strict_random_access("", true).unwrap());
        let exchange = PartialExchange::new(&config, 0, now);
        let mut ingress = CellIngress::new(config.clone(), producer, 0, now).unwrap();
        let mut store = CellStore::new(config, 0, now).unwrap();
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
            vec![GossipTopic::DataColumnSidecar(0), GossipTopic::DataColumnSidecar(1)],
            Default::default(),
            SyncingConfig::default(),
            [0; 4],
            [0; METADATA_SIZE],
            3,
        );
        Self { columns, network, outbound, store, ingress, output, exchange, peers, domain, now }
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
        for column in 0..2 {
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
        self.exchange.spin(&self.ingress, &self.peers, &mut self.output, self.now, &mut |event| {
            let P2pSend::SegmentedGossip { peer_id, frame } = event else {
                panic!("unexpected send")
            };
            frames.push((peer_id, frame));
        });
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

    fn complete(&mut self, peer: usize, frame: CacheFrameRef, written: bool) {
        self.exchange.peer_event(
            &PeerEvent::SegmentedGossipResult(GossipFrameResult {
                p2p_peer: peer,
                frame_seq: frame.read().seq(),
                outcome: if written {
                    GossipFrameOutcome::Written {
                        stream_id: P2pStreamId::new(peer, 4, StreamProtocol::GossipSubV13, false),
                    }
                } else {
                    GossipFrameOutcome::Dropped
                },
            }),
            self.now,
        );
    }
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
        rig.complete(1, frames[0].1, true);
        rig.request(1, 0b0101, 0b1111);
        assert!(rig.spin().is_empty(), "repeated request must not resend written rows");
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
    rig.complete(1, frames[0].1, true);
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
        rig.complete(peer, frame, !has_header);
    }
    assert_eq!(headers, 1);
    rig.now += HEARTBEAT;
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let wire = rig.wire(frames[0].1);
    let rpc = protobuf::RPCView::decode_view(&wire).unwrap();
    assert!(rpc.partial.as_option().unwrap().partial_message.is_some());
    rig.complete(1, frames[0].1, true);
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
    let frames = rig.spin();
    rig.complete(1, frames[0].1, true);
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
    assert!(rig.exchange.pending.is_empty());
}

#[test]
fn disconnect_clears_pending_state_and_late_results_cannot_mark_a_header_sent() {
    let mut rig = Rig::new(ForkName::Fulu);
    rig.connect(1, true, true);
    rig.publish(0);
    let frames = rig.spin();
    assert_eq!(frames.len(), 1);
    let group = rig.message(1, 0, 0).group;
    assert!(!rig.exchange.headers.needed(1, group));
    rig.exchange
        .peer_event(&PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: PeerId::default() }, rig.now);
    assert!(rig.exchange.pending.is_empty());
    rig.complete(1, frames[0].1, true);
    assert!(rig.exchange.headers.needed(1, group));
}

#[test]
fn withdrawn_capabilities_discard_pending_headers_and_late_feedback() {
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
    rig.complete(1, frames[0].1, true);
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
        let frames = rig.spin();
        rig.complete(1, frames[0].1, true);
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
        assert!(rig.exchange.pending.is_empty());
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
