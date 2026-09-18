use buffa::{Message, MessageView};
use silver_common::{
    cell_store::{CellStoreEvent, ColumnAvailability},
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF,
        partial_column::{
            PartialDataColumnSidecarGloasView, gloas_group_id, parts_metadata_len,
            write_parts_metadata,
        },
    },
};

use super::*;

#[path = "../../../../gossip/src/generated/protobuf.gossipsub.rs"]
#[allow(dead_code, clippy::all)]
#[rustfmt::skip]
mod protobuf;

#[test]
fn metadata_crosses_ingress_control_and_segmented_send_spine_queues() {
    let topic = GossipTopic::DataColumnSidecar(0);
    let mut capture = GossipPublications::new(topic, &[]);
    let now = Instant::now();
    let spec = Arc::new(SpecConfig {
        fulu_fork_epoch: 0,
        gloas_fork_epoch: 0,
        max_blobs_per_block_electra: 2,
        blob_schedule: Vec::new(),
        ..SpecConfig::mainnet()
    });
    let config = CellStoreConfig::new(spec.clone(), 1, Duration::from_secs(11)).unwrap();
    let mut columns = TCache::producer("", config.cache_capacity());
    let mut columns_reader = Box::new(columns.cache_ref().retained_random_access("").unwrap());
    let mut outgoing_reader = Box::new(
        capture
            .controller
            .gossip_handler
            .mcache_publish
            .cache_ref()
            .strict_random_access("", true)
            .unwrap(),
    );
    let mut bytes = vec![0; 56];
    bytes[8..12].copy_from_slice(&56u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&((56 + 2 * BYTES_PER_CELL) as u32).to_le_bytes());
    bytes[24..56].fill(7);
    bytes.extend_from_slice(&[0x11; BYTES_PER_CELL]);
    bytes.extend_from_slice(&[0x22; BYTES_PER_CELL]);
    bytes.extend_from_slice(&[0x33; BYTES_PER_KZG_PROOF]);
    bytes.extend_from_slice(&[0x44; BYTES_PER_KZG_PROOF]);
    let full = write_bytes(&mut columns, &bytes);
    capture.controller.spec = spec;
    capture.controller = capture
        .controller
        .with_data_columns_cache(config, columns, 0, now, PartialColumnsMode::SendOnly)
        .unwrap();
    let domain = GossipDomain::new([0; 4], ForkName::Gloas);
    capture.controller.gossip_handler.set_domains(domain, None);
    capture.crank();
    capture.observer.produce(CellStoreEvent::Available(ColumnAvailability {
        block_root: [7; 32],
        column: 0,
        slot: 0,
        blob_count: 2,
        domain,
        available: 3,
        full: Some((full, 56, 56 + 2 * BYTES_PER_CELL)),
        assembly: None,
        header: None,
        expires: now + Duration::from_secs(12),
    }));
    let mut metadata = vec![0; parts_metadata_len(2)];
    write_parts_metadata(1, 2, 2, &mut metadata);
    let rpc = protobuf::RPC {
        subscriptions: vec![protobuf::rpc::SubOpts {
            subscribe: Some(true),
            topic_id: Some(topic.to_wire("00000000")),
            requests_partial: Some(true),
            supports_sending_partial: Some(false),
            ..Default::default()
        }],
        control: buffa::MessageField::some(protobuf::ControlMessage {
            extensions: buffa::MessageField::some(protobuf::ControlExtensions {
                partial_messages: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }),
        partial: buffa::MessageField::some(protobuf::PartialMessagesExtension {
            topic_id: Some(topic.to_wire("00000000").into_bytes()),
            group_id: Some(gloas_group_id(&[7; 32], 0).to_vec()),
            parts_metadata: Some(metadata),
            ..Default::default()
        }),
        ..Default::default()
    };
    let stream = P2pStreamId::new(1, 3, StreamProtocol::GossipSubV13, true);
    let mut incoming = stream.as_ref().to_vec();
    incoming.extend_from_slice(&rpc.encode_to_vec());
    let read = write_bytes(&mut capture.incoming, &incoming);
    capture.observer.produce(GossipMsgIn { p2p_id: stream, tcache: read });
    capture.crank();
    let mut sent = None;
    capture.observer.consume(|event: P2pSend, _| {
        if let P2pSend::SegmentedGossip { peer_id, frame, partial_cells } = event {
            assert_eq!(peer_id, 1);
            assert_eq!(partial_cells, Some(1));
            assert!(sent.replace(frame).is_none());
        }
    });
    let frame = sent.expect("metadata must reach the exchange coordinator");
    let view = frame.acquire(&mut outgoing_reader, Instant::now()).unwrap();
    let descriptor = view.descriptor_range();
    let mut wire = Vec::new();
    for segment in view.segments() {
        if let Some(range) = segment.framing_range() {
            wire.extend_from_slice(&descriptor.as_ref()[range]);
        } else {
            wire.extend_from_slice(
                segment.acquire(&mut outgoing_reader, Some(&mut columns_reader)).unwrap().as_ref(),
            );
        }
    }
    let decoded = protobuf::RPCView::decode_view(&wire).unwrap();
    let payload = decoded.partial.as_option().unwrap().partial_message.unwrap();
    assert_eq!(PartialDataColumnSidecarGloasView::check_size(payload, 2), Some(2));
    assert_eq!(PartialDataColumnSidecarGloasView::cells(payload), &[0x22; BYTES_PER_CELL]);
    assert_eq!(PartialDataColumnSidecarGloasView::proofs(payload), &[0x44; BYTES_PER_KZG_PROOF]);
    // No successful-send feedback is needed to suppress duplicate responses.
    capture.crank();
    capture
        .observer
        .consume(|event: P2pSend, _| assert!(!matches!(event, P2pSend::SegmentedGossip { .. })));
}

#[test]
fn partial_payload_only_frames_stage_directly_and_require_the_receive_gate_and_v13() {
    use silver_common::ssz_view::partial_column::fulu_group_id;

    for format in [ForkName::Fulu, ForkName::Gloas] {
        let topic = GossipTopic::DataColumnSidecar(0);
        let mut capture = GossipPublications::new(topic, &[]);
        let now = Instant::now();
        let spec = Arc::new(SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: if format == ForkName::Gloas { 0 } else { u64::MAX },
            max_blobs_per_block_electra: 2,
            blob_schedule: Vec::new(),
            ..SpecConfig::mainnet()
        });
        let config = CellStoreConfig::new(spec.clone(), 1, Duration::from_secs(11)).unwrap();
        let columns = TCache::producer("", config.cache_capacity());
        let cache = columns.cache_ref();
        let _reader = cache.retained_random_access("").unwrap();
        capture.controller.spec = spec;
        capture.controller = capture
            .controller
            .with_data_columns_cache(config, columns, 0, now, PartialColumnsMode::SendOnly)
            .unwrap();
        capture.controller.gossip_handler.set_domains(GossipDomain::new([0; 4], format), None);
        capture.observer.consume(|_: CellStoreEvent, _| {});
        capture.crank();

        let fixed = if format == ForkName::Fulu { 16 } else { 12 };
        let end = fixed + 1 + BYTES_PER_CELL + BYTES_PER_KZG_PROOF;
        let mut payload = vec![0; end];
        payload[..4].copy_from_slice(&(fixed as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&((fixed + 1) as u32).to_le_bytes());
        payload[8..12].copy_from_slice(&((fixed + 1 + BYTES_PER_CELL) as u32).to_le_bytes());
        if format == ForkName::Fulu {
            payload[12..16].copy_from_slice(&(end as u32).to_le_bytes());
        }
        payload[fixed] = 0b101; // Row zero, with two total rows.
        payload[fixed + 1..].fill(0x11);
        let rpc = protobuf::RPC {
            partial: buffa::MessageField::some(protobuf::PartialMessagesExtension {
                topic_id: Some(topic.to_wire("00000000").into_bytes()),
                group_id: Some(if format == ForkName::Fulu {
                    fulu_group_id(&[7; 32]).to_vec()
                } else {
                    gloas_group_id(&[7; 32], 0).to_vec()
                }),
                partial_message: Some(payload),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (mode, protocol, expected) in [
            (PartialColumnsMode::Off, StreamProtocol::GossipSubV13, 0),
            (PartialColumnsMode::SendOnly, StreamProtocol::GossipSubV13, 0),
            (PartialColumnsMode::Enabled, StreamProtocol::GossipSub, 0),
            (PartialColumnsMode::Enabled, StreamProtocol::GossipSubV13, 1),
            (PartialColumnsMode::Enabled, StreamProtocol::GossipSubV13, 0),
        ] {
            capture.controller.gossip_handler.set_partial_columns_mode(mode);
            let stream = P2pStreamId::new(1, 3, protocol, true);
            let mut incoming = stream.as_ref().to_vec();
            incoming.extend_from_slice(&rpc.encode_to_vec());
            let read = write_bytes(&mut capture.incoming, &incoming);
            capture.observer.produce(GossipMsgIn { p2p_id: stream, tcache: read });
            capture.crank();
            let mut count = 0;
            capture.observer.consume(|event: CellStoreEvent, _| {
                if let CellStoreEvent::Validate(request) = event {
                    count += 1;
                    assert!(std::ptr::eq(
                        &*request.pending.data.reservation().read().cache_ref(),
                        &*cache
                    ));
                    assert_eq!(request.pending.key.row, 0);
                    assert_eq!(request.domain.format(), format);
                }
            });
            assert_eq!(count, expected);
        }
    }
}

#[test]
fn enabled_subscriptions_keep_request_flags_across_the_live_fork_cutover() {
    let topic = GossipTopic::DataColumnSidecar(0);
    let mut capture = GossipPublications::new(topic, &[]);
    let spec = Arc::new(SpecConfig {
        fulu_fork_epoch: 0,
        gloas_fork_epoch: 10,
        blob_schedule: Vec::new(),
        ..SpecConfig::mainnet()
    });
    let config = CellStoreConfig::new(spec.clone(), 1, Duration::from_secs(11)).unwrap();
    let columns = TCache::producer("", config.cache_capacity());
    let _reader = columns.cache_ref().retained_random_access("").unwrap();
    capture.controller.spec = spec.clone();
    capture.controller = capture
        .controller
        .with_data_columns_cache(config, columns, 0, Instant::now(), PartialColumnsMode::Enabled)
        .unwrap();
    let mut ticker = SlotTicker::new(0, Duration::from_secs(12), Duration::from_secs(3));
    ticker.set_current_slot(8 * SLOTS_PER_EPOCH);
    capture.controller.set_gossip_clock(ticker, &[0; 32]);
    for epoch in [8, 9, 10] {
        capture
            .controller
            .gossip_schedule
            .as_mut()
            .unwrap()
            .ticker
            .set_current_slot(epoch * SLOTS_PER_EPOCH);
        capture.crank();
        let mut subscriptions = 0;
        for (_, bytes) in capture.sent() {
            let rpc = protobuf::RPCView::decode_view(&bytes).unwrap();
            for subscription in &rpc.subscriptions {
                if subscription.subscribe != Some(true) {
                    continue;
                }
                subscriptions += 1;
                assert_eq!(subscription.requests_partial, Some(true));
                assert_eq!(subscription.supports_sending_partial, Some(true));
            }
        }
        if epoch < 10 {
            assert!(subscriptions != 0);
        }
        assert_eq!(
            capture.controller.gossip_handler.current_domain().unwrap().format(),
            if epoch < 10 { ForkName::Fulu } else { ForkName::Gloas }
        );
    }
    capture.controller.gossip_handler.handle_peer_control(PeerControl::P2pGossipSubscribe {
        p2p: PeerId::default(),
        p2p_connection: 1,
        topic: GossipTopic::BeaconBlock,
        digest: [0; 4],
    });
    while let Some(event) = capture.controller.gossip_handler.pop_event() {
        if let GossipHandlerEvent::SendGossip(message) = event {
            let read = capture.outbound.acquire(message.tcache);
            let bytes = read.buffer().unwrap().0;
            let rpc = protobuf::RPCView::decode_view(bytes).unwrap();
            let subscription = rpc.subscriptions.iter().next().unwrap();
            assert_eq!(subscription.requests_partial, None);
            assert_eq!(subscription.supports_sending_partial, None);
        }
    }
}
