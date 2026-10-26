use silver_beacon_state_data::{
    BUILDER_INDEX_SELF_BUILD, BodyFork, BodyOffsets, ExecutionPayloadBid, PayloadWithdrawals,
    Withdrawal,
};
use silver_common::{
    BuilderBidsRequest, BuilderBidsResponse, EnginePreparePayloadReq, PayloadFrame,
    ssz_hash_gloas::{
        EMPTY_EXECUTION_REQUESTS, EMPTY_EXECUTION_REQUESTS_ROOT, ExecutionRequestsView,
    },
    ssz_view::{
        BYTES_PER_BLOB, BeaconBlockBodyGloasView, EXECUTION_PAYLOAD_FIXED_GLOAS,
        ExecutionPayloadEnvelopeView, SignedExecutionPayloadBidView,
    },
};

use super::*;
use crate::{bls::G2_POINT_AT_INFINITY, tile::block_production::BlockProduction};

mod publication;

struct ProductionRig {
    // Boxed: cached `AcquiredRead`s point into the tile's reader, and the rig moves.
    tile: Box<BeaconStateTile>,
    proposal: Proposal,
    bid: ExecutionPayloadBid,
    signature: [u8; 96],
    gossip: TProducer,
    adapter: SpineAdapter<SilverSpine>,
    sink: SpineAdapter<SilverSpine>,
    _spine: TestSpine,
    _rpc: TProducer,
}

impl ProductionRig {
    fn separate_parent_payloads(&mut self) {
        let mut fork = self.tile.state.apply_block_view(self.tile.last_applied);
        let state = fork.view.slot.state_mut();
        state.latest_block_hash = [0x11; 32];
        state.latest_execution_payload_bid.parent_block_hash = [0x11; 32];
        state.latest_execution_payload_bid.block_hash = [0x22; 32];
        state.latest_execution_payload_bid.execution_requests_root = *EMPTY_EXECUTION_REQUESTS_ROOT;
        let mut header = fork.view.slot.state().latest_block_header;
        if header.state_root == [0; 32] {
            header.state_root = ssz_hash::hash_tree_root_state(&fork.read());
        }
        fork.view.slot.state_mut().latest_block_root =
            ssz_hash::hash_tree_root_block_header(&header);
        let id = fork.commit();
        self.tile.last_applied = id;
        self.tile.seed_anchor(id, header, self.tile.head_validator_count());
        self.proposal.parent_root = self.tile.head_block_root();
    }

    fn use_full_parent(&mut self) -> EnginePreparePayloadReq {
        self.tile.fork_choice.mark_payload_verified(&self.proposal.parent_root);
        self.tile.recompute_head();
        self.tile.refresh_payload_preparation(&mut self.adapter.producers);
        let [EngineReq::PreparePayload(request)] = engine_requests(&mut self.sink)[..] else {
            panic!("full parent needs a new payload");
        };
        request
    }

    fn new(fixture: &str) -> Self {
        let (pre, block, _) = sanity_fixture_of("gloas", fixture);
        let spec = SpecConfig { fulu_fork_epoch: 0, gloas_fork_epoch: 0, ..SpecConfig::mainnet() };
        let state = BeaconState::from_checkpoint(&pre, &spec, &[]).unwrap();
        let slot = SignedBeaconBlockView::slot(&block);
        let body = SignedBeaconBlockView::body(&block);
        let offsets = BodyOffsets::new(body, BodyFork::Gloas).unwrap();
        let signed = offsets.signed_bid().unwrap();
        let bid = stf::decode_bid(signed).unwrap();
        let signature = *SignedExecutionPayloadBidView::signature(signed);
        let (mut tile, gossip, rpc, mut spine, adapter) = tile_with_producers_on(slot, state, spec);
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
        engine_requests(&mut sink);
        produced_blocks(&mut sink);
        sink.consume(|_: BuilderBidsRequest, _| {});
        tile.default_fee_recipient = Some(bid.fee_recipient);
        let proposal = Proposal {
            slot,
            parent_root: tile.head_block_root(),
            randao_reveal: *BeaconBlockBodyGloasView::randao_reveal(body),
            graffiti: [0; 32],
            bid_policy: BidPolicy::default(),
            builder_config_hash: None,
        };
        let tile = Box::new(tile);
        Self { tile, proposal, bid, signature, gossip, adapter, sink, _spine: spine, _rpc: rpc }
    }

    fn pool_bid(&mut self) {
        self.tile.payload_bids_pool.add(self.bid.clone(), self.signature);
    }

    fn start(&mut self, id: u64) -> EnginePreparePayloadReq {
        self.tile.produce_block(id, self.proposal, &mut self.adapter.producers);
        assert!(self.answers().is_empty());
        let [EngineReq::PreparePayload(request)] = engine_requests(&mut self.sink)[..] else {
            panic!("one payload preparation");
        };
        prepared(&mut self.tile, request.id, [9; 8], &mut self.adapter.producers);
        let [EngineReq::GetPayload(fetch)] = engine_requests(&mut self.sink)[..] else {
            panic!("one payload fetch");
        };
        assert!(fetch.is_gloas);
        request
    }

    fn payload(
        &self,
        attrs: EnginePreparePayloadReq,
        value: u128,
        override_builder: bool,
        blobs: u8,
    ) -> Vec<u8> {
        let mut payload = vec![0; EXECUTION_PAYLOAD_FIXED_GLOAS];
        payload[..32].copy_from_slice(&attrs.head_block_hash);
        payload[32..52].copy_from_slice(&attrs.attrs_fee_recipient);
        payload[372..404].copy_from_slice(&attrs.attrs_prev_randao);
        payload[412..420].copy_from_slice(&attrs.attrs_target_gas_limit.to_le_bytes());
        payload[428..436].copy_from_slice(&attrs.attrs_timestamp.to_le_bytes());
        payload[472..504].copy_from_slice(&[0xa1; 32]);
        for offset in [436, 504, 508] {
            payload[offset..offset + 4]
                .copy_from_slice(&(EXECUTION_PAYLOAD_FIXED_GLOAS as u32).to_le_bytes());
        }
        payload[532..540].copy_from_slice(&attrs.attrs_slot_number.to_le_bytes());
        for withdrawal in attrs.attrs_withdrawals.iter() {
            payload.extend_from_slice(&withdrawal.index.to_le_bytes());
            payload.extend_from_slice(&withdrawal.validator_index.to_le_bytes());
            payload.extend_from_slice(&withdrawal.address);
            payload.extend_from_slice(&withdrawal.amount.to_le_bytes());
        }
        let end = payload.len() as u32;
        payload[528..532].copy_from_slice(&end.to_le_bytes());
        let mut frame = vec![0; PayloadFrame::HEADER_LEN];
        PayloadFrame::write_header(
            &mut frame,
            payload.len(),
            EMPTY_EXECUTION_REQUESTS.len(),
            blobs,
            override_builder,
            &wei_le(value),
        );
        frame.extend_from_slice(&payload);
        frame.extend(vec![0x33; usize::from(blobs) * 48]);
        frame.extend_from_slice(&EMPTY_EXECUTION_REQUESTS);
        frame.extend(vec![0x44; usize::from(blobs) * PayloadFrame::CELL_PROOFS_PER_BLOB_LEN]);
        frame.extend(vec![0x55; usize::from(blobs) * BYTES_PER_BLOB]);
        frame
    }

    fn respond(&mut self, id: u64, frame: &[u8]) {
        let data = Some(publish_block_bytes(&mut self.gossip, frame).1);
        self.tile.on_payload(EngineGetPayloadResp { id, data }, &mut self.adapter.producers);
    }

    fn answers(&mut self) -> Vec<(u64, Result<ProducedBlock, ProduceBlockFailure>)> {
        let mut answers = Vec::new();
        self.sink.consume(|response: BeaconApiResponse, _| {
            if let BeaconApiResponse::ProducedBlock { request_id, block } = response {
                answers.push((request_id, block));
            }
        });
        answers
    }

    fn one_block(&mut self, id: u64) -> ProducedBlock {
        let answers = self.answers();
        let [(answered, Ok(block))] = answers[..] else {
            panic!("{answers:?}");
        };
        assert_eq!(answered, id);
        block
    }

    fn bid_of(&self, block: ProducedBlock) -> ExecutionPayloadBid {
        let bytes = self.tile.events_producer.read_buffer(block.header).unwrap();
        let body = BodyOffsets::validated(&bytes[84..], BodyFork::Gloas).unwrap();
        stf::decode_bid(body.signed_bid().unwrap()).unwrap()
    }
}

#[test]
fn self_build_commits_payload_fields_and_caches_its_unsigned_envelope() {
    let mut rig = ProductionRig::new("empty_block_transition");
    let attrs = rig.start(1);
    let frame = rig.payload(attrs, 123_456_789, false, 1);
    rig.respond(attrs.id, &frame);
    let block = rig.one_block(1);
    let bid = rig.bid_of(block);
    assert_eq!(
        (bid.builder_index, bid.value, bid.execution_payment),
        (BUILDER_INDEX_SELF_BUILD, 0, 0)
    );
    assert_eq!(block.execution_payload_value, wei_le(123_456_789));
    assert_eq!(block.builder_entry, None);
    assert_eq!(bid.block_hash, [0xa1; 32]);
    assert_eq!(bid.parent_block_hash, attrs.head_block_hash);
    assert_eq!(bid.parent_block_root, rig.proposal.parent_root);
    assert_eq!(bid.prev_randao, attrs.attrs_prev_randao);
    assert_eq!(bid.blob_kzg_commitments, [[0x33; 48]]);
    assert_eq!(
        bid.execution_requests_root,
        ExecutionRequestsView::hash_tree_root(&EMPTY_EXECUTION_REQUESTS)
    );
    let bytes = rig.tile.events_producer.read_buffer(block.header).unwrap().to_vec();
    let body = BodyOffsets::validated(&bytes[84..], BodyFork::Gloas).unwrap();
    assert_eq!(
        *SignedExecutionPayloadBidView::signature(body.signed_bid().unwrap()),
        G2_POINT_AT_INFINITY
    );
    let header = block.envelope_header.unwrap();
    let root = *ExecutionPayloadEnvelopeView::beacon_block_root(&header);
    let envelope = rig.tile.local_payload_envelope(rig.proposal.slot, &root).unwrap();
    assert_eq!(envelope.header, header);
    let frame = PayloadFrame::parse(&frame).unwrap();
    let encoded = [&header[..], frame.execution_payload, frame.execution_requests].concat();
    assert!(ExecutionPayloadEnvelopeView::check_size(&encoded));
    assert_eq!(ExecutionPayloadEnvelopeView::builder_index(&encoded), BUILDER_INDEX_SELF_BUILD);
    assert_eq!(ExecutionPayloadEnvelopeView::payload(&encoded), frame.execution_payload);
    assert_eq!(
        ExecutionPayloadEnvelopeView::execution_requests(&encoded),
        EMPTY_EXECUTION_REQUESTS
    );
    assert_eq!(
        *ExecutionPayloadEnvelopeView::parent_beacon_block_root(&encoded),
        rig.proposal.parent_root
    );
    let (body_root, _) = stf::hash_body(&body);
    let header = BeaconBlockHeader {
        slot: rig.proposal.slot,
        proposer_index: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        parent_root: rig.proposal.parent_root,
        state_root: bytes[48..80].try_into().unwrap(),
        body_root,
    };
    assert_eq!(root, ssz_hash::hash_tree_root_block_header(&header));
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot, &[99; 32]).is_none());
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot + 1, &root).is_none());

    rig.tile.produce_block(2, rig.proposal, &mut rig.adapter.producers);
    assert_eq!(rig.one_block(2).header, block.header);
    assert!(engine_requests(&mut rig.sink).is_empty(), "cached proposal needs no EL fetch");
    rig.proposal.graffiti = [3; 32];
    rig.tile.produce_block(3, rig.proposal, &mut rig.adapter.producers);
    let another = rig.one_block(3);
    assert_ne!(another.envelope_header, block.envelope_header);
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot, &root).is_some());
    rig.tile.block_production.prune_before(rig.proposal.slot + 1, &mut rig.adapter.producers);
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot, &root).is_none());
}

#[test]
fn local_payload_wins_ties_and_honors_override_without_rounding_wei() {
    for (local_delta, override_builder, local_wins) in
        [(0i128, false, true), (-1, false, false), (-1, true, true)]
    {
        let mut rig = ProductionRig::new("builder_payment_after_missed_epochs");
        assert_ne!(rig.bid.builder_index, BUILDER_INDEX_SELF_BUILD);
        rig.pool_bid();
        rig.proposal.bid_policy.builder_boost_factor = 150;
        let value = (u128::from(rig.bid.value) * 1_000_000_000 * 150 / 100) as i128 + local_delta;
        assert!(value >= 0);
        let attrs = rig.start(1);
        rig.respond(attrs.id, &rig.payload(attrs, value as u128, override_builder, 0));
        let block = rig.one_block(1);
        assert_eq!(block.payload.is_some(), local_wins);
        assert_eq!(rig.bid_of(block).builder_index == BUILDER_INDEX_SELF_BUILD, local_wins);
    }
}

#[test]
fn builder_replies_and_payload_replies_can_arrive_in_either_order() {
    for builders_first in [true, false] {
        let mut rig = ProductionRig::new("empty_block_transition");
        rig.proposal.builder_config_hash = Some([1; 32]);
        let attrs = rig.start(1);
        let payload = rig.payload(attrs, 3, false, 0);
        let reply = BuilderBidsResponse { request_id: 1, bids: None };
        if builders_first {
            rig.tile.on_builder_bids(reply, &mut rig.adapter.producers);
            assert!(rig.answers().is_empty());
            rig.respond(attrs.id, &payload);
        } else {
            rig.respond(attrs.id, &payload);
            assert!(rig.answers().is_empty());
            rig.tile.on_builder_bids(reply, &mut rig.adapter.producers);
        }
        assert!(rig.one_block(1).payload.is_some());
        rig.tile.on_builder_bids(reply, &mut rig.adapter.producers);
        assert!(rig.answers().is_empty(), "duplicate reply ignored");
    }
}

#[test]
fn timed_out_local_preference_falls_back_to_a_bid_and_ignores_late_replies() {
    let mut rig = ProductionRig::new("builder_payment_after_missed_epochs");
    rig.pool_bid();
    rig.proposal.bid_policy.builder_boost_factor = 0;
    rig.proposal.builder_config_hash = Some([1; 32]);
    rig.tile.block_production = BlockProduction::new(Duration::ZERO);
    let attrs = rig.start(1);
    rig.tile.expire_payload_waits(&mut rig.adapter.producers);
    assert!(rig.one_block(1).payload.is_none());
    rig.respond(attrs.id, &rig.payload(attrs, u128::MAX, true, 0));
    rig.tile.on_builder_bids(
        BuilderBidsResponse { request_id: 1, bids: None },
        &mut rig.adapter.producers,
    );
    assert!(rig.answers().is_empty());
}

#[test]
fn malformed_local_payload_falls_back_to_the_pool() {
    let mut rig = ProductionRig::new("builder_payment_after_missed_epochs");
    rig.pool_bid();
    let attrs = rig.start(1);
    let mut payload = rig.payload(attrs, u128::MAX, true, 0);
    payload[PayloadFrame::HEADER_LEN + 532..PayloadFrame::HEADER_LEN + 540]
        .copy_from_slice(&(attrs.attrs_slot_number + 1).to_le_bytes());
    rig.respond(attrs.id, &payload);
    assert!(rig.one_block(1).payload.is_none());
}

#[test]
fn slot_pruning_releases_requests_waiting_on_builders() {
    let mut rig = ProductionRig::new("empty_block_transition");
    rig.proposal.builder_config_hash = Some([1; 32]);
    let attrs = rig.start(1);
    rig.tile.block_production.prune_before(rig.proposal.slot + 1, &mut rig.adapter.producers);
    let answers = rig.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].1.err(), Some(ProduceBlockFailure::PayloadUnavailable));
    rig.respond(attrs.id, &rig.payload(attrs, 1, false, 0));
    rig.tile.on_builder_bids(
        BuilderBidsResponse { request_id: 1, bids: None },
        &mut rig.adapter.producers,
    );
    assert!(rig.answers().is_empty());
}

#[test]
fn a_changed_execution_parent_invalidates_the_block_and_envelope() {
    let mut rig = ProductionRig::new("empty_block_transition");
    rig.separate_parent_payloads();
    let empty = rig.start(1);
    assert_eq!(empty.head_block_hash, [0x11; 32]);
    rig.respond(empty.id, &rig.payload(empty, 1, false, 0));
    let old = rig.one_block(1).envelope_header.unwrap();
    let old_root = *ExecutionPayloadEnvelopeView::beacon_block_root(&old);
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot, &old_root).is_some());
    let full = rig.use_full_parent();
    assert_eq!(full.head_block_hash, [0x22; 32]);
    assert_ne!(full.id, empty.id);
    assert!(rig.tile.local_payload_envelope(rig.proposal.slot, &old_root).is_none());
    rig.tile.produce_block(2, rig.proposal, &mut rig.adapter.producers);
    assert!(rig.answers().is_empty());
    prepared(&mut rig.tile, full.id, [8; 8], &mut rig.adapter.producers);
    rig.respond(full.id, &rig.payload(full, 2, false, 0));
    let block = rig.one_block(2);
    assert_eq!(rig.bid_of(block).parent_block_hash, [0x22; 32]);
    assert_ne!(block.envelope_header.unwrap(), old);
}

#[test]
fn changing_execution_parents_does_not_extend_a_pending_deadline() {
    let mut rig = ProductionRig::new("empty_block_transition");
    rig.separate_parent_payloads();
    rig.tile.block_production = BlockProduction::new(Duration::ZERO);
    let empty = rig.start(1);
    let full = rig.use_full_parent();
    rig.respond(empty.id, &rig.payload(empty, 1, false, 0));
    assert!(rig.answers().is_empty(), "stale completion cannot satisfy the request");
    rig.tile.expire_payload_waits(&mut rig.adapter.producers);
    let answers = rig.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].1.err(), Some(ProduceBlockFailure::NoAcceptableBid));
    prepared(&mut rig.tile, full.id, [8; 8], &mut rig.adapter.producers);
    assert!(engine_requests(&mut rig.sink).is_empty(), "late preparation ignored");
}

#[test]
fn incorrect_local_withdrawals_fall_back_to_the_pool() {
    let mut rig = ProductionRig::new("builder_payment_after_missed_epochs");
    rig.pool_bid();
    let mut attrs = rig.start(1);
    attrs.attrs_withdrawals = PayloadWithdrawals::new();
    attrs.attrs_withdrawals.push(Withdrawal {
        index: 999,
        validator_index: 0,
        address: [7; 20],
        amount: 42,
    });
    rig.respond(attrs.id, &rig.payload(attrs, u128::MAX, true, 0));
    assert!(rig.one_block(1).payload.is_none());
}
