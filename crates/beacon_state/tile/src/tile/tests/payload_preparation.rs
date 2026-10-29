use silver_beacon_state_data::{
    BuilderPendingPayment, BuilderPendingWithdrawal, StateWriterView, Withdrawal,
};
use silver_common::{
    EnginePreparePayloadReq, PreparedPayloadAttributes,
    ssz_hash_gloas::{EMPTY_EXECUTION_REQUESTS_ROOT, ExecutionRequestsView},
    ssz_view::{
        CONSOLIDATION_REQUEST_SIZE, ProposerPreferencesView, SIGNED_PROPOSER_PREFERENCES_SIZE,
    },
};

use super::*;
use crate::{bls, tile::seen_proposer_preferences::ProposerPreferences};

const FULL_HASH: B256 = [0x22; 32];
const EMPTY_HASH: B256 = [0x11; 32];

struct PreparationRig {
    tile: BeaconStateTile,
    adapter: SpineAdapter<SilverSpine>,
    sink: SpineAdapter<SilverSpine>,
    _spine: TestSpine,
    _gossip: TProducer,
    _rpc: TProducer,
}

impl PreparationRig {
    fn new(state: BeaconState, spec: SpecConfig, slot: Slot) -> Self {
        let (tile, gossip, rpc, mut spine, adapter) = tile_with_producers_on(slot, state, spec);
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
        engine_requests(&mut sink);
        sink.consume(|_: BeaconStateEvent, _| {});
        Self { tile, adapter, sink, _spine: spine, _gossip: gossip, _rpc: rpc }
    }

    fn gloas(change: impl FnOnce(&mut StateWriterView)) -> Self {
        let (pre, _, _) = sanity_fixture_of("gloas", "empty_block_transition");
        let spec = SpecConfig { fulu_fork_epoch: 0, gloas_fork_epoch: 0, ..SpecConfig::mainnet() };
        let state = BeaconState::from_checkpoint(&pre, &spec, &[]).unwrap();
        let mut rig = Self::new(state, spec, 1);
        let parent = rig.tile.last_applied;
        let id = {
            let mut fork = rig.tile.state.apply_block_view(parent);
            let slot = fork.view.slot.state_mut();
            slot.latest_block_hash = EMPTY_HASH;
            slot.latest_execution_payload_bid.parent_block_hash = EMPTY_HASH;
            slot.latest_execution_payload_bid.block_hash = FULL_HASH;
            slot.latest_execution_payload_bid.gas_limit = 40_000_000;
            slot.latest_execution_payload_bid.execution_requests_root =
                *EMPTY_EXECUTION_REQUESTS_ROOT;
            change(&mut fork.view);
            fork.commit()
        };
        rig.tile.last_applied = id;
        let header = rig.tile.state.read_view(id).slot.state().latest_block_header;
        let capacity = rig.tile.head_validator_count();
        rig.tile.seed_anchor(id, header, capacity);
        rig
    }

    fn register(&mut self, slot: Slot) -> u64 {
        let head = self.tile.state.read_view(self.tile.last_applied);
        let epoch_start = head.slot.state().slot / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
        let proposer = head.epoch.proposer_at((slot - epoch_start) as usize).unwrap();
        register_proposer(&mut self.tile, proposer, [7; 20]);
        proposer
    }

    fn prepare(&mut self, slot: Slot) -> EnginePreparePayloadReq {
        self.tile.prepare_payload(slot, None, &mut self.adapter.producers).unwrap();
        self.preparation()
    }

    fn preparation(&mut self) -> EnginePreparePayloadReq {
        let [EngineReq::PreparePayload(request)] = engine_requests(&mut self.sink)[..] else {
            panic!("expected one preparation");
        };
        request
    }

    fn payload_attributes(&mut self) -> Vec<PreparedPayloadAttributes> {
        let mut published = Vec::new();
        self.sink.consume(|event: BeaconStateEvent, _| {
            if let BeaconStateEvent::PayloadAttributes(attributes) = event {
                published.push(attributes);
            }
        });
        published
    }

    fn mark_full(&mut self) {
        let root = self.tile.head_block_root();
        self.tile.fork_choice.mark_payload_verified(&root);
        self.tile.recompute_head();
    }

    fn state_root(&self) -> B256 {
        ssz_hash::hash_tree_root_state(&self.tile.state.read_view(self.tile.last_applied))
    }
}

#[test]
fn empty_parent_reuses_withdrawals_and_fetches_v6() {
    let mut rig = PreparationRig::gloas(|view| {
        view.slot.state_mut().payload_expected_withdrawals =
            vec![Withdrawal { index: 42, validator_index: 3, address: [4; 20], amount: 5 }];
    });
    rig.register(1);
    let before = rig.state_root();
    let request = rig.prepare(1);
    assert!(request.is_gloas);
    assert_eq!(request.head_block_hash, EMPTY_HASH);
    assert_eq!(request.attrs_slot_number, 1);
    assert_eq!(request.attrs_target_gas_limit, 40_000_000);
    assert_eq!(request.attrs_fee_recipient, [7; 20]);
    assert_eq!(request.attrs_parent_beacon_block_root, rig.tile.head_block_root());
    let state = rig.tile.state.read_view(rig.tile.last_applied);
    assert_eq!(request.attrs_timestamp, state.imm.genesis_time + 12);
    assert_eq!(request.attrs_prev_randao, state.randao_mixes.at_epoch(0));
    let [withdrawal] = request.attrs_withdrawals[..] else { panic!("one carried withdrawal") };
    assert_eq!((withdrawal.index, withdrawal.validator_index, withdrawal.amount), (42, 3, 5));
    assert_eq!(withdrawal.address, [4; 20]);
    assert_eq!(rig.state_root(), before);

    prepared(&mut rig.tile, request.id, [3; 8], &mut rig.adapter.producers);
    let proposal = proposal(&rig.tile, 1);
    rig.tile.start_local_payload(&proposal, &mut rig.adapter.producers).unwrap();
    let [EngineReq::GetPayload(fetch)] = engine_requests(&mut rig.sink)[..] else {
        panic!("expected one fetch");
    };
    assert!(fetch.is_gloas);
    assert_eq!(fetch.payload_id, [3; 8]);
}

#[test]
fn preparation_publishes_the_attributes_it_asks_the_el_for() {
    let mut rig = PreparationRig::gloas(|view| {
        view.slot.state_mut().payload_expected_withdrawals =
            vec![Withdrawal { index: 42, validator_index: 3, address: [4; 20], amount: 5 }];
    });
    rig.tile.payload_attributes.wanted = true;
    let proposer = rig.register(1);
    let request = rig.prepare(1);
    let [attributes] = rig.payload_attributes()[..] else { panic!("one event per preparation") };
    assert_eq!((attributes.proposal_slot, attributes.proposer_index), (1, proposer));
    assert_eq!(attributes.parent_block_root, request.attrs_parent_beacon_block_root);
    assert_eq!(attributes.parent_block_hash, request.head_block_hash);
    assert_eq!(attributes.parent_block_number, None, "removed from Gloas");
    assert_eq!(attributes.target_gas_limit, request.attrs_target_gas_limit);
    assert_eq!(attributes.timestamp, request.attrs_timestamp);
    assert_eq!(attributes.prev_randao, request.attrs_prev_randao);
    assert_eq!(attributes.fee_recipient, request.attrs_fee_recipient);
    let mut withdrawals = Vec::new();
    request.attrs_withdrawals[0].write_ssz(&mut withdrawals).unwrap();
    let posted = attributes.withdrawals.expect("one withdrawal is posted");
    assert_eq!(rig.tile.events_producer.read_buffer(posted).unwrap(), withdrawals);

    rig.tile.publish_status(&mut rig.adapter.producers);
    assert!(engine_requests(&mut rig.sink).is_empty());
    assert!(rig.payload_attributes().is_empty(), "an unchanged preparation is not republished");

    let mut unsubscribed = PreparationRig::gloas(|_| {});
    unsubscribed.register(1);
    unsubscribed.prepare(1);
    assert!(unsubscribed.payload_attributes().is_empty(), "published only to subscribers");
}

#[test]
fn full_parent_applies_deferred_requests_before_withdrawals() {
    let mut requests = Vec::new();
    let mut rig = PreparationRig::gloas(|view| {
        let mut credentials = Withdrawals::default();
        credentials.0[0] = 1;
        credentials.0[12..].fill(9);
        view.validators.set_credentials(0, credentials);
        view.balances.set(0, MAX_EFFECTIVE_BALANCE + 3_000_000_000);
        let pubkey = view.validators.pubkey(0);
        let end = (20 + CONSOLIDATION_REQUEST_SIZE) as u32;
        for offset in [20u32, 20, 20, end, end] {
            requests.extend_from_slice(&offset.to_le_bytes());
        }
        requests.extend_from_slice(&[9; 20]);
        requests.extend_from_slice(pubkey);
        requests.extend_from_slice(pubkey);
        view.slot.state_mut().latest_execution_payload_bid.execution_requests_root =
            ExecutionRequestsView::hash_tree_root(&requests);
    });
    rig.register(1);
    rig.mark_full();
    let parent_root = rig.tile.head_block_root();
    let before = rig.state_root();
    assert_eq!(
        rig.tile.prepare_payload(1, None, &mut rig.adapter.producers),
        Err(ProduceBlockFailure::PayloadUnavailable),
        "missing requests must not be treated as empty"
    );
    assert!(engine_requests(&mut rig.sink).is_empty());
    {
        let fork = rig.tile.state.apply_block_view(rig.tile.last_applied);
        let without_requests = stf::get_expected_withdrawals_gloas(&fork.view).withdrawals;
        assert!(without_requests.iter().any(|w| w.validator_index == 0));
    }
    rig.tile.payload_execution_requests.insert(parent_root, &requests);
    let request = rig.prepare(1);
    assert_eq!(request.head_block_hash, FULL_HASH);
    assert!(request.attrs_withdrawals.iter().all(|w| w.validator_index != 0));
    assert_eq!(rig.state_root(), before);
    let unchanged = rig.tile.state.read_view(rig.tile.last_applied);
    assert!(unchanged.validators.credentials(0).has_eth1_credential());
    assert_eq!(unchanged.balances.get(0), MAX_EFFECTIVE_BALANCE + 3_000_000_000);
}

#[test]
fn full_parent_settles_builder_payment_before_withdrawals() {
    let mut rig = PreparationRig::gloas(|view| {
        let slot = view.slot.state_mut();
        slot.builder_pending_payments[SLOTS_PER_EPOCH as usize] = BuilderPendingPayment {
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: [8; 20],
                amount: 123,
                builder_index: 0,
            },
            ..BuilderPendingPayment::default()
        };
    });
    rig.register(1);
    rig.mark_full();
    let before = rig.state_root();
    let request = rig.prepare(1);
    let payment = &request.attrs_withdrawals[0];
    assert_eq!((payment.validator_index, payment.amount), (1 << 40, 123));
    assert_eq!(payment.address, [8; 20]);
    assert_eq!(rig.state_root(), before);
}

#[test]
fn changed_parent_payload_replaces_preparation_without_a_beacon_reorg() {
    let mut rig = PreparationRig::gloas(|_| {});
    rig.register(1);
    let parent_root = rig.tile.head_block_root();
    let empty = rig.prepare(1);
    rig.mark_full();
    rig.tile.publish_status(&mut rig.adapter.producers);
    let full = rig.preparation();
    assert_eq!(full.attrs_parent_beacon_block_root, parent_root);
    assert_eq!(full.head_block_hash, FULL_HASH);
    assert_ne!(empty.id, full.id);
    prepared(&mut rig.tile, empty.id, [1; 8], &mut rig.adapter.producers);
    assert_eq!(rig.tile.block_production.payload_id(1, parent_root), None);
    prepared(&mut rig.tile, full.id, [2; 8], &mut rig.adapter.producers);
    let proposal = proposal(&rig.tile, 1);
    rig.tile.start_local_payload(&proposal, &mut rig.adapter.producers).unwrap();
    assert!(matches!(engine_requests(&mut rig.sink)[..], [EngineReq::GetPayload(_)]));

    for index in 0..257 {
        rig.tile.fork_choice.record_ptc_vote(&parent_root, index, true, false);
    }
    rig.tile.publish_status(&mut rig.adapter.producers);
    let empty_again = rig.preparation();
    assert_eq!(empty_again.head_block_hash, EMPTY_HASH);
    assert_ne!(empty_again.id, full.id);
    no_payload(&mut rig.tile, full.id, &mut rig.adapter.producers);
    assert!(rig.tile.block_production.awaits_local_payload(1, parent_root));
    rig.tile.publish_status(&mut rig.adapter.producers);
    assert!(engine_requests(&mut rig.sink).is_empty(), "same context reuses the preparation");
}

#[test]
fn network_preferences_do_not_register_a_local_proposer() {
    let mut rig = PreparationRig::gloas(|_| {});
    let root = rig.tile.head_block_root();
    let prefs = ProposerPreferences { fee_recipient: [6; 20], target_gas_limit: 60_000_000 };
    rig.tile.seen_proposer_preferences.insert(1, root, prefs, false);
    assert_eq!(
        rig.tile.prepare_payload(1, None, &mut rig.adapter.producers),
        Err(ProduceBlockFailure::NoFeeRecipient)
    );
    rig.tile.seen_proposer_preferences.insert(1, root, prefs, true);
    let request = rig.prepare(1);
    assert_eq!(request.attrs_fee_recipient, [6; 20]);
    assert_eq!(request.attrs_target_gas_limit, 60_000_000);
}

#[test]
fn arriving_preferences_replace_default_payload_attributes() {
    let mut rig = PreparationRig::gloas(|_| {});
    rig.register(1);
    let first = rig.prepare(1);
    let root = rig.tile.head_block_root();
    rig.tile.seen_proposer_preferences.insert(
        1,
        root,
        ProposerPreferences { fee_recipient: [6; 20], target_gas_limit: 60_000_000 },
        true,
    );
    let second = rig.prepare(1);
    assert_ne!(first.id, second.id);
    assert_eq!(second.attrs_fee_recipient, [6; 20]);
    assert_eq!(second.attrs_target_gas_limit, 60_000_000);
}

#[test]
fn local_duplicate_preferences_are_authenticated_before_registration() {
    let (mut tile, mut gossip, _rpc, mut spine, mut adapter) = tile_with_producers(0);
    seed_tile_with_keys(&mut tile, 4, 0);
    tile.spec = Arc::new(SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() });
    let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
    sink.consume(|_: BeaconStateEvent, _| {});
    sink.consume(|_: PeerEvent, _| {});
    let mut bytes = [0u8; SIGNED_PROPOSER_PREFERENCES_SIZE];
    bytes[..32].copy_from_slice(&ANCHOR_ROOT);
    bytes[32..40].copy_from_slice(&1u64.to_le_bytes());
    bytes[48..68].fill(7);
    bytes[68..76].copy_from_slice(&60_000_000u64.to_le_bytes());
    let imm = tile.state.read_view(tile.last_applied).imm;
    let domain = bls::compute_domain(
        bls::DOMAIN_PROPOSER_PREFERENCES,
        imm.gloas_fork_version,
        &imm.genesis_validators_root,
    );
    let root = ProposerPreferencesView::hash_tree_root(bytes[..76].try_into().unwrap());
    let signature = test_signing::sign(0, &bls::compute_signing_root(&root, &domain));
    bytes[76..].copy_from_slice(&signature);
    let msg = gossip_msg(&mut gossip, &bytes, GossipTopic::ProposerPreferences);
    tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
    assert!(tile.seen_proposer_preferences.contains(1, &ANCHOR_ROOT));
    assert!(!tile.seen_proposer_preferences.is_local(1, &ANCHOR_ROOT));
    let mut relays = Vec::new();
    sink.consume(|event: PeerEvent, _| {
        if let PeerEvent::SendGossip { topic: GossipTopic::ProposerPreferences, ssz, .. } = event {
            relays.push(ssz.seq());
        }
    });
    assert_eq!(relays, [msg.ssz.seq()]);

    bytes[76..].fill(0);
    let mut msg = gossip_msg(&mut gossip, &bytes, GossipTopic::ProposerPreferences);
    msg.stream_id = LOCAL_GOSSIP_STREAM_ID;
    tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
    assert!(!tile.seen_proposer_preferences.is_local(1, &ANCHOR_ROOT));

    bytes[76..].copy_from_slice(&signature);
    let mut msg = gossip_msg(&mut gossip, &bytes, GossipTopic::ProposerPreferences);
    msg.stream_id = LOCAL_GOSSIP_STREAM_ID;
    tile.handle_gossip(msg.ssz, msg, true, false, &mut adapter.producers);
    assert!(tile.seen_proposer_preferences.is_local(1, &ANCHOR_ROOT));
    sink.consume(|event: PeerEvent, _| {
        assert!(!matches!(event, PeerEvent::SendGossip { .. }), "duplicates are not relayed");
    });
}

#[test]
fn local_preferences_relay_only_after_successful_validation() {
    let (mut tile, mut gossip, _rpc, _spine, mut adapter) = tile_with_producers(0);
    seed_tile_with_keys(&mut tile, 4, 0);
    tile.spec = Arc::new(SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() });
    adapter.consume(|_: PeerEvent, _| {});

    let mut bytes = [0u8; SIGNED_PROPOSER_PREFERENCES_SIZE];
    bytes[..32].copy_from_slice(&ANCHOR_ROOT);
    bytes[32..40].copy_from_slice(&1u64.to_le_bytes());
    bytes[48..68].fill(7);
    bytes[68..76].copy_from_slice(&60_000_000u64.to_le_bytes());
    let mut invalid = gossip_msg(&mut gossip, &bytes, GossipTopic::ProposerPreferences);
    invalid.stream_id = LOCAL_GOSSIP_STREAM_ID;
    tile.handle_gossip(invalid.ssz, invalid, true, false, &mut adapter.producers);
    assert!(!tile.seen_proposer_preferences.contains(1, &ANCHOR_ROOT));
    adapter.consume(|event: PeerEvent, _| {
        assert!(
            !matches!(event, PeerEvent::SendGossip { .. }),
            "invalid preferences are not relayed"
        );
    });

    let imm = tile.state.read_view(tile.last_applied).imm;
    let domain = bls::compute_domain(
        bls::DOMAIN_PROPOSER_PREFERENCES,
        imm.gloas_fork_version,
        &imm.genesis_validators_root,
    );
    let root = ProposerPreferencesView::hash_tree_root(bytes[..76].try_into().unwrap());
    bytes[76..].copy_from_slice(&test_signing::sign(0, &bls::compute_signing_root(&root, &domain)));
    let mut valid = gossip_msg(&mut gossip, &bytes, GossipTopic::ProposerPreferences);
    valid.stream_id = LOCAL_GOSSIP_STREAM_ID;
    tile.handle_gossip(valid.ssz, valid, true, false, &mut adapter.producers);
    assert!(tile.seen_proposer_preferences.is_local(1, &ANCHOR_ROOT));
    let mut relays = Vec::new();
    adapter.consume(|event: PeerEvent, _| {
        if let PeerEvent::SendGossip { topic, originator_stream_id, ssz, .. } = event {
            assert_eq!(topic, GossipTopic::ProposerPreferences);
            assert_eq!(originator_stream_id, LOCAL_GOSSIP_STREAM_ID);
            relays.push(ssz.seq());
        }
    });
    assert_eq!(relays, [valid.ssz.seq()]);
}

#[test]
fn first_gloas_slot_prepares_on_the_last_fulu_payload() {
    let (pre, block, _) = sanity_fixture("empty_epoch_transition");
    let slot = SignedBeaconBlockView::slot(&block);
    assert!(slot.is_multiple_of(SLOTS_PER_EPOCH));
    let spec = SpecConfig {
        fulu_fork_epoch: 0,
        gloas_fork_epoch: slot / SLOTS_PER_EPOCH,
        ..SpecConfig::mainnet()
    };
    let state = BeaconState::from_checkpoint(&pre, &spec, &[]).unwrap();
    let mut rig = PreparationRig::new(state, spec, slot);
    let before = rig.state_root();
    let head = rig.tile.state.read_view(rig.tile.last_applied);
    assert!(!head.is_gloas());
    let parent = head.slot.state().latest_execution_payload_header.clone();
    rig.register(slot);
    rig.tile.payload_attributes.wanted = true;
    let request = rig.prepare(slot);
    assert!(request.is_gloas);
    assert_eq!(request.head_block_hash, parent.block_hash);
    assert_eq!(request.attrs_target_gas_limit, parent.gas_limit);
    assert_eq!(request.attrs_slot_number, slot);
    let [attributes] = rig.payload_attributes()[..] else { panic!("one event per preparation") };
    assert_eq!(attributes.parent_block_number, None, "keyed on the proposal's fork");
    assert!(request.attrs_withdrawals.is_empty());
    assert!(attributes.withdrawals.is_none());
    let advanced = rig.tile.epoch_start_state(rig.tile.last_applied, slot);
    assert!(rig.tile.state.read_view(advanced).is_gloas());
    assert_eq!(rig.state_root(), before);
}
