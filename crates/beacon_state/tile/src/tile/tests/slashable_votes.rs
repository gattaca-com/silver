use blst::min_pk::{AggregateSignature, Signature};
use silver_common::{
    TCacheReader, TReadMode, compute_subnet_for_attestation,
    ssz_view::{ATTESTATION_FIXED, AttesterSlashingView},
};

use super::*;

struct Duty {
    slot: Slot,
    committee_index: usize,
    committee: Vec<u32>,
    subnet: u64,
}

struct Votes {
    tile: BeaconStateTile,
    gossip: TProducer,
    handoff: TCacheReader,
    adapter: SpineAdapter<SilverSpine>,
    sink: SpineAdapter<SilverSpine>,
    imm: Immutable,
    _spine: TestSpine,
}

impl Votes {
    fn at(wall_slot: Slot, surround_epochs: u8) -> Self {
        let state = BeaconState::empty_test(0);
        let (mut tile, gossip, _rpc, _replay) =
            make_tile_with_producers(wall_slot, state, SpecConfig::mainnet(), surround_epochs);
        let (mut spine, adapter) = spine_adapter(&tile);
        seed_tile_with_keys(&mut tile, 128, 0);
        tile.sync_target = SyncUpdate::Following;
        let handoff = TCacheReader::single(
            tile.events_producer.cache_ref(),
            "double_votes_handoff",
            TReadMode::Sliding,
        )
        .unwrap();
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
        sink.consume(|_: BeaconStateEvent, _| {});
        let imm = seed_immutable(&tile);
        Self { tile, gossip, handoff, adapter, sink, imm, _spine: spine }
    }

    /// Votes in epochs 0 and 1 are current at this wall slot.
    fn started(surround_epochs: u8) -> Self {
        let mut rig = Self::at(2 * SLOTS_PER_EPOCH - 1, surround_epochs);
        rig.step();
        rig
    }

    /// Validator 0's attestation duty in `epoch`.
    fn duty(&mut self, epoch: Epoch) -> Duty {
        let view = self.tile.state.read_view(self.tile.canonical_state_id());
        self.tile.shuffling_cache.ensure_window(&view, epoch);
        let shuffling = self.tile.shuffling_cache.lookup(&view, epoch).expect("shuffling");
        let (slot, ci) = (epoch * SLOTS_PER_EPOCH..(epoch + 1) * SLOTS_PER_EPOCH)
            .flat_map(|slot| (0..shuffling.committees_per_slot).map(move |ci| (slot, ci)))
            .find(|&(slot, ci)| shuffling.committee(slot, ci).contains(&0))
            .expect("validator 0 attests once per epoch");
        let committees = shuffling.committees_per_slot as u64;
        Duty {
            slot,
            committee_index: ci,
            committee: shuffling.committee(slot, ci).to_vec(),
            subnet: compute_subnet_for_attestation(committees, slot, ci as u64),
        }
    }

    fn vote_in(&mut self, epoch: Epoch, source_epoch: u64) -> ([u8; SINGLE_ATT_SIZE], u64) {
        let duty = self.duty(epoch);
        (self.signed_vote(&duty, 0, source_epoch), duty.subnet)
    }

    fn signed_vote(&self, duty: &Duty, validator: u32, source_epoch: u64) -> [u8; SINGLE_ATT_SIZE] {
        let key = validator as usize % 3;
        let (bbr, epoch) = (self.tile.head_block_root(), duty.slot / SLOTS_PER_EPOCH);
        let mut vote = test_signing::sign_single_attestation(
            key,
            validator.into(),
            duty.committee_index as u64,
            duty.slot,
            bbr,
            epoch,
            bbr,
            &self.imm,
        );
        vote[64..72].copy_from_slice(&source_epoch.to_le_bytes());
        test_signing::resign_single_attestation(key, &mut vote, &self.imm);
        vote
    }

    /// `signers`' epoch 1 votes, from validator 0's committee, aggregated by
    /// the member `aggregator`.
    fn aggregate(&mut self, signers: &[u32], source_epoch: u64, aggregator: u32) -> Vec<u8> {
        let duty = self.duty(1);
        let votes: Vec<_> =
            signers.iter().map(|&signer| self.signed_vote(&duty, signer, source_epoch)).collect();
        let signatures: Vec<_> = votes
            .iter()
            .map(|vote| Signature::from_bytes(SingleAttestationView::signature(vote)).unwrap())
            .collect();
        let signature =
            AggregateSignature::aggregate(&signatures.iter().collect::<Vec<_>>(), false);

        let committee_len = duty.committee.len();
        let mut attestation = vec![0; ATTESTATION_FIXED + (committee_len + 1).div_ceil(8)];
        attestation[..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        attestation[4..132].copy_from_slice(SingleAttestationView::data(&votes[0]).as_bytes());
        attestation[132..228].copy_from_slice(&signature.unwrap().to_signature().to_bytes());
        attestation[228 + duty.committee_index / 8] |= 1 << (duty.committee_index % 8);
        let positions = signers.iter().map(|signer| {
            duty.committee.iter().position(|member| member == signer).expect("a member")
        });
        for at in positions.chain([committee_len]) {
            attestation[ATTESTATION_FIXED + at / 8] |= 1 << (at % 8);
        }
        let key = aggregator as usize % 3;
        test_signing::wrap_aggregate_and_proof(key, aggregator.into(), &attestation, &self.imm)
    }

    fn forged(&self, mut vote: [u8; SINGLE_ATT_SIZE]) -> [u8; SINGLE_ATT_SIZE] {
        test_signing::resign_single_attestation(1, &mut vote, &self.imm);
        vote
    }

    fn submit(&mut self, vote: &[u8; SINGLE_ATT_SIZE], subnet: u64, local: bool) {
        self.gossip_in(vote, GossipTopic::BeaconAttestation(subnet), local);
    }

    fn gossip_in(&mut self, ssz: &[u8], topic: GossipTopic, local: bool) {
        let mut message = gossip_msg(&mut self.gossip, ssz, topic);
        if local {
            message.stream_id = LOCAL_GOSSIP_STREAM_ID;
        }
        self.sink.produce(message);
    }

    fn step(&mut self) -> GossipPublications {
        self.tile.loop_body(&mut self.adapter);
        self.drain()
    }

    fn drain(&mut self) -> GossipPublications {
        GossipPublications::drain(&mut self.sink, &mut self.tile.reader, &mut self.handoff)
    }
}

#[test]
fn repeat_vote_is_ignored_without_verification() {
    for one_batch in [true, false] {
        let mut rig = Votes::started(0);
        let (first, subnet) = rig.vote_in(1, 0);
        let (conflicting, _) = rig.vote_in(1, 1);
        rig.submit(&first, subnet, false);
        if !one_batch {
            assert_eq!(rig.step().relayed_votes, 1);
        }
        rig.submit(&conflicting, subnet, false);
        rig.submit(&rig.forged(conflicting), subnet, false);

        let drained = rig.step();

        let case = format!("one batch: {one_batch}");
        assert_eq!(drained.relayed_votes, usize::from(one_batch), "{case}: only the first relays");
        assert_eq!(drained.invalid_msgs, 0, "{case}: no repeat is verified");
        assert!(drained.originated.is_empty(), "{case}");
    }
}

#[test]
fn public_surrounds_publish_only_when_enabled_and_useful() {
    for (history, first_local, covered, slashed, expected) in [
        (1, false, false, false, true),
        (0, false, false, false, false),
        (1, true, false, false, true),
        (1, false, true, false, false),
        (1, false, false, true, false),
    ] {
        for one_batch in [false, true] {
            let mut rig = Votes::started(history);
            if slashed {
                slash_head(&mut rig.tile, 0);
            }
            if covered {
                let proof = test_signing::sign_attester_slashing_double_vote(0, 0, 0, 0, &rig.imm);
                rig.gossip_in(&proof, GossipTopic::AttesterSlashing, false);
                rig.step();
                assert_eq!(pooled(&rig.tile).1.as_deref(), Some(proof.as_slice()));
            }
            let (inner, inner_subnet) = rig.vote_in(0, 1);
            let (outer, outer_subnet) = rig.vote_in(1, 0);
            rig.submit(&inner, inner_subnet, first_local);
            if !one_batch {
                rig.step();
            }
            rig.submit(&outer, outer_subnet, false);
            let drained = rig.step();
            assert_eq!(drained.originated.len(), usize::from(expected));
            if expected {
                let (topic, proof) = &drained.originated[0];
                assert_eq!(*topic, GossipTopic::AttesterSlashing);
                let actual = [
                    AttesterSlashingView::att1_data(proof),
                    AttesterSlashingView::att2_data(proof),
                ];
                assert_eq!(
                    actual.map(|d| *d.as_bytes()),
                    [&outer, &inner].map(|v| *SingleAttestationView::data(v).as_bytes())
                );
                rig.gossip_in(proof, *topic, false);
                rig.step();
                assert_eq!(pooled(&rig.tile).1.as_ref(), Some(proof));
            }
        }
    }
}

/// Refusal commits nothing, so a forged copy of the refused vote is no repeat.
/// It must verify on its own signature.
#[test]
fn refused_local_surround_leaves_no_vote_unverified() {
    let mut rig = Votes::started(1);
    let (inner, inner_subnet) = rig.vote_in(0, 1);
    let (outer, outer_subnet) = rig.vote_in(1, 0);
    let forged = rig.forged(outer);
    rig.submit(&inner, inner_subnet, false);
    assert_eq!(rig.step().relayed_votes, 1);
    rig.submit(&outer, outer_subnet, true);
    rig.submit(&forged, outer_subnet, false);

    let drained = rig.step();

    assert_eq!(drained.verdicts(), [Err(LocalGossipFailure::SlashableAgainstPublicGossip)]);
    assert_eq!(drained.relayed_votes, 0);
    assert_eq!(drained.invalid_msgs, 1, "the forged vote is rejected");
    assert!(drained.originated.is_empty());
}

#[test]
fn failed_handoff_keeps_the_attester_proof_queued() {
    let mut rig = Votes::started(0);
    let [x, y, _] = peers(&mut rig);
    for (source, aggregator) in [(0, x), (1, y)] {
        let aggregate = rig.aggregate(&[0], source, aggregator);
        assert_eq!(rig.tile.handle_aggregate_and_proof(&aggregate), Feedback::Accept);
    }
    rig.drain();
    let mut reservations = Vec::new();
    while let Some(reserved) = rig.tile.events_producer.reserve(256, true) {
        reservations.push(reserved);
    }
    rig.tile.publish_slashings(&mut rig.adapter.producers);
    assert!(rig.drain().originated.is_empty());
    drop(reservations);
    rig.tile.events_producer.loop_start();
    rig.handoff.free();
    rig.handoff.free();
    rig.tile.publish_slashings(&mut rig.adapter.producers);
    assert!(matches!(&rig.drain().originated[..], [(GossipTopic::AttesterSlashing, _)]));
}

#[test]
fn local_vote_is_refused_only_against_public_evidence() {
    let refused = Err(LocalGossipFailure::SlashableAgainstPublicGossip);
    // Votes are (target epoch, source epoch).
    for (surround_epochs, public_at, local_at, signed, verdict) in [
        (0, (1, 0), (1, 1), true, refused),
        (0, (1, 0), (1, 0), true, Ok(())),
        (0, (1, 0), (1, 1), false, Err(LocalGossipFailure::Invalid)),
        (1, (0, 1), (1, 0), true, refused),
        (1, (0, 1), (1, 1), true, Ok(())),
        (0, (0, 1), (1, 0), true, Ok(())),
    ] {
        for (one_batch, first_local) in [(true, false), (false, false), (true, true), (false, true)]
        {
            let mut rig = Votes::started(surround_epochs);
            let (public, public_subnet) = rig.vote_in(public_at.0, public_at.1);
            let (mut local, local_subnet) = rig.vote_in(local_at.0, local_at.1);
            if !signed {
                local = rig.forged(local);
            }
            rig.submit(&public, public_subnet, first_local);
            if !one_batch {
                assert_eq!(rig.step().relayed_votes, 1);
            }
            rig.submit(&local, local_subnet, true);

            let drained = rig.step();

            let case = format!(
                "surround_epochs {surround_epochs}, public {public_at:?}, local {local_at:?}, \
                 signed: {signed}, one batch: {one_batch}, first local: {first_local}"
            );
            let expected =
                if one_batch && first_local { vec![Ok(()), verdict] } else { vec![verdict] };
            assert_eq!(drained.verdicts(), expected, "{case}");
            let local_relays = verdict == Ok(()) && public_at.0 != local_at.0;
            assert_eq!(
                drained.relayed_votes,
                usize::from(one_batch) + usize::from(local_relays),
                "{case}: only accepted votes relay"
            );
            assert!(drained.originated.is_empty(), "{case}: not reported");
            if verdict == refused && surround_epochs > 0 {
                assert_eq!(drained.relayed_votes, usize::from(one_batch), "{case}: not published");
                rig.submit(&local, local_subnet, false);
                let reported = rig.step().originated;
                assert!(
                    matches!(&reported[..], [(GossipTopic::AttesterSlashing, _)]),
                    "{case}: reported once public: {reported:?}"
                );
            }
        }
    }
}

/// Validator 0's committee peers. The first precedes validator 0 in
/// committee order, so a proof must sort its signers.
fn peers(rig: &mut Votes) -> [u32; 3] {
    let committee = rig.duty(1).committee;
    let before = committee.iter().take_while(|&&member| member != 0).count();
    assert!(before > 0, "fixture: validator 0 leads its committee");
    let mut peers = committee.into_iter().filter(|&member| member != 0);
    std::array::from_fn(|_| peers.next().expect("fixture: a committee of four"))
}

#[test]
fn aggregates_prove_only_public_conflicting_overlaps_once() {
    for case in ["double", "same", "disjoint", "local first", "local second"] {
        let mut rig = Votes::started(0);
        let [x, y, z] = peers(&mut rig);
        let first = rig.aggregate(&[0, x], 0, x);
        let second_signers = if case == "disjoint" { vec![y] } else { vec![0, y] };
        let second = rig.aggregate(&second_signers, u64::from(case != "same"), y);
        rig.gossip_in(&first, GossipTopic::BeaconAggregateAndProof, case == "local first");
        rig.gossip_in(&second, GossipTopic::BeaconAggregateAndProof, case == "local second");
        let drained = rig.step();
        assert_eq!(drained.relayed_votes, 2, "{case}: both accepted");
        let proves = matches!(case, "double" | "local first" | "local second");
        assert_eq!(drained.originated.len(), usize::from(proves), "{case}");
        if !proves {
            continue;
        }
        let (topic, slashing) = &drained.originated[0];
        assert_eq!(*topic, GossipTopic::AttesterSlashing);
        let signers = |indices: &[u8]| -> Vec<_> {
            indices.chunks(8).map(|index| u64::from_le_bytes(index.try_into().unwrap())).collect()
        };
        let first = signers(AttesterSlashingView::att1_attesting_indices(slashing));
        let second = signers(AttesterSlashingView::att2_attesting_indices(slashing));
        assert_eq!(first.iter().filter(|index| second.contains(index)).collect::<Vec<_>>(), [&0]);
        let third = rig.aggregate(&[0, z], 1, z);
        rig.gossip_in(&third, GossipTopic::BeaconAggregateAndProof, false);
        assert!(rig.step().originated.is_empty());
        rig.gossip_in(slashing, *topic, false);
        rig.step();
        assert_eq!(pooled(&rig.tile).1.as_ref(), Some(slashing));
    }
}

fn signed_epoch(tile: &BeaconStateTile, validators: usize) -> Vec<([u8; SINGLE_ATT_SIZE], u64)> {
    let view = tile.state.read_view(tile.canonical_state_id());
    let shuffling = tile.shuffling_cache.lookup(&view, 0).expect("epoch 0 shuffling");
    let bbr = tile.head_block_root();
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_ATTESTER,
        view.epoch.fork_version_at(0),
        &view.imm.genesis_validators_root,
    );
    let mut votes = Vec::with_capacity(validators);
    for slot in 0..SLOTS_PER_EPOCH {
        for ci in 0..shuffling.committees_per_slot {
            let subnet = compute_subnet_for_attestation(
                shuffling.committees_per_slot as u64,
                slot,
                ci as u64,
            );
            for &validator in shuffling.committee(slot, ci) {
                let imm = Immutable::default();
                let mut vote = test_signing::sign_single_attestation(
                    0,
                    validator as u64,
                    ci as u64,
                    slot,
                    bbr,
                    0,
                    bbr,
                    &imm,
                );
                let data = SingleAttestationView::data(&vote).as_bytes();
                let signing_root =
                    bls::compute_signing_root(&ssz_hash::hash_attestation_data(data), &domain);
                let key = test_signing::pyspec_privkey(validator as u64);
                vote[144..].copy_from_slice(&key.sign(&signing_root, bls::DST, &[]).to_bytes());
                votes.push((vote, subnet));
            }
        }
    }
    votes
}

fn tile_with_distinct_keys(validators: usize, surround_epochs: u8) -> Votes {
    let mut rig = Votes::at(31, surround_epochs);
    let (epoch_base, mut seeds) = build_seed_finalized(validators, false);
    for (i, seed) in seeds.iter_mut().enumerate() {
        seed.pubkey = test_signing::pyspec_privkey(i as u64).sk_to_pk().to_bytes();
    }
    arm_tile(&mut rig.tile, epoch_base, &seeds, 0);
    // Production sizes the history for the checkpoint's registry; this one
    // is armed after construction.
    rig.tile.detection = SlashingDetection::new(surround_epochs, validators);
    rig
}

// Includes gossip tcache writes and initial history population for epoch 0.
// Fixture signing and tile construction are outside the timed interval.
#[test]
#[ignore = "opt-in timing harness"]
fn vote_flush_timing() {
    const VALIDATORS: usize = 8192;
    const ROUNDS: usize = 4;
    const SETTINGS: [u8; 3] = [0, 1, 16];

    let votes = signed_epoch(&tile_with_distinct_keys(VALIDATORS, 0).tile, VALIDATORS);
    let mut totals = [Duration::ZERO; SETTINGS.len()];
    for round in 0..ROUNDS {
        for k in 0..SETTINGS.len() {
            let setting = (round + k) % SETTINGS.len();
            let mut rig = tile_with_distinct_keys(VALIDATORS, SETTINGS[setting]);

            let start = std::time::Instant::now();
            for (vote, subnet) in &votes {
                let message =
                    gossip_msg(&mut rig.gossip, vote, GossipTopic::BeaconAttestation(*subnet));
                rig.tile.defer_vote(message, &mut rig.adapter.producers);
                if rig.tile.vote_batch.is_empty() {
                    rig.tile.reader.free();
                }
            }
            rig.tile.flush_votes(&mut rig.adapter.producers);
            rig.tile.publish_slashings(&mut rig.adapter.producers);
            totals[setting] += start.elapsed();

            let accepted = (0..VALIDATORS).filter(|&v| rig.tile.seen_attesters.contains(0, v));
            assert_eq!(accepted.count(), VALIDATORS, "every vote verifies");
        }
    }
    for (setting, total) in SETTINGS.iter().zip(totals) {
        let per_vote = total / (ROUNDS * VALIDATORS) as u32;
        eprintln!("surround_epochs = {setting:2}: {per_vote:?} per accepted single");
    }
}
