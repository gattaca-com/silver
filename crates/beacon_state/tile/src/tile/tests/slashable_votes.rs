use silver_common::{TCacheReader, TReadMode, compute_subnet_for_attestation};

use super::*;

struct Duty {
    slot: Slot,
    committee_index: usize,
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
    fn at(wall_slot: Slot) -> Self {
        let state = BeaconState::empty_test(0);
        let (mut tile, gossip, _rpc, _replay) =
            make_tile_with_producers(wall_slot, state, SpecConfig::mainnet());
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
    fn started() -> Self {
        let mut rig = Self::at(2 * SLOTS_PER_EPOCH - 1);
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
        let mut rig = Votes::started();
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
fn local_vote_is_refused_only_against_public_evidence() {
    let refused = Err(LocalGossipFailure::SlashableAgainstPublicGossip);
    // Votes are (target epoch, source epoch).
    for (public_at, local_at, signed, verdict) in [
        ((1, 0), (1, 1), true, refused),
        ((1, 0), (1, 0), true, Ok(())),
        ((1, 0), (1, 1), false, Err(LocalGossipFailure::Invalid)),
    ] {
        for one_batch in [true, false] {
            let mut rig = Votes::started();
            let (public, public_subnet) = rig.vote_in(public_at.0, public_at.1);
            let (mut local, local_subnet) = rig.vote_in(local_at.0, local_at.1);
            if !signed {
                local = rig.forged(local);
            }
            rig.submit(&public, public_subnet, false);
            if !one_batch {
                rig.step();
            }
            rig.submit(&local, local_subnet, true);

            let drained = rig.step();

            let case = format!(
                "public {public_at:?}, local {local_at:?}, \
                 signed: {signed}, one batch: {one_batch}"
            );
            assert_eq!(drained.verdicts(), [verdict], "{case}");
            assert!(drained.originated.is_empty(), "{case}: not reported");
        }
    }
}
