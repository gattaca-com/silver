use silver_common::TCacheReader;

use super::*;

fn fulu_from_genesis() -> SpecConfig {
    SpecConfig { fulu_fork_epoch: 0, ..SpecConfig::mainnet() }
}

fn sanity_file(name: &str, file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("consensus-spec-tests/tests/mainnet/fulu/sanity/blocks/pyspec_tests")
        .join(name)
        .join(file);
    let raw = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run `just ef-tests-download`)", path.display()));
    snap::Decoder::new().decompress_vec(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn sanity_fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    (sanity_file(name, "pre.ssz_snappy"), sanity_file(name, "blocks_0.ssz_snappy"))
}

struct BlockPublications {
    tile: BeaconStateTile,
    handoff: TCacheReader,
    gossip: TProducer,
    rpc: TProducer,
    replay: TProducer,
    adapter: SpineAdapter<SilverSpine>,
    sink: SpineAdapter<SilverSpine>,
    _spine: TestSpine,
}

impl BlockPublications {
    fn new(pre_ssz: &[u8], block_ssz: &[u8], target: SyncUpdate) -> Self {
        Self::at_wall_slot(pre_ssz, SignedBeaconBlockView::slot(block_ssz) + 1, target)
    }

    fn at_wall_slot(pre_ssz: &[u8], wall_slot: Slot, target: SyncUpdate) -> Self {
        let state = BeaconState::from_checkpoint(pre_ssz, &fulu_from_genesis(), &[])
            .unwrap_or_else(|e| panic!("decompose checkpoint: {e}"));
        let (mut tile, gossip, rpc, replay) =
            make_tile_with_producers(wall_slot, state, fulu_from_genesis(), 0);
        tile.sync_target = target;
        let handoff = TCacheReader::single(
            tile.events_producer.cache_ref(),
            "block_publications_handoff",
            TReadMode::Sliding,
        )
        .unwrap();
        let (mut spine, adapter) = spine_adapter(&tile);
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
        sink.consume(|_: BeaconStateEvent, _| {});
        sink.consume(|_: PeerEvent, _| {});
        Self { tile, handoff, gossip, rpc, replay, adapter, sink, _spine: spine }
    }

    fn on_gossip(&mut self, block_ssz: &[u8]) {
        let m = gossip_msg(&mut self.gossip, block_ssz, GossipTopic::BeaconBlock);
        self.tile.on_gossip(m, &mut self.adapter.producers);
    }

    fn on_gossip_unrelayed(&mut self, block_ssz: &[u8]) {
        let m = gossip_msg(&mut self.gossip, block_ssz, GossipTopic::BeaconBlock);
        self.tile.handle_gossip(m.ssz, m, false, &mut self.adapter.producers);
    }

    fn on_rpc_block(&mut self, block_ssz: &[u8]) {
        let (_, read) = publish_block_bytes(&mut self.rpc, block_ssz);
        self.tile.on_rpc_inbound(live_block_response(read), &mut self.adapter.producers);
    }

    fn on_replay(&mut self, block_ssz: &[u8]) {
        let (_, read) = publish_block_bytes(&mut self.replay, block_ssz);
        self.tile.on_replay(ReplayBlock::Block { ssz: read }, &mut self.adapter.producers);
    }

    fn on_local_gossip(&mut self, topic: GossipTopic, ssz: &[u8]) {
        let mut m = gossip_msg(&mut self.gossip, ssz, topic);
        m.stream_id = LOCAL_GOSSIP_STREAM_ID;
        self.tile.on_gossip(m, &mut self.adapter.producers);
    }

    fn on_block(&mut self, path: Path, block_ssz: &[u8]) {
        match path {
            Path::Gossip => self.on_gossip(block_ssz),
            Path::Rpc => self.on_rpc_block(block_ssz),
            Path::Replay => self.on_replay(block_ssz),
            Path::Local => self.on_local_gossip(GossipTopic::BeaconBlock, block_ssz),
            Path::LocalUnrelayed => {
                let mut m = gossip_msg(&mut self.gossip, block_ssz, GossipTopic::BeaconBlock);
                m.stream_id = LOCAL_GOSSIP_STREAM_ID;
                let parent = *SignedBeaconBlockView::parent_root(block_ssz);
                let pin = self.tile.reader.acquire(m.ssz);
                assert!(self.tile.buffer_awaiting_payload(
                    parent,
                    block_root_fulu(block_ssz),
                    SignedBeaconBlockView::slot(block_ssz),
                    BlockSourceMsg::Gossip(m, pin),
                    &mut self.adapter.producers,
                ));
                self.tile.drain_awaiting_payload(parent, &mut self.adapter.producers);
            }
        }
    }

    /// Publishes what the tile loop would after this step.
    fn drain(&mut self) -> GossipPublications {
        self.tile.publish_slashings(&mut self.adapter.producers);
        GossipPublications::drain(&mut self.sink, &mut self.tile.reader, &mut self.handoff)
    }

    fn signed_by(&self, mut block: Vec<u8>, signer: u64) -> Vec<u8> {
        let epoch = SignedBeaconBlockView::slot(&block) / SLOTS_PER_EPOCH;
        let genesis_validators_root = self.tile.state.state().immutable.genesis_validators_root;
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            self.tile.spec.fork_version_at(epoch),
            &genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&block_root_fulu(&block), &domain);
        let key = test_signing::pyspec_privkey(signer);
        block[4..100].copy_from_slice(&key.sign(&signing_root, bls::DST, &[]).to_bytes());
        block
    }

    fn equivocation_of(&self, block: &[u8]) -> Vec<u8> {
        self.signed_by(sibling_of(block), SignedBeaconBlockView::proposer_index(block))
    }
}

#[derive(Debug, Clone, Copy)]
enum Path {
    Gossip,
    Rpc,
    Replay,
    Local,
    LocalUnrelayed,
}

const SYNC_MODES: [SyncUpdate; 2] =
    [SyncUpdate::Following, SyncUpdate::SyncingHead { head_slot: 400, head_root: [9; 32] }];

/// Changing graffiti invalidates the signature and, even after re-signing,
/// the state root. This lets tests distinguish relay from successful import.
fn sibling_of(block: &[u8]) -> Vec<u8> {
    nth_sibling_of(block, 0)
}

fn nth_sibling_of(block: &[u8], n: usize) -> Vec<u8> {
    let mut sibling = block.to_vec();
    sibling[BODY + 96 + 72 + n] ^= 1; // graffiti, after randao_reveal and eth1_data
    sibling
}

fn stages_of(receipts: &[Receipt]) -> Vec<BlockStage> {
    receipts.iter().map(|r| r.stage).collect()
}

#[test]
fn stalled_after_syncing_imports_gossip() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let expected = fulu_relayed(&block_ssz);
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::SyncingHead {
        head_slot: 400,
        head_root: [9; 32],
    });
    rig.tile.on_sync_update(SyncUpdate::Stalled);
    rig.on_gossip(&block_ssz);

    assert!(rig.drain().receipts().contains(&Receipt {
        slot: expected.slot,
        block_root: expected.block_root,
        stage: BlockStage::Applied,
        source: BlockSource::Gossip,
    }));
}

#[test]
fn a_blob_block_is_relayed_once_across_staging_and_import() {
    let (pre_ssz, block_ssz) = sanity_fixture("one_blob");
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::Following);
    let expected = fulu_relayed(&block_ssz);

    rig.on_gossip(&block_ssz);
    let published = rig.drain();
    assert_eq!(published.relays, [expected]);
    assert_eq!(stages_of(&published.receipts()), [BlockStage::AwaitData]);

    rig.on_gossip(&block_ssz);
    let repeated = rig.drain();
    assert!(repeated.relays.is_empty());

    rig.tile.handle_data_columns_available(
        expected.block_root,
        expected.slot,
        &mut rig.adapter.producers,
    );
    let imported = rig.drain();
    assert_eq!(stages_of(&imported.receipts()), [BlockStage::Applied]);
    assert!(imported.relays.is_empty(), "DA completion does not relay the block again");
}

/// `drain_awaiting_payload` disables relay when retrying a Gloas block.
/// No fixture covers that retry, so this checks the handler's flag directly.
#[test]
fn disabling_relay_suppresses_the_gossip_notification() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let expected = fulu_relayed(&block_ssz);
    for target in
        [SyncUpdate::Following, SyncUpdate::SyncingHead { head_slot: 400, head_root: [9; 32] }]
    {
        let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
        rig.on_gossip_unrelayed(&block_ssz);

        let published = rig.drain();
        assert!(published.relays.is_empty(), "{target:?}: relay is disabled");
        if target.is_following() {
            assert!(
                published.receipts().iter().any(|r| {
                    r.block_root == expected.block_root && r.stage == BlockStage::Applied
                }),
                "disabling relay still imports the block"
            );
        }
    }
}

/// A missing parent fails precheck before signature verification. The parent's
/// import retries the child through the block handler.
#[test]
fn parked_blocks_keep_their_source_and_relay_when_admitted() {
    let (pre, first) = sanity_fixture("attestation");
    let second = sanity_file("attestation", "blocks_1.ssz_snappy");
    for (path, source) in
        [(Path::Gossip, BlockSource::Gossip), (Path::Local, BlockSource::LocalGossip)]
    {
        let mut rig = BlockPublications::new(&pre, &second, SyncUpdate::Following);
        rig.on_block(path, &second);
        let parked = rig.drain();
        assert_eq!(stages_of(&parked.receipts()), [BlockStage::AwaitParent]);
        assert!(parked.relays.is_empty());
        rig.on_block(path, &first);
        let released = rig.drain();
        assert_eq!(released.relays, [fulu_relayed(&first), fulu_relayed(&second)]);
        let child = block_root_fulu(&second);
        assert!(
            released
                .receipts()
                .iter()
                .any(|r| r.block_root == child && r.stage == BlockStage::Applied)
        );
        assert!(parked.receipts().iter().chain(&released.receipts()).all(|r| r.source == source));
    }
}

#[test]
fn a_relay_request_does_not_imply_successful_import() {
    let pre_ssz = sanity_file("invalid_incorrect_state_root", "pre.ssz_snappy");
    let block_ssz = sanity_file("invalid_incorrect_state_root", "blocks_0.ssz_snappy");
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::Following);

    rig.on_gossip(&block_ssz);
    let published = rig.drain();
    let expected = fulu_relayed(&block_ssz);
    assert_eq!(published.relays, [expected]);
    assert!(published.receipts().is_empty());
    assert!(
        published.events.iter().any(|event| matches!(event,
            BeaconStateEvent::BlockRejected { block_root, source: BlockSource::Gossip }
                if *block_root == expected.block_root
        )),
        "state transition rejected the relayed block"
    );
}

#[test]
fn verified_sources_reserve_and_public_pairs_round_trip() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let proposer = SignedBeaconBlockView::proposer_index(&block_ssz);
    for (target, first) in SYNC_MODES
        .into_iter()
        .flat_map(|t| [Path::Gossip, Path::Rpc, Path::Replay, Path::Local].map(|p| (t, p)))
    {
        let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
        let equivocation = rig.equivocation_of(&block_ssz);
        let third = rig.signed_by(nth_sibling_of(&block_ssz, 1), proposer);
        if matches!(first, Path::Gossip | Path::Rpc) {
            rig.on_block(first, &sibling_of(&block_ssz));
            let invalid = rig.drain();
            assert!(invalid.receipts().is_empty() && invalid.relays.is_empty());
        }
        rig.on_block(first, &block_ssz);
        let accepted = rig.drain();
        let relays = usize::from(matches!(first, Path::Gossip | Path::Local));
        assert_eq!(accepted.relays.len(), relays);
        if relays > 0 {
            assert_eq!(accepted.relays, [fulu_relayed(&block_ssz)]);
        }
        if matches!(first, Path::Rpc | Path::Replay) || target.is_following() {
            assert_eq!(rig.tile.head_state_slot(), SignedBeaconBlockView::slot(&block_ssz));
        }
        rig.on_gossip(&sibling_of(&block_ssz));
        assert_eq!(rig.drain().invalid_msgs, 1);
        rig.on_gossip(&equivocation);
        rig.on_gossip(&third);

        let published = rig.drain();
        assert!(published.relays.is_empty(), "{target:?}: conflicts are not relayed");
        assert!(published.receipts().is_empty(), "{target:?}");
        assert!(published.rejected(&equivocation).is_empty(), "{target:?}: no STF ran");
        assert_eq!(published.invalid_msgs, 0, "{target:?}");
        let [(GossipTopic::ProposerSlashing, slashing)] = &published.originated[..] else {
            panic!("{target:?}: one proposer slashing: {:?}", published.originated);
        };
        assert!(rig.drain().originated.is_empty(), "{target:?}: proven once");

        rig.on_local_gossip(GossipTopic::ProposerSlashing, slashing);
        assert_eq!(rig.drain().relayed_slashings, [slashing.as_slice()], "{target:?}: it verifies");
        let pooled_slashing: [u8; PROPOSER_SLASHING_SIZE] = slashing[..].try_into().unwrap();
        assert_eq!(pooled(&rig.tile).0, [pooled_slashing], "{target:?}");

        rig.on_rpc_block(&block_ssz);
        rig.on_gossip(&nth_sibling_of(&block_ssz, 2));
        let later = rig.drain();
        assert_eq!(later.invalid_msgs, 0, "{target:?}: a closed key ignores unverified blocks");
        assert!(later.relays.is_empty() && later.originated.is_empty(), "{target:?}");
    }
}

#[test]
fn closed_gossip_keys_skip_hashing_but_reject_malformed_blocks() {
    let (pre, block) = sanity_fixture("attestation");
    let proposer = SignedBeaconBlockView::proposer_index(&block);
    let mut witness = BlockPublications::new(&pre, &block, SyncUpdate::Following);
    let conflict = witness.equivocation_of(&block);
    witness.on_gossip(&block);
    witness.on_gossip(&conflict);
    let proof = witness.drain().originated.remove(0).1;
    for target in SYNC_MODES {
        for cause in ["free", "open", "private", "reported", "covered", "slashed"] {
            let mut rig = BlockPublications::new(&pre, &block, target);
            if cause != "free" {
                rig.on_block(
                    if cause == "private" { Path::LocalUnrelayed } else { Path::Gossip },
                    &block,
                );
            }
            match cause {
                "reported" => rig.on_gossip(&conflict),
                "covered" => rig.on_local_gossip(GossipTopic::ProposerSlashing, &proof),
                "slashed" => slash_head(&mut rig.tile, proposer as u32),
                _ => {}
            }
            rig.drain();
            let closed = !matches!(cause, "free" | "open");
            let mut malformed = block.clone();
            malformed[BODY + 200..BODY + 204].fill(0xff);
            rig.on_gossip(&malformed);
            let result = rig.drain();
            assert_eq!(result.invalid_msgs, 1, "{cause}: {target:?}: malformed at any key");
            assert!(result.relays.is_empty() && result.originated.is_empty());
            if closed {
                rig.on_gossip(&block);
                assert!(
                    rig.drain().receipts().is_empty(),
                    "closed repeats ignore before BlockKnown"
                );
            }
            rig.on_gossip(&[]);
            assert_eq!(rig.drain().invalid_msgs, 1);
            assert!(matches!(rig.tile.try_apply_block(&[]), Feedback::Reject(_)));
            assert!(matches!(rig.tile.ef_gossip_block(&[]), Feedback::Reject(_)));
        }
    }
}

#[test]
fn local_same_root_blocks_complete_when_known_or_staged() {
    for fixture in ["attestation", "one_blob"] {
        let (pre, block) = sanity_fixture(fixture);
        for first in [Path::Gossip, Path::Local] {
            let mut rig = BlockPublications::new(&pre, &block, SyncUpdate::Following);
            rig.on_block(first, &block);
            let expected =
                if fixture == "one_blob" { BlockStage::AwaitData } else { BlockStage::Applied };
            assert_eq!(stages_of(&rig.drain().receipts()), [expected]);
            rig.on_local_gossip(GossipTopic::BeaconBlock, &block);
            let result = rig.drain();
            assert_eq!(result.verdicts(), [Ok(())]);
            assert!(result.relays.is_empty() && result.originated.is_empty());
        }
    }
}

#[test]
fn block_beyond_the_lookahead_takes_the_place() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let slot = (SignedBeaconBlockView::slot(&block_ssz) / SLOTS_PER_EPOCH + 2) * SLOTS_PER_EPOCH;
    let mut rig = BlockPublications::at_wall_slot(&pre_ssz, slot + 1, SyncUpdate::Following);

    let mut unrelayable = empty_block_at(slot, *SignedBeaconBlockView::parent_root(&block_ssz));
    let payload = BODY + BEACON_BLOCK_BODY_FIXED;
    let genesis_time = rig.tile.state.state().immutable.genesis_time;
    let timestamp = genesis_time + slot * rig.tile.spec.seconds_per_slot();
    unrelayable[payload + 428..payload + 436].copy_from_slice(&timestamp.to_le_bytes());
    let unrelayable = rig.signed_by(unrelayable, 0);
    let equivocation = rig.equivocation_of(&unrelayable);

    rig.on_gossip(&unrelayable);
    rig.on_gossip(&equivocation);

    let published = rig.drain();
    assert!(published.relays.is_empty());
    assert_eq!(published.rejected(&unrelayable), [BlockSource::Gossip], "the fixture is sound");
    assert!(published.rejected(&equivocation).is_empty(), "no STF ran");
    assert!(matches!(&published.originated[..], [(GossipTopic::ProposerSlashing, _)]));
}

#[test]
fn conflicting_rpc_block_is_processed_and_reported() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    for target in SYNC_MODES {
        for gossiped_first in [false, true] {
            let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
            let equivocation = rig.equivocation_of(&block_ssz);
            rig.on_gossip(&block_ssz);
            if gossiped_first {
                rig.on_gossip(&equivocation);
            }
            let mut originated = rig.drain().originated;

            rig.on_rpc_block(&equivocation);

            let published = rig.drain();
            let case = format!("{target:?}, gossiped first: {gossiped_first}");
            assert_eq!(published.rejected(&equivocation), [BlockSource::Rpc], "{case}: STF ran");
            originated.extend(published.originated);
            assert!(matches!(&originated[..], [(GossipTopic::ProposerSlashing, _)]), "{case}");
        }
    }
}

#[test]
fn local_double_proposal_is_refused_only_against_public_evidence() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let refused = Err(LocalGossipFailure::SlashableAgainstPublicGossip);
    for target in SYNC_MODES {
        for (first, signed, verdict) in [
            (Path::Gossip, true, refused),
            (Path::Rpc, true, refused),
            (Path::Gossip, false, Err(LocalGossipFailure::Invalid)),
            (Path::Local, true, refused),
            (Path::Local, false, Err(LocalGossipFailure::Invalid)),
            (Path::LocalUnrelayed, true, Err(LocalGossipFailure::Unverifiable)),
            (Path::LocalUnrelayed, false, Err(LocalGossipFailure::Invalid)),
        ] {
            let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
            let second =
                if signed { rig.equivocation_of(&block_ssz) } else { sibling_of(&block_ssz) };
            rig.on_block(first, &block_ssz);
            rig.drain();

            rig.on_local_gossip(GossipTopic::BeaconBlock, &second);

            let published = rig.drain();
            let case = format!("{target:?}, first by {first:?}, signed: {signed}");
            assert_eq!(published.verdicts(), [verdict], "{case}");
            assert!(published.relays.is_empty(), "{case}: not published");
            assert!(published.receipts().is_empty(), "{case}: not applied");
            assert!(published.originated.is_empty(), "{case}: not reported");
        }
    }
}

#[test]
fn local_proposals_become_evidence_only_after_publication() {
    let (pre, block) = sanity_fixture("attestation");
    for target in SYNC_MODES {
        for (first, copy) in [
            (Path::Local, None),
            (Path::LocalUnrelayed, None),
            (Path::LocalUnrelayed, Some(Path::Rpc)),
            (Path::LocalUnrelayed, Some(Path::Replay)),
        ] {
            let mut rig = BlockPublications::new(&pre, &block, target);
            let conflict = rig.equivocation_of(&block);
            rig.on_block(first, &block);
            let initial = rig.drain();
            let relayed = matches!(first, Path::Local);
            assert_eq!(initial.relays.len(), usize::from(relayed));
            assert!(initial.originated.is_empty());
            if target.is_following() {
                assert_eq!(rig.tile.head_state_slot(), SignedBeaconBlockView::slot(&block));
            }
            if let Some(path) = copy {
                let mut forged = block.clone();
                forged[4] ^= 0xff;
                rig.on_block(path, &forged);
                rig.drain();
                rig.on_gossip(&conflict);
                assert!(rig.drain().originated.is_empty(), "a forged copy is not evidence");
                rig.on_block(path, &block);
                assert!(rig.drain().originated.is_empty(), "a public copy is not a conflict");
            }
            rig.on_gossip(&conflict);
            let result = rig.drain();
            assert!(result.relays.is_empty());
            assert_eq!(result.invalid_msgs, 0);
            if relayed || copy.is_some() {
                assert!(matches!(&result.originated[..], [(GossipTopic::ProposerSlashing, _)]));
            } else {
                assert!(result.originated.is_empty());
                rig.on_gossip(&sibling_of(&block));
                assert_eq!(rig.drain().invalid_msgs, 0, "a private first keeps its key closed");
            }
        }
    }
}
