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
            make_tile_with_producers(wall_slot, state, fulu_from_genesis());
        tile.sync_target = target;
        let (mut spine, adapter) = spine_adapter(&tile);
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine.spine);
        sink.consume(|_: BeaconStateEvent, _| {});
        sink.consume(|_: PeerEvent, _| {});
        Self { tile, gossip, rpc, replay, adapter, sink, _spine: spine }
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
            Path::Local => self.on_local_gossip(GossipTopic::BeaconBlock, block_ssz),
        }
    }

    fn drain(&mut self) -> GossipPublications {
        GossipPublications::drain(&mut self.sink, &mut self.tile.reader)
    }
}

#[derive(Debug, Clone, Copy)]
enum Path {
    Gossip,
    Local,
}

fn stages_of(receipts: &[Receipt]) -> Vec<BlockStage> {
    receipts.iter().map(|r| r.stage).collect()
}

#[test]
fn a_gossip_relay_names_the_block_in_either_sync_mode() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let expected = fulu_relayed(&block_ssz);
    for target in
        [SyncUpdate::Following, SyncUpdate::SyncingHead { head_slot: 400, head_root: [9; 32] }]
    {
        let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
        rig.on_gossip(&block_ssz);

        let published = rig.drain();
        assert_eq!(published.relays, [expected], "{target:?}");
        if target.is_following() {
            assert!(published.receipts().contains(&Receipt {
                slot: expected.slot,
                block_root: expected.block_root,
                stage: BlockStage::Applied,
                source: BlockSource::Gossip,
            }));
        }
    }
}

#[test]
fn an_rpc_block_is_imported_without_a_gossip_notification() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let expected = fulu_relayed(&block_ssz);
    for target in
        [SyncUpdate::Following, SyncUpdate::SyncingHead { head_slot: 400, head_root: [9; 32] }]
    {
        let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
        rig.on_rpc_block(&block_ssz);

        let published = rig.drain();
        assert!(published.relays.is_empty(), "{target:?}: RPC never requests relay");
        assert!(
            published
                .receipts()
                .iter()
                .any(|r| { r.block_root == expected.block_root && r.stage == BlockStage::Applied }),
            "{target:?}: the RPC block was imported"
        );
    }
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
fn a_block_with_a_bad_signature_reports_nothing() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let mut forged = block_ssz.clone();
    forged[4] ^= 0xFF; // the proposer signature occupies [4..100)

    for target in
        [SyncUpdate::Following, SyncUpdate::SyncingHead { head_slot: 400, head_root: [9; 32] }]
    {
        let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, target);
        rig.on_gossip(&forged);
        let published = rig.drain();
        assert!(published.receipts().is_empty(), "{target:?}");
        assert!(published.relays.is_empty(), "{target:?}: a bad signature cannot be relayed");
    }
}

#[test]
fn a_replayed_block_reports_no_gossip() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::Following);

    rig.on_replay(&block_ssz);

    assert_eq!(
        rig.tile.head_state_slot(),
        SignedBeaconBlockView::slot(&block_ssz),
        "replay imported the block"
    );
    let published = rig.drain();
    assert!(published.receipts().is_empty(), "replay emits no block receipts");
    assert!(published.relays.is_empty(), "replay requests no gossip relay");
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
            assert!(result.relays.is_empty());
        }
    }
}
