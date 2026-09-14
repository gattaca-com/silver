use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Receipt {
    slot: Slot,
    block_root: B256,
    stage: BlockStage,
    source: BlockSource,
}

struct Published {
    events: Vec<BeaconStateEvent>,
    relays: Vec<GossipBlock>,
}

impl Published {
    fn drain(sink: &mut SpineAdapter<SilverSpine>) -> Self {
        let mut events = Vec::new();
        sink.consume(|event: BeaconStateEvent, _| events.push(event));
        let mut relays = Vec::new();
        sink.consume(|event: PeerEvent, _| {
            if let PeerEvent::SendGossip { topic, block, .. } = event {
                assert_eq!(topic, GossipTopic::BeaconBlock);
                relays.push(block.expect("every block relay carries its metadata"));
            }
        });
        Self { events, relays }
    }

    fn receipts(&self) -> Vec<Receipt> {
        self.events
            .iter()
            .filter_map(|event| match *event {
                BeaconStateEvent::BlockReceived { slot, block_root, stage, source, .. } => {
                    Some(Receipt { slot, block_root, stage, source })
                }
                _ => None,
            })
            .collect()
    }
}

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
    _spine: Box<SilverSpine>,
}

impl BlockPublications {
    fn new(pre_ssz: &[u8], block_ssz: &[u8], target: SyncUpdate) -> Self {
        let state = BeaconState::from_checkpoint(pre_ssz, &fulu_from_genesis(), &[])
            .unwrap_or_else(|e| panic!("decompose checkpoint: {e}"));
        let block_slot = SignedBeaconBlockView::slot(block_ssz);
        let (mut tile, gossip, rpc, replay) =
            make_tile_with_producers(block_slot + 1, state, fulu_from_genesis());
        tile.sync_target = target;
        let (mut spine, adapter) = spine_adapter(&tile);
        let mut sink = SpineAdapter::connect_tile(&Sink, &mut spine);
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
        self.tile.handle_gossip(m.ssz, m, false, false, &mut self.adapter.producers);
    }

    fn on_rpc_block(&mut self, block_ssz: &[u8]) {
        let (_, read) = publish_block_bytes(&mut self.rpc, block_ssz);
        self.tile.on_rpc_inbound(live_block_response(read), &mut self.adapter.producers);
    }

    fn on_replay(&mut self, block_ssz: &[u8]) {
        let (_, read) = publish_block_bytes(&mut self.replay, block_ssz);
        self.tile.on_replay(ReplayBlock::Block { ssz: read }, &mut self.adapter.producers);
    }

    fn drain(&mut self) -> Published {
        Published::drain(&mut self.sink)
    }
}

fn stages_of(receipts: &[Receipt]) -> Vec<BlockStage> {
    receipts.iter().map(|r| r.stage).collect()
}

fn fulu_gossip_block(bytes: &[u8]) -> GossipBlock {
    GossipBlock { slot: SignedBeaconBlockView::slot(bytes), block_root: block_root_fulu(bytes) }
}

#[test]
fn gossip_relay_carries_block_metadata_in_either_sync_mode() {
    let (pre_ssz, block_ssz) = sanity_fixture("attestation");
    let expected = fulu_gossip_block(&block_ssz);
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
    let expected = fulu_gossip_block(&block_ssz);
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
fn a_blob_block_is_relayed_once_across_staging_and_import() {
    let (pre_ssz, block_ssz) = sanity_fixture("one_blob");
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::Following);
    let expected = fulu_gossip_block(&block_ssz);

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
    let expected = fulu_gossip_block(&block_ssz);
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
fn a_parked_block_is_relayed_by_the_retry_that_admits_it() {
    let (pre_ssz, first) = sanity_fixture("attestation");
    let second = sanity_file("attestation", "blocks_1.ssz_snappy");
    let mut rig = BlockPublications::new(&pre_ssz, &second, SyncUpdate::Following);

    rig.on_gossip(&second);
    let parked = rig.drain();
    assert_eq!(stages_of(&parked.receipts()), [BlockStage::AwaitParent]);
    assert!(parked.relays.is_empty(), "the missing parent prevents validation");
    let child = parked.receipts()[0].block_root;

    rig.on_gossip(&first);
    let released = rig.drain();
    assert_eq!(released.relays, [fulu_gossip_block(&first), fulu_gossip_block(&second)]);
    let of_child =
        released.receipts().into_iter().filter(|r| r.block_root == child).collect::<Vec<_>>();
    assert_eq!(stages_of(&of_child), [BlockStage::Applied]);
}

#[test]
fn a_relay_request_does_not_imply_successful_import() {
    let pre_ssz = sanity_file("invalid_incorrect_state_root", "pre.ssz_snappy");
    let block_ssz = sanity_file("invalid_incorrect_state_root", "blocks_0.ssz_snappy");
    let mut rig = BlockPublications::new(&pre_ssz, &block_ssz, SyncUpdate::Following);

    rig.on_gossip(&block_ssz);
    let published = rig.drain();
    let expected = fulu_gossip_block(&block_ssz);
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
