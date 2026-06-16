use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flux::{spine::SpineAdapter, tile::Tile, timing::Nanos};
use serde::Deserialize;
use silver_beacon_state::{
    ssz_hash::{
        StateHashScratch, hash_tree_root_block_header, hash_tree_root_body, hash_tree_root_state,
    },
    tile::BeaconStateTile,
};
use silver_beacon_state_data::{BeaconBlockHeader, BeaconState, SpecConfig, StateWriterView};
use silver_common::{
    BeaconStateEvent, DataColumnsAvailable, GossipTopic, MessageId, NewGossipMsg, P2pStreamId,
    PeerEvent, RpcInbound, RpcResponseInbound, SilverSpine, StreamProtocol, SyncUpdate, TCache,
    TCacheProducer, TProducer, TRandomAccess, hex32,
    ssz_view::{STATUS_V2_SIZE, SignedBeaconBlockView},
    ticker::SlotTicker,
};
use silver_config::SyncingConfig;

fn null_stream_id() -> P2pStreamId {
    P2pStreamId::new(0, 0, StreamProtocol::Unset, false)
}

#[derive(Debug, Deserialize)]
pub struct Setup {
    /// Startup checkpoint state path (required; use `null` for no
    /// checkpoint — scenario 2 shape).
    /// - relative: resolved against `consensus-spec-tests/`
    /// - absolute (leading `/`): taken as-is
    pub startup_checkpoint: Option<String>,
    /// Slots the wall clock sits ahead of the checkpoint state. When no
    /// checkpoint is present, this is absolute (checkpoint slot is taken
    /// as 0). The harness forces `wall_slot >= checkpoint_slot + 3` so
    /// bootstrap picks Syncing rather than Following.
    pub slots_missing: u64,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Advance the tile one `loop_body` call, then drain outbound.
    Step,
    /// Inject an inbound gossip block.
    GossipBlock { from: String },
    /// Inject an RPC BlocksByRange response chunk.
    BlocksRangeResp { from: String },
    /// Inject a `DataColumnsAvailable` for the block at `from`.
    DataColumnsAvailable { from: String },
    /// Inject an inbound Status from a peer.
    Status { head_slot: u64, finalized_epoch: u64, finalized_root: String },
    /// Inject a `SyncUpdate` from peer-manager. `target` is one of:
    /// `syncing_finalized`, `syncing_head`, `following`. Syncing variants
    /// take `target_slot` (mapped to the appropriate enum payload).
    SyncTarget { target: String, target_slot: Option<u64> },
    /// Assertions against observable state and accumulated outbound.
    Check(Checks),
    /// Assert the tile's current head state has `hash_tree_root` equal to the
    /// EF post-state at `from`. Path resolves like `GossipBlock { from }`:
    /// relative is rooted at `consensus-spec-tests/`.
    StateRootMatches { from: String },
}

#[derive(Debug, Default, Deserialize)]
pub struct Checks {
    #[serde(default)]
    pub outbound_has: Vec<String>,
    #[serde(default)]
    pub outbound_lacks: Vec<String>,
}

struct Injector;

impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

pub struct Harness {
    _spine: Box<SilverSpine>,
    tile: BeaconStateTile,
    tile_adapter: SpineAdapter<SilverSpine>,
    inj_adapter: SpineAdapter<SilverSpine>,
    gossip_in_producer: TProducer,
    rpc_in_producer: TProducer,
    // Kept alive to back the tile's replay consumer; unused by these tests.
    _replay_in_producer: TProducer,
    outbound_log: Vec<OutboundKind>,
    _base_dir: PathBuf, // owned to keep temp files around for the run
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Status,
    PersistBlock,
    BlockRejected,
    SendGossip,
    ReplayComplete,
    BacktrackStall,
}

impl OutboundKind {
    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "status" => Self::Status,
            "persist_block" => Self::PersistBlock,
            "block_rejected" => Self::BlockRejected,
            "send_gossip" => Self::SendGossip,
            "replay_complete" => Self::ReplayComplete,
            "backtrack_stall" => Self::BacktrackStall,
            _ => return None,
        })
    }

    fn classify(ev: &BeaconStateEvent) -> Self {
        match ev {
            BeaconStateEvent::Status { .. } => Self::Status,
            BeaconStateEvent::PersistBlock { .. } => Self::PersistBlock,
            BeaconStateEvent::BlockRejected { .. } => Self::BlockRejected,
            BeaconStateEvent::ReplayComplete => Self::ReplayComplete,
            BeaconStateEvent::BacktrackStall => Self::BacktrackStall,
        }
    }
}

impl Harness {
    pub fn new(wall_slot: u64, checkpoint_ssz: &[u8]) -> Self {
        Self::build(wall_slot, |ticker, gc, rc, ec, repc| {
            let state = BeaconState::from_checkpoint(checkpoint_ssz, &SpecConfig::mainnet(), &[])
                .unwrap_or_else(|e| panic!("decompose checkpoint: {e}"));
            BeaconStateTile::new(
                ticker,
                SpecConfig::mainnet(),
                &SyncingConfig::default(),
                gc,
                rc,
                ec,
                repc,
                true,
                state,
            )
        })
    }

    fn build<F>(wall_slot: u64, build_tile: F) -> Self
    where
        F: FnOnce(
            SlotTicker,
            TRandomAccess,
            TRandomAccess,
            TRandomAccess,
            TRandomAccess,
        ) -> BeaconStateTile,
    {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "silver-ef-{}-{}-{}",
            process::id(),
            seq,
            rand::random::<u64>()
        ));
        fs::create_dir_all(&base).expect("create temp base");

        let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));

        // Ticker: genesis positioned so `current_slot()` == wall_slot at
        // construction.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(wall_slot * 12);
        let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));

        let gossip_in_producer = TCache::producer("gossip_in", 1 << 24);
        let rpc_in_producer = TCache::producer("rpc_in", 1 << 24);
        let engine_resp_producer = TCache::producer("engine_resp", 1 << 24);
        let replay_in_producer = TCache::producer("replay_in", 1 << 24);
        let gossip_consumer =
            gossip_in_producer.cache_ref().random_access("test", true).expect("gossip ra");
        let rpc_consumer = rpc_in_producer.cache_ref().random_access("test", true).expect("rpc ra");
        let engine_resp_consumer =
            engine_resp_producer.cache_ref().random_access("test", true).expect("engine resp ra");
        let replay_consumer =
            replay_in_producer.cache_ref().random_access("test", true).expect("replay ra");

        let tile = build_tile(
            ticker,
            gossip_consumer,
            rpc_consumer,
            engine_resp_consumer,
            replay_consumer,
        );

        // Order matters: attach tile first so its tile_id stays 0 for the
        // real consumer of `inbound`; Injector gets tile_id 1.
        let tile_adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        let inj = Injector;
        let mut inj_adapter = SpineAdapter::connect_tile(&inj, &mut spine);

        // flux consumers initialize their cursor to the queue's current head
        // on first consume. Call consume once now, while queues are empty, so
        // the injector's cursors don't skip past messages produced by the
        // tile between now and the first `drain_outbound` call.
        inj_adapter.consume(|_: BeaconStateEvent, _| {});
        inj_adapter.consume(|_: PeerEvent, _| {});

        Self {
            _spine: spine,
            tile,
            tile_adapter,
            inj_adapter,
            gossip_in_producer,
            rpc_in_producer,
            _replay_in_producer: replay_in_producer,
            outbound_log: Vec::new(),
            _base_dir: base,
        }
    }

    pub fn step(&mut self) {
        self.tile.loop_body(&mut self.tile_adapter);
        self.drain_outbound();
    }

    fn drain_outbound(&mut self) {
        let log = &mut self.outbound_log;
        self.inj_adapter.consume(|ev: BeaconStateEvent, _| {
            log.push(OutboundKind::classify(&ev));
        });
        self.inj_adapter.consume(|ev: PeerEvent, _| {
            if let PeerEvent::SendGossip { .. } = ev {
                log.push(OutboundKind::SendGossip);
            }
        });
    }

    fn inj_reserve(
        producer: &mut TProducer,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> silver_common::TCacheRead {
        let mut r = producer.reserve(len, true).expect("tcache reserve");
        if let Ok(buf) = r.buffer() {
            fill(buf);
        }
        r.increment_offset(len);
        let read = r.read();
        producer.publish_head();
        read
    }

    pub fn inject_gossip_block(&mut self, ssz: &[u8]) {
        let len = ssz.len();
        let tcache = Self::inj_reserve(&mut self.gossip_in_producer, len, |buf| {
            buf[..len].copy_from_slice(ssz)
        });
        self.inj_adapter.produce(NewGossipMsg {
            stream_id: null_stream_id(),
            topic: GossipTopic::BeaconBlock,
            msg_hash: MessageId { id: [0u8; 20] },
            recv_ts: Nanos(0),
            ssz: tcache,
            protobuf: tcache,
        });
    }

    pub fn inject_blocks_range_resp(&mut self, ssz: &[u8]) {
        let len = ssz.len();
        let tcache = Self::inj_reserve(&mut self.rpc_in_producer, len, |buf| {
            buf[..len].copy_from_slice(ssz)
        });
        self.inj_adapter.produce(RpcInbound::Response(RpcResponseInbound {
            application_id: 0,
            stream_id: null_stream_id(),
            response: silver_common::RpcResponse::BeaconBlock {
                fork_digest: [0, 0, 0, 0],
                ssz: tcache,
            },
        }));
    }

    pub fn inject_sync_target(&mut self, target: SyncUpdate) {
        self.inj_adapter.produce(target);
    }

    pub fn inject_data_columns_available(&mut self, block: &[u8]) {
        let block_root = hash_tree_root_block_header(&BeaconBlockHeader {
            slot: SignedBeaconBlockView::slot(block),
            proposer_index: SignedBeaconBlockView::proposer_index(block),
            parent_root: *SignedBeaconBlockView::parent_root(block),
            state_root: *SignedBeaconBlockView::state_root(block),
            body_root: hash_tree_root_body(SignedBeaconBlockView::body(block)),
        });
        self.inj_adapter
            .produce(DataColumnsAvailable { block_root, slot: SignedBeaconBlockView::slot(block) });
    }

    pub fn inject_status(
        &mut self,
        head_slot: u64,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
    ) {
        let mut buf = [0u8; STATUS_V2_SIZE];
        buf[0..4].fill(0);
        buf[4..36].copy_from_slice(&finalized_root);
        buf[36..44].copy_from_slice(&finalized_epoch.to_le_bytes());
        buf[44..76].fill(0);
        buf[76..84].copy_from_slice(&head_slot.to_le_bytes());
        buf[84..92].copy_from_slice(&(finalized_epoch * 32).to_le_bytes());

        self.inj_adapter.produce(RpcInbound::Response(RpcResponseInbound {
            application_id: 0,
            stream_id: null_stream_id(),
            response: silver_common::RpcResponse::StatusV2(buf),
        }));
    }

    pub fn assert_state_root(&mut self, post_ssz: &[u8]) {
        // Decompose the EF post-state into per-tier finalized bases with an
        // empty anchored delta, then hash via `StateWriterView` (mirrors
        // ef_common).
        let mut bs = BeaconState::decompose(post_ssz, &SpecConfig::mainnet(), None)
            .expect("decompose post.ssz");

        // Hold a fresh fork's writers directly (`roll_fresh` anchors each at
        // the decoded base); epoch/longtail stay lazy (`None` reads the base).
        let view = StateWriterView {
            imm: &bs.immutable,
            balances: bs.balances.roll_fresh(),
            eth1: bs.eth1.roll_fresh(),
            pending: bs.pending.roll_fresh(),
            previous_participation: bs.previous_participation.roll_fresh(),
            current_participation: bs.current_participation.roll_fresh(),
            inactivity: bs.inactivity.roll_fresh(),
            slot: bs.slot_states.roll_fresh(),
            validators: bs.validators.roll_fresh(),
        };

        let mut scratch = StateHashScratch::new();

        let expected = {
            let rv = view.read(bs.epoch.view_opt(None), bs.longtail.view_opt(None));
            hash_tree_root_state(&rv, &mut scratch)
        };
        let got = self.tile.head_state_root();
        assert_eq!(
            got,
            expected,
            "head state root mismatch: got {} expected {}",
            hex32(&got),
            hex32(&expected),
        );
    }

    pub fn assert_checks(&mut self, c: &Checks) {
        for want in &c.outbound_has {
            let want = OutboundKind::from_str(want)
                .unwrap_or_else(|| panic!("unknown outbound kind: {want}"));
            assert!(
                self.outbound_log.contains(&want),
                "expected outbound {want:?} in log {:?}",
                self.outbound_log,
            );
        }
        for want in &c.outbound_lacks {
            let want = OutboundKind::from_str(want)
                .unwrap_or_else(|| panic!("unknown outbound kind: {want}"));
            assert!(
                !self.outbound_log.contains(&want),
                "unexpected outbound {want:?} in log {:?}",
                self.outbound_log,
            );
        }
        self.outbound_log.clear();
    }
}

pub fn run_scenario(case_dir: &Path) {
    let transcript_yaml = fs::read_to_string(case_dir.join("steps.yaml")).expect("read steps.yaml");
    let t: Setup = serde_yml::from_str(&transcript_yaml).expect("parse steps.yaml");

    let spec_root = spec_tests_dir();
    let resolve = |p: &str| -> PathBuf {
        if p.starts_with('/') { PathBuf::from(p) } else { spec_root.join(p) }
    };

    // Skip when the referenced EF vectors aren't fetched (CI or fresh
    // checkout without `make` in the crate dir).
    for p in t.startup_checkpoint.iter().chain(t.steps.iter().filter_map(|s| match s {
        Step::GossipBlock { from } |
        Step::BlocksRangeResp { from } |
        Step::DataColumnsAvailable { from } |
        Step::StateRootMatches { from } => Some(from),
        _ => None,
    })) {
        if !resolve(p).exists() {
            eprintln!("{}: missing EF vector {p}, skipping", case_dir.display());
            return;
        }
    }

    let checkpoint_ssz = match &t.startup_checkpoint {
        Some(p) => snappy_decode(&resolve(p)),
        None => Vec::new(),
    };

    // BeaconState SSZ layout: genesis_time (8B), genesis_validators_root (32B),
    // slot (8B). Pull slot out directly; don't decompose the whole state.
    let checkpoint_slot = if checkpoint_ssz.len() >= 48 {
        u64::from_le_bytes(checkpoint_ssz[40..48].try_into().unwrap())
    } else {
        0
    };
    // Force Syncing: bootstrap compares `wall_slot > slot + 2`.
    let wall_slot = checkpoint_slot + t.slots_missing.max(3);

    let mut h = Harness::new(wall_slot, &checkpoint_ssz);
    // First `step` to let the tile do its post-bootstrap work (emit sync req
    // if needed) before the scenario's explicit steps run.
    h.step();

    for step in &t.steps {
        match step {
            Step::Step => h.step(),
            Step::GossipBlock { from } => {
                let ssz = snappy_decode(&resolve(from));
                h.inject_gossip_block(&ssz);
            }
            Step::BlocksRangeResp { from } => {
                let ssz = snappy_decode(&resolve(from));
                h.inject_blocks_range_resp(&ssz);
            }
            Step::DataColumnsAvailable { from } => {
                let ssz = snappy_decode(&resolve(from));
                h.inject_data_columns_available(&ssz);
            }
            Step::Status { head_slot, finalized_epoch, finalized_root } => {
                h.inject_status(*head_slot, *finalized_epoch, parse_b256(finalized_root));
            }
            Step::SyncTarget { target, target_slot } => {
                let upd = match target.as_str() {
                    "syncing_finalized" => SyncUpdate::SyncingFinalized {
                        target_epoch: target_slot.expect("target_slot required") / 32,
                        target_root: [0u8; 32],
                    },
                    "syncing_head" => SyncUpdate::SyncingHead {
                        head_slot: target_slot.expect("target_slot required"),
                        head_root: [0u8; 32],
                    },
                    "following" => SyncUpdate::Following,
                    other => panic!("unknown sync target: {other}"),
                };
                h.inject_sync_target(upd);
            }
            Step::Check(c) => {
                h.assert_checks(c);
            }
            Step::StateRootMatches { from } => {
                let ssz = snappy_decode(&resolve(from));
                h.assert_state_root(&ssz);
            }
        }
    }
}

fn parse_b256(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate().take(32) {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

pub fn snappy_decode(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("{}: snappy: {e}", path.display()))
}

pub fn spec_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("consensus-spec-tests")
}
