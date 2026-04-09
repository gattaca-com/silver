use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flux::{spine::SpineAdapter, tile::Tile, timing::Nanos};
use serde::Deserialize;
use silver_beacon_state::{ticker::SlotTicker, tile::BeaconStateTile};
use silver_common::{
    BeaconStateEvent, Gossip, GossipTopic, MessageId, NewGossipMsg, P2pStreamId, PeerRpcIn, RpcMsg,
    SilverSpine, StreamProtocol, TCache, TProducer, TRandomAccess,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BeaconBlocksByRangeRequestView, STATUS_V2_SIZE,
        SignedBeaconBlockView, StatusView,
    },
};

fn null_stream_id() -> P2pStreamId {
    P2pStreamId::new(0, 0, StreamProtocol::Unset)
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
    /// Inject an inbound Status from a peer.
    Status { head_slot: u64, finalized_epoch: u64, finalized_root: String },
    /// Assertions against observable state and accumulated outbound.
    Check(Checks),
}

#[derive(Debug, Default, Deserialize)]
pub struct Checks {
    /// `BeaconStateEvent` kinds that must have appeared since the previous
    /// check (order-insensitive). Accepted values: `synced`, `status`,
    /// `request_blocks_by_range`, `persist_block`.
    #[serde(default)]
    pub outbound_has: Vec<String>,
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
    outbound_log: Vec<OutboundKind>,
    /// Latest `request_id` observed on a
    /// `BeaconStateEvent::RequestBlocksByRange` event. Injected
    /// `BlocksRangeResp` chunks tag themselves with this so the tile's
    /// request-id correlation accepts them.
    last_request_id: u64,
    _base_dir: PathBuf, // owned to keep temp files around for the run
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Synced,
    Status,
    RequestBlocksByRange,
    PersistBlock,
}

impl OutboundKind {
    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "synced" => Self::Synced,
            "status" => Self::Status,
            "request_blocks_by_range" => Self::RequestBlocksByRange,
            "persist_block" => Self::PersistBlock,
            _ => return None,
        })
    }

    fn classify(ev: &BeaconStateEvent) -> Self {
        match ev {
            BeaconStateEvent::Synced(_) => Self::Synced,
            BeaconStateEvent::Status(_) => Self::Status,
            BeaconStateEvent::RequestBlocksByRange { .. } => Self::RequestBlocksByRange,
            BeaconStateEvent::PersistBlock(_) => Self::PersistBlock,
        }
    }
}

impl Harness {
    pub fn new(wall_slot: u64, checkpoint_ssz: &[u8]) -> Self {
        Self::build(wall_slot, |ticker, gc, rp, rc| {
            BeaconStateTile::new_heap(ticker, gc, rp, rc, checkpoint_ssz)
        })
    }

    fn build<F>(wall_slot: u64, build_tile: F) -> Self
    where
        F: FnOnce(SlotTicker, TRandomAccess, TProducer, TRandomAccess) -> BeaconStateTile,
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

        let gossip_in_producer = TCache::producer(1 << 24);
        let rpc_in_producer = TCache::producer(1 << 24);
        let gossip_consumer = gossip_in_producer.cache_ref().random_access().expect("gossip ra");
        let rpc_consumer = rpc_in_producer.cache_ref().random_access().expect("rpc ra");
        let rpc_out_producer = TCache::producer(1 << 24);

        let tile = build_tile(ticker, gossip_consumer, rpc_out_producer, rpc_consumer);

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

        Self {
            _spine: spine,
            tile,
            tile_adapter,
            inj_adapter,
            gossip_in_producer,
            rpc_in_producer,
            outbound_log: Vec::new(),
            last_request_id: 0,
            _base_dir: base,
        }
    }

    pub fn step(&mut self) {
        self.tile.loop_body(&mut self.tile_adapter);
        self.drain_outbound();
    }

    fn drain_outbound(&mut self) {
        let log = &mut self.outbound_log;
        let last_id = &mut self.last_request_id;
        self.inj_adapter.consume(|ev: BeaconStateEvent, _| {
            if let BeaconStateEvent::RequestBlocksByRange { request_id, .. } = &ev {
                *last_id = *request_id;
            }
            log.push(OutboundKind::classify(&ev));
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
        self.inj_adapter.produce(Gossip::NewInbound(NewGossipMsg {
            stream_id: null_stream_id(),
            topic: GossipTopic::BeaconBlock,
            msg_hash: MessageId { id: [0u8; 20] },
            recv_ts: Nanos(0),
            ssz: tcache,
            protobuf: tcache,
        }));
    }

    pub fn inject_blocks_range_resp(&mut self, ssz: &[u8]) {
        let len = ssz.len();
        let tcache = Self::inj_reserve(&mut self.rpc_in_producer, len, |buf| {
            buf[..len].copy_from_slice(ssz)
        });
        self.inj_adapter.produce(PeerRpcIn {
            msg: RpcMsg::BlocksRangeResp(SignedBeaconBlockView),
            sender: null_stream_id(),
            tcache,
            request_id: self.last_request_id,
        });
    }

    pub fn inject_status(
        &mut self,
        head_slot: u64,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
    ) {
        let tcache = Self::inj_reserve(&mut self.rpc_in_producer, STATUS_V2_SIZE, |buf| {
            // fork_digest zero (will mismatch real tile digest — tile
            // drops the body but still enqueues a pending status
            // response).
            buf[0..4].fill(0);
            buf[4..36].copy_from_slice(&finalized_root);
            buf[36..44].copy_from_slice(&finalized_epoch.to_le_bytes());
            buf[44..76].fill(0);
            buf[76..84].copy_from_slice(&head_slot.to_le_bytes());
            buf[84..92].copy_from_slice(&(finalized_epoch * 32).to_le_bytes());
        });
        self.inj_adapter.produce(PeerRpcIn {
            msg: RpcMsg::Status(StatusView),
            sender: null_stream_id(),
            tcache,
            request_id: 0,
        });
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
        self.outbound_log.clear();
    }
}

// Kept to silence "unused import" for symbols only referenced by type.
#[allow(dead_code)]
fn _force_use() {
    let _ = BLOCKS_BY_RANGE_REQ_SIZE;
    let _: u64 = BeaconBlocksByRangeRequestView::start_slot(&[0u8; BLOCKS_BY_RANGE_REQ_SIZE]);
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
        Step::GossipBlock { from } | Step::BlocksRangeResp { from } => Some(from),
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
            Step::Status { head_slot, finalized_epoch, finalized_root } => {
                h.inject_status(*head_slot, *finalized_epoch, parse_b256(finalized_root));
            }
            Step::Check(c) => {
                h.assert_checks(c);
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
