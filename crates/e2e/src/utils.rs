//! Shared PM + BS harness for the `sync_pm_bs*` integration tests.

use std::time::Duration;

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_state::{ticker::SlotTicker, tile::BeaconStateTile};
use silver_common::{
    BeaconState, BeaconStateEvent, BeaconStateOwner, IpBytes, Keypair, P2pSend, P2pStreamId,
    PeerControl, PeerEvent, PeerId, RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound,
    RpcResponse, RpcResponseInbound, ScoreParams, SilverSpine, SpecConfig, StreamProtocol,
    SyncingConfig, TCache, TCacheProducer, TCacheRead, TProducer,
    ssz_view::{
        BeaconBlocksByRangeRequestView, METADATA_SIZE, STATUS_V2_SIZE, SignedBeaconBlockView,
        StatusView,
    },
};
use silver_control::Controller;
use silver_peer::PeerManager;
use tempfile::TempDir;

use crate::perf::fixtures_dir::FixturesDir;

type StatusBytes = [u8; STATUS_V2_SIZE];
type SpineConn = SpineAdapter<SilverSpine>;

pub const SYNTH_PEER_CONN_ID: usize = 1;

pub fn block_slot(ssz: &[u8]) -> u64 {
    SignedBeaconBlockView::slot(ssz)
}

pub fn scan_checkpoint_fixtures(
    fixtures_subdir: &str,
    min_blocks: usize,
) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fixtures_subdir);
    let cp = std::fs::read(dir.join("finalized_state.ssz")).ok()?;
    let blocks: Vec<Vec<u8>> =
        FixturesDir(&dir).read_sorted_next_blocks().into_iter().map(|(_, b)| b).collect();
    (blocks.len() >= min_blocks).then_some((cp, blocks))
}

/// No-op tile so a test can own a `SpineAdapter` for injecting events.
pub struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineConn) {}
}

/// Synthetic mainnet peer Status: same fork_digest + finalized as ours,
/// head pinned at `head_slot` with an arbitrary non-rejected root.
fn peer_status(local: &StatusBytes, head_slot: u64) -> StatusBytes {
    let mut s = [0u8; STATUS_V2_SIZE];
    s[0..4].copy_from_slice(StatusView::fork_digest(local));
    s[4..36].copy_from_slice(StatusView::finalized_root(local));
    s[36..44].copy_from_slice(&StatusView::finalized_epoch(local).to_le_bytes());
    s[44..76].copy_from_slice(&[0xee; 32]); // arbitrary; only `head_slot` drives PM.
    s[76..84].copy_from_slice(&head_slot.to_le_bytes());
    s[84..92].copy_from_slice(&(StatusView::finalized_epoch(local) * 32).to_le_bytes());
    s
}

/// Deterministic but valid secp256k1 identity — PM derefs
/// `peer_id_full.pubkey()` and panics on an invalid curve point.
fn synth_peer_id() -> PeerId {
    let mut secret = [0u8; 32];
    secret[0] = 0x42;
    secret[31] = 1;
    Keypair::from_secret(&secret).expect("valid synthetic secret").peer_id()
}

fn tcache_write(producer: &mut TProducer, bytes: &[u8]) -> TCacheRead {
    let mut r = producer.reserve(bytes.len(), true).expect("tcache reserve");
    r.buffer().expect("tcache buffer").copy_from_slice(bytes);
    r.increment_offset(bytes.len());
    let read = r.read();
    producer.publish_head();
    read
}

/// A `PeerManager` + `BeaconStateTile` wired on one spine against the
/// synthetic peer [`SYNTH_PEER_CONN_ID`], bootstrapped from a checkpoint and
/// run through the initial Status handshake. Owns every piece the `sync_pm_bs*`
/// tests drive.
pub struct PmBsHarness {
    // Declaration order is drop order: the spine connections and the BS tile
    // must drop before the spine and the producers backing their caches.
    inj_a: SpineConn,
    ctl_a: SpineConn,
    ctl: Controller,
    bs_a: SpineConn,
    bs: BeaconStateTile,
    rpc_p: TProducer,
    _gossip_p: TProducer,
    _spine: Box<SilverSpine>,
    _base: TempDir,
    local: StatusBytes,
    fork_digest: [u8; 4],
}

impl PmBsHarness {
    /// `max_batch` caps each `BlocksByRange` request; the rpc-inbound cache
    /// is sized to hold `n_blocks` mainnet blocks (~300 KB each).
    pub fn new(checkpoint: &[u8], max_batch: u64, n_blocks: usize) -> Self {
        let base = TempDir::new().expect("tempdir");
        let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));

        // Position genesis so `current_slot() ≈ checkpoint slot`; otherwise
        // `precheck_block` rejects the following blocks as future-slot.
        let genesis_time = u64::from_le_bytes(checkpoint[0..8].try_into().unwrap());
        let ticker = SlotTicker::new(genesis_time, Duration::from_secs(12), Duration::from_secs(4));

        let gossip_p = TCache::producer("gossip_in", 1 << 20);
        let rpc_cap = (n_blocks * 300 * 1024).next_power_of_two().max(1 << 22);
        let rpc_p = TCache::producer("rpc_in", rpc_cap);
        let gossip_c = gossip_p.cache_ref().random_access("test", true).expect("gossip ra");
        let rpc_c = rpc_p.cache_ref().random_access("test", true).expect("rpc ra");

        let state = BeaconStateOwner::new(BeaconState::default());
        let mut bs =
            BeaconStateTile::new(ticker, SpecConfig::mainnet(), state, gossip_c, rpc_c, checkpoint);
        let mut bs_a = SpineAdapter::connect_tile(&bs, &mut *spine);

        let pm = PeerManager::new(
            Vec::new(),
            ScoreParams::default(),
            SyncingConfig {
                max_blocks_by_range_batch: max_batch,
                head_lag_threshold_slots: 1,
                ..SyncingConfig::default()
            },
            [0u8; 4], // overwritten via set_status from BS's first emission
            [0u8; METADATA_SIZE],
        );
        let mut ctl = Controller::new(pm, TCache::producer("rpc_out_dummy", 32));
        let mut ctl_a = SpineAdapter::connect_tile(&ctl, &mut spine);

        let mut inj_a = SpineAdapter::connect_tile(&Injector, &mut spine);
        // Snap every cursor we consume on to head=0 before anyone produces.
        inj_a.consume(|_: P2pSend, _| {});
        inj_a.consume(|_: PeerControl, _| {});
        inj_a.consume(|_: BeaconStateEvent, _| {});

        // Controller before BS so its cursors snap to head=0 before BS emits
        // its initial Status.
        ctl.loop_body(&mut ctl_a);
        bs.loop_body(&mut bs_a);
        ctl.loop_body(&mut ctl_a);

        let mut local_status: Option<StatusBytes> = None;
        inj_a.consume::<BeaconStateEvent, _>(|ev, _| {
            if let BeaconStateEvent::Status { ssz, .. } = ev {
                local_status = Some(ssz);
            }
        });
        let local = local_status.expect("BS emitted initial Status");
        let fork_digest = *StatusView::fork_digest(&local);

        Self {
            inj_a,
            ctl_a,
            ctl,
            bs_a,
            bs,
            rpc_p,
            _gossip_p: gossip_p,
            _spine: spine,
            _base: base,
            local,
            fork_digest,
        }
    }

    /// BS's initial Status SSZ — carries the fork digest and local head the
    /// peer's advertised Status should mirror.
    pub fn local_status(&self) -> &StatusBytes {
        &self.local
    }

    /// Connect the synthetic peer advertising a head at `peer_head_slot`,
    /// then let BS + Controller react.
    pub fn connect_peer(&mut self, peer_head_slot: u64) {
        self.inj_a.produce(PeerEvent::P2pNewConnection {
            p2p_peer_id: SYNTH_PEER_CONN_ID,
            peer_id_full: synth_peer_id(),
            ip: IpBytes::V4([127, 0, 0, 1]),
            port: 9000,
            local_dial: false,
        });
        let status = peer_status(&self.local, peer_head_slot);
        self.inj_a.produce(RpcInbound::Response(RpcResponseInbound {
            application_id: 0,
            stream_id: P2pStreamId::new(SYNTH_PEER_CONN_ID, 0, StreamProtocol::StatusV2, true),
            response: RpcResponse::StatusV2(status),
        }));
        self.pump_bs();
        self.pump_ctl();
    }

    /// Next `BlocksByRange` request on `p2p_send` as `(start_slot, count,
    /// peer)`; panics if none was emitted.
    pub fn next_range_request(&mut self) -> (u64, u64, usize) {
        let mut hit = None;
        self.inj_a.consume::<P2pSend, _>(|ev, _| {
            if hit.is_none() &&
                let P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                    peer,
                    request: RpcRequest::BlocksByRange(ssz),
                    ..
                })) = ev
            {
                hit = Some((
                    BeaconBlocksByRangeRequestView::start_slot(&ssz),
                    BeaconBlocksByRangeRequestView::count(&ssz),
                    peer,
                ));
            }
        });
        hit.expect("expected a BlocksByRange request on p2p_send")
    }

    /// Feed one block response from the peer, tagged for request `start_slot`.
    pub fn inject_block(&mut self, start_slot: u64, block: &[u8]) {
        let ssz = tcache_write(&mut self.rpc_p, block);
        self.inj_a.produce(RpcInbound::Response(RpcResponseInbound {
            application_id: start_slot,
            stream_id: P2pStreamId::new(
                SYNTH_PEER_CONN_ID,
                0,
                StreamProtocol::BeaconBlocksByRange,
                true,
            ),
            response: RpcResponse::BeaconBlock { fork_digest: self.fork_digest, ssz },
        }));
    }

    /// Assert the next `BlocksByRange` request matches `expected = (start,
    /// count)`, feed all `blocks`, and pump BS once.
    pub fn drive_batch(&mut self, expected: (u64, u64), blocks: &[Vec<u8>]) {
        let (start, count, peer) = self.next_range_request();
        assert_eq!((start, count, peer), (expected.0, expected.1, SYNTH_PEER_CONN_ID));
        for b in blocks {
            self.inject_block(start, b);
        }
        self.pump_bs();
    }

    pub fn pump_bs(&mut self) {
        self.bs.loop_body(&mut self.bs_a);
    }

    pub fn pump_ctl(&mut self) {
        self.ctl.loop_body(&mut self.ctl_a);
    }

    pub fn head_state_slot(&self) -> u64 {
        self.bs.head_state_slot()
    }

    pub fn head_state_root(&mut self) -> [u8; 32] {
        self.bs.head_state_root()
    }

    pub fn head_validator_count(&self) -> usize {
        self.bs.head_validator_count()
    }
}
