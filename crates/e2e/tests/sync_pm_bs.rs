//! End-to-end: peer-manager + beacon-state on one spine. PM issues two
//! `BlocksByRange` batches of 2 against a synthetic peer; BS applies the
//! 4 mainnet blocks pulled by `make checkpoint-fixtures`. Final head
//! state_root is cross-checked against the canonical mainnet value.

use std::{path::PathBuf, time::Duration};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_state::{ticker::SlotTicker, tile::BeaconStateTile};
use silver_common::{
    BeaconStateEvent, IpBytes, Keypair, P2pSend, P2pStreamId, PeerEvent, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestOutbound, RpcResponse, RpcResponseInbound, ScoreParams, SilverSpine,
    StreamProtocol, SyncingConfig, TCache, TCacheProducer, TProducer,
    ssz_view::{
        BeaconBlocksByRangeRequestView, METADATA_SIZE, STATUS_V2_SIZE, SignedBeaconBlockView,
        StatusView,
    },
};
use silver_control::Controller;
use silver_e2e::canonical::fetch_canonical_state_root;
use silver_peer::PeerManager;
use tempfile::TempDir;

const FIXTURES: &str = "tests/example_checkpoints";
const EXPECTED_BLOCKS: usize = 4;
const BATCH: u64 = 2;
const PEER: usize = 1;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

fn block_slot(ssz: &[u8]) -> u64 {
    SignedBeaconBlockView::slot(ssz)
}

/// Scan `<crate>/tests/example_checkpoints/` for `next_block_<slot>.ssz`
/// fixtures + the anchor state. Returns `None` if we don't have exactly
/// `EXPECTED_BLOCKS` blocks — concrete slot numbers rotate with each
/// Makefile pull, only count + ordering are stable.
fn load_fixtures() -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
    let cp = std::fs::read(dir.join("finalized_state.ssz")).ok()?;
    let mut blocks: Vec<(u64, Vec<u8>)> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let slot = name.strip_prefix("next_block_")?.strip_suffix(".ssz")?.parse().ok()?;
            Some((slot, std::fs::read(e.path()).ok()?))
        })
        .collect();
    blocks.sort_by_key(|(s, _)| *s);
    (blocks.len() == EXPECTED_BLOCKS).then(|| (cp, blocks.into_iter().map(|(_, b)| b).collect()))
}

/// Synthetic mainnet peer Status: same fork_digest + finalized as ours,
/// head pinned at `head_slot` with an arbitrary non-rejected root.
fn peer_status(local: &[u8; STATUS_V2_SIZE], head_slot: u64) -> [u8; STATUS_V2_SIZE] {
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
fn synth_peer_id() -> silver_common::PeerId {
    let mut secret = [0u8; 32];
    secret[0] = 0x42;
    secret[31] = 1;
    Keypair::from_secret(&secret).expect("valid synthetic secret").peer_id()
}

/// Reserve, fill, publish — returns the resulting `TCacheRead`.
fn tcache_write(producer: &mut TProducer, bytes: &[u8]) -> silver_common::TCacheRead {
    let mut r = producer.reserve(bytes.len(), true).expect("tcache reserve");
    r.buffer().expect("tcache buffer").copy_from_slice(bytes);
    r.increment_offset(bytes.len());
    let read = r.read();
    producer.publish_head();
    read
}

/// Drain `p2p_send` for the next BlocksByRange request and return its
/// `(start_slot, count, peer)`. Panics if no such request was emitted.
fn next_range_request(inj: &mut SpineAdapter<SilverSpine>) -> (u64, u64, usize) {
    let mut hit = None;
    inj.consume::<P2pSend, _>(|ev, _| {
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

fn inject_block_response(
    inj: &mut SpineAdapter<SilverSpine>,
    rpc_in: &mut TProducer,
    application_id: u64,
    fork_digest: [u8; 4],
    block: &[u8],
) {
    let ssz = tcache_write(rpc_in, block);
    inj.produce(RpcInbound::Response(RpcResponseInbound {
        application_id,
        stream_id: P2pStreamId::new(PEER, 0, StreamProtocol::BeaconBlocksByRange, true),
        response: RpcResponse::BeaconBlock { fork_digest, ssz },
    }));
}

#[test]
#[ignore]
fn pm_drives_two_batches_against_real_checkpoint() {
    // Skip cleanly when fixtures are missing or the API is unreachable —
    // either makes the test meaningless rather than failing.
    let Some((checkpoint, blocks)) = load_fixtures() else {
        eprintln!("skipping: run `make -C crates/e2e checkpoint-fixtures` first");
        return;
    };
    let final_slot = block_slot(&blocks[3]);
    let Some(expected_root) = fetch_canonical_state_root(final_slot) else {
        eprintln!("skipping: canonical state_root for slot {final_slot} unavailable");
        return;
    };

    // ── Wiring ─────────────────────────────────────────────────────────
    let base = TempDir::new().expect("tempdir");
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));

    // Ticker: position genesis so `current_slot() ≈ checkpoint_slot`,
    // otherwise `precheck_block` rejects the next blocks as future-slot.
    let genesis_time = u64::from_le_bytes(checkpoint[0..8].try_into().unwrap());
    let ticker = SlotTicker::new(genesis_time, Duration::from_secs(12), Duration::from_secs(4));

    let gossip_p = TCache::producer("gossip_in", 1 << 20);
    let mut rpc_p = TCache::producer("rpc_in", 1 << 22); // largest mainnet block ~250KB × 4
    let gossip_c = gossip_p.cache_ref().random_access("test", true).expect("gossip ra");
    let rpc_c = rpc_p.cache_ref().random_access("test", true).expect("rpc ra");

    let mut bs = BeaconStateTile::new_heap(
        ticker,
        silver_common::SpecConfig::mainnet(),
        gossip_c,
        rpc_c,
        &checkpoint,
    );
    let mut bs_a = SpineAdapter::connect_tile(&bs, &mut spine);

    // PM forces 2 blocks per request; threshold=1 so a 4-slot-ahead peer
    // qualifies for SyncingHead (default head_lag_threshold is 32).
    let pm = PeerManager::new(
        Vec::new(),
        ScoreParams::default(),
        SyncingConfig {
            max_blocks_by_range_batch: BATCH,
            head_lag_threshold_slots: 1,
            ..SyncingConfig::default()
        },
        [0u8; 4], // overwritten via set_status from BS's first emission
        [0u8; METADATA_SIZE],
    );
    let rpc_out_p = TCache::producer("rpc_out_dummy", 32); // dummy rpc out for Controller
    let mut ctl = Controller::new(pm, rpc_out_p);
    let mut ctl_a = SpineAdapter::connect_tile(&ctl, &mut spine);

    let mut inj_a = SpineAdapter::connect_tile(&Injector, &mut spine);
    // Snap every cursor we'll consume on to head=0 before anyone produces.
    inj_a.consume(|_: P2pSend, _| {});
    inj_a.consume(|_: silver_common::PeerControl, _| {});
    inj_a.consume(|_: BeaconStateEvent, _| {});

    // Controller before BS so Controller's cursors also snap to head=0
    // before BS produces its initial Status.
    ctl.loop_body(&mut ctl_a);
    bs.loop_body(&mut bs_a);
    ctl.loop_body(&mut ctl_a);

    // Capture BS's initial Status — gives us fork_digest + the local
    // chain position we'll mirror into the peer's Status payload.
    let mut local_status: Option<[u8; STATUS_V2_SIZE]> = None;
    inj_a.consume::<BeaconStateEvent, _>(|ev, _| {
        if let BeaconStateEvent::Status { ssz, .. } = ev {
            local_status = Some(ssz);
        }
    });
    let local = local_status.expect("BS emitted initial Status");
    let fork_digest = *StatusView::fork_digest(&local);
    let first_batch_start = StatusView::head_slot(&local) + 1;
    assert_eq!(first_batch_start, block_slot(&blocks[0]));

    // ── Peer connects + advertises a 4-slot-ahead head ─────────────────
    inj_a.produce(PeerEvent::P2pNewConnection {
        p2p_peer_id: PEER,
        peer_id_full: synth_peer_id(),
        ip: IpBytes::V4([127, 0, 0, 1]),
        port: 9000,
        local_dial: false,
    });
    inj_a.produce(RpcInbound::Response(RpcResponseInbound {
        application_id: 0,
        stream_id: P2pStreamId::new(PEER, 0, StreamProtocol::StatusV2, true),
        response: RpcResponse::StatusV2(peer_status(&local, final_slot)),
    }));
    bs.loop_body(&mut bs_a);
    ctl.loop_body(&mut ctl_a);

    // ── Batch 1: assert request, feed blocks, BS applies ───────────────
    let (start, count, peer) = next_range_request(&mut inj_a);
    assert_eq!((start, count, peer), (first_batch_start, BATCH, PEER));
    for b in &blocks[0..2] {
        inject_block_response(&mut inj_a, &mut rpc_p, start, fork_digest, b);
    }
    // BS consumes + applies both in one pass; Controller then sees the
    // post-apply Status and queues the next batch.
    bs.loop_body(&mut bs_a);
    ctl.loop_body(&mut ctl_a);
    assert!(bs.head_state_slot() >= block_slot(&blocks[1]));

    // ── Batch 2: same pattern ──────────────────────────────────────────
    let (start, count, peer) = next_range_request(&mut inj_a);
    assert_eq!((start, count, peer), (block_slot(&blocks[1]) + 1, BATCH, PEER));
    for b in &blocks[2..4] {
        inject_block_response(&mut inj_a, &mut rpc_p, start, fork_digest, b);
    }
    // Stop here. Running Controller again would emit `SyncUpdate::Following`
    // (peer's head reached), BS would flip to `Mode::Following`, and
    // `ticker.tick()` would process slots over real wall-clock time —
    // diverging head_state_root from the gold value below.
    bs.loop_body(&mut bs_a);

    assert!(bs.head_state_slot() >= final_slot);
    assert_eq!(bs.head_state_root(), expected_root);
}
