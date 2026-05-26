//! End-to-end: same wiring as `sync_pm_bs`, but a single big batch.
//! PM issues one `BlocksByRange { count = N }` request covering every
//! `next_block_*.ssz` fixture and BS applies them all in a single
//! `loop_body` pass. Stresses sustained STF + parser flow against a
//! ~100-block stretch of canonical mainnet, the regime where slot-N
//! body-offset corruption / proposer-cache bugs surface.
//!
//! Skipped unless at least `MIN_BLOCKS` (= 64) post-anchor blocks are
//! on disk — run `make -C crates/e2e checkpoint-fixtures-large` first.

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
/// Below this fixture count the test is uninteresting (covered by
/// `sync_pm_bs`'s 4-block setup). 64 blocks already spans 2 epochs and
/// catches body-parse / proposer-cache edge cases.
const MIN_BLOCKS: usize = 64;
const PEER: usize = 1;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

fn block_slot(ssz: &[u8]) -> u64 {
    SignedBeaconBlockView::slot(ssz)
}

/// Same scanner as `sync_pm_bs::load_fixtures`, but returns whatever's
/// on disk rather than requiring an exact count. `None` when there's no
/// anchor state or too few blocks to be worth running.
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
    (blocks.len() >= MIN_BLOCKS).then(|| (cp, blocks.into_iter().map(|(_, b)| b).collect()))
}

fn peer_status(local: &[u8; STATUS_V2_SIZE], head_slot: u64) -> [u8; STATUS_V2_SIZE] {
    let mut s = [0u8; STATUS_V2_SIZE];
    s[0..4].copy_from_slice(StatusView::fork_digest(local));
    s[4..36].copy_from_slice(StatusView::finalized_root(local));
    s[36..44].copy_from_slice(&StatusView::finalized_epoch(local).to_le_bytes());
    s[44..76].copy_from_slice(&[0xee; 32]);
    s[76..84].copy_from_slice(&head_slot.to_le_bytes());
    s[84..92].copy_from_slice(&(StatusView::finalized_epoch(local) * 32).to_le_bytes());
    s
}

fn synth_peer_id() -> silver_common::PeerId {
    let mut secret = [0u8; 32];
    secret[0] = 0x42;
    secret[31] = 1;
    Keypair::from_secret(&secret).expect("valid synthetic secret").peer_id()
}

fn tcache_write(producer: &mut TProducer, bytes: &[u8]) -> silver_common::TCacheRead {
    let mut r = producer.reserve(bytes.len(), true).expect("tcache reserve");
    r.buffer().expect("tcache buffer").copy_from_slice(bytes);
    r.increment_offset(bytes.len());
    let read = r.read();
    producer.publish_head();
    read
}

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
#[ignore = "ignored by default — run explicitly with `cargo test ... -- --ignored`"]
fn pm_drives_single_big_batch_against_real_checkpoint() {
    // Install a tracing subscriber driven by `RUST_LOG` so the test
    // can print BS/PM intermediate logs when run with `--nocapture`.
    // `try_init` makes this idempotent if some other test in the same
    // process already set one up.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let Some((checkpoint, blocks)) = load_fixtures() else {
        eprintln!(
            "skipping: need >= {MIN_BLOCKS} blocks — run \
             `make -C crates/e2e checkpoint-fixtures-large` first"
        );
        return;
    };
    let n_blocks: u64 = blocks.len() as u64;
    let final_slot = block_slot(blocks.last().unwrap());
    let Some(expected_root) = fetch_canonical_state_root(final_slot) else {
        eprintln!("skipping: canonical state_root for slot {final_slot} unavailable");
        return;
    };

    // ── Wiring ─────────────────────────────────────────────────────────
    let base = TempDir::new().expect("tempdir");
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));

    let genesis_time = u64::from_le_bytes(checkpoint[0..8].try_into().unwrap());
    let ticker = SlotTicker::new(genesis_time, Duration::from_secs(12), Duration::from_secs(4));

    let gossip_p = TCache::producer("gossip_in", 1 << 20);
    // ~250KB per mainnet block × N blocks, plus headroom for any
    // tcache-internal accounting.
    let rpc_cap_bytes = ((n_blocks as usize) * 300 * 1024).next_power_of_two();
    let mut rpc_p = TCache::producer("rpc_in", rpc_cap_bytes);
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

    // One batch covers everything.
    let pm = PeerManager::new(
        Vec::new(),
        ScoreParams::default(),
        SyncingConfig {
            max_blocks_by_range_batch: n_blocks,
            head_lag_threshold_slots: 1,
            ..SyncingConfig::default()
        },
        [0u8; 4],
        [0u8; METADATA_SIZE],
    );
    let rpc_out_p = TCache::producer("rpc_out_dummy", 32); // dummy rpc out for Controller
    let mut ctl = Controller::new(pm, rpc_out_p);
    let mut ctl_a = SpineAdapter::connect_tile(&ctl, &mut spine);

    let mut inj_a = SpineAdapter::connect_tile(&Injector, &mut spine);
    inj_a.consume(|_: P2pSend, _| {});
    inj_a.consume(|_: silver_common::PeerControl, _| {});
    inj_a.consume(|_: BeaconStateEvent, _| {});

    ctl.loop_body(&mut ctl_a);
    bs.loop_body(&mut bs_a);
    ctl.loop_body(&mut ctl_a);

    let mut local_status: Option<[u8; STATUS_V2_SIZE]> = None;
    inj_a.consume::<BeaconStateEvent, _>(|ev, _| {
        if let BeaconStateEvent::Status { ssz, .. } = ev {
            local_status = Some(ssz);
        }
    });
    let local = local_status.expect("BS emitted initial Status");
    let fork_digest = *StatusView::fork_digest(&local);
    let first_block_slot = block_slot(&blocks[0]);
    assert_eq!(StatusView::head_slot(&local) + 1, first_block_slot);

    // ── Peer connect + Status ──────────────────────────────────────────
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

    // ── Single batch ──────────────────────────────────────────────────
    let (start, count, peer) = next_range_request(&mut inj_a);
    assert_eq!((start, count, peer), (first_block_slot, n_blocks, PEER));

    for b in &blocks {
        inject_block_response(&mut inj_a, &mut rpc_p, start, fork_digest, b);
    }
    // BS drains the rpc_inbound queue and applies every block in one
    // consume pass. No second loop_body — stop before Controller can
    // emit `SyncUpdate::Following` and let `ticker.tick()` mutate state
    // past the canonical final slot.
    bs.loop_body(&mut bs_a);

    assert!(
        bs.head_state_slot() >= final_slot,
        "BS head should reach final block slot {final_slot}; got {}",
        bs.head_state_slot(),
    );
    assert_eq!(
        bs.head_state_root(),
        expected_root,
        "post-catchup head_state_root must match canonical mainnet"
    );
}
