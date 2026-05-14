//! Loads a real mainnet finalized state SSZ from disk and bootstraps a
//! `BeaconStateTile` from it. The blob is large (~330 MB) and gitignored —
//! fetch it locally with:
//!
//! ```sh
//! curl -s -H 'Accept: application/octet-stream' \
//!   https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states/finalized \
//!   -o crates/beacon_state/tests/example_checkpoints/finalized_state.ssz
//! ```

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use silver_beacon_state::{
    decompose::decompose_beacon_state,
    ssz_hash::{compute_zero_hashes, hash_tree_root_block_header},
    ticker::SlotTicker,
    tile::BeaconStateTile,
    types::{
        EpochData, HistoricalLongtail, Immutable, SlotData, SlotRoots, ValidatorIdentity,
        box_zeroed,
    },
};
use silver_common::{TCache, TCacheProducer};

#[test]
fn finalized_state_loads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/example_checkpoints/finalized_state.ssz");
    let Ok(ssz) = std::fs::read(&path) else {
        eprintln!("skipping: {} not present (see module docs for fetch cmd)", path.display());
        return;
    };

    // Minimal harness: SlotTicker + two TCache adapters. Genesis is positioned
    // so the ticker is in the rough vicinity of the checkpoint slot; the
    // exact value doesn't matter for the bootstrap-time assertions below.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let ticker = SlotTicker::new(now - 12, Duration::from_secs(12), Duration::from_secs(4));
    let gossip_p = TCache::producer(1 << 20);
    let rpc_p = TCache::producer(1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access().unwrap();
    let rpc_c = rpc_p.cache_ref().random_access().unwrap();

    let tile = BeaconStateTile::new_heap(ticker, gossip_c, rpc_c, &ssz);

    let head = tile.head_block_root();
    assert_ne!(head, [0u8; 32], "head_block_root is zero after bootstrap");
    // Fork choice's lone node *is* the anchor — find_head must agree.
    assert_eq!(tile.fork_choice_head(), head, "find_head should return head_block_root");

    // Offline regression assertion: catch a bootstrap that forgets to patch
    // `latest_block_header.state_root` from the post-state. We re-decompose
    // into our own buffers and verify that hashing the *raw* (unpatched)
    // latest_block_header yields a different value than the tile reports.
    // If bootstrap regresses, the two would match.
    let zh = compute_zero_hashes();
    let mut imm: Box<Immutable> = box_zeroed();
    let mut vid: Box<ValidatorIdentity> = box_zeroed();
    let mut longtail: Box<HistoricalLongtail> = box_zeroed();
    let mut epoch: Box<EpochData> = box_zeroed();
    let mut roots: Box<SlotRoots> = box_zeroed();
    let mut sd: Box<SlotData> = box_zeroed();
    decompose_beacon_state(
        &ssz,
        &zh,
        &mut imm,
        &mut vid,
        &mut longtail,
        &mut epoch,
        &mut roots,
        &mut sd,
    )
    .expect("re-decompose");
    if sd.latest_block_header.state_root == [0u8; 32] {
        let raw_root = hash_tree_root_block_header(&sd.latest_block_header, &zh);
        assert_ne!(
            head, raw_root,
            "bootstrap returned the raw-header hash; it should patch state_root first",
        );
    }

    // Cross-check against the canonical block_root from chainsafe's API for
    // the snapshot's slot. Skips with a notice if curl is missing or the
    // network is unreachable — keeps the test local-friendly.
    let slot = tile.head_state_slot();
    match fetch_canonical_block_root(slot) {
        Some(expected) => assert_eq!(
            head,
            expected,
            "bootstrap block_root mismatch for slot {slot}: tile 0x{} vs canonical 0x{}",
            hex(&head),
            hex(&expected),
        ),
        None => eprintln!("skipping canonical block_root cross-check (network unavailable)"),
    }
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Hit `/eth/v1/beacon/blocks/{slot}/root` on chainsafe's mainnet endpoint.
/// Response shape: `{"data":{"root":"0x..."},...}` (with or without the `0x`
/// prefix). Returns `None` if curl fails (offline / not installed) so the
/// test stays usable locally.
fn fetch_canonical_block_root(slot: u64) -> Option<[u8; 32]> {
    let url = format!("https://beaconstate-mainnet.chainsafe.io/eth/v1/beacon/blocks/{slot}/root");
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "10", "-H", "Accept: application/json", &url])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = std::str::from_utf8(&out.stdout).ok()?;
    let needle = "\"root\":\"";
    let mut start = body.find(needle)? + needle.len();
    if body.get(start..start + 2) == Some("0x") {
        start += 2;
    }
    let hex = body.get(start..start + 64)?;
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(root)
}
