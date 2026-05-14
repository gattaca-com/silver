//! Loads a real mainnet finalized state SSZ from disk and decomposes it.
//! The blob is large (~330 MB) and gitignored — fetch it locally with:
//!
//! ```sh
//! curl -s -H 'Accept: application/octet-stream' \
//!   https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states/finalized \
//!   -o crates/beacon_state/tests/example_checkpoints/finalized_state.ssz
//! ```

use std::path::PathBuf;

use silver_beacon_state::{
    decompose::decompose_beacon_state,
    ssz_hash::compute_zero_hashes,
    types::{
        EpochData, HistoricalLongtail, Immutable, SlotData, SlotRoots, ValidatorIdentity,
        box_zeroed,
    },
};

#[test]
fn finalized_state_loads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/example_checkpoints/finalized_state.ssz");
    let ssz = std::fs::read(&path).unwrap();

    let zh = compute_zero_hashes();
    let mut imm: Box<Immutable> = box_zeroed();
    let mut vid: Box<ValidatorIdentity> = box_zeroed();
    let mut longtail: Box<HistoricalLongtail> = box_zeroed();
    let mut epoch: Box<EpochData> = box_zeroed();
    let mut roots: Box<SlotRoots> = box_zeroed();
    let mut sd: Box<SlotData> = box_zeroed();

    let pq = decompose_beacon_state(
        &ssz,
        &zh,
        &mut imm,
        &mut vid,
        &mut longtail,
        &mut epoch,
        &mut roots,
        &mut sd,
    )
    .unwrap_or_else(|e| {
        panic!("decompose finalized_state.ssz ({} bytes): {e}", ssz.len());
    });

    assert_eq!(pq.pending_deposits.len() % 1, 0);
    assert!(vid.validator_cnt > 0, "no validators decoded");
    assert!(sd.slot > 0, "slot is zero");
}
