//! Bootstraps `BeaconStateTile` from a real mainnet finalized state and
//! applies the following blocks. Fixtures are gitignored; fetch with
//! `make -C crates/e2e checkpoint-fixtures`.

use std::{path::PathBuf, time::Duration};

use silver_beacon_state::{
    ssz_hash::hash_tree_root_block_header,
    ticker::SlotTicker,
    tile::{BeaconStateTile, Feedback},
};
use silver_common::{BeaconState, BeaconStateOwner, Finalized, SpecConfig, TCache, TCacheProducer};
use silver_e2e::mainnet_api::fetch_canonical_state_root;

const FIXTURES: &str = "tests/example_checkpoints";
const BLOCK_PREFIX: &str = "next_block_";
const BLOCK_SUFFIX: &str = ".ssz";

#[test]
fn finalized_state_loads() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
    let state_path = dir.join("finalized_state.ssz");
    let Ok(ssz) = std::fs::read(&state_path) else {
        eprintln!(
            "skipping: {} not present (run `make -C crates/e2e checkpoint-fixtures`)",
            state_path.display()
        );
        return;
    };

    // Ticker against the SSZ's genesis_time so `current_slot()` returns the
    // real mainnet slot — otherwise `precheck_block` ignores blocks as future.
    let genesis_time = u64::from_le_bytes(ssz[0..8].try_into().unwrap());
    let ticker = SlotTicker::new(genesis_time, Duration::from_secs(12), Duration::from_secs(4));
    let gossip_p = TCache::producer("gossip_in", 1 << 20);
    let rpc_p = TCache::producer("rpc_in", 1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access("test", false).unwrap();
    let rpc_c = rpc_p.cache_ref().random_access("test", false).unwrap();

    let state = BeaconStateOwner::new(BeaconState::default());
    let mut tile = BeaconStateTile::new(
        ticker,
        silver_common::SpecConfig::mainnet(),
        state,
        gossip_c,
        rpc_c,
        &ssz,
    );

    let head = tile.head_block_root();
    assert_ne!(head, [0u8; 32], "head_block_root is zero after bootstrap");
    assert_eq!(tile.fork_choice_head(), head, "find_head should return head_block_root");

    // Regression: bootstrap must patch `latest_block_header.state_root` before
    // hashing, otherwise the head root is the raw-header hash.
    let mut fin = Box::new(Finalized::default());
    fin.decompose(&ssz, &SpecConfig::mainnet()).expect("decompose");
    let raw_header = fin.slot.slot.latest_block_header;
    if raw_header.state_root == [0u8; 32] {
        let raw_root = hash_tree_root_block_header(&raw_header);
        assert_ne!(
            head, raw_root,
            "bootstrap returned the raw-header hash; it should patch state_root first",
        );
    }

    // Collect and sort `next_block_<slot>.ssz` fixtures.
    let mut blocks = list_block_fixtures(&dir);
    if blocks.is_empty() {
        eprintln!(
            "skipping next-block apply: no {BLOCK_PREFIX}*.{BLOCK_SUFFIX} fixtures in {}",
            dir.display()
        );
        return;
    }

    let mut prev_head = head;
    for (block_slot, block_ssz) in blocks.drain(..) {
        // parent_root sits at offset 116 in SignedBeaconBlock SSZ.
        let parent_root: [u8; 32] = block_ssz[116..148].try_into().unwrap();
        assert_eq!(
            parent_root,
            prev_head,
            "block at slot {block_slot}: parent_root 0x{} != prev head 0x{}",
            hex(&parent_root),
            hex(&prev_head),
        );

        let feedback = tile.try_apply_block(&block_ssz);
        assert_eq!(
            feedback,
            Feedback::Accept,
            "block at slot {block_slot} not accepted (got {feedback:?})",
        );
        assert!(
            tile.head_state_slot() >= block_slot,
            "head did not advance to applied block slot {block_slot}",
        );

        prev_head = tile.head_block_root();
    }

    // Cross-check the final post-state root against a canonical beacon API.
    // Silent skip when offline — STF correctness is still covered above.
    let final_slot = tile.head_state_slot();
    match fetch_canonical_state_root(final_slot) {
        Some(expected) => {
            let got = tile.head_state_root();
            assert_eq!(
                got,
                expected,
                "head_state_root mismatch at slot {final_slot}: tile 0x{} vs canonical 0x{}",
                hex(&got),
                hex(&expected),
            );
        }
        None => eprintln!(
            "skipping canonical head_state_root cross-check at slot {final_slot} \
             (network unavailable)"
        ),
    }
}

fn list_block_fixtures(dir: &std::path::Path) -> Vec<(u64, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(BLOCK_PREFIX) else {
            continue;
        };
        let Some(slot_str) = rest.strip_suffix(BLOCK_SUFFIX) else {
            continue;
        };
        let Ok(slot) = slot_str.parse::<u64>() else {
            continue;
        };
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        out.push((slot, bytes));
    }
    out.sort_by_key(|(s, _)| *s);
    out
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bootstrap from an EF pre-state and apply its first block via the tile.
/// If this rejects, the bug is in the tile's bootstrap/apply (not in STF).
#[test]
fn tile_apply_block_ef_fixture() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../beacon_state/consensus-spec-tests/tests/mainnet/fulu/sanity/blocks/pyspec_tests/attestation");
    let pre_path = dir.join("pre.ssz_snappy");
    let block_path = dir.join("blocks_0.ssz_snappy");
    if !pre_path.exists() || !block_path.exists() {
        eprintln!("skipping: EF fixture not present at {}", dir.display());
        return;
    }
    let pre_ssz = snap::raw::Decoder::new()
        .decompress_vec(&std::fs::read(&pre_path).unwrap())
        .expect("snappy pre");
    let block_ssz = snap::raw::Decoder::new()
        .decompress_vec(&std::fs::read(&block_path).unwrap())
        .expect("snappy block");

    // Offset genesis_time so wall_slot is far ahead of the small EF slot.
    let genesis_time = u64::from_le_bytes(pre_ssz[0..8].try_into().unwrap());
    let ticker = SlotTicker::new(
        genesis_time.saturating_sub(60 * 60 * 24 * 365),
        Duration::from_secs(12),
        Duration::from_secs(4),
    );
    let gossip_p = TCache::producer("gossip_ef", 1 << 20);
    let rpc_p = TCache::producer("rpc_ef", 1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access("test", false).unwrap();
    let rpc_c = rpc_p.cache_ref().random_access("test", false).unwrap();

    let state = BeaconStateOwner::new(BeaconState::default());
    let mut tile = BeaconStateTile::new(
        ticker,
        silver_common::SpecConfig::mainnet(),
        state,
        gossip_c,
        rpc_c,
        &pre_ssz,
    );

    let fb = tile.try_apply_block(&block_ssz);
    assert_eq!(
        fb,
        Feedback::Accept,
        "EF block rejected through tile (bootstrap or apply path is buggy, independent of mainnet scale)",
    );
}
