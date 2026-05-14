//! Loads a real mainnet finalized state SSZ from disk, bootstraps a
//! `BeaconStateTile` from it, and applies the next N canonical blocks. Both
//! the state blob and the following-block fixtures are large and gitignored
//! — fetch them locally with:
//!
//! ```sh
//! make -C crates/beacon_state checkpoint-fixtures
//! ```
//!
//! Files land in `tests/example_checkpoints/`: `finalized_state.ssz` plus
//! one `next_block_<slot>.ssz` per following block. The test scans for
//! `next_block_*.ssz`, sorts by slot, and applies them in order.

use std::{path::PathBuf, time::Duration};

use silver_beacon_state::{
    decompose::decompose_beacon_state,
    ssz_hash::{compute_zero_hashes, hash_tree_root_block_header},
    ticker::SlotTicker,
    tile::{BeaconStateTile, GossipFeedback},
    types::{
        EpochData, HistoricalLongtail, Immutable, SlotData, SlotRoots, ValidatorIdentity,
        box_zeroed,
    },
};
use silver_common::{TCache, TCacheProducer};

const FIXTURES: &str = "tests/example_checkpoints";
const BLOCK_PREFIX: &str = "next_block_";
const BLOCK_SUFFIX: &str = ".ssz";

#[test]
fn finalized_state_loads() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
    let state_path = dir.join("finalized_state.ssz");
    let Ok(ssz) = std::fs::read(&state_path) else {
        eprintln!(
            "skipping: {} not present (run `make -C crates/beacon_state checkpoint-fixtures`)",
            state_path.display()
        );
        return;
    };

    // Position the ticker against the SSZ's own genesis_time (byte 0, u64 LE)
    // so `current_slot()` returns the real mainnet slot — otherwise
    // `precheck_block` ignores the following blocks as "future slot".
    let genesis_time = u64::from_le_bytes(ssz[0..8].try_into().unwrap());
    let ticker = SlotTicker::new(genesis_time, Duration::from_secs(12), Duration::from_secs(4));
    let gossip_p = TCache::producer(1 << 20);
    let rpc_p = TCache::producer(1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access().unwrap();
    let rpc_c = rpc_p.cache_ref().random_access().unwrap();

    let mut tile = BeaconStateTile::new_heap(ticker, gossip_c, rpc_c, &ssz);

    let head = tile.head_block_root();
    assert_ne!(head, [0u8; 32], "head_block_root is zero after bootstrap");
    assert_eq!(tile.fork_choice_head(), head, "find_head should return head_block_root");

    // Offline regression assertion: a bootstrap that forgets to patch
    // `latest_block_header.state_root` would have produced the raw-header
    // hash; verify that didn't happen.
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

    // Collect and sort `next_block_<slot>.ssz` fixtures.
    let mut blocks = list_block_fixtures(&dir);
    if blocks.is_empty() {
        eprintln!(
            "skipping next-block apply: no {BLOCK_PREFIX}*.{BLOCK_SUFFIX} fixtures in {}",
            dir.display()
        );
        return;
    }

    // Apply each in order. Each block's parent_root must equal the previous
    // head_block_root (or, for the first one, the bootstrap anchor root —
    // unless empty slots separate them, in which case `process_slots`
    // advances over them and the chain still descends from the same anchor
    // by transitivity, so this assertion still holds for the very next
    // non-empty block whose parent is the anchor).
    let mut prev_head = head;
    for (block_slot, block_ssz) in blocks.drain(..) {
        // SignedBeaconBlock: sig(96) + BeaconBlock{ slot@100, prop@108,
        // parent_root@116, state_root@148, body_off@180 }.
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
            GossipFeedback::Accept,
            "block at slot {block_slot} not accepted (got {feedback:?})",
        );
        assert!(
            tile.head_state_slot() >= block_slot,
            "head did not advance to applied block slot {block_slot}",
        );

        prev_head = tile.head_block_root();
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
