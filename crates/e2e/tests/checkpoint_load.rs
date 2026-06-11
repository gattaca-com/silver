//! Bootstraps `BeaconStateTile` from a real mainnet finalized state and
//! applies the following blocks. Fixtures are gitignored; fetch with
//! `make -C crates/e2e checkpoint-fixtures`.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use silver_beacon_state::{
    ssz_hash::hash_tree_root_block_header,
    tile::{BeaconStateTile, Feedback},
};
use silver_beacon_state_data::{
    BeaconState, BeaconStateOwner, CheckpointChunk, SpecConfig, decode_checkpoint_pubkeys,
};
use silver_common::{TCache, TCacheProducer, ticker::SlotTicker};
use silver_e2e::mainnet_api::fetch_canonical_state_root;

const FIXTURES: &str = "tests/example_checkpoints";
const BLOCK_PREFIX: &str = "next_block_";
const BLOCK_SUFFIX: &str = ".ssz";

/// Pull the full checkpoint (state SSZ + pubkeys sidecar) out of `bs` through
/// the production cursor path: publish an anchor so the reader has a
/// snapshot, then step `checkpoint_chunk` to completion.
fn checkpoint_via_cursor(bs: BeaconState) -> (Vec<u8>, Vec<u8>) {
    let mut owner = BeaconStateOwner::new(bs);
    let anchor = owner.roll_fresh();
    owner.publish_state_id(anchor);
    let reader = owner.reader();

    let mut cursor = reader.begin_checkpoint().expect("snapshot published");
    let (mut state_out, mut pubkeys_out, mut buf) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        match reader.checkpoint_chunk(&mut cursor, &mut buf).expect("chunk") {
            CheckpointChunk::Ssz => state_out.extend_from_slice(&buf),
            CheckpointChunk::Pubkeys => pubkeys_out.extend_from_slice(&buf),
            CheckpointChunk::Restarted => {
                state_out.clear();
                pubkeys_out.clear();
            }
            CheckpointChunk::Done => return (state_out, pubkeys_out),
        }
    }
}

#[test]
fn checkpoint_with_pubkeys_loads() {
    let Ok(home) = std::env::var("HOME") else {
        eprintln!("skipping: HOME unset");
        return;
    };
    let root = PathBuf::from(home).join(".local/silver/finalized_checkpoints");
    let Ok(entries) = std::fs::read_dir(&root) else {
        eprintln!("skipping: {} absent", root.display());
        return;
    };

    let mut seen = 0;
    for entry in entries.flatten() {
        let dir = entry.path();
        let Some(slot) = dir.file_name().and_then(|s| s.to_str()).map(str::to_owned) else {
            continue;
        };
        let Ok(ssz) = std::fs::read(dir.join(format!("{slot}.ssz"))) else {
            continue;
        };
        seen += 1;

        match std::fs::read(dir.join(format!("{slot}.pubkeys"))) {
            Ok(raw) => {
                let pubkeys = decode_checkpoint_pubkeys(&raw).expect("decode pubkeys");
                BeaconState::decompose(&ssz, &SpecConfig::mainnet(), Some(&pubkeys))
                    .expect("decompose with pubkeys");
                eprintln!("slot {slot}: ok (with pubkeys)");
            }
            Err(_) => {
                BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).expect("decompose");
                eprintln!("slot {slot}: ok (no pubkeys)");
            }
        }
    }

    if seen == 0 {
        eprintln!("skipping: no checkpoints under {}", root.display());
    }
}

/// Cold `decompose` (sqrt-decompress every 48-byte pubkey) vs
/// `decompose_with_pubkeys` (deserialize the 96-byte sidecar, no sqrt) on the
/// mainnet checkpoint at the workspace root. Ignored manual bench; the sidecar
/// is built in-memory up front (decompose once → re-encode → decode) so no
/// sidecar fixture is needed. `CHECKPOINT_SSZ` overrides the state path,
/// `DECOMPOSE_BENCH_ITERS` the iteration count.
#[test]
#[ignore]
fn decompose_pubkeys_bench() {
    let ssz_path = std::env::var("CHECKPOINT_SSZ").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../finalized_state.ssz")
    });
    let Ok(ssz) = std::fs::read(&ssz_path) else {
        eprintln!("skipping: {} absent", ssz_path.display());
        return;
    };
    let spec = SpecConfig::mainnet();
    let iters: u32 =
        std::env::var("DECOMPOSE_BENCH_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);

    // Prepare the decompressed-pubkey sidecar once (untimed): decompose, then
    // pull the sidecar bytes back out through the checkpoint cursor and decode
    // them — exactly the bytes the persist path would write/read.
    let pubkeys = {
        let bs = BeaconState::decompose(&ssz, &spec, None).expect("prep decompose");
        let (_, sidecar) = checkpoint_via_cursor(bs);
        decode_checkpoint_pubkeys(&sidecar).expect("decode pubkeys")
    };
    eprintln!("bench: {} validators, ssz {} MiB, {iters} iters", pubkeys.len(), ssz.len() >> 20,);

    let bench = |with_pubkeys: bool| {
        let mut total = Duration::ZERO;
        for _ in 0..iters {
            let sidecar = with_pubkeys.then_some(pubkeys.as_slice());
            let t = Instant::now();
            BeaconState::decompose(&ssz, &spec, sidecar).expect("decompose");
            total += t.elapsed();
        }
        total / iters
    };

    let cold = bench(false);
    let warm = bench(true);
    eprintln!("decompose                {cold:>12.2?}");
    eprintln!("decompose_with_pubkeys   {warm:>12.2?}");
    eprintln!("speedup                  {:>11.2}x", cold.as_secs_f64() / warm.as_secs_f64());
}

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

    let state = BeaconStateOwner::pre_bootstrap();
    let mut tile = BeaconStateTile::new(
        ticker,
        silver_beacon_state_data::SpecConfig::mainnet(),
        state,
        gossip_c,
        rpc_c,
        &ssz,
        &[],
    );

    let head = tile.head_block_root();
    assert_ne!(head, [0u8; 32], "head_block_root is zero after bootstrap");
    assert_eq!(tile.fork_choice_head(), head, "find_head should return head_block_root");

    // Regression: bootstrap must patch `latest_block_header.state_root` before
    // hashing, otherwise the head root is the raw-header hash.
    let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).expect("decompose");

    // Round-trip gate: re-encoding the decomposed state must reproduce the
    // exact canonical SSZ bytes it came from.
    let mut reencoded = Vec::with_capacity(bs.ssz_len());
    bs.encode_ssz(&mut reencoded).expect("encode_ssz");
    if reencoded != ssz {
        let at = reencoded.iter().zip(&ssz).position(|(a, b)| a != b);
        panic!(
            "re-encoded SSZ differs from original: first mismatch at {:?} (lens {} vs {})",
            at,
            reencoded.len(),
            ssz.len(),
        );
    }

    let raw_header = bs.slot_states.finalized_view().state().latest_block_header;

    // Same gate via the chunked checkpoint-cursor path (the live persist's
    // path — ~18 validators chunks at mainnet scale, plus the pubkeys
    // sidecar stage). Must also reproduce the original bytes.
    let (streamed, _) = checkpoint_via_cursor(bs);
    if streamed != ssz {
        let at = streamed.iter().zip(&ssz).position(|(a, b)| a != b);
        panic!(
            "chunk-streamed SSZ differs from original: first mismatch at {:?} (lens {} vs {})",
            at,
            streamed.len(),
            ssz.len(),
        );
    }

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
        assert!(
            matches!(feedback, Feedback::Accept(_)),
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

    let state = BeaconStateOwner::pre_bootstrap();
    let mut tile = BeaconStateTile::new(
        ticker,
        silver_beacon_state_data::SpecConfig::mainnet(),
        state,
        gossip_c,
        rpc_c,
        &pre_ssz,
        &[],
    );

    let fb = tile.try_apply_block(&block_ssz);
    assert!(
        matches!(fb, Feedback::Accept(_)),
        "EF block rejected through tile (bootstrap or apply path is buggy, independent of mainnet scale)",
    );
}
