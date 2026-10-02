#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{
    compare_states, iter_test_cases, load_state, load_state_gloas, snappy_decode, spec_tests_dir,
};
use silver_beacon_state::stf::{self, BlockInput, BlockVotes, ShufflingRef, StfScratch};
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, SLOTS_PER_EPOCH, SpecConfig,
};
use silver_common::ssz_view::SignedBeaconBlockView;

#[test]
fn fulu_sanity_blocks() {
    sanity_blocks_fork("fulu", SpecConfig::mainnet());
}

#[test]
fn gloas_sanity_blocks() {
    let mut cfg = SpecConfig::mainnet();
    cfg.gloas_fork_epoch = 0;
    sanity_blocks_fork("gloas", cfg);
}

/// A proposer fills `state_root` from `post_state_root_unchecked`; every
/// accepted block's root must come out of it unchanged. `random` and
/// `finality` blocks carry the operations a packed body will.
#[test]
fn fulu_state_roots_match_the_proposal_path() {
    let cfg = SpecConfig::mainnet();
    for suite in ["sanity/blocks", "random/random", "finality/finality"] {
        let base = spec_tests_dir().join("tests/mainnet/fulu").join(suite);
        let mut checked = 0;
        for (name, dir) in &iter_test_cases(&base) {
            if !dir.join("post.ssz_snappy").exists() {
                continue;
            }
            let mut pre = load_state(&dir.join("pre.ssz_snappy"));
            for i in 0.. {
                let path = dir.join(format!("blocks_{i}.ssz_snappy"));
                if !path.exists() {
                    break;
                }
                let block = snappy_decode(&path);
                let expected = *SignedBeaconBlockView::state_root(&block);
                let got = proposal_state_root(&cfg, &mut pre, &block);
                assert_eq!(got, Ok(expected), "{suite}/{name}: block {i}");
                pre.apply_block(&cfg, &block).unwrap();
                checked += 1;
            }
        }
        assert!(checked > 0, "{suite}: no blocks ran");
        eprintln!("{suite}: {checked} blocks match the proposal path");
    }
}

fn proposal_state_root(
    cfg: &SpecConfig,
    pre: &mut ef_common::LoadedState,
    block: &[u8],
) -> Result<B256, String> {
    let slot = SignedBeaconBlockView::slot(block);
    let body = SignedBeaconBlockView::body(block);
    let offsets = BodyOffsets::validated(body, BodyFork::Fulu).map_err(|e| e.to_string())?;
    let (body_root, fork) = stf::hash_body(&offsets);
    let header = BeaconBlockHeader {
        slot,
        proposer_index: SignedBeaconBlockView::proposer_index(block),
        parent_root: *SignedBeaconBlockView::parent_root(block),
        state_root: [0; 32],
        body_root,
    };

    let mut scratch = StfScratch::new(0);
    let mut writer = pre.bs.fork_writer(pre.state_id);
    let epoch = slot / SLOTS_PER_EPOCH;
    if writer.view.slot.state().slot < epoch * SLOTS_PER_EPOCH {
        stf::process_slots(cfg, &mut writer, epoch * SLOTS_PER_EPOCH, &mut scratch);
    }
    let (mut current, mut previous) = (Vec::new(), Vec::new());
    let shuffling = ShufflingRef::build(&writer.read(), epoch, &mut current, &mut previous);
    let input = BlockInput {
        header: &header,
        block_root: [0; 32],
        body: offsets,
        fork,
        shuffling: &shuffling,
    };
    let mut votes = BlockVotes::default();
    stf::post_state_root_unchecked(cfg, &mut writer, &input, &mut scratch, &mut votes)
        .map_err(|e| e.to_string())
}

fn sanity_blocks_fork(fork: &str, cfg: SpecConfig) {
    let base = spec_tests_dir().join(format!("tests/mainnet/{fork}/sanity/blocks"));
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("sanity_blocks[{fork}]: no test cases, skipping");
        return;
    }
    let loader = if fork == "gloas" { load_state_gloas } else { load_state };

    let mut pass = 0;
    let mut fail = 0;
    let skip = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        let expect_failure = !post_path.exists();

        // Count block files.
        let mut block_count = 0;
        while dir.join(format!("blocks_{block_count}.ssz_snappy")).exists() {
            block_count += 1;
        }
        if block_count == 0 {
            // Try meta.yaml for block count.
            if let Ok(meta) = fs::read_to_string(dir.join("meta.yaml")) {
                for line in meta.lines() {
                    if let Some(n) = line.strip_prefix("blocks_count:") {
                        block_count = n.trim().parse().unwrap_or(0);
                    }
                }
            }
        }

        let mut pre = loader(&pre_path);

        let mut block_rejected = false;
        for i in 0..block_count {
            let block_ssz = snappy_decode(&dir.join(format!("blocks_{i}.ssz_snappy")));
            if let Err(reason) = pre.apply_block(&cfg, &block_ssz) {
                if !expect_failure {
                    eprintln!("{name}: block {i}: {reason}");
                }
                block_rejected = true;
                break;
            }
        }

        if expect_failure {
            if block_rejected {
                pass += 1;
            } else {
                fail += 1;
                eprintln!("{name}: expected rejection but all blocks accepted");
            }
            continue;
        }

        if block_rejected {
            fail += 1;
            continue;
        }

        let mut post = loader(&post_path);
        let diffs = compare_states(name, &mut pre, &mut post);
        if diffs.is_empty() {
            pass += 1;
        } else {
            fail += 1;
            for d in &diffs {
                eprintln!("{d}");
            }
        }
    }
    eprintln!("sanity_blocks[{fork}]: {pass} passed, {fail} failed, {skip} skipped");
    assert_eq!(fail, 0, "sanity_blocks[{fork}]: {fail} test(s) failed");
}
