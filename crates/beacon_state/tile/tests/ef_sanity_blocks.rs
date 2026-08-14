#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{
    compare_states, iter_test_cases, load_state, load_state_gloas, snappy_decode, spec_tests_dir,
};
use silver_beacon_state_data::SpecConfig;

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
