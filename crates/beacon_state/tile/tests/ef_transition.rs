#![cfg(feature = "ef_tests")]

use std::{fs, path::Path};

mod ef_common;

use ef_common::{
    compare_states, iter_test_cases, load_state, load_state_gloas, snappy_decode, spec_tests_dir,
};
use silver_beacon_state_data::SpecConfig;

/// `{post_fork: gloas, fork_epoch: N, blocks_count: M, ...}` flow-YAML meta.
fn parse_meta(dir: &Path) -> (u64, usize) {
    let raw = fs::read_to_string(dir.join("meta.yaml")).expect("meta.yaml");
    let body = raw.trim().trim_start_matches('{').trim_end_matches('}');
    let (mut fork_epoch, mut blocks_count) = (0u64, 0usize);
    for kv in body.split(',') {
        let mut it = kv.splitn(2, ':');
        let (k, v) = (it.next().unwrap_or("").trim(), it.next().unwrap_or("").trim());
        match k {
            "fork_epoch" => fork_epoch = v.parse().unwrap_or(0),
            "blocks_count" => blocks_count = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    (fork_epoch, blocks_count)
}

/// Fulu → Gloas `transition` vectors: a Fulu `pre`, a run of blocks that
/// crosses `fork_epoch` (the live `process_slots` upgrade fires), and a Gloas
/// `post`.
#[test]
fn transition() {
    let base = spec_tests_dir().join("tests/mainnet/gloas/transition/core");
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("transition: no test cases, skipping");
        return;
    }

    let mut pass = 0;
    let mut fail = 0;
    for (name, dir) in &cases {
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }
        let (fork_epoch, blocks_count) = parse_meta(dir);
        let mut cfg = SpecConfig::mainnet();
        cfg.gloas_fork_epoch = fork_epoch;

        let mut pre = load_state(&dir.join("pre.ssz_snappy"));
        let mut rejected = false;
        for i in 0..blocks_count {
            let block = snappy_decode(&dir.join(format!("blocks_{i}.ssz_snappy")));
            if let Err(reason) = pre.apply_block(&cfg, &block) {
                eprintln!("{name}: block {i}/{blocks_count}: {reason}");
                rejected = true;
                break;
            }
        }
        if rejected {
            fail += 1;
            continue;
        }

        let mut post = load_state_gloas(&post_path);
        let diffs = compare_states(name, &mut pre, &mut post);
        if diffs.is_empty() {
            pass += 1;
        } else {
            fail += 1;
            for d in &diffs {
                eprintln!("{name}: {d}");
            }
        }
    }
    eprintln!("transition: {pass} passed, {fail} failed, {} skipped", cases.len() - pass - fail);
    assert_eq!(fail, 0, "transition: {fail} test(s) failed");
}
