#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{compare_states, iter_test_cases, load_state, load_state_gloas, spec_tests_dir};
use silver_beacon_state::stf;
use silver_beacon_state_data::SpecConfig;

#[test]
fn fulu_sanity_slots() {
    sanity_slots_fork("fulu", SpecConfig::mainnet());
}

#[test]
fn gloas_sanity_slots() {
    let mut cfg = SpecConfig::mainnet();
    cfg.gloas_fork_epoch = 0;
    sanity_slots_fork("gloas", cfg);
}

fn sanity_slots_fork(fork: &str, cfg: SpecConfig) {
    let base =
        spec_tests_dir().join("tests").join("mainnet").join(fork).join("sanity").join("slots");
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("sanity_slots[{fork}]: no test cases at {}, skipping", base.display());
        return;
    }
    let loader = if fork == "gloas" { load_state_gloas } else { load_state };

    let mut pass = 0;
    let mut fail = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }

        let slots_raw = fs::read_to_string(dir.join("slots.yaml"))
            .unwrap_or_else(|e| panic!("{name}: slots.yaml: {e}"));
        // Strip YAML document end marker.
        let slots_str = slots_raw.split('\n').next().unwrap_or("").trim();
        let target_slots: u64 = slots_str
            .parse()
            .unwrap_or_else(|e| panic!("{name}: bad slots value '{slots_str}': {e}"));

        let mut pre = loader(&pre_path);
        let target_slot = pre.slot() + target_slots;
        let mut scratch = stf::StfScratch::new(0);
        let sid = pre.state_id;
        let (mut v, epoch, longtail) = pre.view();
        let (epoch_idx, longtail_idx) =
            stf::process_slots(&cfg, &mut v, epoch, longtail, sid, target_slot, &mut scratch);
        // Write the (possibly epoch/longtail-rolled) bundle back for the
        // post-state comparison.
        pre.state_id = v.commit(epoch_idx, longtail_idx);
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
    eprintln!(
        "sanity_slots[{fork}]: {pass} passed, {fail} failed, {} skipped",
        cases.len() - pass - fail
    );
    assert_eq!(fail, 0, "sanity_slots[{fork}]: {fail} test(s) failed");
}
