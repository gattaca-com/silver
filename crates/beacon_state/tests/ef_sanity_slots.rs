#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{compare_states, iter_test_cases, load_state, spec_tests_dir};
use silver_beacon_state::{ssz_hash::StateHashScratch, state_transition};

#[test]
fn sanity_slots() {
    let base =
        spec_tests_dir().join("tests").join("mainnet").join("fulu").join("sanity").join("slots");
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("sanity_slots: no test cases at {}, skipping", base.display());
        return;
    }

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

        let mut pre = load_state(&pre_path);
        let target_slot = pre.delta.slot.slot.slot + target_slots;
        let mut scratch = Vec::new();
        let mut postponed = Vec::new();
        let mut replace_u64 = Vec::new();
        let mut replace_u8 = Vec::new();
        let mut eff = Vec::new();
        let mut state_hash = StateHashScratch::new();
        let mut view = pre.view();
        state_transition::process_slots(
            &silver_common::SpecConfig::mainnet(),
            &mut view,
            target_slot,
            &mut scratch,
            &mut postponed,
            &mut replace_u64,
            &mut replace_u8,
            &mut eff,
            &mut state_hash,
        );
        let mut post = load_state(&post_path);

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
    eprintln!("sanity_slots: {pass} passed, {fail} failed, {} skipped", cases.len() - pass - fail);
    assert_eq!(fail, 0, "sanity_slots: {fail} test(s) failed");
}
