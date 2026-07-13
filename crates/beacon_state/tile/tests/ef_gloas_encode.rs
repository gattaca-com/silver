#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state_data::{BeaconState, SpecConfig};

#[test]
fn gloas_encode_round_trip() {
    let root = spec_tests_dir().join("tests").join("mainnet").join("gloas");
    if !root.exists() {
        eprintln!("gloas_encode_round_trip: no fixtures at {}, skipping", root.display());
        return;
    }

    // Collect every Gloas post-state, then stride-sample: each decode+encode
    // moves the ~3.1 MB fixed part, so a bounded spread across handlers is
    // enough to cover the layout.
    let mut posts = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().and_then(|n| n.to_str()) == Some("post.ssz_snappy") {
                posts.push(p);
            }
        }
    }
    posts.sort();

    const MAX_CASES: usize = 64;
    let stride = (posts.len() / MAX_CASES).max(1);

    let cfg = SpecConfig::mainnet();
    let mut checked = 0;
    let mut skipped = 0;
    for path in posts.iter().step_by(stride) {
        let ssz = snappy_decode(path);
        // A post-state is always a full BeaconState; decode failures here are a
        // real regression, not a mixed-fork input.
        let bs = BeaconState::decompose_gloas(&ssz, &cfg, None)
            .unwrap_or_else(|e| panic!("{}: decompose_gloas: {e}", path.display()));
        // Encode routes on the finalized fork; the rare fork-mutated signature
        // vector decodes as Gloas but would route Fulu on encode — skip it.
        if !bs.is_finalized_post_gloas() {
            skipped += 1;
            continue;
        }
        let mut out = Vec::with_capacity(bs.ssz_len());
        bs.encode_ssz(&mut out).expect("encode");
        assert_eq!(out, ssz, "gloas encode round-trip mismatch: {}", path.display());
        checked += 1;
    }
    eprintln!("gloas_encode_round_trip: {checked} states checked, {skipped} fork-mutated skipped");
    assert!(checked > 0, "gloas fixtures present but none round-tripped");
}
