#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{compare_states, iter_test_cases, load_state, spec_tests_dir};
use silver_beacon_state::stf;

/// EF `fork` vectors for the Fulu → Gloas upgrade: decode the Fulu `pre`, apply
/// `upgrade_to_gloas`, and check the result hashes to the Gloas `post`.
#[test]
fn gloas_fork() {
    let base =
        spec_tests_dir().join("tests").join("mainnet").join("gloas").join("fork").join("fork");
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("gloas_fork: no test cases at {}, skipping", base.display());
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

        let mut pre = load_state(&pre_path);
        // The upgrade writes the epoch tier (`fork` + `ptc_window`), so roll its
        // boundary writer — the production `process_slots`-at-boundary shape.
        let sid = pre.state_id;
        pre.state_id = {
            let (mut view, epoch, _longtail) = pre.view();
            let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
            stf::upgrade_to_gloas(&mut view, &mut epoch_w);
            view.commit(Some(epoch_w.commit()), sid.longtail_idx)
        };

        let mut post = load_state(&post_path);
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
    eprintln!("gloas_fork: {pass} passed, {fail} failed, {} skipped", cases.len() - pass - fail);
    assert_eq!(fail, 0, "gloas_fork: {fail} test(s) failed");
}
