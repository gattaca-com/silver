#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{LoadedState, compare_states, iter_test_cases, load_state, spec_tests_dir};
use silver_beacon_state::{
    epoch_transition, ssz_hash::compute_zero_hashes, types::SLOTS_PER_EPOCH,
};

fn epoch_handler(handler_name: &str, run: impl Fn(&mut LoadedState)) {
    let base = spec_tests_dir()
        .join("tests")
        .join("mainnet")
        .join("fulu")
        .join("epoch_processing")
        .join(handler_name);
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{handler_name}: no test cases at {}, skipping", base.display());
        return;
    }

    let zh = compute_zero_hashes();
    let mut pass = 0;
    let mut fail = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            // No post state means the operation should fail — skip for now.
            continue;
        }

        let mut pre = load_state(&pre_path, &zh);
        run(&mut pre);
        let post = load_state(&post_path, &zh);

        let diffs = compare_states(name, &pre, &post, &zh);
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
        "{handler_name}: {pass} passed, {fail} failed, {} skipped",
        cases.len() - pass - fail
    );
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

#[test]
fn justification_and_finalization() {
    epoch_handler("justification_and_finalization", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let n = s.vid.validator_cnt;
        epoch_transition::process_justification_and_finalization(
            &s.epoch,
            &mut s.sd,
            &s.roots,
            n,
            current_epoch,
        );
    });
}

#[test]
fn inactivity_updates() {
    epoch_handler("inactivity_updates", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let n = s.vid.validator_cnt;
        epoch_transition::process_inactivity_updates(&mut s.epoch, &s.sd, n, current_epoch);
    });
}

#[test]
fn rewards_and_penalties() {
    epoch_handler("rewards_and_penalties", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let n = s.vid.validator_cnt;
        epoch_transition::process_rewards_and_penalties(&s.epoch, &mut s.sd, n, current_epoch);
    });
}

#[test]
fn registry_updates() {
    epoch_handler("registry_updates", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let n = s.vid.validator_cnt;
        epoch_transition::process_registry_updates(&mut s.epoch, &mut s.sd, n, current_epoch);
    });
}

#[test]
fn slashings() {
    epoch_handler("slashings", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let n = s.vid.validator_cnt;
        epoch_transition::process_slashings(&s.epoch, &mut s.sd, n, current_epoch);
    });
}

#[test]
fn eth1_data_reset() {
    epoch_handler("eth1_data_reset", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        epoch_transition::process_eth1_data_reset(&mut s.sd, current_epoch);
    });
}

#[test]
fn pending_deposits() {
    let zh = compute_zero_hashes();
    epoch_handler("pending_deposits", move |s| {
        epoch_transition::process_pending_deposits(
            &mut s.vid,
            &mut s.epoch,
            &mut s.sd,
            &mut s.pq,
            &zh,
            &mut Vec::new(),
        );
    });
}

#[test]
fn pending_consolidations() {
    epoch_handler("pending_consolidations", |s| {
        epoch_transition::process_pending_consolidations(&mut s.epoch, &mut s.sd, &mut s.pq);
    });
}

#[test]
fn effective_balance_updates() {
    epoch_handler("effective_balance_updates", |s| {
        epoch_transition::process_effective_balance_updates(&s.vid, &mut s.epoch, &s.sd);
    });
}

#[test]
fn slashings_reset() {
    epoch_handler("slashings_reset", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        epoch_transition::process_slashings_reset(&mut s.epoch, current_epoch);
    });
}

#[test]
fn randao_mixes_reset() {
    epoch_handler("randao_mixes_reset", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        epoch_transition::process_randao_mixes_reset(&mut s.epoch, &s.sd, current_epoch);
    });
}

#[test]
fn historical_summaries_update() {
    let zh = compute_zero_hashes();
    epoch_handler("historical_summaries_update", move |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        epoch_transition::process_historical_summaries_update(
            &mut s.longtail,
            &s.roots,
            current_epoch,
            &zh,
        );
    });
}

#[test]
fn participation_flag_updates() {
    epoch_handler("participation_flag_updates", |s| {
        epoch_transition::process_participation_flag_updates(&mut s.sd, s.vid.validator_cnt);
    });
}

#[test]
fn sync_committee_updates() {
    epoch_handler("sync_committee_updates", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let mut scratch = Vec::new();
        epoch_transition::process_sync_committee_updates(
            &s.vid,
            &mut s.longtail,
            &s.epoch,
            current_epoch,
            &mut scratch,
        );
    });
}

#[test]
fn proposer_lookahead() {
    epoch_handler("proposer_lookahead", |s| {
        let current_epoch = s.sd.slot / SLOTS_PER_EPOCH;
        let mut scratch = Vec::new();
        epoch_transition::process_proposer_lookahead(
            &s.vid,
            &s.epoch,
            &mut s.sd,
            current_epoch,
            &mut scratch,
        );
    });
}
