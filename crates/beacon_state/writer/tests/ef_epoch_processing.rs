#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{LoadedState, compare_states, iter_test_cases, load_state, spec_tests_dir};
use silver_beacon_state::{epoch_transition, ssz_hash::StateHashScratch};
use silver_beacon_state_data::StateDeltaView;

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

    let mut pass = 0;
    let mut fail = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }

        let mut pre = load_state(&pre_path);
        run(&mut pre);
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
    eprintln!(
        "{handler_name}: {pass} passed, {fail} failed, {} skipped",
        cases.len() - pass - fail
    );
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

fn view_mut(s: &mut LoadedState) -> StateDeltaView<'_> {
    s.view()
}

#[test]
fn justification_and_finalization() {
    epoch_handler("justification_and_finalization", |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        v.ensure_epoch_delta();
        epoch_transition::process_justification_and_finalization(&mut v, current_epoch);
    });
}

#[test]
fn inactivity_updates() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("inactivity_updates", move |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        let mut scratch = Vec::new();
        epoch_transition::process_inactivity_updates(&cfg, &mut v, current_epoch, &mut scratch);
    });
}

#[test]
fn rewards_and_penalties() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("rewards_and_penalties", move |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        let mut scratch = Vec::new();
        epoch_transition::process_rewards_and_penalties(&cfg, &mut v, current_epoch, &mut scratch);
    });
}

#[test]
fn registry_updates() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("registry_updates", move |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        epoch_transition::process_registry_updates(&cfg, &mut v, current_epoch);
    });
}

#[test]
fn slashings() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("slashings", move |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        epoch_transition::process_slashings(&cfg, &mut v, current_epoch);
    });
}

#[test]
fn eth1_data_reset() {
    epoch_handler("eth1_data_reset", |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        epoch_transition::process_eth1_data_reset(&mut v, current_epoch);
    });
}

#[test]
fn pending_deposits() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("pending_deposits", move |s| {
        let mut v = view_mut(s);
        epoch_transition::process_pending_deposits(&cfg, &mut v, &mut Vec::new());
    });
}

#[test]
fn pending_consolidations() {
    epoch_handler("pending_consolidations", |s| {
        let mut v = view_mut(s);
        epoch_transition::process_pending_consolidations(&mut v);
    });
}

#[test]
fn effective_balance_updates() {
    epoch_handler("effective_balance_updates", |s| {
        let mut v = view_mut(s);
        epoch_transition::process_effective_balance_updates(&mut v);
    });
}

#[test]
fn slashings_reset() {
    epoch_handler("slashings_reset", |s| {
        let mut v = view_mut(s);
        epoch_transition::process_slashings_reset(&mut v);
    });
}

#[test]
fn randao_mixes_reset() {
    epoch_handler("randao_mixes_reset", |s| {
        let mut v = view_mut(s);
        epoch_transition::process_randao_mixes_reset(&mut v);
    });
}

#[test]
fn historical_summaries_update() {
    epoch_handler("historical_summaries_update", move |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        let mut scratch = StateHashScratch::new();
        epoch_transition::process_historical_summaries_update(&mut v, current_epoch, &mut scratch);
    });
}

#[test]
fn participation_flag_updates() {
    epoch_handler("participation_flag_updates", |s| {
        let mut v = view_mut(s);
        let mut scratch = Vec::new();
        epoch_transition::process_participation_flag_updates(&mut v, &mut scratch);
    });
}

#[test]
fn sync_committee_updates() {
    epoch_handler("sync_committee_updates", |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        let mut active = Vec::new();
        let mut eff = Vec::new();
        epoch_transition::process_sync_committee_updates(
            &mut v,
            current_epoch,
            &mut active,
            &mut eff,
        );
    });
}

#[test]
fn proposer_lookahead() {
    epoch_handler("proposer_lookahead", |s| {
        let mut v = view_mut(s);
        let current_epoch = v.current_epoch();
        v.ensure_epoch_delta();
        let mut scratch = Vec::new();
        let mut eff = Vec::new();
        epoch_transition::process_proposer_lookahead(&mut v, current_epoch, &mut scratch, &mut eff);
    });
}
