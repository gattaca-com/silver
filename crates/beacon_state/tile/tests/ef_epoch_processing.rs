#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{LoadedState, compare_states, iter_test_cases, load_state, spec_tests_dir};
use silver_beacon_state::{
    ssz_hash::StateHashScratch,
    stf::{self, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, HISTORICAL_SUMMARY_PERIOD},
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

#[test]
fn justification_and_finalization() {
    epoch_handler("justification_and_finalization", |s| {
        let sid = s.state_id;
        let (mut view, epoch, _) = s.view();
        let current_epoch = view.slot.reader().current_epoch();
        let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
        stf::process_justification_and_finalization(&mut view, &mut epoch_w, current_epoch);
        s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
    });
}

#[test]
fn inactivity_updates() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("inactivity_updates", move |s| {
        s.with_view_and_epoch(|view, e| {
            let current_epoch = view.slot.reader().current_epoch();
            stf::process_inactivity_updates(&cfg, view, e, current_epoch, &mut Vec::new());
        });
    });
}

#[test]
fn rewards_and_penalties() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("rewards_and_penalties", move |s| {
        s.with_view_and_epoch(|view, e| {
            let current_epoch = view.slot.reader().current_epoch();
            stf::process_rewards_and_penalties(&cfg, view, e, current_epoch, &mut Vec::new());
        });
    });
}

#[test]
fn registry_updates() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("registry_updates", move |s| {
        s.with_view_and_epoch(|view, e| {
            let current_epoch = view.slot.reader().current_epoch();
            stf::process_registry_updates(&cfg, view, e, current_epoch);
        });
    });
}

#[test]
fn slashings() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("slashings", move |s| {
        s.with_view_and_epoch(|view, e| {
            let current_epoch = view.slot.reader().current_epoch();
            stf::process_slashings(&cfg, view, e, current_epoch);
        });
    });
}

#[test]
fn eth1_data_reset() {
    epoch_handler("eth1_data_reset", |s| {
        s.with_view(|view| {
            let current_epoch = view.slot.reader().current_epoch();
            stf::process_eth1_data_reset(&mut view.eth1, current_epoch);
        });
    });
}

#[test]
fn pending_deposits() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    epoch_handler("pending_deposits", move |s| {
        let sid = s.state_id;
        let (mut view, epoch, _) = s.view();
        let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
        stf::process_pending_deposits(&cfg, &mut view, &mut epoch_w, &mut Vec::new());
        s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
    });
}

#[test]
fn pending_consolidations() {
    epoch_handler("pending_consolidations", |s| {
        s.with_view(|view| stf::process_pending_consolidations(view));
    });
}

#[test]
fn effective_balance_updates() {
    epoch_handler("effective_balance_updates", |s| {
        s.with_view(|view| stf::process_effective_balance_updates(view));
    });
}

#[test]
fn slashings_reset() {
    epoch_handler("slashings_reset", |s| {
        let sid = s.state_id;
        let (mut view, epoch, _) = s.view();
        let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
        stf::process_slashings_reset(&mut view, &mut epoch_w);
        s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
    });
}

#[test]
fn randao_mixes_reset() {
    epoch_handler("randao_mixes_reset", |s| {
        let sid = s.state_id;
        let (view, epoch, _) = s.view();
        let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
        stf::process_randao_mixes_reset(&view, &mut epoch_w);
        s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
    });
}

#[test]
fn historical_summaries_update() {
    epoch_handler("historical_summaries_update", move |s| {
        let sid = s.state_id;
        let (mut view, _, longtail) = s.view();
        let current_epoch = view.slot.reader().current_epoch();
        // The hub's rotation gate: no-op vectors never roll the longtail.
        if !(current_epoch + 1).is_multiple_of(HISTORICAL_SUMMARY_PERIOD) {
            return;
        }
        let mut longtail_w = longtail.roll_inheriting(sid.longtail_idx);
        let mut scratch = StateHashScratch::new();
        stf::process_historical_summaries_update(&mut view, &mut longtail_w, &mut scratch);
        s.state_id = view.commit(sid.epoch_idx, Some(longtail_w.commit()));
    });
}

#[test]
fn participation_flag_updates() {
    epoch_handler("participation_flag_updates", |s| {
        s.with_view(|view| {
            stf::process_participation_flag_updates(view, &mut Vec::new());
        });
    });
}

#[test]
fn sync_committee_updates() {
    epoch_handler("sync_committee_updates", |s| {
        let sid = s.state_id;
        let (mut view, epoch, longtail) = s.view();
        let current_epoch = view.slot.reader().current_epoch();
        // The hub's rotation gate: no-op vectors never roll the longtail.
        if !(current_epoch + 1).is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
            return;
        }
        let mut longtail_w = longtail.roll_inheriting(sid.longtail_idx);
        let epoch_view = epoch.view_opt(sid.epoch_idx);
        let mut active = Vec::new();
        let mut eff = Vec::new();
        stf::process_sync_committee_updates(
            &mut view,
            &epoch_view,
            &mut longtail_w,
            current_epoch,
            &mut active,
            &mut eff,
        );
        s.state_id = view.commit(sid.epoch_idx, Some(longtail_w.commit()));
    });
}

#[test]
fn proposer_lookahead() {
    epoch_handler("proposer_lookahead", |s| {
        let sid = s.state_id;
        let (mut view, epoch, _) = s.view();
        let current_epoch = view.slot.reader().current_epoch();
        let mut epoch_w = epoch.roll_inheriting(sid.epoch_idx);
        let mut scratch = Vec::new();
        let mut eff = Vec::new();
        stf::process_proposer_lookahead(
            &mut view,
            &mut epoch_w,
            current_epoch,
            &mut scratch,
            &mut eff,
        );
        s.state_id = view.commit(Some(epoch_w.commit()), sid.longtail_idx);
    });
}
