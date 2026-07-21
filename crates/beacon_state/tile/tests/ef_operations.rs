#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{
    LoadedState, compare_states, iter_test_cases, load_state, load_state_gloas, snappy_decode,
    spec_tests_dir,
};
use silver_beacon_state::{
    bls::SigBatch,
    shuffling,
    stf::{self, ShufflingRef},
};
use silver_beacon_state_data::SLOTS_PER_EPOCH;

fn operations_handler(
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    operations_handler_fork("fulu", handler_name, operation_file, detects_reject, run);
}

fn gloas_cfg() -> silver_beacon_state_data::SpecConfig {
    let mut cfg = silver_beacon_state_data::SpecConfig::mainnet();
    cfg.gloas_fork_epoch = 0;
    cfg
}

fn operations_handler_fork(
    fork: &str,
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    let base =
        spec_tests_dir().join("tests/mainnet").join(fork).join("operations").join(handler_name);
    let loader = if fork == "gloas" { load_state_gloas } else { load_state };
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{handler_name}: no test cases, skipping");
        return;
    }

    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        let op_path = dir.join(format!("{operation_file}.ssz_snappy"));

        if !op_path.exists() {
            skip += 1;
            continue;
        }

        let mut pre = loader(&pre_path);
        let op_ssz = snappy_decode(&op_path);

        if !post_path.exists() {
            if !detects_reject {
                skip += 1;
                continue;
            }
            // Expected-reject case: op must be rejected and pre-state
            // must not be mutated past the rejection point.
            let mut pre_snapshot = loader(&pre_path);
            let accepted = run(&mut pre, &op_ssz);
            if accepted {
                fail += 1;
                eprintln!("{name}: expected reject, but op was accepted");
                continue;
            }
            let diffs = compare_states(name, &mut pre, &mut pre_snapshot);
            if diffs.is_empty() {
                pass += 1;
            } else {
                fail += 1;
                eprintln!("{name}: rejected but pre-state was mutated");
                for d in &diffs {
                    eprintln!("{d}");
                }
            }
            continue;
        }

        let accepted = run(&mut pre, &op_ssz);
        if !accepted {
            fail += 1;
            eprintln!("{name}: expected accept, but op was rejected");
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
    eprintln!("{handler_name}: {pass} passed, {fail} failed, {skip} skipped");
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

fn run_proposer_slashing(s: &mut LoadedState, op: &[u8]) -> bool {
    let mut batch = SigBatch::new();
    let sid = s.state_id;
    {
        let (p, eg, _) = s.view();
        let ev = eg.view_opt(sid.epoch_idx);
        if stf::collect_sigs_proposer_slashings(p.imm, &ev, &p.validators.reader(), op, &mut batch)
            .is_err()
        {
            return false;
        }
    }
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    if !batch.verify_all() {
        return false;
    }
    s.with_view_and_epoch(|view, e| stf::process_proposer_slashings(view, *e, &cfg, op).is_ok())
}

#[test]
fn fulu_proposer_slashing() {
    operations_handler("proposer_slashing", "proposer_slashing", true, run_proposer_slashing);
}

#[test]
fn gloas_proposer_slashing() {
    operations_handler_fork(
        "gloas",
        "proposer_slashing",
        "proposer_slashing",
        true,
        run_proposer_slashing,
    );
}

#[test]
fn fulu_attester_slashing() {
    operations_handler("attester_slashing", "attester_slashing", true, move |s, op| {
        // The op SSZ here is a single AttesterSlashing; wrap as a List[1].
        let mut list = Vec::with_capacity(4 + op.len());
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        let sid = s.state_id;
        {
            let (p, eg, _) = s.view();
            let ev = eg.view_opt(sid.epoch_idx);
            if stf::collect_sigs_attester_slashings(
                p.imm,
                &ev,
                &p.validators.reader(),
                &list,
                &mut active_scratch,
                &mut batch,
            )
            .is_err()
            {
                return false;
            }
        }
        let cfg = silver_beacon_state_data::SpecConfig::mainnet();
        if !batch.verify_all() {
            return false;
        }
        s.with_view_and_epoch(|view, e| {
            stf::process_attester_slashings(
                view,
                *e,
                &cfg,
                &list,
                &mut active_scratch,
                &mut Vec::new(),
            )
            .is_ok()
        })
    });
}

fn run_attestation(s: &mut LoadedState, op: &[u8]) -> bool {
    let mut list = Vec::with_capacity(4 + op.len());
    list.extend_from_slice(&4u32.to_le_bytes());
    list.extend_from_slice(op);
    let block_slot = s.slot();
    let curr_epoch = block_slot / SLOTS_PER_EPOCH;
    let prev_epoch = curr_epoch.saturating_sub(1);

    let proposer_index;
    let curr_seed;
    let prev_seed;
    let mut curr_active = Vec::new();
    let mut prev_active = Vec::new();
    {
        let sid = s.state_id;
        let (mut v, epoch, longtail) = s.view();
        let rv = v.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
        proposer_index =
            rv.epoch.proposer_at((block_slot % SLOTS_PER_EPOCH) as usize).unwrap() as u32;
        curr_seed = shuffling::get_seed_from_state(
            &rv.epoch,
            &rv.slot,
            curr_epoch,
            shuffling::DOMAIN_BEACON_ATTESTER,
        );
        prev_seed = shuffling::get_seed_from_state(
            &rv.epoch,
            &rv.slot,
            prev_epoch,
            shuffling::DOMAIN_BEACON_ATTESTER,
        );
        shuffling::get_active_validator_indices_into(&rv.validators, curr_epoch, &mut curr_active);
        shuffling::get_active_validator_indices_into(&rv.validators, prev_epoch, &mut prev_active);
    }
    let curr_committees_per_slot = shuffling::committees_per_slot(curr_active.len());
    let prev_committees_per_slot = shuffling::committees_per_slot(prev_active.len());
    shuffling::shuffle_list(&mut curr_active, &curr_seed);
    shuffling::shuffle_list(&mut prev_active, &prev_seed);

    let sref = ShufflingRef {
        curr_epoch,
        curr_shuffled: &curr_active,
        curr_committees_per_slot,
        prev_epoch,
        prev_shuffled: &prev_active,
        prev_committees_per_slot,
    };
    let mut votes_sink = Vec::new();
    let mut active_scratch = Vec::new();
    let mut batch = SigBatch::new();
    let sid = s.state_id;
    {
        let (p, eg, _) = s.view();
        let ev = eg.view_opt(sid.epoch_idx);
        if stf::collect_sigs_attestations(
            p.imm,
            &ev,
            &p.validators.reader(),
            &list,
            block_slot,
            Some(&sref),
            &mut active_scratch,
            &mut batch,
        )
        .is_err()
        {
            return false;
        }
    }
    if !batch.verify_all() {
        return false;
    }
    s.with_view_and_epoch(|view, e| {
        stf::process_attestations(
            view,
            *e,
            &list,
            block_slot,
            proposer_index,
            Some(&sref),
            &mut votes_sink,
            &mut active_scratch,
        )
        .is_ok()
    })
}

#[test]
fn fulu_attestation() {
    operations_handler("attestation", "attestation", true, run_attestation);
}

#[test]
fn gloas_attestation() {
    operations_handler_fork("gloas", "attestation", "attestation", true, run_attestation);
}

#[test]
fn fulu_deposit() {
    operations_handler("deposit", "deposit", true, move |s, op| {
        s.with_view(|view| stf::process_deposits(view, op).is_ok())
    });
}

#[test]
fn fulu_voluntary_exit() {
    operations_handler("voluntary_exit", "voluntary_exit", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let (p, _, _) = s.view();
            stf::collect_sigs_voluntary_exits(p.imm, &p.validators.reader(), op, &mut batch);
        }
        let cfg = silver_beacon_state_data::SpecConfig::mainnet();
        if !batch.verify_all() {
            return false;
        }
        s.with_view(|view| stf::process_voluntary_exits(view, &cfg, op).is_ok())
    });
}

#[test]
fn fulu_bls_to_execution_change() {
    operations_handler("bls_to_execution_change", "address_change", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let (p, _, _) = s.view();
            if stf::collect_sigs_bls_to_execution_changes(
                p.imm,
                &p.validators.reader(),
                op,
                &mut batch,
            )
            .is_err()
            {
                return false;
            }
        }
        if !batch.verify_all() {
            return false;
        }
        s.with_view(|p| stf::process_bls_to_execution_changes(&mut p.validators, op).is_ok())
    });
}

#[test]
fn fulu_sync_aggregate() {
    operations_handler("sync_aggregate", "sync_aggregate", true, move |s, op| {
        let block_slot = s.slot();
        let proposer_index;
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        {
            let sid = s.state_id;
            let (mut p, epoch, longtail) = s.view();
            let rv = p.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
            proposer_index =
                rv.epoch.proposer_at((block_slot % SLOTS_PER_EPOCH) as usize).unwrap() as u32;
            stf::collect_sigs_sync_aggregate(&rv, op, block_slot, &mut active_scratch, &mut batch);
        }
        if !batch.verify_all() {
            return false;
        }
        let sid = s.state_id;
        let (mut view, _, longtail) = s.view();
        let longtail_view = longtail.view_opt(sid.longtail_idx);
        let ok = stf::process_sync_aggregate(&mut view, longtail_view, op, proposer_index).is_ok();
        s.state_id = view.commit(sid.epoch_idx, sid.longtail_idx);
        ok
    });
}

#[test]
fn fulu_deposit_request() {
    operations_handler("deposit_request", "deposit_request", false, |s, op| {
        s.with_view(|view| stf::process_deposit_requests(view, op));
        true
    });
}

#[test]
fn fulu_withdrawal_request() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler("withdrawal_request", "withdrawal_request", false, move |s, op| {
        s.with_view(|view| stf::process_withdrawal_requests(view, &cfg, op));
        true
    });
}

#[test]
fn fulu_consolidation_request() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler("consolidation_request", "consolidation_request", false, move |s, op| {
        s.with_view(|view| stf::process_consolidation_requests(view, &cfg, op));
        true
    });
}

#[test]
fn fulu_withdrawals() {
    operations_handler("withdrawals", "execution_payload", true, |s, op| {
        s.with_view(|view| stf::process_withdrawals_fulu(view, op).is_ok())
    });
}

#[test]
fn fulu_execution_payload() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler("execution_payload", "body", false, move |s, op| {
        if op.len() < 396 {
            return true;
        }
        let off = |pos: usize| u32::from_le_bytes(op[pos..pos + 4].try_into().unwrap()) as usize;
        let exec_off = off(380);
        let bls_off = off(384);
        if exec_off < bls_off && bls_off <= op.len() {
            let payload = &op[exec_off..bls_off];
            let block_slot = s.slot();
            s.with_view(|view| {
                let _ = stf::process_execution_payload(view, &cfg, payload, block_slot);
                let _ = stf::process_withdrawals_fulu(view, payload);
            });
        }
        true
    });
}

#[test]
fn gloas_builder_deposit_request() {
    operations_handler_fork(
        "gloas",
        "builder_deposit_request",
        "builder_deposit_request",
        false,
        |s, op| {
            s.with_view(|view| stf::process_builder_deposit_request(view, op));
            true
        },
    );
}

#[test]
fn gloas_builder_exit_request() {
    operations_handler_fork(
        "gloas",
        "builder_exit_request",
        "builder_exit_request",
        false,
        |s, op| {
            let sid = s.state_id;
            let finalized_epoch = {
                let (_, epoch, _) = s.view();
                epoch.view_opt(sid.epoch_idx).state().finalized_checkpoint.epoch
            };
            s.with_view(|view| stf::process_builder_exit_request(view, finalized_epoch, op));
            true
        },
    );
}

#[test]
fn gloas_execution_payload_bid() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler_fork(
        "gloas",
        "execution_payload_bid",
        "execution_payload_bid",
        true,
        move |s, op| {
            let current_epoch = s.slot() / SLOTS_PER_EPOCH;
            let mut batch = SigBatch::new();
            let sid = s.state_id;
            {
                let (p, eg, _) = s.view();
                let ev = eg.view_opt(sid.epoch_idx);
                if stf::collect_sigs_execution_payload_bid(
                    p.imm,
                    &ev,
                    &p.builders.reader(),
                    op,
                    current_epoch,
                    &mut batch,
                )
                .is_err()
                {
                    return false;
                }
            }
            if !batch.verify_all() {
                return false;
            }
            s.with_view_and_epoch(|view, e| {
                stf::process_execution_payload_bid(view, e, &cfg, op).is_ok()
            })
        },
    );
}

#[test]
fn gloas_withdrawals() {
    // Gloas `process_withdrawals` is deterministic (no payload); the EF case
    // carries only pre/post, so this runs like an epoch handler.
    let base = spec_tests_dir().join("tests/mainnet/gloas/operations/withdrawals");
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("gloas withdrawals: no test cases, skipping");
        return;
    }
    let mut fail = 0;
    for (name, dir) in &cases {
        let post_path = dir.join("post.ssz_snappy");
        if !post_path.exists() {
            continue;
        }
        let mut pre = load_state_gloas(&dir.join("pre.ssz_snappy"));
        pre.with_view(|view| stf::process_withdrawals_gloas(view));
        let mut post = load_state_gloas(&post_path);
        let diffs = compare_states(name, &mut pre, &mut post);
        if !diffs.is_empty() {
            fail += 1;
            for d in &diffs {
                eprintln!("{d}");
            }
        }
    }
    assert_eq!(fail, 0, "gloas withdrawals: {fail} test(s) failed");
}

#[test]
fn gloas_parent_execution_payload() {
    let cfg = gloas_cfg();
    operations_handler_fork("gloas", "parent_execution_payload", "block", true, move |s, op| {
        // op is a BeaconBlock: the body offset sits at [80..84).
        if op.len() < 84 {
            return false;
        }
        let body_off = u32::from_le_bytes(op[80..84].try_into().unwrap()) as usize;
        if body_off > op.len() {
            return false;
        }
        let body = &op[body_off..];
        s.with_view_and_epoch(|view, e| {
            stf::process_parent_execution_payload(view, e, &cfg, body).is_ok()
        })
    });
}

#[test]
fn gloas_payload_attestation() {
    operations_handler_fork(
        "gloas",
        "payload_attestation",
        "payload_attestation",
        true,
        |s, op| {
            let state_slot = s.slot();
            let mut batch = SigBatch::new();
            {
                let sid = s.state_id;
                let (p, epoch, _) = s.view();
                let epoch_view = epoch.view_opt(sid.epoch_idx);
                if stf::collect_sigs_payload_attestations(
                    p.imm,
                    &p.validators.reader(),
                    &epoch_view,
                    state_slot,
                    op,
                    &mut batch,
                )
                .is_err()
                {
                    return false;
                }
            }
            if !batch.verify_all() {
                return false;
            }
            // Validation only — no state mutation, so no commit.
            let (p, _, _) = s.view();
            stf::process_payload_attestations(&p, op).is_ok()
        },
    );
}

#[test]
fn fulu_block_header() {
    operations_handler("block_header", "block", true, move |s, op| {
        // op is a BeaconBlock SSZ: slot(8) + proposer_index(8) + parent_root(32) +
        // state_root(32) + body_offset(4) + body(...)
        if op.len() < 84 {
            return false;
        }
        let slot = u64::from_le_bytes(op[0..8].try_into().unwrap());
        let proposer_index = u64::from_le_bytes(op[8..16].try_into().unwrap());
        let parent_root = op[16..48].try_into().unwrap();
        let body_off = u32::from_le_bytes(op[80..84].try_into().unwrap()) as usize;
        let body = if body_off <= op.len() { &op[body_off..] } else { &[] };
        let body_root = silver_beacon_state::ssz_hash::hash_tree_root_body_fulu(body);
        s.with_view_and_epoch(|view, e| {
            stf::process_block_header(view, e, slot, proposer_index, parent_root, body_root).is_ok()
        })
    });
}
