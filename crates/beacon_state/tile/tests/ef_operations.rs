#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{
    LoadedState, compare_states, iter_test_cases, load_state, snappy_decode, spec_tests_dir,
};
use silver_beacon_state::{
    bls::SigBatch,
    shuffling,
    state_transition::{self, ShufflingRef},
};
use silver_beacon_state_data::{SLOTS_PER_EPOCH, StateDeltaView};

fn operations_handler(
    handler_name: &str,
    operation_file: &str,
    detects_reject: bool,
    run: impl Fn(&mut LoadedState, &[u8]) -> bool,
) {
    let base = spec_tests_dir().join("tests/mainnet/fulu/operations").join(handler_name);
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

        let mut pre = load_state(&pre_path);
        let op_ssz = snappy_decode(&op_path);

        if !post_path.exists() {
            if !detects_reject {
                skip += 1;
                continue;
            }
            // Expected-reject case: op must be rejected and pre-state
            // must not be mutated past the rejection point.
            let mut pre_snapshot = load_state(&pre_path);
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
    eprintln!("{handler_name}: {pass} passed, {fail} failed, {skip} skipped");
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

fn view_mut(s: &mut LoadedState) -> StateDeltaView<'_> {
    s.view()
}

fn view_ref(s: &mut LoadedState) -> StateDeltaView<'_> {
    s.view()
}

#[test]
fn proposer_slashing() {
    operations_handler("proposer_slashing", "proposer_slashing", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let v = view_ref(s);
            if state_transition::collect_sigs_proposer_slashings(&v, op, &mut batch).is_err() {
                return false;
            }
        }
        let cfg = silver_beacon_state_data::SpecConfig::mainnet();
        if !batch.verify_all() {
            return false;
        }
        let mut vm = view_mut(s);
        state_transition::process_proposer_slashings(&cfg, &mut vm, op).is_ok()
    });
}

#[test]
fn attester_slashing() {
    operations_handler("attester_slashing", "attester_slashing", true, move |s, op| {
        // The op SSZ here is a single AttesterSlashing; wrap as a List[1].
        let mut list = Vec::with_capacity(4 + op.len());
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        {
            let v = view_ref(s);
            if state_transition::collect_sigs_attester_slashings(
                &v,
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
        let mut vm = view_mut(s);
        let mut scratch = Vec::new();
        state_transition::process_attester_slashings(&cfg, &mut vm, &list, &mut scratch).is_ok()
    });
}

#[test]
fn attestation() {
    operations_handler("attestation", "attestation", true, move |s, op| {
        let mut list = Vec::with_capacity(4 + op.len());
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        let block_slot = s.delta.slot.slot.slot;
        let curr_epoch = block_slot / SLOTS_PER_EPOCH;
        let prev_epoch = curr_epoch.saturating_sub(1);

        let proposer_index;
        let curr_seed;
        let prev_seed;
        let mut curr_active = Vec::new();
        let mut prev_active = Vec::new();
        {
            let v = view_ref(s);
            proposer_index =
                v.epoch_state().proposer_lookahead[(block_slot % SLOTS_PER_EPOCH) as usize] as u32;
            curr_seed =
                shuffling::get_seed_from_state(&v, curr_epoch, shuffling::DOMAIN_BEACON_ATTESTER);
            prev_seed =
                shuffling::get_seed_from_state(&v, prev_epoch, shuffling::DOMAIN_BEACON_ATTESTER);
            shuffling::get_active_validator_indices_into(&v, curr_epoch, &mut curr_active);
            shuffling::get_active_validator_indices_into(&v, prev_epoch, &mut prev_active);
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
        {
            let v = view_ref(s);
            if state_transition::collect_sigs_attestations(
                &v,
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
        let mut vm = view_mut(s);
        state_transition::process_attestations(
            &mut vm,
            &list,
            block_slot,
            proposer_index,
            Some(&sref),
            &mut votes_sink,
            &mut active_scratch,
        )
        .is_ok()
    });
}

#[test]
fn deposit() {
    operations_handler("deposit", "deposit", true, move |s, op| {
        let mut vm = view_mut(s);
        state_transition::process_deposits(&mut vm, op).is_ok()
    });
}

#[test]
fn voluntary_exit() {
    operations_handler("voluntary_exit", "voluntary_exit", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let v = view_ref(s);
            state_transition::collect_sigs_voluntary_exits(&v, op, &mut batch);
        }
        let cfg = silver_beacon_state_data::SpecConfig::mainnet();
        if !batch.verify_all() {
            return false;
        }
        let mut vm = view_mut(s);
        state_transition::process_voluntary_exits(&cfg, &mut vm, op).is_ok()
    });
}

#[test]
fn bls_to_execution_change() {
    operations_handler("bls_to_execution_change", "address_change", true, move |s, op| {
        let mut batch = SigBatch::new();
        {
            let v = view_ref(s);
            if state_transition::collect_sigs_bls_to_execution_changes(&v, op, &mut batch).is_err()
            {
                return false;
            }
        }
        if !batch.verify_all() {
            return false;
        }
        let mut vm = view_mut(s);
        state_transition::process_bls_to_execution_changes(&mut vm, op).is_ok()
    });
}

#[test]
fn sync_aggregate() {
    operations_handler("sync_aggregate", "sync_aggregate", true, move |s, op| {
        let block_slot = s.delta.slot.slot.slot;
        let proposer_index;
        let mut active_scratch = Vec::new();
        let mut batch = SigBatch::new();
        {
            let v = view_ref(s);
            proposer_index =
                v.epoch_state().proposer_lookahead[(block_slot % SLOTS_PER_EPOCH) as usize] as u32;
            state_transition::collect_sigs_sync_aggregate(
                &v,
                op,
                block_slot,
                &mut active_scratch,
                &mut batch,
            );
        }
        if !batch.verify_all() {
            return false;
        }
        let mut vm = view_mut(s);
        state_transition::process_sync_aggregate(&mut vm, op, proposer_index).is_ok()
    });
}

#[test]
fn deposit_request() {
    operations_handler("deposit_request", "deposit_request", false, |s, op| {
        let mut vm = view_mut(s);
        state_transition::process_deposit_requests(&mut vm, op);
        true
    });
}

#[test]
fn withdrawal_request() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler("withdrawal_request", "withdrawal_request", false, move |s, op| {
        let mut vm = view_mut(s);
        state_transition::process_withdrawal_requests(&cfg, &mut vm, op);
        true
    });
}

#[test]
fn consolidation_request() {
    let cfg = silver_beacon_state_data::SpecConfig::mainnet();
    operations_handler("consolidation_request", "consolidation_request", false, move |s, op| {
        let mut vm = view_mut(s);
        state_transition::process_consolidation_requests(&cfg, &mut vm, op);
        true
    });
}

#[test]
fn withdrawals() {
    operations_handler("withdrawals", "execution_payload", true, |s, op| {
        let mut vm = view_mut(s);
        state_transition::process_withdrawals(&mut vm, op).is_ok()
    });
}

#[test]
fn execution_payload() {
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
            let block_slot = s.delta.slot.slot.slot;
            let mut vm = view_mut(s);
            let _ = state_transition::process_execution_payload(&cfg, &mut vm, payload, block_slot);
            let _ = state_transition::process_withdrawals(&mut vm, payload);
        }
        true
    });
}

#[test]
fn block_header() {
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
        let body_root = silver_beacon_state::ssz_hash::hash_tree_root_body(body);
        let mut vm = view_mut(s);
        state_transition::process_block_header(
            &mut vm,
            slot,
            proposer_index,
            parent_root,
            body_root,
        )
        .is_ok()
    });
}
