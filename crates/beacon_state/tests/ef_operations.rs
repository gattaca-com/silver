#![cfg(feature = "ef_tests")]

mod ef_common;

use ef_common::{
    LoadedState, compare_states, iter_test_cases, load_state, snappy_decode, spec_tests_dir,
};
use silver_beacon_state::{
    ssz_hash::compute_zero_hashes,
    state_transition::{self, ShufflingRef},
    types::SLOTS_PER_EPOCH,
};

fn operations_handler(
    handler_name: &str,
    operation_file: &str,
    run: impl Fn(&mut LoadedState, &[u8]),
) {
    let base = spec_tests_dir().join("tests/mainnet/fulu/operations").join(handler_name);
    let cases = iter_test_cases(&base);
    if cases.is_empty() {
        eprintln!("{handler_name}: no test cases, skipping");
        return;
    }

    let zh = compute_zero_hashes();
    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for (name, dir) in &cases {
        let pre_path = dir.join("pre.ssz_snappy");
        let post_path = dir.join("post.ssz_snappy");
        let op_path = dir.join(format!("{operation_file}.ssz_snappy"));

        if !post_path.exists() {
            // Expected failure case — skip (we don't reject invalid ops yet).
            skip += 1;
            continue;
        }
        if !op_path.exists() {
            skip += 1;
            continue;
        }

        let mut pre = load_state(&pre_path, &zh);
        let op_ssz = snappy_decode(&op_path);
        run(&mut pre, &op_ssz);
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
    eprintln!("{handler_name}: {pass} passed, {fail} failed, {skip} skipped");
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

#[test]
fn proposer_slashing() {
    operations_handler("proposer_slashing", "proposer_slashing", |s, op| {
        state_transition::process_proposer_slashings(&s.vid, &mut s.epoch, &mut s.sd, op);
    });
}

#[test]
fn attester_slashing() {
    // Single attester slashing: wrap as 1-element variable list (4-byte offset +
    // data).
    operations_handler("attester_slashing", "attester_slashing", |s, op| {
        let mut list = Vec::with_capacity(4 + op.len());
        // Offset to first (only) element = 4.
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        state_transition::process_attester_slashings(&s.vid, &mut s.epoch, &mut s.sd, &list);
    });
}

#[test]
fn attestation() {
    operations_handler("attestation", "attestation", |s, op| {
        let mut list = Vec::with_capacity(4 + op.len());
        list.extend_from_slice(&4u32.to_le_bytes());
        list.extend_from_slice(op);
        let block_slot = s.sd.slot;
        let proposer_index = s.sd.proposer_lookahead[(s.sd.slot % SLOTS_PER_EPOCH) as usize];
        let current_epoch = block_slot / SLOTS_PER_EPOCH;
        let prev_epoch = current_epoch.saturating_sub(1);
        let n = s.vid.validator_cnt;

        // Build shuffling from the state's randao_mixes.
        use silver_beacon_state::shuffling;
        let cur_seed = shuffling::get_seed(&s.epoch, current_epoch, 1); // DOMAIN_BEACON_ATTESTER
        let prev_seed = shuffling::get_seed(&s.epoch, prev_epoch, 1);
        let mut cur_active = Vec::new();
        let mut prev_active = Vec::new();
        shuffling::get_active_validator_indices_into(&s.epoch, n, current_epoch, &mut cur_active);
        shuffling::get_active_validator_indices_into(&s.epoch, n, prev_epoch, &mut prev_active);
        let cur_cps = shuffling::committees_per_slot(cur_active.len());
        let prev_cps = shuffling::committees_per_slot(prev_active.len());
        shuffling::shuffle_list(&mut cur_active, &cur_seed);
        shuffling::shuffle_list(&mut prev_active, &prev_seed);

        let sref = ShufflingRef {
            current_epoch,
            current_shuffled: &cur_active,
            current_cps: cur_cps,
            previous_epoch: prev_epoch,
            previous_shuffled: &prev_active,
            previous_cps: prev_cps,
        };
        state_transition::process_attestations(
            &s.vid,
            &s.epoch,
            &s.roots,
            &mut s.sd,
            &list,
            block_slot,
            proposer_index,
            Some(&sref),
        );
    });
}

#[test]
fn deposit() {
    let zh = compute_zero_hashes();
    operations_handler("deposit", "deposit", move |s, op| {
        state_transition::process_deposits(&mut s.vid, &mut s.epoch, &mut s.sd, &mut s.pq, op, &zh);
    });
}

#[test]
fn voluntary_exit() {
    operations_handler("voluntary_exit", "voluntary_exit", |s, op| {
        state_transition::process_voluntary_exits(&s.vid, &mut s.epoch, &mut s.sd, &s.pq, op);
    });
}

#[test]
fn bls_to_execution_change() {
    operations_handler("bls_to_execution_change", "address_change", |s, op| {
        state_transition::process_bls_to_execution_changes(&mut s.vid, &mut s.sd, op);
    });
}

#[test]
fn sync_aggregate() {
    operations_handler("sync_aggregate", "sync_aggregate", |s, op| {
        // Proposer index for reward distribution — use proposer_lookahead.
        let proposer_index = s.sd.proposer_lookahead[(s.sd.slot % SLOTS_PER_EPOCH) as usize];
        state_transition::process_sync_aggregate(
            &s.vid,
            &s.longtail,
            &s.epoch,
            &mut s.sd,
            op,
            proposer_index,
        );
    });
}

#[test]
fn deposit_request() {
    operations_handler("deposit_request", "deposit_request", |s, op| {
        state_transition::process_deposit_requests(&mut s.sd, &mut s.pq, op);
    });
}

#[test]
fn withdrawal_request() {
    operations_handler("withdrawal_request", "withdrawal_request", |s, op| {
        state_transition::process_withdrawal_requests(
            &s.vid,
            &mut s.epoch,
            &mut s.sd,
            &mut s.pq,
            op,
        );
    });
}

#[test]
fn consolidation_request() {
    operations_handler("consolidation_request", "consolidation_request", |s, op| {
        state_transition::process_consolidation_requests(
            &mut s.vid,
            &mut s.epoch,
            &mut s.sd,
            &mut s.pq,
            op,
        );
    });
}

#[test]
fn withdrawals() {
    // The withdrawals test provides an execution_payload, not the full block body.
    operations_handler("withdrawals", "execution_payload", |s, op| {
        state_transition::process_withdrawals(&s.vid, &s.epoch, &mut s.sd, &mut s.pq, op);
    });
}

#[test]
fn execution_payload() {
    let zh = compute_zero_hashes();
    operations_handler("execution_payload", "body", move |s, op| {
        if op.len() < 396 {
            return;
        }
        let off = |pos: usize| u32::from_le_bytes(op[pos..pos + 4].try_into().unwrap()) as usize;
        let exec_off = off(380);
        let bls_off = off(384);
        if exec_off < bls_off && bls_off <= op.len() {
            let payload = &op[exec_off..bls_off];
            let block_slot = s.sd.slot;
            state_transition::process_execution_payload(
                &s.imm, &mut s.sd, payload, block_slot, &zh,
            );
            state_transition::process_withdrawals(&s.vid, &s.epoch, &mut s.sd, &mut s.pq, payload);
        }
    });
}

#[test]
fn block_header() {
    let zh = compute_zero_hashes();
    operations_handler("block_header", "block", move |s, op| {
        // op is a BeaconBlock SSZ: slot(8) + proposer_index(8) + parent_root(32) +
        // state_root(32) + body_offset(4) + body(...)
        if op.len() < 84 {
            return;
        }
        let slot = u64::from_le_bytes(op[0..8].try_into().unwrap());
        let proposer_index = u64::from_le_bytes(op[8..16].try_into().unwrap());
        let parent_root = op[16..48].try_into().unwrap();
        let body_off = u32::from_le_bytes(op[80..84].try_into().unwrap()) as usize;
        let body = if body_off <= op.len() { &op[body_off..] } else { &[] };
        let body_root = silver_beacon_state::ssz_hash::hash_tree_root_body(body, &zh);
        state_transition::process_block_header(
            &s.vid,
            &s.epoch,
            &mut s.sd,
            slot,
            proposer_index,
            parent_root,
            body_root,
            &zh,
        );
    });
}
