#![cfg(feature = "ef_tests")]

use std::{fs, path::Path};

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state::{
    decompose::decompose_beacon_state, epoch_transition, ssz_hash::compute_zero_hashes, types::*,
};

// Mirror the constants from epoch_transition.
const TIMELY_SOURCE_FLAG: u8 = 1 << 0;
const TIMELY_TARGET_FLAG: u8 = 1 << 1;
const TIMELY_HEAD_FLAG: u8 = 1 << 2;
const PARTICIPATION_FLAGS: [u8; 3] = [TIMELY_SOURCE_FLAG, TIMELY_TARGET_FLAG, TIMELY_HEAD_FLAG];
const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
const WEIGHT_DENOMINATOR: u64 = 64;
const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
const BASE_REWARD_FACTOR: u64 = 64;
const INACTIVITY_SCORE_BIAS: u64 = 4;
const INACTIVITY_PENALTY_QUOTIENT: u64 = 1 << 24;
const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

fn is_active(e: &EpochData, i: usize, epoch: Epoch) -> bool {
    e.val_activation_epoch[i] <= epoch && epoch < e.val_exit_epoch[i]
}

fn is_eligible(e: &EpochData, i: usize, current_epoch: Epoch) -> bool {
    let prev = current_epoch.saturating_sub(1);
    is_active(e, i, prev) || (e.val_slashed(i) && current_epoch < e.val_withdrawable_epoch[i])
}

fn is_in_inactivity_leak(sd: &SlotData) -> bool {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);
    previous_epoch.saturating_sub(sd.finalized_checkpoint.epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

/// Compute per-flag reward/penalty deltas for all validators.
fn compute_flag_deltas(
    vid: &ValidatorIdentity,
    e: &EpochData,
    sd: &SlotData,
    flag_index: usize,
) -> (Vec<u64>, Vec<u64>) {
    let n = vid.validator_cnt;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);

    let mut total_active = 0u64;
    for i in 0..n {
        if is_active(e, i, current_epoch) {
            total_active += e.val_effective_balance[i];
        }
    }
    total_active = total_active.max(EFFECTIVE_BALANCE_INCREMENT);
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;
    let is_leak = is_in_inactivity_leak(sd);

    let flag = PARTICIPATION_FLAGS[flag_index];
    let weight = PARTICIPATION_WEIGHTS[flag_index];

    // Compute unslashed participating increments for this flag.
    let mut flag_increments = 0u64;
    for i in 0..n {
        if !is_active(e, i, previous_epoch) || e.val_slashed(i) {
            continue;
        }
        if sd.previous_epoch_participation[i] & flag != 0 {
            flag_increments += e.val_effective_balance[i] / EFFECTIVE_BALANCE_INCREMENT;
        }
    }
    let active_increments = total_active / EFFECTIVE_BALANCE_INCREMENT;

    let mut rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    for i in 0..n {
        if !is_eligible(e, i, current_epoch) {
            continue;
        }
        let base_reward =
            (e.val_effective_balance[i] / EFFECTIVE_BALANCE_INCREMENT) * base_reward_per_increment;
        let is_unslashed = !e.val_slashed(i);
        let participating = is_unslashed && sd.previous_epoch_participation[i] & flag != 0;

        if participating && !is_leak {
            rewards[i] =
                base_reward * weight * flag_increments / (active_increments * WEIGHT_DENOMINATOR);
        } else if !participating && flag_index != 2 {
            // Head flag (index 2) doesn't penalize.
            penalties[i] = base_reward * weight / WEIGHT_DENOMINATOR;
        }
    }
    (rewards, penalties)
}

fn compute_inactivity_deltas(
    vid: &ValidatorIdentity,
    e: &EpochData,
    sd: &SlotData,
) -> (Vec<u64>, Vec<u64>) {
    let n = vid.validator_cnt;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    for i in 0..n {
        if !is_eligible(e, i, current_epoch) {
            continue;
        }
        let is_unslashed = !e.val_slashed(i);
        let target_ok =
            is_unslashed && sd.previous_epoch_participation[i] & TIMELY_TARGET_FLAG != 0;
        if !target_ok {
            penalties[i] = e.val_effective_balance[i] * e.inactivity_scores[i] /
                (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT);
        }
    }
    (rewards, penalties)
}

/// Decode a Deltas SSZ: Container{rewards: List[uint64, N], penalties:
/// List[uint64, N]}. Fixed part: 2 offsets (8 bytes). Variable: two packed
/// uint64 lists.
fn decode_deltas(ssz: &[u8]) -> (Vec<u64>, Vec<u64>) {
    if ssz.len() < 8 {
        return (vec![], vec![]);
    }
    let off1 = u32::from_le_bytes(ssz[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(ssz[4..8].try_into().unwrap()) as usize;

    let rewards_bytes = &ssz[off1..off2];
    let penalties_bytes = &ssz[off2..];

    let parse_u64_list = |data: &[u8]| -> Vec<u64> {
        data.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    };
    (parse_u64_list(rewards_bytes), parse_u64_list(penalties_bytes))
}

fn run_rewards_handler(handler_name: &str) {
    let base = spec_tests_dir().join("tests/mainnet/fulu/rewards").join(handler_name);
    let Ok(suites) = fs::read_dir(&base) else {
        eprintln!("{handler_name}: no test dir, skipping");
        return;
    };

    let mut pass = 0;
    let mut fail = 0;
    for suite in suites.flatten() {
        if !suite.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(tests) = fs::read_dir(suite.path()) else {
            continue;
        };
        for test in tests.flatten() {
            if !test.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let dir = test.path();
            let name = format!(
                "{}/{}",
                suite.file_name().to_string_lossy(),
                test.file_name().to_string_lossy()
            );
            let pre_path = dir.join("pre.ssz_snappy");
            if !pre_path.exists() {
                continue;
            }

            let ssz = snappy_decode(&pre_path);
            let zh = compute_zero_hashes();
            let mut s = ef_common::LoadedState::blank_pub();
            if decompose_beacon_state(
                &ssz,
                &zh,
                &mut s.imm,
                &mut s.vid,
                &mut s.longtail,
                &mut s.epoch,
                &mut s.roots,
                &mut s.sd,
            )
            .is_none()
            {
                continue;
            }
            let (vid, e, sd) = (s.vid, s.epoch, s.sd);

            let check = |label: &str, ours: &(Vec<u64>, Vec<u64>), expected_path: &Path| -> bool {
                if !expected_path.exists() {
                    return true;
                }
                let exp_ssz = snappy_decode(expected_path);
                let (exp_r, exp_p) = decode_deltas(&exp_ssz);
                let n = ours.0.len().min(exp_r.len());
                let mut ok = true;
                for i in 0..n {
                    if ours.0[i] != exp_r[i] || ours.1[i] != exp_p[i] {
                        if ok {
                            eprintln!(
                                "{name}/{label} mismatch at [{i}]: r={}vs{} p={}vs{}",
                                ours.0[i], exp_r[i], ours.1[i], exp_p[i]
                            );
                        }
                        ok = false;
                    }
                }
                if ours.0.len() != exp_r.len() {
                    eprintln!(
                        "{name}/{label}: length mismatch {} vs {}",
                        ours.0.len(),
                        exp_r.len()
                    );
                    ok = false;
                }
                ok
            };

            let source = compute_flag_deltas(&vid, &e, &sd, 0);
            let target = compute_flag_deltas(&vid, &e, &sd, 1);
            let head = compute_flag_deltas(&vid, &e, &sd, 2);
            let inactivity = compute_inactivity_deltas(&vid, &e, &sd);

            let ok = check("source", &source, &dir.join("source_deltas.ssz_snappy")) &
                check("target", &target, &dir.join("target_deltas.ssz_snappy")) &
                check("head", &head, &dir.join("head_deltas.ssz_snappy")) &
                check(
                    "inactivity",
                    &inactivity,
                    &dir.join("inactivity_penalty_deltas.ssz_snappy"),
                );

            if ok {
                pass += 1;
            } else {
                fail += 1;
            }
        }
    }
    eprintln!("{handler_name}: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "{handler_name}: {fail} test(s) failed");
}

#[test]
fn rewards_basic() {
    run_rewards_handler("basic");
}

#[test]
fn rewards_leak() {
    run_rewards_handler("leak");
}

#[test]
fn rewards_random() {
    run_rewards_handler("random");
}
