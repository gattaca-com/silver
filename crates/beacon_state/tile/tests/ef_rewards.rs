#![cfg(feature = "ef_tests")]

use std::{fs, path::Path};

mod ef_common;

use ef_common::{load_state, snappy_decode, spec_tests_dir};
use silver_beacon_state::epoch_transition;
use silver_beacon_state_data::{Epoch, StateDeltaView};

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

fn is_in_inactivity_leak(view: &StateDeltaView) -> bool {
    let current_epoch = view.current_epoch();
    let previous_epoch = current_epoch.saturating_sub(1);
    let finalized = view.epoch_state().finalized_checkpoint.epoch;
    previous_epoch.saturating_sub(finalized) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

/// Compute per-flag reward/penalty deltas for all validators.
fn compute_flag_deltas(view: &StateDeltaView, flag_index: usize) -> (Vec<u64>, Vec<u64>) {
    let n = view.validators_count();
    let current_epoch = view.current_epoch();
    let previous_epoch = current_epoch.saturating_sub(1);

    let act: Vec<Epoch> = view.iter_activation_epochs().collect();
    let exit: Vec<Epoch> = view.iter_exit_epochs().collect();
    let slashed: Vec<bool> = view.iter_slashed().collect();
    let eff: Vec<u64> = view.iter_validator_effective_balances().collect();
    let withdr: Vec<u64> = (0..n).map(|i| view.validator_withdrawable_epoch(i)).collect();
    let prev_p: Vec<u8> = view.iter_previous_epoch_participants().collect();

    let mut total_active = 0u64;
    for i in 0..n {
        if act[i] <= current_epoch && current_epoch < exit[i] {
            total_active += eff[i];
        }
    }
    total_active = total_active.max(EFFECTIVE_BALANCE_INCREMENT);
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;
    let is_leak = is_in_inactivity_leak(view);

    let flag = PARTICIPATION_FLAGS[flag_index];
    let weight = PARTICIPATION_WEIGHTS[flag_index];

    let mut flag_increments = 0u64;
    for i in 0..n {
        let active_prev = act[i] <= previous_epoch && previous_epoch < exit[i];
        if !active_prev || slashed[i] {
            continue;
        }
        if prev_p[i] & flag != 0 {
            flag_increments += eff[i] / EFFECTIVE_BALANCE_INCREMENT;
        }
    }
    let active_increments = total_active / EFFECTIVE_BALANCE_INCREMENT;

    let mut rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    for i in 0..n {
        let eligible = (act[i] <= previous_epoch && previous_epoch < exit[i]) ||
            (slashed[i] && current_epoch < withdr[i]);
        if !eligible {
            continue;
        }
        let base_reward = (eff[i] / EFFECTIVE_BALANCE_INCREMENT) * base_reward_per_increment;
        let is_unslashed = !slashed[i];
        let participating = is_unslashed && prev_p[i] & flag != 0;

        if participating && !is_leak {
            rewards[i] =
                base_reward * weight * flag_increments / (active_increments * WEIGHT_DENOMINATOR);
        } else if !participating && flag_index != 2 {
            penalties[i] = base_reward * weight / WEIGHT_DENOMINATOR;
        }
    }
    (rewards, penalties)
}

fn compute_inactivity_deltas(view: &StateDeltaView) -> (Vec<u64>, Vec<u64>) {
    let n = view.validators_count();
    let current_epoch = view.current_epoch();
    let previous_epoch = current_epoch.saturating_sub(1);

    let act: Vec<Epoch> = view.iter_activation_epochs().collect();
    let exit: Vec<Epoch> = view.iter_exit_epochs().collect();
    let slashed: Vec<bool> = view.iter_slashed().collect();
    let eff: Vec<u64> = view.iter_validator_effective_balances().collect();
    let withdr: Vec<u64> = (0..n).map(|i| view.validator_withdrawable_epoch(i)).collect();
    let prev_p: Vec<u8> = view.iter_previous_epoch_participants().collect();
    let inact: Vec<u64> = view.iter_inactivity_scores().collect();

    let rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    for i in 0..n {
        let eligible = (act[i] <= previous_epoch && previous_epoch < exit[i]) ||
            (slashed[i] && current_epoch < withdr[i]);
        if !eligible {
            continue;
        }
        let is_unslashed = !slashed[i];
        let target_ok = is_unslashed && prev_p[i] & TIMELY_TARGET_FLAG != 0;
        if !target_ok {
            penalties[i] =
                eff[i] * inact[i] / (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT);
        }
    }
    (rewards, penalties)
}

/// Decode a Deltas SSZ: Container{rewards: List[uint64, N], penalties:
/// List[uint64, N]}. Fixed part: 2 offsets (8 bytes).
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

            let mut s = load_state(&pre_path);

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

            let view = s.view();
            let source = compute_flag_deltas(&view, 0);
            let target = compute_flag_deltas(&view, 1);
            let head = compute_flag_deltas(&view, 2);
            let inactivity = compute_inactivity_deltas(&view);

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
