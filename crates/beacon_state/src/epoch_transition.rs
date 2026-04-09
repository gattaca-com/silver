use core::cmp::{max, min};

use crate::{
    bls,
    shuffling::{self, DOMAIN_BEACON_PROPOSER},
    ssz_hash,
    types::{
        self, B256, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, Epoch,
        EpochData, HistoricalLongtail, HistoricalSummary, MIN_SEED_LOOKAHEAD,
        PROPOSER_LOOKAHEAD_SIZE, PendingQueues, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
        SlotData, SlotRoots, ValidatorIdentity,
    },
};

// Participation flag bits and weights (Altair+).
const TIMELY_SOURCE_FLAG: u8 = 1 << 0;
const TIMELY_TARGET_FLAG: u8 = 1 << 1;
const TIMELY_HEAD_FLAG: u8 = 1 << 2;

const PARTICIPATION_FLAGS: [u8; 3] = [TIMELY_SOURCE_FLAG, TIMELY_TARGET_FLAG, TIMELY_HEAD_FLAG];
const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14]; // source, target, head
const WEIGHT_DENOMINATOR: u64 = 64;

// Balance constants (gwei).
const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
const MAX_EFFECTIVE_BALANCE: u64 = 2048 * EFFECTIVE_BALANCE_INCREMENT;
const MIN_ACTIVATION_BALANCE: u64 = 32 * EFFECTIVE_BALANCE_INCREMENT;
const HYSTERESIS_QUOTIENT: u64 = 4;
const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

// Rewards.
const BASE_REWARD_FACTOR: u64 = 64;

// Inactivity.
const INACTIVITY_SCORE_BIAS: u64 = 4;
const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
const INACTIVITY_PENALTY_QUOTIENT: u64 = 1 << 24;
const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

// Slashing.
const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 3;

// Registry.
const EJECTION_BALANCE: u64 = 16 * EFFECTIVE_BALANCE_INCREMENT;
const MAX_SEED_LOOKAHEAD: u64 = 4;
const CHURN_LIMIT_QUOTIENT: u64 = 1 << 16;
const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 128_000_000_000; // 128 ETH
const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64 = 256_000_000_000; // 256 ETH
pub const MAX_PENDING_DEPOSITS_PER_EPOCH: usize = 16;
const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

// Historical summaries emitted every this many epochs.
const HISTORICAL_SUMMARY_PERIOD: u64 = SLOTS_PER_HISTORICAL_ROOT as u64 / SLOTS_PER_EPOCH;

/// Run all epoch processing sub-functions in Fulu spec order.
#[allow(clippy::too_many_arguments)]
pub fn process_epoch(
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    roots: &SlotRoots,
    zh: &[B256],
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<types::PendingDeposit>,
) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;

    process_justification_and_finalization(epoch, sd, roots, n, current_epoch);
    process_inactivity_updates(epoch, sd, n, current_epoch);
    process_rewards_and_penalties(epoch, sd, n, current_epoch);
    process_registry_updates(epoch, sd, n, current_epoch);
    process_slashings(epoch, sd, n, current_epoch);
    process_eth1_data_reset(sd, current_epoch);
    process_pending_deposits(vid, epoch, sd, pq, zh, postponed_scratch);
    process_pending_consolidations(epoch, sd, pq);
    process_effective_balance_updates(vid, epoch, sd);
    process_slashings_reset(epoch, current_epoch);
    process_randao_mixes_reset(epoch, sd, current_epoch);
    process_historical_summaries_update(longtail, roots, current_epoch, zh);
    process_participation_flag_updates(sd, vid.validator_cnt);
    process_sync_committee_updates(vid, longtail, epoch, current_epoch, active_scratch);
    process_proposer_lookahead(vid, epoch, sd, current_epoch, active_scratch);
}

pub fn process_justification_and_finalization(
    epoch: &EpochData,
    sd: &mut SlotData,
    roots: &SlotRoots,
    n: usize,
    current_epoch: Epoch,
) {
    if current_epoch <= 1 {
        return;
    }

    let previous_epoch = current_epoch - 1;

    let mut total_active: u64 = 0;
    let mut prev_target: u64 = 0;
    let mut curr_target: u64 = 0;

    for i in 0..n {
        let eff = epoch.val_effective_balance[i];

        // total_active_balance uses current_epoch.
        if is_active(epoch, i, current_epoch) {
            total_active += eff;

            if !epoch.val_slashed(i) && sd.current_epoch_participation[i] & TIMELY_TARGET_FLAG != 0
            {
                curr_target += eff;
            }
        }

        // previous_target uses previous_epoch for active check.
        if is_active(epoch, i, previous_epoch) &&
            !epoch.val_slashed(i) &&
            sd.previous_epoch_participation[i] & TIMELY_TARGET_FLAG != 0
        {
            prev_target += eff;
        }
    }
    total_active = total_active.max(EFFECTIVE_BALANCE_INCREMENT);

    let old_prev_justified = sd.previous_justified_checkpoint;
    let old_curr_justified = sd.current_justified_checkpoint;

    sd.previous_justified_checkpoint = sd.current_justified_checkpoint;
    sd.justification_bits = (sd.justification_bits << 1) & 0x0F;

    if prev_target * 3 >= total_active * 2 {
        sd.current_justified_checkpoint = Checkpoint {
            epoch: previous_epoch,
            root: get_block_root_at_epoch(roots, previous_epoch),
        };
        sd.justification_bits |= 0x02; // bit 1
    }
    if curr_target * 3 >= total_active * 2 {
        sd.current_justified_checkpoint = Checkpoint {
            epoch: current_epoch,
            root: get_block_root_at_epoch(roots, current_epoch),
        };
        sd.justification_bits |= 0x01; // bit 0
    }

    let bits = sd.justification_bits;

    if bits & 0x0E == 0x0E && old_prev_justified.epoch + 3 == current_epoch {
        sd.finalized_checkpoint = old_prev_justified;
    }
    if bits & 0x06 == 0x06 && old_prev_justified.epoch + 2 == current_epoch {
        sd.finalized_checkpoint = old_prev_justified;
    }
    if bits & 0x07 == 0x07 && old_curr_justified.epoch + 2 == current_epoch {
        sd.finalized_checkpoint = old_curr_justified;
    }
    if bits & 0x03 == 0x03 && old_curr_justified.epoch + 1 == current_epoch {
        sd.finalized_checkpoint = old_curr_justified;
    }
}

pub fn process_inactivity_updates(
    epoch: &mut EpochData,
    sd: &SlotData,
    n: usize,
    current_epoch: Epoch,
) {
    if current_epoch == 0 {
        return;
    }
    let is_leak = is_in_inactivity_leak(sd);

    for i in 0..n {
        if !is_eligible(epoch, sd, i, current_epoch) {
            continue;
        }

        if sd.previous_epoch_participation[i] & TIMELY_TARGET_FLAG != 0 && !epoch.val_slashed(i) {
            if epoch.inactivity_scores[i] > 0 {
                epoch.inactivity_scores[i] -= 1;
            }
        } else {
            epoch.inactivity_scores[i] += INACTIVITY_SCORE_BIAS;
        }

        if !is_leak {
            let deduction = min(INACTIVITY_SCORE_RECOVERY_RATE, epoch.inactivity_scores[i]);
            epoch.inactivity_scores[i] -= deduction;
        }
    }
}

pub fn process_rewards_and_penalties(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    current_epoch: Epoch,
) {
    if current_epoch == 0 {
        return;
    }
    let total_active = total_active_balance(epoch, n, current_epoch);
    let sqrt_total = integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;
    let is_leak = is_in_inactivity_leak(sd);

    // Pre-compute unslashed participating increments per flag.
    // Uses previous_epoch for active check since participation is from previous
    // epoch.
    let previous_epoch = current_epoch.saturating_sub(1);
    let mut flag_increments = [0u64; 3];
    for i in 0..n {
        if !is_active(epoch, i, previous_epoch) || epoch.val_slashed(i) {
            continue;
        }
        let increments = epoch.val_effective_balance[i] / EFFECTIVE_BALANCE_INCREMENT;
        for (fi, &flag) in PARTICIPATION_FLAGS.iter().enumerate() {
            if sd.previous_epoch_participation[i] & flag != 0 {
                flag_increments[fi] += increments;
            }
        }
    }

    let active_increments = total_active / EFFECTIVE_BALANCE_INCREMENT;

    for i in 0..n {
        if !is_eligible(epoch, sd, i, current_epoch) {
            continue;
        }

        let base_reward = (epoch.val_effective_balance[i] / EFFECTIVE_BALANCE_INCREMENT) *
            base_reward_per_increment;

        let mut reward: u64 = 0;
        let mut penalty: u64 = 0;

        let is_unslashed = !epoch.val_slashed(i);

        // Per-flag deltas.
        for (fi, &flag) in PARTICIPATION_FLAGS.iter().enumerate() {
            let weight = PARTICIPATION_WEIGHTS[fi];
            let participating = is_unslashed && sd.previous_epoch_participation[i] & flag != 0;

            if participating && !is_leak {
                let num = base_reward * weight * flag_increments[fi];
                reward += num / (active_increments * WEIGHT_DENOMINATOR);
            } else if !participating && fi != 2 {
                // Penalise for missing source/target (not head).
                penalty += base_reward * weight / WEIGHT_DENOMINATOR;
            }
        }

        // Inactivity penalty: applied to validators not participating in timely target.
        let target_ok =
            is_unslashed && sd.previous_epoch_participation[i] & TIMELY_TARGET_FLAG != 0;
        if !target_ok {
            let pen_num = epoch.val_effective_balance[i] * epoch.inactivity_scores[i];
            penalty += pen_num / (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT);
        }

        sd.balances[i] = sd.balances[i].saturating_add(reward).saturating_sub(penalty);
    }
}

pub fn process_registry_updates(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    current_epoch: Epoch,
) {
    let activation_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let finalized_epoch = sd.finalized_checkpoint.epoch;

    // Single loop: eligibility, ejection, activation.
    for i in 0..n {
        if is_eligible_for_activation_queue(epoch, i) {
            epoch.val_activation_eligibility_epoch[i] = current_epoch + 1;
        } else if is_active(epoch, i, current_epoch) &&
            epoch.val_effective_balance[i] <= EJECTION_BALANCE
        {
            initiate_validator_exit(epoch, sd, n, i, current_epoch);
        } else if epoch.val_activation_eligibility_epoch[i] <= finalized_epoch &&
            epoch.val_activation_epoch[i] == u64::MAX
        {
            epoch.val_activation_epoch[i] = activation_epoch;
        }
    }
}

/// Churn-limited exit queue.
fn initiate_validator_exit(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    index: usize,
    current_epoch: Epoch,
) {
    if epoch.val_exit_epoch[index] != u64::MAX {
        return;
    }
    let exit_epoch = compute_exit_epoch_and_update_churn(
        epoch,
        sd,
        n,
        epoch.val_effective_balance[index],
        current_epoch,
    );
    epoch.val_exit_epoch[index] = exit_epoch;
    epoch.val_withdrawable_epoch[index] = exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
}

/// Compute the exit epoch for a validator and update churn bookkeeping.
fn compute_exit_epoch_and_update_churn(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let mut earliest = max(sd.earliest_exit_epoch, activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit(epoch, n, current_epoch);

    let mut exit_balance_to_consume = if sd.earliest_exit_epoch < earliest {
        per_epoch_churn
    } else {
        sd.exit_balance_to_consume
    };

    if exit_balance > exit_balance_to_consume {
        let balance_to_process = exit_balance - exit_balance_to_consume;
        let additional_epochs = (balance_to_process - 1) / per_epoch_churn + 1;
        earliest += additional_epochs;
        exit_balance_to_consume += additional_epochs * per_epoch_churn;
    }

    sd.exit_balance_to_consume = exit_balance_to_consume - exit_balance;
    sd.earliest_exit_epoch = earliest;
    earliest
}

fn is_eligible_for_activation_queue(epoch: &EpochData, i: usize) -> bool {
    epoch.val_activation_eligibility_epoch[i] == u64::MAX &&
        epoch.val_effective_balance[i] >= MIN_ACTIVATION_BALANCE
}

pub fn process_slashings(epoch: &EpochData, sd: &mut SlotData, n: usize, current_epoch: Epoch) {
    let total_balance = total_active_balance(epoch, n, current_epoch);

    let sum_slashings: u64 = epoch.slashings.iter().sum();
    let adjusted_total_slashings =
        sum_slashings.saturating_mul(PROPORTIONAL_SLASHING_MULTIPLIER).min(total_balance);

    let target_withdrawable = current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64 / 2;

    let total_increments = total_balance / EFFECTIVE_BALANCE_INCREMENT;
    let penalty_per_increment =
        if total_increments > 0 { adjusted_total_slashings / total_increments } else { 0 };

    for i in 0..n {
        if !epoch.val_slashed(i) {
            continue;
        }
        if epoch.val_withdrawable_epoch[i] != target_withdrawable {
            continue;
        }
        let eff_increments = epoch.val_effective_balance[i] / EFFECTIVE_BALANCE_INCREMENT;
        let penalty = penalty_per_increment * eff_increments;
        sd.balances[i] = sd.balances[i].saturating_sub(penalty);
    }
}

pub fn process_slashings_reset(epoch: &mut EpochData, current_epoch: Epoch) {
    let next_epoch = current_epoch + 1;
    epoch.slashings[next_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR] = 0;
}

pub fn process_effective_balance_updates(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &SlotData,
) {
    let n = vid.validator_cnt;
    let hysteresis_down =
        EFFECTIVE_BALANCE_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER / HYSTERESIS_QUOTIENT;
    let hysteresis_up =
        EFFECTIVE_BALANCE_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER / HYSTERESIS_QUOTIENT;

    for i in 0..n {
        let balance = sd.balances[i];
        let eff = epoch.val_effective_balance[i];
        let max_eff = get_max_effective_balance(vid, i);

        if balance + hysteresis_down < eff || eff + hysteresis_up < balance {
            let new_eff = (balance - balance % EFFECTIVE_BALANCE_INCREMENT).min(max_eff);
            epoch.val_effective_balance[i] = new_eff;
        }
    }
}

/// Compounding (0x02) validators can go up to 2048 ETH.
fn get_max_effective_balance(vid: &ValidatorIdentity, i: usize) -> u64 {
    if vid.val_withdrawal_credentials[i][0] == COMPOUNDING_WITHDRAWAL_PREFIX {
        MAX_EFFECTIVE_BALANCE
    } else {
        MIN_ACTIVATION_BALANCE
    }
}

pub fn process_participation_flag_updates(sd: &mut SlotData, validator_cnt: usize) {
    sd.previous_epoch_participation[..validator_cnt]
        .copy_from_slice(&sd.current_epoch_participation[..validator_cnt]);
    sd.current_epoch_participation[..validator_cnt].fill(0);
}

pub fn process_eth1_data_reset(sd: &mut SlotData, current_epoch: Epoch) {
    let next_epoch = current_epoch + 1;
    if next_epoch.is_multiple_of(types::EPOCHS_PER_ETH1_VOTING_PERIOD) {
        sd.eth1_votes.clear();
    }
}

fn get_balance_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let total = total_active_balance(epoch, n, current_epoch);
    let churn = max(MIN_PER_EPOCH_CHURN_LIMIT, total / CHURN_LIMIT_QUOTIENT);
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

fn get_activation_exit_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    min(MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, get_balance_churn_limit(epoch, n, current_epoch))
}

pub fn process_pending_deposits(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    zh: &[B256],
    postponed: &mut Vec<types::PendingDeposit>,
) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let next_epoch = current_epoch + 1;
    let n = vid.validator_cnt;
    let available =
        sd.deposit_balance_to_consume + get_activation_exit_churn_limit(epoch, n, current_epoch);
    let mut processed_amount: u64 = 0;
    let mut next_deposit_index: usize = 0;
    let mut churn_limit_reached = false;
    let finalized_slot = sd.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;

    postponed.clear();

    let pending_len = pq.pending_deposits.len();
    for idx in 0..pending_len {
        let deposit = pq.pending_deposits[idx];

        // Do not process deposit requests if Eth1 bridge deposits are not yet applied.
        if deposit.slot > 0 && sd.eth1_deposit_index < sd.deposit_requests_start_index {
            break;
        }
        if deposit.slot > finalized_slot {
            break;
        }
        if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH {
            break;
        }

        let vi = find_validator_by_pubkey(vid, &deposit.pubkey);
        let is_exited = vi.is_some_and(|v| epoch.val_exit_epoch[v] != u64::MAX);
        let is_withdrawn = vi.is_some_and(|v| epoch.val_withdrawable_epoch[v] < next_epoch);

        if is_withdrawn {
            apply_pending_deposit(vid, epoch, sd, &deposit, zh);
        } else if is_exited {
            postponed.push(deposit);
        } else {
            if processed_amount + deposit.amount > available {
                churn_limit_reached = true;
                break;
            }
            processed_amount += deposit.amount;
            apply_pending_deposit(vid, epoch, sd, &deposit, zh);
        }
        next_deposit_index += 1;
    }

    // Rebuild queue: remove processed prefix, append postponed.
    pq.pending_deposits.drain(..next_deposit_index);
    pq.pending_deposits.append(postponed);

    if churn_limit_reached {
        sd.deposit_balance_to_consume = available - processed_amount;
    } else {
        sd.deposit_balance_to_consume = 0;
    }
}

fn apply_pending_deposit(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    deposit: &types::PendingDeposit,
    zh: &[B256],
) {
    let vi = find_validator_by_pubkey(vid, &deposit.pubkey);
    if let Some(v) = vi {
        sd.balances[v] = sd.balances[v].saturating_add(deposit.amount);
    } else {
        // New validator: verify deposit signature (proof of possession).
        if !is_valid_deposit_signature(
            &deposit.pubkey,
            &deposit.withdrawal_credentials,
            deposit.amount,
            &deposit.signature,
            zh,
        ) {
            return;
        }
        let idx = vid.validator_cnt;
        vid.val_pubkey[idx] = deposit.pubkey;
        vid.val_withdrawal_credentials[idx] = deposit.withdrawal_credentials;
        epoch.val_effective_balance[idx] = min(
            deposit.amount - deposit.amount % EFFECTIVE_BALANCE_INCREMENT,
            get_max_effective_balance_for_credentials(&deposit.withdrawal_credentials),
        );
        epoch.set_val_slashed(idx, false);
        epoch.val_activation_eligibility_epoch[idx] = u64::MAX;
        epoch.val_activation_epoch[idx] = u64::MAX;
        epoch.val_exit_epoch[idx] = u64::MAX;
        epoch.val_withdrawable_epoch[idx] = u64::MAX;
        epoch.inactivity_scores[idx] = 0;
        sd.balances[idx] = deposit.amount;
        sd.previous_epoch_participation[idx] = 0;
        sd.current_epoch_participation[idx] = 0;
        vid.validator_cnt = idx + 1;
    }
}

pub fn is_valid_deposit_signature(
    pubkey: &[u8; 48],
    withdrawal_credentials: &B256,
    amount: u64,
    signature: &[u8; 96],
    zh: &[B256],
) -> bool {
    // DepositMessage = {pubkey(48), withdrawal_credentials(32), amount(uint64)}.
    // SSZ hash: merkleize([pubkey_root, wc, amount_chunk]).
    let mut pk_chunk = [0u8; 64];
    pk_chunk[..48].copy_from_slice(pubkey);
    let pubkey_root = ssz_hash::sha256(&pk_chunk);
    let mut amount_chunk = [0u8; 32];
    amount_chunk[..8].copy_from_slice(&amount.to_le_bytes());
    let deposit_msg_root =
        ssz_hash::merkleize(&[pubkey_root, *withdrawal_credentials, amount_chunk], zh);

    // Fork-agnostic domain: DOMAIN_DEPOSIT(0x03), GENESIS_FORK_VERSION([0;4]), zero
    // root.
    let domain = {
        let version_chunk = [0u8; 32];
        // GENESIS_FORK_VERSION = 0x00000000, already zero.
        let fork_data_root = ssz_hash::merkleize(&[version_chunk, [0u8; 32]], zh);
        let mut d = [0u8; 32];
        d[0..4].copy_from_slice(&0x03u32.to_le_bytes());
        d[4..32].copy_from_slice(&fork_data_root[..28]);
        d
    };
    let signing_root = ssz_hash::merkleize(&[deposit_msg_root, domain], zh);

    bls::verify_deposit_signature(pubkey, signature, &signing_root)
}

fn get_max_effective_balance_for_credentials(withdrawal_credentials: &B256) -> u64 {
    if withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX {
        MAX_EFFECTIVE_BALANCE
    } else {
        MIN_ACTIVATION_BALANCE
    }
}

fn find_validator_by_pubkey(vid: &ValidatorIdentity, pubkey: &[u8; 48]) -> Option<usize> {
    vid.val_pubkey[..vid.validator_cnt].iter().position(|pk| pk == pubkey)
}

pub fn process_pending_consolidations(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let next_epoch = current_epoch + 1;
    let mut next_pending: usize = 0;

    let pending_len = pq.pending_consolidations.len();
    for idx in 0..pending_len {
        let pc = pq.pending_consolidations[idx];
        let src = pc.source_index as usize;

        if epoch.val_slashed(src) {
            next_pending += 1;
            continue;
        }
        if epoch.val_withdrawable_epoch[src] > next_epoch {
            break;
        }

        let source_eff = min(sd.balances[src], epoch.val_effective_balance[src]);
        sd.balances[src] = sd.balances[src].saturating_sub(source_eff);
        sd.balances[pc.target_index as usize] =
            sd.balances[pc.target_index as usize].saturating_add(source_eff);
        next_pending += 1;
    }

    // Remove processed prefix.
    pq.pending_consolidations.drain(..next_pending);
}

pub fn process_historical_summaries_update(
    longtail: &mut HistoricalLongtail,
    roots: &SlotRoots,
    current_epoch: Epoch,
    zh: &[B256],
) {
    let next_epoch = current_epoch + 1;
    if !next_epoch.is_multiple_of(HISTORICAL_SUMMARY_PERIOD) {
        return;
    }
    let block_summary_root =
        ssz_hash::merkleize_padded(&roots.block_roots, SLOTS_PER_HISTORICAL_ROOT, zh);
    let state_summary_root =
        ssz_hash::merkleize_padded(&roots.state_roots, SLOTS_PER_HISTORICAL_ROOT, zh);
    longtail
        .historical_summaries
        .push(HistoricalSummary { block_summary_root, state_summary_root });
}

pub fn process_randao_mixes_reset(epoch: &mut EpochData, sd: &SlotData, current_epoch: Epoch) {
    let current_idx = current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR;
    let next_idx = (current_epoch + 1) as usize % EPOCHS_PER_HISTORICAL_VECTOR;

    // Commit the per-block accumulated RANDAO mix from SlotData into EpochData.
    epoch.randao_mixes[current_idx] = sd.randao_mix_current;
    // Copy to next epoch as the starting point.
    epoch.randao_mixes[next_idx] = sd.randao_mix_current;
}

pub fn process_sync_committee_updates(
    vid: &ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &EpochData,
    current_epoch: Epoch,
    active_scratch: &mut Vec<u32>,
) {
    let next_epoch = current_epoch + 1;
    if !next_epoch.is_multiple_of(types::EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
        return;
    }
    // Rotate: current = next, compute new next.
    longtail.current_sync_committee = longtail.next_sync_committee;

    // get_next_sync_committee_indices.
    let sync_epoch = next_epoch;
    let seed = shuffling::get_seed(epoch, sync_epoch, 7); // DOMAIN_SYNC_COMMITTEE
    shuffling::get_active_validator_indices_into(
        epoch,
        vid.validator_cnt,
        sync_epoch,
        active_scratch,
    );
    if active_scratch.is_empty() {
        return;
    }

    let mut new_committee = longtail.next_sync_committee;
    let mut sampler = shuffling::WeightedSampler::new(&seed, active_scratch.len());
    let mut selected = 0usize;

    while selected < types::SYNC_COMMITTEE_SIZE {
        let (candidate, accepted) = sampler.next(active_scratch, &epoch.val_effective_balance);
        if accepted {
            new_committee.pubkeys[selected] = vid.val_pubkey[candidate];
            selected += 1;
        }
    }

    // Aggregate pubkey — requires BLS aggregation.
    new_committee.aggregate_pubkey = bls::aggregate_pubkeys(&new_committee.pubkeys);

    longtail.next_sync_committee = new_committee;

    // Rebuild sync_committee_indices for the new current committee.
    rebuild_sync_committee_indices(vid, longtail);
}

/// Rebuild the sync_committee_indices cache from current_sync_committee
/// pubkeys.
// TODO(perf): O(SYNC_COMMITTEE_SIZE × n_validators) — 512 × 2M = 1B
// comparisons per sync rotation. Use the per-VID-tier pubkey index proposed
// at find_validator_by_pubkey for O(committee × log n) or O(committee).
pub fn rebuild_sync_committee_indices(vid: &ValidatorIdentity, longtail: &mut HistoricalLongtail) {
    for i in 0..types::SYNC_COMMITTEE_SIZE {
        let target_pk = &longtail.current_sync_committee.pubkeys[i];
        longtail.sync_committee_indices[i] = u32::MAX; // sentinel: not found
        for vi in 0..vid.validator_cnt {
            if &vid.val_pubkey[vi] == target_pk {
                longtail.sync_committee_indices[i] = vi as u32;
                break;
            }
        }
    }
}

pub fn process_proposer_lookahead(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &mut SlotData,
    current_epoch: Epoch,
    active_scratch: &mut Vec<u32>,
) {
    let slots_per_epoch = SLOTS_PER_EPOCH as usize;
    let last_epoch_start = PROPOSER_LOOKAHEAD_SIZE - slots_per_epoch;

    // Shift: drop first epoch, slide the rest down.
    sd.proposer_lookahead.copy_within(slots_per_epoch.., 0);

    // Fill the last epoch with new proposer indices.
    let target_epoch = current_epoch + MIN_SEED_LOOKAHEAD + 1;
    shuffling::get_active_validator_indices_into(
        epoch,
        vid.validator_cnt,
        target_epoch,
        active_scratch,
    );
    // Seed uses DOMAIN_BEACON_PROPOSER = 0.
    let seed = shuffling::get_seed(epoch, target_epoch, DOMAIN_BEACON_PROPOSER);

    for i in 0..slots_per_epoch {
        let slot = target_epoch * SLOTS_PER_EPOCH + i as u64;
        let proposer = shuffling::compute_proposer_index(epoch, active_scratch, slot, &seed);
        sd.proposer_lookahead[last_epoch_start + i] = proposer as u64;
    }
}

fn is_active(epoch: &EpochData, i: usize, e: Epoch) -> bool {
    epoch.val_activation_epoch[i] <= e && e < epoch.val_exit_epoch[i]
}

/// Eligible for rewards/penalties: active in previous epoch OR
/// slashed-but-not-yet-withdrawable.
fn is_eligible(epoch: &EpochData, _sd: &SlotData, i: usize, current_epoch: Epoch) -> bool {
    let prev = current_epoch.saturating_sub(1);
    is_active(epoch, i, prev) ||
        (epoch.val_slashed(i) && current_epoch < epoch.val_withdrawable_epoch[i])
}

fn is_in_inactivity_leak(sd: &SlotData) -> bool {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);
    // Spec: previous_epoch - finalized > MIN_EPOCHS_TO_INACTIVITY_PENALTY (4).
    previous_epoch.saturating_sub(sd.finalized_checkpoint.epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

fn total_active_balance(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let mut total: u64 = 0;
    for i in 0..n {
        if is_active(epoch, i, current_epoch) {
            total += epoch.val_effective_balance[i];
        }
    }
    total.max(EFFECTIVE_BALANCE_INCREMENT)
}

pub fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn get_block_root_at_epoch(roots: &SlotRoots, epoch: Epoch) -> B256 {
    let slot = epoch * SLOTS_PER_EPOCH;
    roots.block_roots[slot as usize % SLOTS_PER_HISTORICAL_ROOT]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::box_zeroed;

    const MAX_EFFECTIVE_BALANCE: u64 = 32 * EFFECTIVE_BALANCE_INCREMENT;

    fn checkpoint(epoch: Epoch, tag: u8) -> Checkpoint {
        let mut root = [0u8; 32];
        root[0] = tag;
        Checkpoint { epoch, root }
    }

    /// Build the deposit signing root for a (pubkey, wc, amount) triple.
    fn deposit_signing_root(pubkey: &[u8; 48], wc: &B256, amount: u64, zh: &[B256]) -> B256 {
        let mut pk_chunk = [0u8; 64];
        pk_chunk[..48].copy_from_slice(pubkey);
        let pubkey_root = ssz_hash::sha256(&pk_chunk);
        let mut amt = [0u8; 32];
        amt[..8].copy_from_slice(&amount.to_le_bytes());
        let msg_root = ssz_hash::merkleize(&[pubkey_root, *wc, amt], zh);

        let version_chunk = [0u8; 32];
        let fork_data_root = ssz_hash::merkleize(&[version_chunk, [0u8; 32]], zh);
        let mut domain = [0u8; 32];
        domain[0..4].copy_from_slice(&0x03u32.to_le_bytes());
        domain[4..32].copy_from_slice(&fork_data_root[..28]);
        ssz_hash::merkleize(&[msg_root, domain], zh)
    }

    #[test]
    fn pending_deposit_valid_sig_adds_validator() {
        use blst::min_pk::SecretKey;

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut e: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();

        let current_epoch = 10u64;
        sd.slot = current_epoch * SLOTS_PER_EPOCH;
        sd.finalized_checkpoint = checkpoint(current_epoch, 0x01);
        vid.validator_cnt = 0;

        // Build a deposit with a valid BLS signature.
        let sk_bytes: [u8; 32] = [
            0x26, 0x3d, 0xbd, 0x79, 0x2f, 0x5b, 0x1b, 0xe4, 0x7e, 0xd8, 0x5f, 0x89, 0x38, 0xc0,
            0xf2, 0x95, 0x86, 0xaf, 0x0d, 0x3a, 0xc7, 0xb9, 0x77, 0xf2, 0x1c, 0x27, 0x8f, 0xe1,
            0x46, 0x20, 0x40, 0xe3,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.sk_to_pk().to_bytes();
        let wc = [0xAAu8; 32];
        let amount = 32_000_000_000u64;

        let zh = ssz_hash::compute_zero_hashes();
        let signing_root = deposit_signing_root(&pk, &wc, amount, &zh);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let sig = sk.sign(&signing_root, dst, &[]).to_bytes();

        pq.pending_deposits.push(types::PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
            signature: sig,
            slot: 0, // genesis deposit
        });

        process_pending_deposits(&mut vid, &mut e, &mut sd, &mut pq, &zh, &mut Vec::new());

        assert_eq!(vid.validator_cnt, 1);
        assert_eq!(vid.val_pubkey[0], pk);
        assert_eq!(sd.balances[0], amount);
        assert_eq!(pq.pending_deposits.len(), 0);
    }

    #[test]
    fn pending_deposit_invalid_sig_rejected() {
        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut e: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();

        let current_epoch = 10u64;
        sd.slot = current_epoch * SLOTS_PER_EPOCH;
        sd.finalized_checkpoint = checkpoint(current_epoch, 0x01);
        vid.validator_cnt = 0;

        // Deposit with zeroed (invalid) signature.
        let zh = ssz_hash::compute_zero_hashes();
        let pk = [0x01u8; 48]; // invalid pubkey too, but sig check comes first via blst
        pq.pending_deposits.push(types::PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: [0u8; 32],
            amount: 32_000_000_000,
            signature: [0u8; 96],
            slot: 0,
        });

        process_pending_deposits(&mut vid, &mut e, &mut sd, &mut pq, &zh, &mut Vec::new());

        // Deposit consumed from queue but validator NOT added.
        assert_eq!(vid.validator_cnt, 0);
        assert_eq!(pq.pending_deposits.len(), 0);
    }

    #[test]
    fn pending_deposit_existing_validator_no_sig_check() {
        use blst::min_pk::SecretKey;

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut e: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();

        let current_epoch = 10u64;
        sd.slot = current_epoch * SLOTS_PER_EPOCH;
        sd.finalized_checkpoint = checkpoint(current_epoch, 0x01);

        // Pre-existing validator.
        let sk_bytes: [u8; 32] = [
            0x26, 0x3d, 0xbd, 0x79, 0x2f, 0x5b, 0x1b, 0xe4, 0x7e, 0xd8, 0x5f, 0x89, 0x38, 0xc0,
            0xf2, 0x95, 0x86, 0xaf, 0x0d, 0x3a, 0xc7, 0xb9, 0x77, 0xf2, 0x1c, 0x27, 0x8f, 0xe1,
            0x46, 0x20, 0x40, 0xe3,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.sk_to_pk().to_bytes();

        vid.val_pubkey[0] = pk;
        e.val_activation_epoch[0] = 0;
        e.val_exit_epoch[0] = u64::MAX;
        e.val_effective_balance[0] = MAX_EFFECTIVE_BALANCE;
        sd.balances[0] = MAX_EFFECTIVE_BALANCE;
        vid.validator_cnt = 1;

        // Deposit to existing validator — signature is ignored per spec.
        let zh = ssz_hash::compute_zero_hashes();
        let top_up = 1_000_000_000u64;
        pq.pending_deposits.push(types::PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: [0u8; 32],
            amount: top_up,
            signature: [0u8; 96], // invalid sig, doesn't matter
            slot: 0,
        });

        process_pending_deposits(&mut vid, &mut e, &mut sd, &mut pq, &zh, &mut Vec::new());

        assert_eq!(vid.validator_cnt, 1);
        assert_eq!(sd.balances[0], MAX_EFFECTIVE_BALANCE + top_up);
        assert_eq!(pq.pending_deposits.len(), 0);
    }
}
