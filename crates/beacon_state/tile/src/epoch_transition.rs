use core::cmp::{max, min};

use silver_beacon_state_data::{
    self as common, Checkpoint, EPOCHS_PER_SLASHINGS_VECTOR, Epoch, EpochView, EpochWriteView,
    Eth1WriteView, HistoricalSummary, LongtailGroup, LongtailId, LongtailWriteView,
    MIN_SEED_LOOKAHEAD, PROPOSER_LOOKAHEAD_SIZE, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
    SYNC_COMMITTEE_SIZE, SpecConfig, StateWriterView, iter_validator_rows,
};
use silver_common::metrics::timed;

use crate::{
    bls,
    shuffling::{self, DOMAIN_BEACON_PROPOSER},
    ssz_hash,
    state_transition::{StfScratch, total_active_balance},
};

pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

// Participation flag bits and weights (Altair+).
const TIMELY_SOURCE_FLAG: u8 = 1 << 0;
const TIMELY_TARGET_FLAG: u8 = 1 << 1;
const TIMELY_HEAD_FLAG: u8 = 1 << 2;

const PARTICIPATION_FLAGS: [u8; 3] = [TIMELY_SOURCE_FLAG, TIMELY_TARGET_FLAG, TIMELY_HEAD_FLAG];
const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
pub(crate) const WEIGHT_DENOMINATOR: u64 = 64;
pub(crate) const PROPOSER_WEIGHT: u64 = 8;

// Balance constants (gwei).
pub(crate) const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
const MIN_ACTIVATION_BALANCE: u64 = 32 * EFFECTIVE_BALANCE_INCREMENT;
const HYSTERESIS_QUOTIENT: u64 = 4;
const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

// Rewards.
pub(crate) const BASE_REWARD_FACTOR: u64 = 64;

// Registry.
pub const MAX_PENDING_DEPOSITS_PER_EPOCH: usize = 16;

// Historical summaries emitted every this many epochs.
pub const HISTORICAL_SUMMARY_PERIOD: u64 = SLOTS_PER_HISTORICAL_ROOT as u64 / SLOTS_PER_EPOCH;

/// Run all epoch processing sub-functions in Fulu spec order. `epoch` is the
/// fork's private boundary writer, rolled and HELD by `process_slots` at the
/// advance's first boundary (one ring entry per advance, however many
/// boundaries it crosses). The longtail writer rolls here iff a rotation gate
/// fires and commits at the end, storing its id in `longtail_idx` — so a
/// second boundary in the same advance derives from the first's committed
/// entry (publish-last like the slot tiers).
#[timed]
pub fn process_epoch(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochWriteView,
    longtail: &mut LongtailGroup,
    longtail_idx: &mut Option<LongtailId>,
    scratch: &mut StfScratch,
) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    // Longtail boundary roll: once iff either rotation gate fires, derived
    // from the inherited entry (fresh off the base when no ancestor rotated).
    let next_epoch = current_epoch + 1;
    let rotates_summary = next_epoch.is_multiple_of(HISTORICAL_SUMMARY_PERIOD);
    let rotates_sync_committee = next_epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    let needs_longtail = rotates_sync_committee || rotates_summary;
    let mut longtail_w = needs_longtail.then(|| longtail.roll_inheriting(*longtail_idx));

    process_justification_and_finalization(view, epoch, current_epoch);
    process_inactivity_updates(cfg, view, &epoch.reader(), current_epoch, &mut scratch.replace_u64);
    process_rewards_and_penalties(
        cfg,
        view,
        &epoch.reader(),
        current_epoch,
        &mut scratch.replace_u64,
    );
    process_registry_updates(cfg, view, &epoch.reader(), current_epoch);
    process_slashings(cfg, view, &epoch.reader(), current_epoch);
    process_eth1_data_reset(&mut view.eth1, current_epoch);
    process_pending_deposits(cfg, view, epoch, &mut scratch.postponed);
    process_pending_consolidations(view);
    process_effective_balance_updates(view);
    process_slashings_reset(view, epoch);
    process_randao_mixes_reset(view, epoch);
    if rotates_summary {
        let lt = longtail_w.as_mut().expect("longtail rolled at boundary");
        process_historical_summaries_update(view, lt, &mut scratch.state_hash);
    }
    process_participation_flag_updates(view, &mut scratch.replace_u8);
    if rotates_sync_committee {
        let lt = longtail_w.as_mut().expect("longtail rolled at boundary");
        process_sync_committee_updates(
            view,
            &epoch.reader(),
            lt,
            current_epoch,
            &mut scratch.active,
            &mut scratch.eff,
        );
    }
    process_proposer_lookahead(view, epoch, current_epoch, &mut scratch.active, &mut scratch.eff);

    // Commit the boundary-rolled longtail entry: its id surfaces only here,
    // after the rotation leaves are done mutating it.
    if let Some(w) = longtail_w {
        *longtail_idx = Some(w.commit());
    }
}

#[timed]
pub fn process_justification_and_finalization(
    view: &mut StateWriterView,
    epoch: &mut EpochWriteView,
    current_epoch: Epoch,
) {
    if current_epoch <= 1 {
        return;
    }
    let previous_epoch = current_epoch - 1;

    // Single zipped read sweep over merged validator rows.
    let (mut total_active, mut curr_target, mut prev_target) = (0u64, 0u64, 0u64);
    for r in validator_rows(view) {
        if r.activation_epoch <= current_epoch && current_epoch < r.exit_epoch {
            total_active += r.effective_balance;
            if !r.slashed && r.current_participation & TIMELY_TARGET_FLAG != 0 {
                curr_target += r.effective_balance;
            }
        }
        if r.activation_epoch <= previous_epoch &&
            previous_epoch < r.exit_epoch &&
            !r.slashed &&
            r.previous_participation & TIMELY_TARGET_FLAG != 0
        {
            prev_target += r.effective_balance;
        }
    }
    total_active = total_active.max(EFFECTIVE_BALANCE_INCREMENT);

    let prev_root = if prev_target * 3 >= total_active * 2 {
        Some(view.slot.block_root_at_slot(previous_epoch * SLOTS_PER_EPOCH))
    } else {
        None
    };
    let curr_root = if curr_target * 3 >= total_active * 2 {
        Some(view.slot.block_root_at_slot(current_epoch * SLOTS_PER_EPOCH))
    } else {
        None
    };

    let es = epoch.state_mut();
    let old_prev_justified = es.previous_justified_checkpoint;
    let old_curr_justified = es.current_justified_checkpoint;
    es.previous_justified_checkpoint = es.current_justified_checkpoint;
    es.justification_bits = (es.justification_bits << 1) & 0x0F;

    if let Some(root) = prev_root {
        es.current_justified_checkpoint = Checkpoint { epoch: previous_epoch, root };
        es.justification_bits |= 0x02;
    }
    if let Some(root) = curr_root {
        es.current_justified_checkpoint = Checkpoint { epoch: current_epoch, root };
        es.justification_bits |= 0x01;
    }

    let bits = es.justification_bits;
    if bits & 0x0E == 0x0E && old_prev_justified.epoch + 3 == current_epoch {
        es.finalized_checkpoint = old_prev_justified;
    }
    if bits & 0x06 == 0x06 && old_prev_justified.epoch + 2 == current_epoch {
        es.finalized_checkpoint = old_prev_justified;
    }
    if bits & 0x07 == 0x07 && old_curr_justified.epoch + 2 == current_epoch {
        es.finalized_checkpoint = old_curr_justified;
    }
    if bits & 0x03 == 0x03 && old_curr_justified.epoch + 1 == current_epoch {
        es.finalized_checkpoint = old_curr_justified;
    }
}

#[timed]
pub fn process_inactivity_updates(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &EpochView,
    current_epoch: Epoch,
    scratch: &mut Vec<(u32, u64)>,
) {
    if current_epoch == 0 {
        return;
    }
    let is_leak = is_inactivity_leak(cfg, epoch, current_epoch);

    scratch.clear();
    for (i, r) in validator_rows(view).enumerate() {
        let new = if !eligibility(&r, current_epoch) {
            r.inactivity_score
        } else {
            let mut s = r.inactivity_score;
            if r.previous_participation & TIMELY_TARGET_FLAG != 0 && !r.slashed {
                s = s.saturating_sub(1);
            } else {
                s += cfg.inactivity_score_bias;
            }
            if !is_leak {
                s -= min(cfg.inactivity_score_recovery_rate, s);
            }
            s
        };
        // Only changed scores: set_many's cost is per touched chunk, and in a
        // healthy (non-leak) chain nearly every score is 0 and stays 0.
        if new != r.inactivity_score {
            scratch.push((i as u32, new));
        }
    }
    view.inactivity.set_many(scratch);
}

#[timed]
pub fn process_rewards_and_penalties(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &EpochView,
    current_epoch: Epoch,
    scratch: &mut Vec<(u32, u64)>,
) {
    if current_epoch == 0 {
        return;
    }
    let total_active = total_active_balance(&view.validators.reader(), current_epoch);
    let sqrt_total = integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;
    let is_leak = is_inactivity_leak(cfg, epoch, current_epoch);

    let previous_epoch = current_epoch.saturating_sub(1);

    // Pass 1: flag-weighted active increments (pure read sweep).
    let mut flag_increments = [0u64; 3];
    for r in validator_rows(view) {
        if r.activation_epoch > previous_epoch || previous_epoch >= r.exit_epoch || r.slashed {
            continue;
        }
        let incs = r.effective_balance / EFFECTIVE_BALANCE_INCREMENT;
        for (fi, &flag) in PARTICIPATION_FLAGS.iter().enumerate() {
            if r.previous_participation & flag != 0 {
                flag_increments[fi] += incs;
            }
        }
    }
    let active_increments = total_active / EFFECTIVE_BALANCE_INCREMENT;

    // Pass 2: per-validator reward/penalty → changed balances into scratch.
    scratch.clear();
    for (i, r) in validator_rows(view).enumerate() {
        if !eligibility(&r, current_epoch) {
            continue;
        }
        let base_reward =
            (r.effective_balance / EFFECTIVE_BALANCE_INCREMENT) * base_reward_per_increment;
        let is_unslashed = !r.slashed;
        let mut reward: u64 = 0;
        let mut penalty: u64 = 0;
        for (fi, &flag) in PARTICIPATION_FLAGS.iter().enumerate() {
            let weight = PARTICIPATION_WEIGHTS[fi];
            let participating = is_unslashed && r.previous_participation & flag != 0;
            if participating && !is_leak {
                let num = base_reward * weight * flag_increments[fi];
                reward += num / (active_increments * WEIGHT_DENOMINATOR);
            } else if !participating && fi != 2 {
                penalty += base_reward * weight / WEIGHT_DENOMINATOR;
            }
        }
        let target_ok = is_unslashed && r.previous_participation & TIMELY_TARGET_FLAG != 0;
        if !target_ok {
            let pen_num = r.effective_balance * r.inactivity_score;
            penalty += pen_num / (cfg.inactivity_score_bias * cfg.inactivity_penalty_quotient);
        }
        let new = r.balance.saturating_add(reward).saturating_sub(penalty);
        if new != r.balance {
            scratch.push((i as u32, new));
        }
    }
    view.balances.set_many(scratch);
}

#[timed]
pub fn process_registry_updates(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &EpochView,
    current_epoch: Epoch,
) {
    let activation_epoch_new = current_epoch + 1 + cfg.max_seed_lookahead;
    let finalized_epoch = epoch.state().finalized_checkpoint.epoch;
    let n = view.validators.count();

    for i in 0..n {
        let vi = i as u32;
        let effective_balance = view.validators.effective_balance(i);
        let elig = view.validators.activation_eligibility_epoch(i);
        let act = view.validators.activation_epoch(i);
        let exit = view.validators.exit_epoch(i);

        let in_queue = elig == u64::MAX && effective_balance >= MIN_ACTIVATION_BALANCE;
        let active_now = act <= current_epoch && current_epoch < exit;

        if in_queue {
            view.validators.set_activation_eligibility_epoch(vi, current_epoch + 1);
        } else if active_now && effective_balance <= cfg.ejection_balance {
            initiate_validator_exit(cfg, view, vi, current_epoch);
        } else if elig <= finalized_epoch && act == u64::MAX {
            view.validators.set_activation_epoch(vi, activation_epoch_new);
        }
    }
}

#[timed]
pub fn process_slashings(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &EpochView,
    current_epoch: Epoch,
) {
    let total_balance = total_active_balance(&view.validators.reader(), current_epoch);

    let mut sum_slashings: u64 = 0;
    for off in 0..EPOCHS_PER_SLASHINGS_VECTOR as u64 {
        let e =
            current_epoch + off - (EPOCHS_PER_SLASHINGS_VECTOR as u64 / 2 - 1).min(current_epoch);
        // The current epoch's bucket holds its live total in the accumulator;
        // it isn't flushed into the ring until `process_slashings_reset` (runs
        // after us), so `slashings_at` would return the stale finalized
        // baseline. Mirrors `effective_slashings`' overlay of this bucket.
        let bucket = if e == current_epoch {
            view.slot.state().current_epoch_slashings
        } else {
            let fin_epoch = view.slot.finalized_state().slot / SLOTS_PER_EPOCH;
            epoch.slashings_at(e, fin_epoch)
        };
        sum_slashings = sum_slashings.saturating_add(bucket);
    }

    let adjusted =
        sum_slashings.saturating_mul(cfg.proportional_slashing_multiplier).min(total_balance);
    let target_withdrawable = current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64 / 2;
    let total_increments = total_balance / EFFECTIVE_BALANCE_INCREMENT;
    let penalty_per_increment = if total_increments > 0 { adjusted / total_increments } else { 0 };

    let n = view.validators.count();
    for i in 0..n {
        let vi = i as u32;
        if !view.validators.is_slashed(i) {
            continue;
        }
        if view.validators.withdrawable_epoch(i) != target_withdrawable {
            continue;
        }
        let effective_balance = view.validators.effective_balance(i);
        let balance = view.balances.get(i);
        let penalty = penalty_per_increment * (effective_balance / EFFECTIVE_BALANCE_INCREMENT);
        view.balances.set(vi, balance.saturating_sub(penalty));
    }
}

/// At epoch boundary: flush the per-block `current_epoch_slashings`
/// accumulator into `epoch_state.slashings` (one entry per completed epoch
/// since fin) and reset the accumulator. The entry stores the *total*
/// slashings for the completed epoch (loaded baseline + new slashings) so
/// `effective_slashings` can overwrite the spec-position directly.
#[timed]
pub fn process_slashings_reset(view: &mut StateWriterView, epoch: &mut EpochWriteView) {
    let total = view.slot.state().current_epoch_slashings;
    epoch.push_slashings(total);
    view.slot.state_mut().current_epoch_slashings = 0;
}

pub fn process_effective_balance_updates(view: &mut StateWriterView) {
    let hys_down =
        EFFECTIVE_BALANCE_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER / HYSTERESIS_QUOTIENT;
    let hys_up = EFFECTIVE_BALANCE_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER / HYSTERESIS_QUOTIENT;
    let total = view.validators.count();
    for i in 0..total {
        let effective_balance = view.validators.effective_balance(i);
        let b = view.balances.get(i);
        let creds = *view.validators.credentials(i);
        let max_eff = creds.max_effective_balance();
        let new = if b + hys_down < effective_balance || effective_balance + hys_up < b {
            (b - b % EFFECTIVE_BALANCE_INCREMENT).min(max_eff)
        } else {
            effective_balance
        };
        if new != effective_balance {
            view.validators.set_effective_balance(i as u32, new);
        }
    }
}

#[timed]
pub fn process_participation_flag_updates(
    view: &mut StateWriterView,
    scratch: &mut Vec<(u32, u8)>,
) {
    let n = view.validators.count();
    rotate_previous_participation(view, n, scratch);
    clear_current_participation(view, n, scratch);
}

/// previous_epoch_participation = current_epoch_participation. Only changed
/// flags: the rotation is mostly a no-op (a validator timely in both epochs
/// keeps identical flags), so prev and curr are equal almost everywhere.
#[timed]
fn rotate_previous_participation(
    view: &mut StateWriterView,
    n: usize,
    scratch: &mut Vec<(u32, u8)>,
) {
    scratch.clear();
    {
        let mut prev = view.previous_participation.iter();
        let mut curr = view.current_participation.iter();
        for i in 0..n {
            let (p, c) = (prev.next().unwrap(), curr.next().unwrap());
            if c != p {
                scratch.push((i as u32, c));
            }
        }
    }
    view.previous_participation.set_many(scratch);
}

/// current_epoch_participation = 0. ~n-participants sized (only the
/// already-zero non-participants are skipped).
#[timed]
fn clear_current_participation(view: &mut StateWriterView, n: usize, scratch: &mut Vec<(u32, u8)>) {
    scratch.clear();
    {
        let mut curr = view.current_participation.iter();
        for i in 0..n {
            if curr.next().unwrap() != 0 {
                scratch.push((i as u32, 0));
            }
        }
    }
    view.current_participation.set_many(scratch);
}

pub fn process_eth1_data_reset(eth1: &mut Eth1WriteView, current_epoch: Epoch) {
    let next_epoch = current_epoch + 1;
    if next_epoch.is_multiple_of(EPOCHS_PER_ETH1_VOTING_PERIOD) {
        eth1.clear();
    }
}

#[timed]
pub fn process_pending_deposits(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochWriteView,
    postponed: &mut Vec<common::PendingDeposit>,
) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let next_epoch = current_epoch + 1;
    let dep_balance_to_consume = epoch.state_mut().deposit_balance_to_consume;
    let available =
        dep_balance_to_consume + get_activation_exit_churn_limit(cfg, view, current_epoch);
    let finalized_slot = epoch.state_mut().finalized_checkpoint.epoch * SLOTS_PER_EPOCH;

    postponed.clear();
    let mut processed_amount: u64 = 0;
    let mut next_deposit_index: usize = 0;
    let mut churn_limit_reached = false;

    let pending_len = view.pending.pending_deposits_len();
    for di in 0..pending_len {
        let deposit = *view.pending.pending_deposit(di);

        if deposit.slot > 0 &&
            view.slot.state().eth1_deposit_index < view.slot.state().deposit_requests_start_index
        {
            break;
        }
        if deposit.slot > finalized_slot {
            break;
        }
        if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH {
            break;
        }

        let vi = view.validators.find_by_pubkey(&deposit.pubkey);
        let is_exited = vi.is_some_and(|v| view.validators.exit_epoch(v as usize) != u64::MAX);
        let is_withdrawn =
            vi.is_some_and(|v| view.validators.withdrawable_epoch(v as usize) < next_epoch);

        if is_withdrawn {
            apply_pending_deposit(view, &deposit);
        } else if is_exited {
            postponed.push(deposit);
        } else {
            if processed_amount + deposit.amount > available {
                churn_limit_reached = true;
                break;
            }
            processed_amount += deposit.amount;
            apply_pending_deposit(view, &deposit);
        }
        next_deposit_index += 1;
    }

    view.pending.drain_pending_deposits(next_deposit_index);
    view.pending.append_pending_deposits(postponed);

    epoch.state_mut().deposit_balance_to_consume =
        if churn_limit_reached { available - processed_amount } else { 0 };
}

#[timed]
fn apply_pending_deposit(view: &mut StateWriterView, deposit: &common::PendingDeposit) {
    if let Some(v) = view.validators.find_by_pubkey(&deposit.pubkey) {
        let balance = view.balances.get(v as usize);
        view.balances.set(v, balance.saturating_add(deposit.amount));
        return;
    }
    if !is_valid_deposit_signature(
        &deposit.pubkey,
        &deposit.withdrawal_credentials,
        deposit.amount,
        &deposit.signature,
    ) {
        return;
    }
    let pk_decompressed = blst::min_pk::PublicKey::from_bytes(&deposit.pubkey).unwrap_or_default();
    let idx = common::append_validator(
        view,
        deposit.pubkey,
        pk_decompressed,
        deposit.withdrawal_credentials,
    );
    let initial_eff = min(
        deposit.amount - deposit.amount % EFFECTIVE_BALANCE_INCREMENT,
        deposit.withdrawal_credentials.max_effective_balance(),
    );
    view.validators.set_effective_balance(idx, initial_eff);
    view.balances.set(idx, deposit.amount);
}

#[timed]
pub fn is_valid_deposit_signature(
    pubkey: &[u8; 48],
    withdrawal_credentials: &common::Withdrawals,
    amount: u64,
    signature: &[u8; 96],
) -> bool {
    let mut pk_chunk = [0u8; 64];
    pk_chunk[..48].copy_from_slice(pubkey);
    let pubkey_root = ssz_hash::sha256(&pk_chunk);
    let mut amount_chunk = [0u8; 32];
    amount_chunk[..8].copy_from_slice(&amount.to_le_bytes());
    let deposit_msg_root =
        ssz_hash::merkleize(&[pubkey_root, withdrawal_credentials.0, amount_chunk]);

    let domain = {
        let fork_data_root = ssz_hash::hash_tree_root_fork_data([0; 4], &[0u8; 32]);
        let mut d = [0u8; 32];
        d[0..4].copy_from_slice(&0x03u32.to_le_bytes());
        d[4..32].copy_from_slice(&fork_data_root[..28]);
        d
    };
    let signing_root = ssz_hash::merkleize(&[deposit_msg_root, domain]);
    bls::verify_deposit_signature(pubkey, signature, &signing_root)
}

#[timed]
pub fn process_pending_consolidations(view: &mut StateWriterView) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let next_epoch = current_epoch + 1;
    let mut next_pending: usize = 0;

    let pending_len = view.pending.pending_consolidations_len();
    for ci in 0..pending_len {
        let pc = *view.pending.pending_consolidation(ci);
        let src = pc.source_index as u32;
        if view.validators.is_slashed(src as usize) {
            next_pending += 1;
            continue;
        }
        if view.validators.withdrawable_epoch(src as usize) > next_epoch {
            break;
        }
        let tgt = pc.target_index as u32;
        let src_bal = view.balances.get(src as usize);
        let src_eff = view.validators.effective_balance(src as usize);
        let moved = min(src_bal, src_eff);
        view.balances.set(src, src_bal.saturating_sub(moved));
        let tgt_bal = view.balances.get(tgt as usize);
        view.balances.set(tgt, tgt_bal.saturating_add(moved));
        next_pending += 1;
    }
    view.pending.drain_pending_consolidations(next_pending);
}

/// Gated by the hub: runs only when `current_epoch + 1` is a
/// `HISTORICAL_SUMMARY_PERIOD` multiple (which is what rolled `longtail`).
#[timed]
pub fn process_historical_summaries_update(
    view: &mut StateWriterView,
    longtail: &mut LongtailWriteView,
    scratch: &mut ssz_hash::StateHashScratch,
) {
    // Effective `block_roots` / `state_roots` circular vectors with delta
    // entries overlaid on the finalized ring (SLOTS_PER_HISTORICAL_ROOT = 8192
    // entries).
    view.slot.reader().effective_block_roots_into(&mut scratch.block_roots);
    view.slot.reader().effective_state_roots_into(&mut scratch.state_roots);

    let block_summary_root =
        ssz_hash::merkleize_padded(&scratch.block_roots, SLOTS_PER_HISTORICAL_ROOT);
    let state_summary_root =
        ssz_hash::merkleize_padded(&scratch.state_roots, SLOTS_PER_HISTORICAL_ROOT);
    longtail.push_historical_summary(HistoricalSummary { block_summary_root, state_summary_root });
}

/// At epoch boundary: publish the per-block `randao_mix_current` accumulator
/// to the epoch tier. `randao_mix_current` is NOT reset — spec carries the
/// previous epoch's final mix forward as the starting value for next epoch.
#[timed]
pub fn process_randao_mixes_reset(view: &StateWriterView, epoch: &mut EpochWriteView) {
    let mix = view.slot.state().randao_mix_current;
    epoch.push_randao_mix(mix);
}

/// Gated by the hub: runs only when `current_epoch + 1` is an
/// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` multiple (which is what rolled
/// `longtail`).
#[timed]
pub fn process_sync_committee_updates(
    view: &mut StateWriterView,
    epoch: &EpochView,
    longtail: &mut LongtailWriteView,
    current_epoch: Epoch,
    active_scratch: &mut Vec<u32>,
    eff_scratch: &mut Vec<u64>,
) {
    // Read seed/active-indices/effective-balances into locals FIRST,
    // then take &mut longtail.
    let sync_epoch = current_epoch + 1;
    let seed = shuffling::get_seed_from_state(
        epoch,
        &view.slot.reader(),
        sync_epoch,
        shuffling::DOMAIN_SYNC_COMMITTEE,
    );
    shuffling::get_active_validator_indices_into(
        &view.validators.reader(),
        sync_epoch,
        active_scratch,
    );
    if active_scratch.is_empty() {
        return;
    }
    eff_scratch.clear();
    eff_scratch.extend(view.validators.iter_effective_balances());

    let lt = longtail.state_mut();

    // Rotate: current <- next.
    let next_committee = lt.next_sync_committee;
    lt.current_sync_committee = next_committee;

    // Compute new next committee.
    let mut new_committee = lt.next_sync_committee;
    let mut sampler = shuffling::WeightedSampler::new(&seed, active_scratch.len());
    let mut selected = 0usize;
    while selected < SYNC_COMMITTEE_SIZE {
        let (candidate, accepted) = sampler.next(active_scratch, eff_scratch);
        if accepted {
            new_committee.pubkeys[selected] = *view.validators.pubkey(candidate);
            selected += 1;
        }
    }
    new_committee.aggregate_pubkey = bls::aggregate_pubkeys(&new_committee.pubkeys);
    lt.next_sync_committee = new_committee;

    // Rebuild sync_committee_indices for the rotated current committee.
    // Match spec: look up against the finalized validator index only (the
    // committee pubkeys were committed at a prior boundary).
    let curr_pubkeys = lt.current_sync_committee.pubkeys;
    let mut indices = [u32::MAX; SYNC_COMMITTEE_SIZE];
    for i in 0..SYNC_COMMITTEE_SIZE {
        if let Some(idx) = view.validators.find_by_finalized_pubkey(&curr_pubkeys[i]) {
            indices[i] = idx;
        }
    }
    lt.sync_committee_indices = indices;
}

#[timed]
pub fn process_proposer_lookahead(
    view: &mut StateWriterView,
    epoch: &mut EpochWriteView,
    current_epoch: Epoch,
    active_scratch: &mut Vec<u32>,
    eff_scratch: &mut Vec<u64>,
) {
    let slots_per_epoch = SLOTS_PER_EPOCH as usize;
    let last_epoch_start = PROPOSER_LOOKAHEAD_SIZE - slots_per_epoch;
    let target_epoch = current_epoch + MIN_SEED_LOOKAHEAD + 1;

    // Read seed/active-indices into locals FIRST, then take &mut epoch.
    let seed = shuffling::get_seed_from_state(
        &epoch.reader(),
        &view.slot.reader(),
        target_epoch,
        DOMAIN_BEACON_PROPOSER,
    );
    shuffling::get_active_validator_indices_into(
        &view.validators.reader(),
        target_epoch,
        active_scratch,
    );
    eff_scratch.clear();
    eff_scratch.extend(view.validators.iter_effective_balances());

    let es = epoch.state_mut();
    es.proposer_lookahead.copy_within(slots_per_epoch.., 0);
    for i in 0..slots_per_epoch {
        let slot = target_epoch * SLOTS_PER_EPOCH + i as u64;
        let proposer = shuffling::compute_proposer_index(active_scratch, eff_scratch, slot, &seed);
        es.proposer_lookahead[last_epoch_start + i] = proposer as u64;
    }
}

// ============================================================================
// Helpers
// ============================================================================

#[timed]
fn initiate_validator_exit(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    vi: u32,
    current_epoch: Epoch,
) {
    if view.validators.exit_epoch(vi as usize) != u64::MAX {
        return;
    }
    let effective_balance = view.validators.effective_balance(vi as usize);
    let exit_epoch =
        compute_exit_epoch_and_update_churn(cfg, view, effective_balance, current_epoch);
    view.validators.set_exit_epoch(vi, exit_epoch);
    view.validators
        .set_withdrawable_epoch(vi, exit_epoch + cfg.min_validator_withdrawability_delay);
}

#[timed]
fn compute_exit_epoch_and_update_churn(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + cfg.max_seed_lookahead;
    let prev_earliest = view.slot.state().earliest_exit_epoch;
    let mut earliest = max(prev_earliest, activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit(cfg, view, current_epoch);

    let mut consume = if prev_earliest < earliest {
        per_epoch_churn
    } else {
        view.slot.state().exit_balance_to_consume
    };
    if exit_balance > consume {
        let to_process = exit_balance - consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        consume += additional * per_epoch_churn;
    }
    view.slot.state_mut().exit_balance_to_consume = consume - exit_balance;
    view.slot.state_mut().earliest_exit_epoch = earliest;
    earliest
}

#[timed]
fn get_balance_churn_limit(cfg: &SpecConfig, view: &StateWriterView, current_epoch: Epoch) -> u64 {
    let total = total_active_balance(&view.validators.reader(), current_epoch);
    let churn = max(cfg.min_per_epoch_churn_limit, total / cfg.churn_limit_quotient);
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

#[inline]
#[timed]
fn get_activation_exit_churn_limit(
    cfg: &SpecConfig,
    view: &StateWriterView,
    current_epoch: Epoch,
) -> u64 {
    min(
        cfg.max_per_epoch_activation_exit_churn_limit,
        get_balance_churn_limit(cfg, view, current_epoch),
    )
}

/// Inactivity-leak predicate: the chain hasn't finalized for more than
/// `min_epochs_to_inactivity_penalty` epochs before the previous one.
fn is_inactivity_leak(cfg: &SpecConfig, epoch: &EpochView, current_epoch: Epoch) -> bool {
    let previous_epoch = current_epoch.saturating_sub(1);
    let finalized = epoch.state().finalized_checkpoint.epoch;
    previous_epoch.saturating_sub(finalized) > cfg.min_epochs_to_inactivity_penalty
}

/// Merged validator-row iterator over the view's per-validator tiers.
fn validator_rows<'a>(
    view: &'a StateWriterView<'_>,
) -> impl Iterator<Item = common::ValidatorRow> + 'a {
    iter_validator_rows(
        view.validators.reader(),
        view.balances.reader(),
        &view.previous_participation,
        &view.current_participation,
        &view.inactivity,
    )
}

#[inline]
fn eligibility(row: &common::ValidatorRow, current_epoch: Epoch) -> bool {
    let prev = current_epoch.saturating_sub(1);
    let active_prev = row.activation_epoch <= prev && prev < row.exit_epoch;
    active_prev || (row.slashed && current_epoch < row.withdrawable_epoch)
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

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;
    use silver_beacon_state_data::{B256, PendingDeposit, ValSeed, Withdrawals};

    use super::*;

    const MAX_EFFECTIVE_BALANCE: u64 = 32 * EFFECTIVE_BALANCE_INCREMENT;

    use silver_beacon_state_data::{
        EPOCHS_PER_HISTORICAL_VECTOR, EpochGroup, EpochId, EpochState, EpochStateFinalized,
    };

    fn checkpoint(epoch: Epoch, tag: u8) -> Checkpoint {
        let mut root = [0u8; 32];
        root[0] = tag;
        Checkpoint { epoch, root }
    }

    /// Build the deposit signing root for a (pubkey, wc, amount) triple.
    fn deposit_signing_root(pubkey: &[u8; 48], wc: &Withdrawals, amount: u64) -> B256 {
        let mut pk_chunk = [0u8; 64];
        pk_chunk[..48].copy_from_slice(pubkey);
        let pubkey_root = ssz_hash::sha256(&pk_chunk);
        let mut amt = [0u8; 32];
        amt[..8].copy_from_slice(&amount.to_le_bytes());
        let msg_root = ssz_hash::merkleize(&[pubkey_root, wc.0, amt]);

        let fork_data_root = ssz_hash::hash_tree_root_fork_data([0; 4], &[0u8; 32]);
        let mut domain = [0u8; 32];
        domain[0..4].copy_from_slice(&0x03u32.to_le_bytes());
        domain[4..32].copy_from_slice(&fork_data_root[..28]);
        ssz_hash::merkleize(&[msg_root, domain])
    }

    /// Epoch-tier base anchored at `current_epoch` with `finalized_checkpoint`
    /// pinned there and a generous `deposit_balance_to_consume` so the churn
    /// gate never masks the signature-handling assertions. The epoch tier rides
    /// its own group; `TestState::new` builds the group from this base and
    /// derives the anchor slot from it.
    fn fresh(current_epoch: u64) -> EpochStateFinalized {
        EpochStateFinalized::from_parts(
            EpochState {
                finalized_checkpoint: checkpoint(current_epoch, 0x01),
                deposit_balance_to_consume: u64::MAX / 2,
                ..Default::default()
            },
            vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            vec![0u64; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
        )
    }

    /// Roll the boundary epoch writer off the inherited `epoch_idx` and run
    /// `leaf` over it — the harness analog of `process_epoch`'s boundary roll
    /// (no longtail: these cases never touch it). Returns the committed id.
    fn at_boundary(
        view: &mut StateWriterView<'_>,
        epoch: &mut EpochGroup,
        epoch_idx: Option<EpochId>,
        leaf: impl FnOnce(&mut StateWriterView, &mut EpochWriteView),
    ) -> EpochId {
        let mut epoch_w = match epoch_idx {
            Some(pe) => epoch.roll_from(pe),
            None => epoch.roll_fresh(),
        };
        leaf(view, &mut epoch_w);
        epoch_w.commit()
    }

    use crate::test_state::TestState;

    /// Fixed secret key reused across the valid-signature tests.
    fn test_keypair() -> (SecretKey, [u8; 48]) {
        let sk_bytes: [u8; 32] = [
            0x26, 0x3d, 0xbd, 0x79, 0x2f, 0x5b, 0x1b, 0xe4, 0x7e, 0xd8, 0x5f, 0x89, 0x38, 0xc0,
            0xf2, 0x95, 0x86, 0xaf, 0x0d, 0x3a, 0xc7, 0xb9, 0x77, 0xf2, 0x1c, 0x27, 0x8f, 0xe1,
            0x46, 0x20, 0x40, 0xe3,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.sk_to_pk().to_bytes();
        (sk, pk)
    }

    #[test]
    fn pending_deposit_valid_sig_adds_validator() {
        let mut st = TestState::new(fresh(10), &[], &[]);
        let sid = st.state_id;
        let (mut view, epoch, _) = st.view();

        let (sk, pk) = test_keypair();
        let wc = Withdrawals([0xAAu8; 32]);
        let amount = 32_000_000_000u64;
        let signing_root = deposit_signing_root(&pk, &wc, amount);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let sig = sk.sign(&signing_root, dst, &[]).to_bytes();

        view.pending.push_pending_deposit(PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
            signature: sig,
            slot: 0, // genesis deposit
        });

        at_boundary(&mut view, epoch, sid.epoch_idx, |v, e| {
            process_pending_deposits(&SpecConfig::mainnet(), v, e, &mut Vec::new());
        });

        assert_eq!(view.validators.count(), 1);
        assert_eq!(*view.validators.pubkey(0), pk);
        assert_eq!(view.balances.get(0), amount);
        assert_eq!(view.pending.pending_deposits_len(), 0);
    }

    #[test]
    fn slashings_reset_does_not_double_count_baseline() {
        // Boot epoch with a non-zero loaded slashings bucket and no new
        // slashings this session. `decompose` seeds the accumulator
        // (`current_epoch_slashings`) = `slashings[current]`, so the flush must
        // push that value directly — adding `slashings_at(current)` again would
        // double the baseline (200 instead of 100). EF's `slashings_reset`
        // vector has a zero current bucket and so cannot catch this.
        let current_epoch = 5u64;
        let bucket = current_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR;
        let mut slashings = vec![0u64; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice();
        slashings[bucket] = 100;
        let epoch_base = EpochStateFinalized::from_parts(
            EpochState {
                finalized_checkpoint: checkpoint(current_epoch, 0x01),
                deposit_balance_to_consume: u64::MAX / 2,
                ..Default::default()
            },
            vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            slashings,
        );

        let mut st = TestState::new(epoch_base, &[], &[]);
        // Pre-seed the accumulator append-only: roll, set, write the id back.
        let mut sw = st.bs.slot_states.roll_from(st.state_id.slot_idx);
        sw.state_mut().current_epoch_slashings = 100;
        st.state_id.slot_idx = sw.commit();
        let sid = st.state_id;
        let (mut view, epoch, _) = st.view();

        let eid =
            at_boundary(&mut view, epoch, sid.epoch_idx, |v, e| process_slashings_reset(v, e));

        let ev = epoch.view(eid);
        let fin_epoch = view.slot.finalized_state().slot / SLOTS_PER_EPOCH;
        assert_eq!(
            ev.slashings_at(current_epoch, fin_epoch),
            100,
            "must not double-count baseline"
        );
    }

    #[test]
    fn pending_deposit_invalid_sig_rejected() {
        let mut st = TestState::new(fresh(10), &[], &[]);
        let sid = st.state_id;
        let (mut view, epoch, _) = st.view();

        // Zeroed (invalid) signature; pubkey also bogus, but the sig check
        // rejects first.
        view.pending.push_pending_deposit(PendingDeposit {
            pubkey: [0x01u8; 48],
            withdrawal_credentials: Withdrawals::ZERO,
            amount: 32_000_000_000,
            signature: [0u8; 96],
            slot: 0,
        });

        at_boundary(&mut view, epoch, sid.epoch_idx, |v, e| {
            process_pending_deposits(&SpecConfig::mainnet(), v, e, &mut Vec::new());
        });

        // Deposit consumed from queue but validator NOT added.
        assert_eq!(view.validators.count(), 0);
        assert_eq!(view.pending.pending_deposits_len(), 0);
    }

    #[test]
    fn pending_deposit_existing_validator_no_sig_check() {
        let (_sk, pk) = test_keypair();
        // Pre-existing active validator at max effective balance.
        let seeds = [ValSeed {
            pubkey: pk,
            withdrawal_credentials: Withdrawals::ZERO,
            effective_balance: MAX_EFFECTIVE_BALANCE,
            balance: MAX_EFFECTIVE_BALANCE,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }];
        // Existing validator's base balance must live in the balances base.
        let mut st = TestState::new(fresh(10), &seeds, &[MAX_EFFECTIVE_BALANCE]);
        let sid = st.state_id;
        let (mut view, epoch, _) = st.view();

        // Top-up to existing validator — signature is ignored per spec.
        let top_up = 1_000_000_000u64;
        view.pending.push_pending_deposit(PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: Withdrawals::ZERO,
            amount: top_up,
            signature: [0u8; 96], // invalid sig, doesn't matter
            slot: 0,
        });

        at_boundary(&mut view, epoch, sid.epoch_idx, |v, e| {
            process_pending_deposits(&SpecConfig::mainnet(), v, e, &mut Vec::new());
        });

        assert_eq!(view.validators.count(), 1);
        assert_eq!(view.balances.get(0), MAX_EFFECTIVE_BALANCE + top_up);
        assert_eq!(view.pending.pending_deposits_len(), 0);
    }
}
