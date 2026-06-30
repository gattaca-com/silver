use core::cmp::{max, min};

use silver_beacon_state_data::{
    Epoch, EpochView, PendingView, SLOTS_PER_EPOCH, SlotStateWriteView, SpecConfig, ValidatorsView,
    ValidatorsWriteView,
};

use crate::stf::EFFECTIVE_BALANCE_INCREMENT;

pub(crate) fn initiate_validator_exit(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &mut ValidatorsWriteView,
    vi: u32,
    current_epoch: Epoch,
) {
    if validators.exit_epoch(vi as usize) != u64::MAX {
        return;
    }
    let effective_balance = validators.effective_balance(vi as usize);
    let exit_epoch = compute_exit_epoch_and_update_churn(
        cfg,
        slot,
        &validators.reader(),
        effective_balance,
        current_epoch,
    );
    validators.set_exit_epoch(vi, exit_epoch);
    validators.set_withdrawable_epoch(vi, exit_epoch + cfg.min_validator_withdrawability_delay);
}

pub(crate) fn compute_exit_epoch_and_update_churn(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &ValidatorsView,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + cfg.max_seed_lookahead;
    let prev_earliest = slot.state().earliest_exit_epoch;
    let mut earliest = max(prev_earliest, activation_exit_epoch);
    let per_epoch_churn = get_exit_churn_limit(cfg, validators, current_epoch);

    let mut balance_to_consume = if prev_earliest < earliest {
        per_epoch_churn
    } else {
        slot.state().exit_balance_to_consume
    };

    if exit_balance > balance_to_consume {
        let to_process = exit_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    slot.state_mut().exit_balance_to_consume = balance_to_consume - exit_balance;
    slot.state_mut().earliest_exit_epoch = earliest;
    earliest
}

pub(crate) fn compute_consolidation_epoch_and_update_churn(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &ValidatorsView,
    consolidation_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + cfg.max_seed_lookahead;
    let prev_earliest = slot.state().earliest_consolidation_epoch;
    let mut earliest = max(prev_earliest, activation_exit_epoch);
    let per_epoch_churn = get_consolidation_churn_limit(cfg, validators, current_epoch);

    let mut balance_to_consume = if prev_earliest < earliest {
        per_epoch_churn
    } else {
        slot.state().consolidation_balance_to_consume
    };

    if consolidation_balance > balance_to_consume {
        let to_process = consolidation_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    slot.state_mut().consolidation_balance_to_consume = balance_to_consume - consolidation_balance;
    slot.state_mut().earliest_consolidation_epoch = earliest;
    earliest
}

fn get_balance_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    let total = total_active_balance(validators, current_epoch);
    let quotient = if cfg.is_gloas_at(current_epoch) {
        cfg.churn_limit_quotient_gloas
    } else {
        cfg.churn_limit_quotient
    };
    let churn = max(cfg.min_per_epoch_churn_limit, total / quotient);
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

fn get_activation_exit_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    min(
        cfg.max_per_epoch_activation_exit_churn_limit,
        get_balance_churn_limit(cfg, validators, current_epoch),
    )
}

/// EIP-8061 (Gloas): exit churn is the uncapped base churn; pre-Gloas it
/// shares the activation/exit cap.
fn get_exit_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    let base = get_balance_churn_limit(cfg, validators, current_epoch);
    if cfg.is_gloas_at(current_epoch) {
        base
    } else {
        min(cfg.max_per_epoch_activation_exit_churn_limit, base)
    }
}

pub(crate) fn get_consolidation_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    // EIP-8061 (Gloas): independently derived from total active balance.
    if cfg.is_gloas_at(current_epoch) {
        let total = total_active_balance(validators, current_epoch);
        let churn = total / cfg.consolidation_churn_limit_quotient;
        return churn - churn % EFFECTIVE_BALANCE_INCREMENT;
    }
    get_balance_churn_limit(cfg, validators, current_epoch) -
        get_activation_exit_churn_limit(cfg, validators, current_epoch)
}

/// O(N + |edits|): single sweep over activation/exit/effective_balance columns.
pub(crate) fn total_active_balance(validators: &ValidatorsView, current_epoch: Epoch) -> u64 {
    let n = validators.count();
    let mut act = validators.iter_activation_epochs();
    let mut exit = validators.iter_exit_epochs();
    let mut effective_balance = validators.iter_effective_balances();
    let mut total: u64 = 0;
    for _ in 0..n {
        let a = act.next().unwrap();
        let x = exit.next().unwrap();
        let b = effective_balance.next().unwrap();
        if a <= current_epoch && current_epoch < x {
            total += b;
        }
    }
    total.max(EFFECTIVE_BALANCE_INCREMENT)
}

pub(crate) fn get_pending_balance_to_withdraw(pending: &PendingView, vi: u32) -> u64 {
    let n = pending.partial_withdrawals.len();
    let mut total = 0u64;
    for i in 0..n {
        let pw = pending.partial_withdrawals.get(i);
        if pw.index == vi as u64 {
            total += pw.amount;
        }
    }
    total
}

#[inline]
pub(crate) fn is_active(validators: &ValidatorsView, vi: u32, e: Epoch) -> bool {
    validators.activation_epoch(vi as usize) <= e && e < validators.exit_epoch(vi as usize)
}

#[inline]
pub(crate) fn is_slashable_validator(validators: &ValidatorsView, vi: u32, e: Epoch) -> bool {
    !validators.is_slashed(vi as usize) &&
        validators.activation_epoch(vi as usize) <= e &&
        e < validators.withdrawable_epoch(vi as usize)
}

/// The validator columns that decide activity/eligibility, built inline per
/// element in the epoch read sweeps (built from separate column iterators, not
/// a bundled row iterator, so the independent loads stay parallel).
#[derive(Clone, Copy)]
pub(crate) struct ActiveStatus {
    pub(crate) activation_epoch: Epoch,
    pub(crate) exit_epoch: Epoch,
    pub(crate) slashed: bool,
}

impl ActiveStatus {
    #[inline]
    pub(crate) fn active_at(self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Eligible for rewards/inactivity accounting this epoch: active in the
    /// previous epoch, or slashed but not yet withdrawable.
    #[inline]
    pub(crate) fn eligible(self, withdrawable_epoch: Epoch, current_epoch: Epoch) -> bool {
        self.active_at(current_epoch.saturating_sub(1)) ||
            (self.slashed && current_epoch < withdrawable_epoch)
    }
}

#[inline]
pub(crate) fn get_beacon_proposer_index(slot: &SlotStateWriteView, epoch: EpochView) -> u32 {
    let s = slot.state().slot;
    epoch
        .proposer_at((s % SLOTS_PER_EPOCH) as usize)
        .expect("slot-in-epoch is within the lookahead window") as u32
}
