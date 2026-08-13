use crate::types::{EFFECTIVE_BALANCE_INCREMENT, Epoch, TIMELY_TARGET_FLAG};

/// Derived per-epoch balance aggregates — not part of the consensus
/// `BeaconState`, so never SSZ-encoded or hashed. Maintained incrementally by
/// every write path, so a stale value is silently wrong rather than a miss.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochBalances {
    /// Spec `get_total_active_balance`: slashed included, ≥ one increment.
    pub total_active: u64,
    /// Unslashed previous-epoch-active TIMELY_TARGET effective balance.
    pub previous_target: u64,
    /// Unslashed current-epoch-active TIMELY_TARGET effective balance.
    pub current_target: u64,
}

impl Default for EpochBalances {
    fn default() -> Self {
        Self { total_active: EFFECTIVE_BALANCE_INCREMENT, previous_target: 0, current_target: 0 }
    }
}

pub struct EpochBalancesRow {
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub slashed: bool,
    pub effective_balance: u64,
    pub previous_participation: u8,
    pub current_participation: u8,
}

impl EpochBalancesRow {
    #[inline]
    fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    #[inline]
    fn counts_current_target(&self, current_epoch: Epoch) -> bool {
        self.is_active_at(current_epoch) &&
            !self.slashed &&
            self.current_participation & TIMELY_TARGET_FLAG != 0
    }

    #[inline]
    fn counts_previous_target(&self, previous_epoch: Epoch) -> bool {
        self.is_active_at(previous_epoch) &&
            !self.slashed &&
            self.previous_participation & TIMELY_TARGET_FLAG != 0
    }
}

impl EpochBalances {
    pub fn sweep(current_epoch: Epoch, rows: impl Iterator<Item = EpochBalancesRow>) -> Self {
        let previous_epoch = current_epoch.saturating_sub(1);
        let mut total_active = 0u64;
        let mut previous_target = 0u64;
        let mut current_target = 0u64;
        for row in rows {
            if row.is_active_at(current_epoch) {
                total_active += row.effective_balance;
            }
            if row.counts_current_target(current_epoch) {
                current_target += row.effective_balance;
            }
            if row.counts_previous_target(previous_epoch) {
                previous_target += row.effective_balance;
            }
        }
        Self {
            total_active: total_active.max(EFFECTIVE_BALANCE_INCREMENT),
            previous_target,
            current_target,
        }
    }

    /// Updates effective balance sum in case attested validators moved back
    /// from slashed state
    #[inline]
    pub fn add_target_attesters(&mut self, is_current: bool, effective_balance: u64) {
        if is_current {
            self.current_target += effective_balance;
        } else {
            self.previous_target += effective_balance;
        }
    }

    /// Updates effective balance sum in case a validator is removed from the
    /// active set (slashed)
    #[inline]
    pub fn remove_slashed(&mut self, row: EpochBalancesRow, current_epoch: Epoch) {
        debug_assert!(!row.slashed, "remove_slashed on an already-slashed validator");
        if row.counts_current_target(current_epoch) {
            self.current_target -= row.effective_balance;
        }
        if row.counts_previous_target(current_epoch.saturating_sub(1)) {
            self.previous_target -= row.effective_balance;
        }
    }
}
