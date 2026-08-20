use silver_beacon_state_data::{Epoch, FAR_FUTURE_EPOCH, ValidatorsView};

/// `ValidatorStatus` of `types/api.yaml`, derived from the validator's epochs
/// and balance against the epoch of the state being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    PendingInitialized,
    PendingQueued,
    ActiveOngoing,
    ActiveExiting,
    ActiveSlashed,
    ExitedUnslashed,
    ExitedSlashed,
    WithdrawalPossible,
    WithdrawalDone,
}

/// The `Validator` columns a status is derived from, apart from the balance —
/// all a sweep needs before it knows whether the filter keeps this validator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Lifecycle {
    pub(crate) slashed: bool,
    pub(crate) activation_eligibility_epoch: Epoch,
    pub(crate) activation_epoch: Epoch,
    pub(crate) exit_epoch: Epoch,
    pub(crate) withdrawable_epoch: Epoch,
}

impl Lifecycle {
    pub(crate) fn read(validators: &ValidatorsView<'_>, index: usize) -> Self {
        Self {
            slashed: validators.is_slashed(index),
            activation_eligibility_epoch: validators.activation_eligibility_epoch(index),
            activation_epoch: validators.activation_epoch(index),
            exit_epoch: validators.exit_epoch(index),
            withdrawable_epoch: validators.withdrawable_epoch(index),
        }
    }
}

impl Status {
    pub(crate) fn of(lifecycle: &Lifecycle, balance: u64, epoch: Epoch) -> Self {
        if epoch < lifecycle.activation_epoch {
            if lifecycle.activation_eligibility_epoch == FAR_FUTURE_EPOCH {
                Self::PendingInitialized
            } else {
                Self::PendingQueued
            }
        } else if epoch < lifecycle.exit_epoch {
            if lifecycle.exit_epoch == FAR_FUTURE_EPOCH {
                Self::ActiveOngoing
            } else if lifecycle.slashed {
                Self::ActiveSlashed
            } else {
                Self::ActiveExiting
            }
        } else if epoch < lifecycle.withdrawable_epoch {
            if lifecycle.slashed { Self::ExitedSlashed } else { Self::ExitedUnslashed }
        } else if balance == 0 {
            Self::WithdrawalDone
        } else {
            Self::WithdrawalPossible
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "pending_initialized" => Self::PendingInitialized,
            "pending_queued" => Self::PendingQueued,
            "active_ongoing" => Self::ActiveOngoing,
            "active_exiting" => Self::ActiveExiting,
            "active_slashed" => Self::ActiveSlashed,
            "exited_unslashed" => Self::ExitedUnslashed,
            "exited_slashed" => Self::ExitedSlashed,
            "withdrawal_possible" => Self::WithdrawalPossible,
            "withdrawal_done" => Self::WithdrawalDone,
            _ => return None,
        })
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// The statuses a `status` filter selects, one bit per [`Status`]. A set is
/// what the schema's `uniqueItems` asks for, and it keeps the per-validator
/// test a single mask test however long the submitted list was.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct StatusMask(u16);

impl StatusMask {
    /// The nine exact status names, and the four coarse ones each covering the
    /// statuses of one stage of a validator's life.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        let bits = match name {
            "pending" => Status::PendingInitialized.bit() | Status::PendingQueued.bit(),
            "active" => {
                Status::ActiveOngoing.bit() |
                    Status::ActiveExiting.bit() |
                    Status::ActiveSlashed.bit()
            }
            "exited" => Status::ExitedUnslashed.bit() | Status::ExitedSlashed.bit(),
            "withdrawal" => Status::WithdrawalPossible.bit() | Status::WithdrawalDone.bit(),
            _ => Status::parse(name)?.bit(),
        };
        Some(Self(bits))
    }

    pub(crate) fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// The empty mask is the spec's "no filtering on that attribute".
    pub(crate) fn accepts(self, status: Status) -> bool {
        self.0 == 0 || self.0 & status.bit() != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Status; 9] = [
        Status::PendingInitialized,
        Status::PendingQueued,
        Status::ActiveOngoing,
        Status::ActiveExiting,
        Status::ActiveSlashed,
        Status::ExitedUnslashed,
        Status::ExitedSlashed,
        Status::WithdrawalPossible,
        Status::WithdrawalDone,
    ];

    const STAGES: [&str; 4] = ["pending", "active", "exited", "withdrawal"];

    /// Every activated validator with no exit filed, the overwhelming
    /// majority of a live registry.
    fn active_ongoing() -> Lifecycle {
        Lifecycle {
            slashed: false,
            activation_eligibility_epoch: 5,
            activation_epoch: 10,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    }

    fn status_at(lifecycle: &Lifecycle, epoch: Epoch) -> Status {
        Status::of(lifecycle, 32_000_000_000, epoch)
    }

    /// The activation epoch is the first epoch of membership, not the last
    /// epoch of the queue.
    #[test]
    fn pending_becomes_active_at_the_activation_epoch() {
        let lifecycle = active_ongoing();
        assert_eq!(status_at(&lifecycle, 9), Status::PendingQueued);
        assert_eq!(status_at(&lifecycle, 10), Status::ActiveOngoing);
        assert_eq!(status_at(&lifecycle, 11), Status::ActiveOngoing);
    }

    /// A deposit that has not been through an eligibility sweep yet carries no
    /// eligibility epoch, which is what separates the two pending statuses.
    #[test]
    fn pending_is_initialized_until_an_eligibility_epoch_is_set() {
        let initialized = Lifecycle {
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            activation_epoch: FAR_FUTURE_EPOCH,
            ..active_ongoing()
        };
        assert_eq!(status_at(&initialized, 0), Status::PendingInitialized);
        assert_eq!(status_at(&initialized, 1_000_000), Status::PendingInitialized);

        let queued = Lifecycle { activation_eligibility_epoch: 3, ..initialized };
        assert_eq!(status_at(&queued, 0), Status::PendingQueued);
    }

    /// A filed exit and a slashing both schedule an exit; the validator stays
    /// active — and the two apart — until that epoch arrives.
    #[test]
    fn a_scheduled_exit_splits_the_active_statuses_until_the_exit_epoch() {
        let exiting = Lifecycle { exit_epoch: 20, withdrawable_epoch: 30, ..active_ongoing() };
        assert_eq!(status_at(&exiting, 19), Status::ActiveExiting);
        assert_eq!(status_at(&exiting, 20), Status::ExitedUnslashed);

        let slashed = Lifecycle { slashed: true, ..exiting };
        assert_eq!(status_at(&slashed, 19), Status::ActiveSlashed);
        assert_eq!(status_at(&slashed, 20), Status::ExitedSlashed);
    }

    #[test]
    fn exited_becomes_withdrawable_at_the_withdrawable_epoch() {
        let exited = Lifecycle { exit_epoch: 20, withdrawable_epoch: 30, ..active_ongoing() };
        assert_eq!(status_at(&exited, 29), Status::ExitedUnslashed);
        assert_eq!(status_at(&exited, 30), Status::WithdrawalPossible);

        let slashed = Lifecycle { slashed: true, ..exited };
        assert_eq!(status_at(&slashed, 29), Status::ExitedSlashed);
        assert_eq!(status_at(&slashed, 30), Status::WithdrawalPossible);
    }

    /// The one status the epochs alone cannot tell: past the withdrawable
    /// epoch it is the balance that says whether the funds have moved.
    #[test]
    fn a_withdrawn_balance_is_the_only_difference_between_the_two_withdrawal_statuses() {
        let withdrawable = Lifecycle { exit_epoch: 20, withdrawable_epoch: 30, ..active_ongoing() };
        assert_eq!(Status::of(&withdrawable, 1, 30), Status::WithdrawalPossible);
        assert_eq!(Status::of(&withdrawable, 0, 30), Status::WithdrawalDone);
        assert_eq!(Status::of(&withdrawable, 0, 29), Status::ExitedUnslashed);
    }

    /// A validator slashed while active is scheduled to exit, so a slashed
    /// flag never reaches the active_ongoing branch in practice — but the
    /// derivation must not depend on that, since `exit_epoch` is what the
    /// spec keys on.
    #[test]
    fn a_slashed_flag_alone_does_not_end_an_active_validator() {
        let slashed = Lifecycle { slashed: true, ..active_ongoing() };
        assert_eq!(status_at(&slashed, 1_000_000), Status::ActiveOngoing);
    }

    #[test]
    fn every_status_name_parses_back_to_its_own_status() {
        for status in ALL {
            assert_eq!(Status::parse(status.name()), Some(status), "{}", status.name());
        }
        assert_eq!(Status::parse("pending"), None, "a stage name is not an exact status");
        assert_eq!(Status::parse("Active_Ongoing"), None, "status names are case-sensitive");
        assert_eq!(Status::parse(""), None);
    }

    /// Each of the four coarse names covers its own statuses and no others,
    /// and every status falls under exactly one.
    #[test]
    fn a_stage_filter_accepts_exactly_the_statuses_of_its_stage() {
        for stage in STAGES {
            let mask = StatusMask::parse(stage).expect(stage);
            let accepted: Vec<_> =
                ALL.into_iter().filter(|&s| mask.accepts(s)).map(Status::name).collect();
            assert!(
                accepted.iter().all(|name| name.starts_with(stage)),
                "{stage} accepted {accepted:?}"
            );
            assert!(!accepted.is_empty(), "{stage} accepted nothing");
        }

        for status in ALL {
            let stages = STAGES
                .into_iter()
                .filter(|stage| StatusMask::parse(stage).unwrap().accepts(status))
                .count();
            assert_eq!(stages, 1, "{} falls under {stages} stages", status.name());
        }
    }

    #[test]
    fn an_exact_filter_accepts_only_its_own_status() {
        for status in ALL {
            let mask = StatusMask::parse(status.name()).expect(status.name());
            for other in ALL {
                assert_eq!(mask.accepts(other), other == status, "{}", other.name());
            }
        }
    }

    #[test]
    fn a_name_that_is_neither_a_status_nor_a_stage_parses_to_nothing() {
        for name in ["", "withdrawn", "active_", "pending_initialised", "exit", "ACTIVE"] {
            assert_eq!(StatusMask::parse(name), None, "{name}");
        }
    }

    /// One bit per status, so the nine exact names partition the mask and a
    /// stage is exactly the union of the statuses it covers.
    #[test]
    fn a_mask_of_every_exact_name_is_the_union_of_every_stage() {
        let union = |names: &[&str]| {
            let mut mask = StatusMask::default();
            for name in names {
                mask.insert(StatusMask::parse(name).expect(name));
            }
            mask
        };
        let exact: Vec<_> = ALL.iter().map(|s| s.name()).collect();
        assert_eq!(union(&exact), union(&STAGES));
        assert_eq!(union(&exact).0.count_ones(), ALL.len() as u32);
    }

    /// `uniqueItems` on the schema's `status`/`statuses` arrays: inserting a
    /// value again leaves the mask, and so the sweep's cost, unchanged.
    #[test]
    fn inserting_a_status_twice_leaves_the_same_mask() {
        let active = StatusMask::parse("active").unwrap();
        let mut repeated = active;
        for _ in 0..1_000 {
            repeated.insert(active);
        }
        assert_eq!(repeated, active);
    }

    /// An empty mask filters on nothing; a mask that names something filters
    /// on exactly that.
    #[test]
    fn an_empty_mask_accepts_every_status() {
        let empty = StatusMask::default();
        for status in ALL {
            assert!(empty.accepts(status), "{}", status.name());
        }
        assert!(!StatusMask::parse("pending").unwrap().accepts(Status::ActiveOngoing));
    }
}
