use silver_beacon_state_data::{BLSPubkey, Epoch, StateReadView, ValidatorsView, Withdrawals};

use crate::validators::{
    filter::Filter,
    status::{Lifecycle, Status},
};

/// SSZ `Validator`, copied out of the columnar registry — the read closure
/// owns everything the body needs so rendering happens outside the seqlock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Validator {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) withdrawal_credentials: Withdrawals,
    pub(crate) effective_balance: u64,
    pub(crate) lifecycle: Lifecycle,
}

/// `ValidatorResponse` of `types/api.yaml`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ValidatorEntry {
    pub(crate) index: u64,
    pub(crate) balance: u64,
    pub(crate) status: Status,
    pub(crate) validator: Validator,
}

impl Validator {
    fn read(validators: &ValidatorsView<'_>, index: usize, lifecycle: Lifecycle) -> Self {
        Self {
            pubkey: *validators.pubkey(index),
            withdrawal_credentials: *validators.credentials(index),
            effective_balance: validators.effective_balance(index),
            lifecycle,
        }
    }
}

impl ValidatorEntry {
    pub(crate) fn read(view: &StateReadView<'_>, index: u32, epoch: Epoch) -> Self {
        Self::accepted(view, index, epoch, &Filter::default())
            .expect("a filter naming no status accepts every status")
    }

    /// The entry at `index` unless `filter` rejects its status. The pubkey and
    /// credentials copies the body needs are paid only for a validator the
    /// answer carries; deriving the status costs the five lifecycle columns.
    fn accepted(
        view: &StateReadView<'_>,
        index: u32,
        epoch: Epoch,
        filter: &Filter,
    ) -> Option<Self> {
        let ix = index as usize;
        let balance = view.balances.get(ix);
        let lifecycle = Lifecycle::read(&view.validators, ix);
        let status = Status::of(&lifecycle, balance, epoch);
        filter.accepts(status).then(|| Self {
            index: index as u64,
            balance,
            status,
            validator: Validator::read(&view.validators, ix, lifecycle),
        })
    }

    /// Every validator `filter` selects, in registry order. Runs under the
    /// seqlock and is re-run whole on a finalize retry, so it must stay a pure
    /// function of `view`: it owns its result and touches nothing else.
    ///
    /// `count()` spans the fork delta's `appended` vec, which
    /// [`silver_beacon_state_data::BeaconStateReader::read`] does not list
    /// among the reads that are safe to make optimistically. Re-reading it per
    /// step stops a concurrent shrink from indexing past the registry, which
    /// latching one bound up front would not.
    pub(crate) fn matching(view: &StateReadView<'_>, filter: &Filter) -> Vec<Self> {
        let epoch = view.slot.current_epoch();
        let in_registry = |index: &u32| (*index as usize) < view.validators.count();
        match filter.resolve_ids(&view.validators) {
            Some(indices) => indices
                .into_iter()
                .filter(in_registry)
                .filter_map(|index| Self::accepted(view, index, epoch, filter))
                .collect(),
            None => {
                let mut entries = Vec::new();
                let mut index = 0;
                while in_registry(&index) {
                    if let Some(entry) = Self::accepted(view, index, epoch, filter) {
                        entries.push(entry);
                    }
                    index += 1;
                }
                entries
            }
        }
    }
}
