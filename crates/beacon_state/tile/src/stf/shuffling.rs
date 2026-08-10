use blst::min_pk::PublicKey;
use silver_beacon_state_data::{
    Epoch, EpochView, SLOTS_PER_EPOCH, Slot, SlotStateView, StateReadView, ValidatorsView,
};

use crate::shuffling::{
    DOMAIN_BEACON_ATTESTER, committees_per_slot, get_active_validator_indices_into,
    get_seed_from_state, shuffle_list,
};

/// One epoch's attester shuffling and the committee split it implies.
pub struct EpochShuffling<'a> {
    pub shuffled: &'a [u32],
    pub committees_per_slot: usize,
    /// Registry size the shuffle was taken against. `get_active_validator_
    /// indices_into` only emits indices below it, so one comparison against a
    /// later count proves every index in `shuffled` is still addressable.
    pub built_against: usize,
    /// One aggregate pubkey per beacon committee, indexed
    /// `slot_in_epoch * committees_per_slot + committee_index`; `None` until
    /// the aggregates have been precomputed for this epoch.
    pub committee_aggs: Option<&'a [PublicKey]>,
}

impl<'a> EpochShuffling<'a> {
    /// Attester shuffling for `epoch`, seeded from the state's randao ring.
    pub fn from_state(rv: &StateReadView, epoch: Epoch, buf: &'a mut Vec<u32>) -> Self {
        Self::build(&rv.validators, &rv.slot, &rv.epoch, epoch, buf)
    }

    /// As [`Self::from_state`], for callers holding the state's views
    /// separately rather than a whole [`StateReadView`].
    pub fn build(
        validators: &ValidatorsView,
        slot: &SlotStateView,
        state_epoch: &EpochView,
        epoch: Epoch,
        buf: &'a mut Vec<u32>,
    ) -> Self {
        let seed = get_seed_from_state(state_epoch, slot, epoch, DOMAIN_BEACON_ATTESTER);
        let built_against = validators.count();
        get_active_validator_indices_into(validators, epoch, buf);
        shuffle_list(buf, &seed);
        Self::new(buf, built_against)
    }

    pub fn new(shuffled: &'a [u32], built_against: usize) -> Self {
        Self {
            shuffled,
            committees_per_slot: committees_per_slot(shuffled.len()),
            built_against,
            committee_aggs: None,
        }
    }

    pub fn indices_in_range(&self, validators_count: usize) -> bool {
        self.built_against <= validators_count
    }

    pub fn with_committee_aggs(self, committee_aggs: Option<&'a [PublicKey]>) -> Self {
        Self { committee_aggs, ..self }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.shuffled.is_empty() || self.committees_per_slot == 0
    }

    /// Proportional split, so sizes differ by at most one and the committees
    /// partition `shuffled` exactly — every active validator lands in one.
    pub fn committee(&self, slot: Slot, committee_index: usize) -> &'a [u32] {
        let epoch_committee_count = self.committees_per_slot * SLOTS_PER_EPOCH as usize;
        let slot_in_epoch = (slot % SLOTS_PER_EPOCH) as usize;
        let index_in_epoch = slot_in_epoch * self.committees_per_slot + committee_index;

        let start = self.shuffled.len() * index_in_epoch / epoch_committee_count;
        let end = self.shuffled.len() * (index_in_epoch + 1) / epoch_committee_count;

        &self.shuffled[start..end]
    }
}

/// The two shufflings an attestation's target epoch may name.
pub struct ShufflingRef<'a> {
    pub curr: EpochShuffling<'a>,
    pub prev: EpochShuffling<'a>,
}

impl<'a> ShufflingRef<'a> {
    /// Populate `curr_buf`/`prev_buf` with the current+previous epoch's
    /// shuffled active-index lists, then bind them into a `ShufflingRef`.
    pub fn build(
        rv: &StateReadView,
        current_epoch: Epoch,
        curr_buf: &'a mut Vec<u32>,
        prev_buf: &'a mut Vec<u32>,
    ) -> Self {
        let previous_epoch = current_epoch.saturating_sub(1);
        Self {
            curr: EpochShuffling::from_state(rv, current_epoch, curr_buf),
            prev: EpochShuffling::from_state(rv, previous_epoch, prev_buf),
        }
    }

    pub(crate) fn for_target(&self, is_current: bool) -> &EpochShuffling<'a> {
        if is_current { &self.curr } else { &self.prev }
    }
}

#[cfg(test)]
mod tests {
    use super::EpochShuffling;

    #[test]
    fn committee_slicing() {
        let shuffled: Vec<u32> = (0..640).collect();
        let sh = EpochShuffling {
            shuffled: &shuffled,
            committees_per_slot: 2,
            built_against: 640,
            committee_aggs: None,
        };

        let c = sh.committee(0, 0);
        assert_eq!(c.len(), 10);

        let c1 = sh.committee(0, 1);
        assert_eq!(c1.len(), 10);
        assert_ne!(c[0], c1[0]);

        let c_last = sh.committee(31, 1);
        assert_eq!(c_last.len(), 10);
    }
}
