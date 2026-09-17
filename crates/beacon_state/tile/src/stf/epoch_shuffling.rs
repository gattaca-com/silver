use blst::min_pk::PublicKey;
use silver_beacon_state_data::{
    Epoch, RandaoMixesView, Slot, StateReadView, ValidatorsView, committee_range,
};
use silver_common::{BeaconStateEvent, TCacheProducer, TProducer};

use crate::shuffling::{DOMAIN_BEACON_ATTESTER, Seed, committees_per_slot};

/// One epoch's attester shuffling and the committee split it implies.
pub struct EpochShuffling<'a> {
    shuffled: &'a [u32],
    pub committees_per_slot: usize,
    /// Registry size the shuffle was taken against. Every index in `shuffled`
    /// is below it, so one comparison against a later count proves the whole
    /// shuffling is still addressable.
    pub built_against: usize,
    /// One aggregate pubkey per beacon committee, indexed
    /// `slot_in_epoch * committees_per_slot + committee_index`; `None` until
    /// the aggregates have been precomputed for this epoch.
    pub committee_aggs: Option<&'a [PublicKey]>,
}

impl<'a> EpochShuffling<'a> {
    /// Attester shuffling for `epoch`, seeded from the state's randao ring.
    pub fn from_state(rv: &StateReadView, epoch: Epoch, buf: &'a mut Vec<u32>) -> Self {
        Self::from_views(&rv.validators, &rv.randao_mixes, epoch, buf)
    }

    pub fn from_views(
        validators: &ValidatorsView,
        randao: &RandaoMixesView,
        epoch: Epoch,
        buf: &'a mut Vec<u32>,
    ) -> Self {
        let seed = Seed::from_randao(randao, epoch, DOMAIN_BEACON_ATTESTER);
        let built_against = validators.count();
        validators.active_indices_into(epoch, buf);
        seed.shuffle(buf);
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

    #[cfg(test)]
    pub(crate) fn with_committees_per_slot(
        shuffled: &'a [u32],
        committees_per_slot: usize,
    ) -> Self {
        Self { shuffled, committees_per_slot, built_against: shuffled.len(), committee_aggs: None }
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

    pub fn post(
        &self,
        epoch: Epoch,
        producer: &mut TProducer,
        emit: impl FnOnce(BeaconStateEvent),
    ) -> bool {
        let len = size_of_val(self.shuffled);
        let Some(mut reservation) = producer.reserve(len, true) else {
            tracing::warn!(epoch, len, "beacon_state tcache full; shuffling not posted");
            return false;
        };
        let Ok(buffer) = reservation.buffer() else {
            return false;
        };
        for (bytes, index) in buffer.chunks_exact_mut(size_of::<u32>()).zip(self.shuffled) {
            bytes.copy_from_slice(&index.to_le_bytes());
        }
        reservation.increment_offset(len);
        emit(BeaconStateEvent::AttestersShuffling {
            epoch,
            committees_per_slot: self.committees_per_slot as u32,
            indices: reservation.read(),
        });
        true
    }

    /// Proportional split, so sizes differ by at most one and the committees
    /// partition `shuffled` exactly — every active validator lands in one.
    pub fn committee(&self, slot: Slot, committee_index: usize) -> &'a [u32] {
        &self.shuffled
            [committee_range(self.shuffled.len(), self.committees_per_slot, slot, committee_index)]
    }
}

/// The two shufflings an attestation's target epoch may name.
pub struct ShufflingRef<'a> {
    pub curr: EpochShuffling<'a>,
    pub prev: EpochShuffling<'a>,
}

impl<'a> ShufflingRef<'a> {
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
        let shuffling = EpochShuffling::with_committees_per_slot(&shuffled, 2);

        let c = shuffling.committee(0, 0);
        assert_eq!(c.len(), 10);

        let c1 = shuffling.committee(0, 1);
        assert_eq!(c1.len(), 10);
        assert_ne!(c[0], c1[0]);

        let c_last = shuffling.committee(31, 1);
        assert_eq!(c_last.len(), 10);
    }
}
