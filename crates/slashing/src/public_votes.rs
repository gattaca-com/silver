use std::collections::hash_map::Entry;

use rustc_hash::FxHashMap;
use silver_beacon_state_data::Slot;
use silver_ssz::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationDataView, SINGLE_ATT_SIZE, SingleAttestationView,
};

pub(crate) fn is_double_vote(first: AttestationDataView, second: AttestationDataView) -> bool {
    first.as_bytes() != second.as_bytes() && first.target_epoch() == second.target_epoch()
}

/// The entries of the latest two slots, each held at `slot % 2`.
pub(crate) struct LatestSlots<T>([(Slot, T); 2]);

impl<T> LatestSlots<T> {
    pub(crate) fn new(entry: impl Fn() -> T) -> Self {
        Self([(0, entry()), (0, entry())])
    }

    /// `reset` empties an entry that held an older slot. None when a newer
    /// slot holds the entry.
    pub(crate) fn at(&mut self, slot: Slot, reset: impl FnOnce(&mut T)) -> Option<&mut T> {
        let (held, entry) = &mut self.0[(slot % 2) as usize];
        if *held != slot {
            if *held > slot {
                return None;
            }
            *held = slot;
            reset(entry);
        }
        Some(entry)
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = &T> {
        self.0.iter().map(|(_, entry)| entry)
    }
}

#[derive(Default)]
struct SlotVotes {
    positions: FxHashMap<u32, u32>,
    data: Vec<[u8; ATTESTATION_DATA_SIZE]>,
}

impl SlotVotes {
    fn clear(&mut self) {
        self.positions.clear();
        self.data.clear();
    }

    fn first(&self, validator_index: u32) -> Option<AttestationDataView<'_>> {
        let at = *self.positions.get(&validator_index)?;
        Some(AttestationDataView::new(&self.data[at as usize]))
    }

    fn record(&mut self, validator_index: u32, data: &[u8; ATTESTATION_DATA_SIZE]) {
        let Entry::Vacant(position) = self.positions.entry(validator_index) else { return };
        if self.data.last() != Some(data) {
            self.data.push(*data);
        }
        position.insert(self.data.len() as u32 - 1);
    }
}

/// Each validator's first public vote in the latest two attestation slots.
pub(crate) struct PublicVotes(LatestSlots<SlotVotes>);

impl Default for PublicVotes {
    fn default() -> Self {
        Self(LatestSlots::new(SlotVotes::default))
    }
}

impl PublicVotes {
    pub(crate) fn record(&mut self, accepted: &[u8; SINGLE_ATT_SIZE]) {
        let Ok(validator_index) = u32::try_from(SingleAttestationView::attester_index(accepted))
        else {
            return;
        };
        let slot = SingleAttestationView::slot(accepted);
        if let Some(votes) = self.0.at(slot, SlotVotes::clear) {
            votes.record(validator_index, SingleAttestationView::data(accepted).as_bytes());
        }
    }

    pub(crate) fn conflicts(&self, single: &[u8; SINGLE_ATT_SIZE]) -> bool {
        let Ok(validator_index) = u32::try_from(SingleAttestationView::attester_index(single))
        else {
            return false;
        };
        let data = SingleAttestationView::data(single);
        self.0
            .entries()
            .filter_map(|votes| votes.first(validator_index))
            .any(|first| is_double_vote(first, data))
    }
}
