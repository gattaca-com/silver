use rustc_hash::FxHashMap;
use silver_beacon_state_data::{Epoch, Slot, Version};
use silver_ssz::ssz_view::{SINGLE_ATT_SIZE, SingleAttestationView};

use crate::versioned_data::VersionedData;

#[derive(Default)]
struct SlotVotes {
    slot: Slot,
    positions: FxHashMap<u32, u32>,
    votes: Vec<VersionedData>,
}

impl SlotVotes {
    fn reset(&mut self, slot: Slot) {
        self.slot = slot;
        self.positions.clear();
        self.votes.clear();
    }

    fn first(&self, validator_index: u32) -> Option<&VersionedData> {
        self.positions.get(&validator_index).map(|&at| &self.votes[at as usize])
    }

    fn record(&mut self, validator_index: u32, vote: VersionedData) {
        let at = self.votes.len() as u32;
        if *self.positions.entry(validator_index).or_insert(at) == at {
            self.votes.push(vote);
        }
    }
}

/// Each validator's first public vote in the latest two attestation slots.
#[derive(Default)]
pub(crate) struct PublicVotes {
    slots: [SlotVotes; 2],
}

impl PublicVotes {
    pub(crate) fn record(&mut self, accepted: &[u8; SINGLE_ATT_SIZE], fork_version: Version) {
        let slot = SingleAttestationView::slot(accepted);
        let Ok(validator_index) = u32::try_from(SingleAttestationView::attester_index(accepted))
        else {
            return;
        };
        let votes = &mut self.slots[(slot % 2) as usize];
        if votes.slot != slot {
            if votes.slot > slot {
                return;
            }
            votes.reset(slot);
        }
        votes.record(
            validator_index,
            VersionedData::new(*SingleAttestationView::data(accepted).as_bytes(), fork_version),
        );
    }

    /// Compares data and recorded fork versions; does not verify signatures.
    pub(crate) fn conflicts(
        &self,
        single: &[u8; SINGLE_ATT_SIZE],
        signing_version: impl Fn(Epoch) -> Version,
    ) -> bool {
        let Ok(validator_index) = u32::try_from(SingleAttestationView::attester_index(single))
        else {
            return false;
        };
        let data = SingleAttestationView::data(single);
        self.slots
            .iter()
            .filter_map(|votes| votes.first(validator_index))
            .any(|first| first.is_double_vote_with(&data) && first.verifies_under(&signing_version))
    }
}
