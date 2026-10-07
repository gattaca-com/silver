use silver_beacon_state_data::{
    Epoch, ShufflingId, Slot, StateReadView, committee_range, committees_per_slot,
};

/// The epoch shufflings Beacon State posts for its head: the current and next
/// epoch, and the previous one while it is still held.
#[derive(Default)]
pub(crate) struct PostedShufflings {
    entries: [Shuffling; 3],
}

const NOT_ACTIVE: u32 = u32::MAX;

#[derive(Default)]
pub(crate) struct Shuffling {
    id: Option<ShufflingId>,
    /// Validator index per position of the shuffled active set, as posted.
    order: Vec<u32>,
    /// The inverse of `order`, so a request resolves its own validators
    /// without a walk over the whole set.
    position_of: Vec<u32>,
}

impl PostedShufflings {
    pub(crate) fn record(&mut self, id: ShufflingId, bytes: &[u8]) {
        if bytes.len() < size_of::<u32>() {
            silver_log::error!(epoch = id.epoch, "shuffling posted with no active validators");
            return;
        }
        self.entry_for(id.epoch).fill(id, bytes);
    }

    fn entry_for(&mut self, epoch: Epoch) -> &mut Shuffling {
        let held =
            self.entries.iter().position(|entry| entry.id.is_some_and(|id| id.epoch == epoch));
        let oldest = || {
            let (index, _) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.id.map(|id| id.epoch))
                .expect("three entries");
            index
        };
        &mut self.entries[held.unwrap_or_else(oldest)]
    }

    pub(crate) fn committees_per_slot(
        &self,
        view: &StateReadView<'_>,
        epoch: Epoch,
    ) -> Option<u64> {
        self.get(ShufflingId::from_state(view, epoch)?)
            .map(|shuffling| shuffling.committees_per_slot() as u64)
    }

    pub(crate) fn get(&self, id: ShufflingId) -> Option<&Shuffling> {
        self.entries.iter().find(|entry| entry.id == Some(id) && !entry.order.is_empty())
    }
}

impl Shuffling {
    /// Replaces whatever this entry held, reusing the tables' allocations.
    fn fill(&mut self, id: ShufflingId, bytes: &[u8]) {
        self.id = Some(id);
        self.order.clear();
        self.order.extend(
            bytes
                .chunks_exact(size_of::<u32>())
                .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes"))),
        );
        self.position_of.clear();
        for (position, &validator_index) in self.order.iter().enumerate() {
            let ix = validator_index as usize;
            if ix >= self.position_of.len() {
                self.position_of.resize(ix + 1, NOT_ACTIVE);
            }
            self.position_of[ix] = position as u32;
        }
    }

    pub(crate) fn shuffled_len(&self) -> usize {
        self.order.len()
    }

    pub(crate) fn committees_per_slot(&self) -> usize {
        committees_per_slot(self.order.len())
    }

    pub(crate) fn position(&self, validator_index: u64) -> Option<u32> {
        let position = *self.position_of.get(usize::try_from(validator_index).ok()?)?;
        (position != NOT_ACTIVE).then_some(position)
    }

    /// Members of committee `committee_index` at `slot`, in committee order.
    pub(crate) fn committee(&self, slot: Slot, committee_index: usize) -> &[u32] {
        let range =
            committee_range(self.order.len(), self.committees_per_slot(), slot, committee_index);
        &self.order[range]
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::SLOTS_PER_EPOCH;

    use super::*;

    const ACTIVE: u32 = 8192;

    fn id(epoch: Epoch) -> ShufflingId {
        ShufflingId { epoch, dependent_root: [0; 32] }
    }

    /// The active set reversed and rotated by `epoch`, so epochs differ.
    fn order(epoch: Epoch) -> Vec<u32> {
        (0..ACTIVE).rev().map(|i| (i + epoch as u32) % ACTIVE).collect()
    }

    fn bytes(epoch: Epoch) -> Vec<u8> {
        order(epoch).iter().flat_map(|i| i.to_le_bytes()).collect()
    }

    /// An empty shuffling has no committee to divide into; answering one
    /// would divide by zero.
    #[test]
    fn empty_shufflings_are_not_recorded() {
        let mut posted = PostedShufflings::default();
        posted.record(id(10), &[]);
        assert!(posted.get(id(10)).is_none());
    }

    /// A repost for an epoch replaces it; a newer epoch evicts the oldest
    /// held.
    #[test]
    fn posted_shufflings_hold_the_three_newest_epochs() {
        let mut posted = PostedShufflings::default();
        posted.record(id(10), &bytes(10));
        posted.record(id(11), &bytes(11));
        posted.record(id(12), &bytes(12));
        posted.record(id(10), &bytes(13));
        for (position, &validator_index) in order(13).iter().enumerate() {
            assert_eq!(
                posted.get(id(10)).unwrap().position(validator_index as u64),
                Some(position as u32)
            );
        }

        posted.record(id(13), &bytes(13));
        assert!(posted.get(id(10)).is_none());
        assert!([11, 12, 13].iter().all(|&epoch| posted.get(id(epoch)).is_some()));
    }

    /// Epoch zero is a real epoch, so recording it must not leave an unfilled
    /// slot looking like the oldest.
    #[test]
    fn epoch_zero_fills_one_slot_and_leaves_the_others_free() {
        let mut posted = PostedShufflings::default();
        posted.record(id(0), &bytes(0));
        posted.record(id(1), &bytes(1));
        posted.record(id(2), &bytes(2));
        assert!([0, 1, 2].iter().all(|&epoch| posted.get(id(epoch)).is_some()));
    }

    /// The committees of an epoch partition the posted order, slot by slot
    /// and index by index.
    #[test]
    fn committees_partition_the_posted_order() {
        let mut posted = PostedShufflings::default();
        posted.record(id(7), &bytes(7));
        let shuffling = posted.get(id(7)).unwrap();
        let per_slot = shuffling.committees_per_slot();
        let joined: Vec<u32> = (0..SLOTS_PER_EPOCH)
            .flat_map(|slot| (0..per_slot).map(move |index| (slot, index)))
            .flat_map(|(slot, index)| shuffling.committee(slot, index).to_vec())
            .collect();
        assert_eq!(joined, order(7));
    }
}
