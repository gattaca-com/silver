use std::ops::Range;

use crate::types::{SLOTS_PER_EPOCH, Slot};

/// Spec `compute_committee` over an epoch's shuffled active set: committee
/// `committee_index` of `slot` is a proportional slice, so sizes differ by at
/// most one and the committees of the epoch partition the set exactly.
pub fn committee_range(
    shuffled_len: usize,
    committees_per_slot: usize,
    slot: Slot,
    committee_index: usize,
) -> Range<usize> {
    let epoch_committee_count = committees_per_slot * SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = (slot % SLOTS_PER_EPOCH) as usize;
    let index_in_epoch = slot_in_epoch * committees_per_slot + committee_index;

    let start = shuffled_len * index_in_epoch / epoch_committee_count;
    let end = shuffled_len * (index_in_epoch + 1) / epoch_committee_count;
    start..end
}
