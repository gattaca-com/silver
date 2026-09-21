use std::ops::Range;

use silver_ssz::ssz_view::MAX_COMMITTEES_PER_SLOT;

use crate::types::{SLOTS_PER_EPOCH, Slot};

pub const TARGET_COMMITTEE_SIZE: usize = 128;

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

pub fn committees_per_slot(active_validator_count: usize) -> usize {
    let per_slot = active_validator_count / SLOTS_PER_EPOCH as usize / TARGET_COMMITTEE_SIZE;
    per_slot.clamp(1, MAX_COMMITTEES_PER_SLOT)
}

/// Where one position of the shuffled active set attests.
pub struct CommitteeSlot {
    pub slot_in_epoch: Slot,
    pub committee_index: usize,
    pub members: Range<usize>,
}

/// Inverse of [`committee_range`]: the committee whose range holds `position`.
pub fn committee_at_position(
    shuffled_len: usize,
    committees_per_slot: usize,
    position: usize,
) -> CommitteeSlot {
    debug_assert!(position < shuffled_len);
    let epoch_committee_count = committees_per_slot * SLOTS_PER_EPOCH as usize;
    let index_in_epoch = ((position + 1) * epoch_committee_count).div_ceil(shuffled_len) - 1;
    let slot_in_epoch = (index_in_epoch / committees_per_slot) as Slot;
    let committee_index = index_in_epoch % committees_per_slot;
    CommitteeSlot {
        slot_in_epoch,
        committee_index,
        members: committee_range(shuffled_len, committees_per_slot, slot_in_epoch, committee_index),
    }
}
