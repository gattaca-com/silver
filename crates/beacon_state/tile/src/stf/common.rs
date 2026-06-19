use silver_beacon_state_data::{B256, Epoch, PendingDeposit, StateReadView};
use silver_ssz::ssz_view::MAX_ATTESTING_INDICES;

use crate::{
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash,
    stf::MAX_PENDING_DEPOSITS_PER_EPOCH,
};

pub(crate) const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;

/// One attester's block-included vote, emitted by `process_attestations` for
/// the tile to fold into the LMD vote tracker.
#[derive(Clone, Copy)]
pub struct AttestationVote {
    pub validator: u32,
    pub block_root: B256,
    pub target_epoch: Epoch,
}

/// Reusable scratch buffers threaded together through the state transition
/// (`apply_block` → `process_slots` → `process_epoch`).
pub struct StfScratch {
    /// Active set / committee participants / participating indices — reused
    /// across the epoch-transition and block-body passes.
    pub active: Vec<u32>,
    pub postponed: Vec<PendingDeposit>,
    /// Sparse-edit rebuild buffers + effective-balance column for the
    /// epoch-transition passes.
    pub replace_u64: Vec<(u32, u64)>,
    pub replace_u8: Vec<(u32, u8)>,
    pub eff: Vec<u64>,
    /// Merged-ring buffers for `hash_tree_root_state`.
    pub state_hash: ssz_hash::StateHashScratch,
}

impl StfScratch {
    pub fn new(validator_cap: usize) -> Self {
        Self {
            active: Vec::with_capacity(validator_cap.max(MAX_ATTESTING_INDICES)),
            postponed: Vec::with_capacity(MAX_PENDING_DEPOSITS_PER_EPOCH),
            replace_u64: Vec::with_capacity(validator_cap),
            replace_u8: Vec::with_capacity(validator_cap),
            eff: Vec::with_capacity(validator_cap),
            state_hash: ssz_hash::StateHashScratch::new(),
        }
    }
}

/// Walk an SSZ variable-size list's offset table, calling `f(item)` per
/// element. Empty or unparseable tables yield zero items; an inverted or
/// out-of-bounds offset pair yields `bad_offsets(start, end)`.
pub(crate) fn for_each_ssz_list_item<E>(
    data: &[u8],
    bad_offsets: impl Fn(usize, usize) -> E,
    mut f: impl FnMut(&[u8]) -> std::result::Result<(), E>,
) -> std::result::Result<(), E> {
    if data.is_empty() {
        return Ok(());
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return Ok(());
    }
    let count = first_offset / 4;
    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start >= end || end > data.len() {
            return Err(bad_offsets(start, end));
        }
        f(&data[start..end])?;
    }
    Ok(())
}

/// Shuffled indices for current and previous epoch, needed for attestation
/// processing.
pub struct ShufflingRef<'a> {
    pub curr_epoch: Epoch,
    pub curr_shuffled: &'a [u32],
    pub curr_committees_per_slot: usize,
    pub prev_epoch: Epoch,
    pub prev_shuffled: &'a [u32],
    pub prev_committees_per_slot: usize,
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
        let (epoch, slot) = (&rv.epoch, &rv.slot);
        let previous_epoch = current_epoch.saturating_sub(1);
        let curr_seed =
            shuffling::get_seed_from_state(epoch, slot, current_epoch, DOMAIN_BEACON_ATTESTER);
        let prev_seed =
            shuffling::get_seed_from_state(epoch, slot, previous_epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::get_active_validator_indices_into(&rv.validators, current_epoch, curr_buf);
        shuffling::get_active_validator_indices_into(&rv.validators, previous_epoch, prev_buf);
        shuffling::shuffle_list(curr_buf, &curr_seed);
        shuffling::shuffle_list(prev_buf, &prev_seed);
        let curr_committees_per_slot = shuffling::committees_per_slot(curr_buf.len());
        let prev_committees_per_slot = shuffling::committees_per_slot(prev_buf.len());
        Self {
            curr_epoch: current_epoch,
            curr_shuffled: curr_buf,
            curr_committees_per_slot,
            prev_epoch: previous_epoch,
            prev_shuffled: prev_buf,
            prev_committees_per_slot,
        }
    }

    /// The (shuffled indices, committees-per-slot) pair for the current or
    /// previous epoch.
    pub(crate) fn epoch_slice(&self, is_current: bool) -> (&'a [u32], usize) {
        if is_current {
            (self.curr_shuffled, self.curr_committees_per_slot)
        } else {
            (self.prev_shuffled, self.prev_committees_per_slot)
        }
    }
}
