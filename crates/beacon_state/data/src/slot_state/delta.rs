use silver_ssz::merkle;

use super::{
    SlotStateGroup, SlotStateId, epoch_balances::EpochBalances, finalized::SlotStateFinalized,
};
use crate::{
    SLOTS_PER_EPOCH,
    ring::{Reset, Slot as RingSlot},
    types::{B256, Epoch, SLOTS_PER_HISTORICAL_ROOT, Slot, SlotState},
};

// size: ~1 KB inline — the `SlotState` scalars.
#[derive(Clone, Default)]
pub(crate) struct SlotStateDelta {
    pub(super) slot: SlotState,
    pub(super) epoch_balances: EpochBalances,
}

impl Reset for SlotStateDelta {
    fn reset(&mut self) {
        self.slot = Default::default();
        self.epoch_balances = Default::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.slot.clone_from(&other.slot);
        self.epoch_balances = other.epoch_balances;
    }
}

/// Value-layer read over the slot tier (base + optional per-fork delta). The
/// delta is `Some` for a published fork (`StateReadView`) and resolved from
/// the published `StateId` bundle for the cross-thread reader
/// (the cross-thread `BeaconStateReader::read`).
#[derive(Clone, Copy)]
pub struct SlotStateView<'a> {
    base: &'a SlotStateFinalized,
    delta: Option<&'a SlotStateDelta>,
}

impl<'a> SlotStateView<'a> {
    #[inline]
    pub(crate) fn new(base: &'a SlotStateFinalized, delta: Option<&'a SlotStateDelta>) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn state(&self) -> &'a SlotState {
        self.delta.map_or(&self.base.slot, |d| &d.slot)
    }

    pub fn bid_versioned_hashes_len(&self, out: &mut [[u8; 32]]) -> Option<usize> {
        let commitments = &self.state().latest_execution_payload_bid.blob_kzg_commitments;
        if commitments.len() > out.len() {
            return None;
        }
        for (i, c) in commitments.iter().enumerate() {
            let mut h = merkle::sha256(c);
            h[0] = 0x01;
            out[i] = h;
        }
        Some(commitments.len())
    }

    #[inline]
    pub fn base_state(&self) -> &'a SlotState {
        &self.base.slot
    }

    #[inline]
    pub fn slot_number(&self) -> Slot {
        self.state().slot
    }

    #[inline]
    pub fn current_epoch(&self) -> Epoch {
        self.state().slot / SLOTS_PER_EPOCH
    }
}

pub struct SlotStateWriteView<'a> {
    base: &'a SlotStateFinalized,
    fork: RingSlot<'a, SlotStateGroup>,
}

impl<'a> SlotStateWriteView<'a> {
    #[inline]
    pub(super) fn new(base: &'a SlotStateFinalized, fork: RingSlot<'a, SlotStateGroup>) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> SlotStateId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> SlotStateView<'_> {
        SlotStateView { base: self.base, delta: Some(&self.fork) }
    }

    #[inline]
    pub fn state(&self) -> &SlotState {
        &self.fork.slot
    }

    #[inline]
    pub fn finalized_state(&self) -> &SlotState {
        &self.base.slot
    }

    #[inline]
    pub fn state_mut(&mut self) -> &mut SlotState {
        &mut self.fork.slot
    }

    #[inline]
    pub fn epoch_balances(&self) -> EpochBalances {
        self.fork.epoch_balances
    }

    #[inline]
    pub fn epoch_balances_mut(&mut self) -> &mut EpochBalances {
        &mut self.fork.epoch_balances
    }

    /// Cached spec `get_total_active_balance` — constant within an epoch
    /// (reseeded at each transition), so callers name the epoch they expect.
    #[inline]
    pub fn total_active_balance(&self, current_epoch: Epoch) -> u64 {
        debug_assert_eq!(self.fork.slot.slot / SLOTS_PER_EPOCH, current_epoch);
        self.fork.epoch_balances.total_active
    }

    #[inline]
    pub fn advance_slot(&mut self) {
        self.fork.slot.slot += 1;
    }

    #[inline]
    pub fn unset_next_payload_availability(&mut self) {
        let next = ((self.fork.slot.slot + 1) % SLOTS_PER_HISTORICAL_ROOT as u64) as usize;
        self.fork.slot.execution_payload_availability[next / 8] &= !(1u8 << (next % 8));
    }

    /// Fill in `state_root` on the latest block header iff it's currently
    /// zero. Called from `process_slot` before computing the block root.
    #[inline]
    pub fn fill_latest_block_header_state_root(&mut self, state_root: B256) {
        let header = &mut self.fork.slot.latest_block_header;
        if header.state_root == [0u8; 32] {
            header.state_root = state_root;
        }
    }
}
