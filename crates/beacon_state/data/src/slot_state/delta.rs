use silver_ssz::ssz_hash;

use super::{SlotStateGroup, SlotStateId, finalized::SlotStateFinalized};
use crate::{
    SLOTS_PER_EPOCH,
    buffer::{Reset, Slot as RingSlot, drain_promoted_prefix},
    types::{B256, Epoch, SLOTS_PER_HISTORICAL_ROOT, Slot, SlotState},
};

// size: ~1 KB inline (SlotState scalars + Vec headers); root tails on the
// heap.
#[derive(Clone, Default)]
pub(crate) struct SlotStateDelta {
    pub(super) slot: SlotState,
    pub(super) block_roots: Vec<B256>,
    pub(super) state_roots: Vec<B256>,
}

impl SlotStateDelta {
    /// Drop the promoted prefix of the root tails (now folded into the base) —
    /// the reanchor half of finalization, run on a fresh copy of a survivor.
    pub(super) fn prune_to_base(&mut self, promoted: &SlotStateDelta) {
        drain_promoted_prefix(&mut self.block_roots, promoted.block_roots.len());
        drain_promoted_prefix(&mut self.state_roots, promoted.state_roots.len());
    }
}

impl Reset for SlotStateDelta {
    fn reset(&mut self) {
        self.slot = Default::default();
        self.block_roots.clear();
        self.state_roots.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.slot.clone_from(&other.slot);
        self.block_roots.clone_from(&other.block_roots);
        self.state_roots.clone_from(&other.state_roots);
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
            let mut h = ssz_hash::sha256(c);
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

    #[inline]
    pub fn finalized_block_roots(&self) -> &'a [B256] {
        &self.base.block_roots
    }

    #[inline]
    pub fn finalized_state_roots(&self) -> &'a [B256] {
        &self.base.state_roots
    }

    #[inline]
    pub fn delta_block_roots(&self) -> &'a [B256] {
        self.delta.map_or(&[][..], |d| &d.block_roots)
    }

    #[inline]
    pub fn delta_state_roots(&self) -> &'a [B256] {
        self.delta.map_or(&[][..], |d| &d.state_roots)
    }

    /// Block root at `slot`: prefer the fork delta tail (entry `slot -
    /// fin_slot`), else the finalized circular buffer (`slot % cap`).
    #[inline]
    pub fn block_root_at_slot(&self, slot: Slot) -> B256 {
        Self::root_at_slot(
            self.base_state().slot,
            self.delta_block_roots(),
            self.finalized_block_roots(),
            slot,
        )
    }

    fn root_at_slot(fin_slot: Slot, delta_roots: &[B256], fin_roots: &[B256], slot: Slot) -> B256 {
        if slot >= fin_slot {
            let i = (slot - fin_slot) as usize;
            if i < delta_roots.len() {
                return delta_roots[i];
            }
        }
        fin_roots[slot as usize % fin_roots.len()]
    }

    pub fn effective_block_roots_into(&self, out: &mut Vec<B256>) {
        self.overlay_ring_into(self.finalized_block_roots(), self.delta_block_roots(), out);
    }

    pub fn effective_state_roots_into(&self, out: &mut Vec<B256>) {
        self.overlay_ring_into(self.finalized_state_roots(), self.delta_state_roots(), out);
    }

    fn overlay_ring_into(&self, fin: &[B256], delta: &[B256], out: &mut Vec<B256>) {
        out.clear();
        out.extend_from_slice(fin);
        let cap = out.len();
        let fin_slot = self.base_state().slot as usize;
        for (k, r) in delta.iter().enumerate() {
            out[(fin_slot + k) % cap] = *r;
        }
    }
}

pub struct SlotStateWriteView<'a> {
    base: &'a SlotStateFinalized,
    fork: RingSlot<'a, SlotStateGroup, SlotStateDelta>,
}

impl<'a> SlotStateWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a SlotStateFinalized,
        fork: RingSlot<'a, SlotStateGroup, SlotStateDelta>,
    ) -> Self {
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

    #[inline]
    pub fn finalized_block_roots(&self) -> &[B256] {
        &self.base.block_roots
    }

    #[inline]
    pub fn finalized_state_roots(&self) -> &[B256] {
        &self.base.state_roots
    }

    #[inline]
    pub fn push_block_root(&mut self, r: B256) {
        self.fork.block_roots.push(r);
    }

    #[inline]
    pub fn push_state_root(&mut self, r: B256) {
        self.fork.state_roots.push(r);
    }

    #[inline]
    pub fn block_root_at_slot(&self, slot: Slot) -> B256 {
        self.reader().block_root_at_slot(slot)
    }
}
