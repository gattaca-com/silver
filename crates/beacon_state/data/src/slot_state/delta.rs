use super::{SlotStateGroup, SlotStateId, finalized::SlotStateFinalized};
use crate::{
    SLOTS_PER_EPOCH,
    buffer::{Reset, Slot as RingSlot, drain_promoted_prefix},
    types::{B256, Epoch, Slot, SlotState},
};

/// Per-fork slot-tier delta: the working `SlotState` scalars plus block/state
/// roots appended since finalization (circular-buffer tail).
// size: ~1 KB inline (SlotState scalars + Vec headers); root tails + eth1_votes
// on the heap.
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

    /// Effective `SlotState` — the fork's if it has a delta, else the base.
    #[inline]
    pub fn state(&self) -> &'a SlotState {
        self.delta.map_or(&self.base.slot, |d| &d.slot)
    }

    /// The finalized base `SlotState` (ignores the fork delta).
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

    /// Finalized circular buffer of block roots (length
    /// `SLOTS_PER_HISTORICAL_ROOT`).
    #[inline]
    pub fn finalized_block_roots(&self) -> &'a [B256] {
        &self.base.block_roots
    }

    #[inline]
    pub fn finalized_state_roots(&self) -> &'a [B256] {
        &self.base.state_roots
    }

    /// Block roots appended on the fork delta (empty if no delta).
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

    /// Merged `block_roots` ring (finalized base + delta-appended roots
    /// overlaid by slot) written into `out`.
    pub fn effective_block_roots_into(&self, out: &mut Vec<B256>) {
        self.overlay_ring_into(self.finalized_block_roots(), self.delta_block_roots(), out);
    }

    /// Merged `state_roots` ring written into `out`.
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

    /// The fork's working `SlotState` (read / mutate).
    #[inline]
    pub fn state(&self) -> &SlotState {
        &self.fork.slot
    }

    /// The finalized base `SlotState`.
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
