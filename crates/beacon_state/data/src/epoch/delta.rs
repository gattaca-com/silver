use super::{EpochGroup, EpochId, finalized::EpochStateFinalized};
use crate::{
    buffer::{Reset, Slot as RingSlot, drain_promoted_prefix},
    types::{B256, Epoch, EpochState},
};

#[derive(Clone, Default)]
pub(crate) struct EpochStateDelta {
    // one entry per completed epoch since finalization
    pub(super) randao_mixes: Vec<B256>,
    // one entry per completed epoch since finalization
    pub(super) slashings: Vec<u64>,
    pub(super) state: EpochState,
}

impl EpochStateDelta {
    /// Drop the promoted prefix of the per-completed-epoch logs (now folded
    /// into the base) — the reanchor half of finalization, run on a fresh copy
    /// of a survivor.
    pub(super) fn prune_to_base(&mut self, promoted: &EpochStateDelta) {
        drain_promoted_prefix(&mut self.randao_mixes, promoted.randao_mixes.len());
        drain_promoted_prefix(&mut self.slashings, promoted.slashings.len());
    }
}

impl Reset for EpochStateDelta {
    fn reset(&mut self) {
        self.randao_mixes.clear();
        self.slashings.clear();
        self.state = Default::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.randao_mixes.clone_from(&other.randao_mixes);
        self.slashings.clone_from(&other.slashings);
        self.state = other.state;
    }
}

/// Value-layer read over the epoch tier (base + optional per-fork delta). The
/// delta is `Some` for a fork that crossed an epoch boundary, else `None` and
/// reads fall through to the base. The circular-buffer overlay needs the
/// finalized epoch (`fin_epoch`) from the slot tier, so the relevant reads take
/// it as an argument.
#[derive(Clone, Copy)]
pub struct EpochView<'a> {
    base: &'a EpochStateFinalized,
    delta: Option<&'a EpochStateDelta>,
}

impl<'a> EpochView<'a> {
    #[inline]
    pub(crate) fn new(base: &'a EpochStateFinalized, delta: Option<&'a EpochStateDelta>) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn state(&self) -> &'a EpochState {
        self.delta.map_or(&self.base.state, |d| &d.state)
    }

    /// Expected proposer at `lookahead_idx` (slots since the lookahead's
    /// anchor epoch start; the window covers current + next epoch), `None`
    /// outside the window.
    #[inline]
    pub fn proposer_at(&self, lookahead_idx: usize) -> Option<u64> {
        self.state().proposer_lookahead.get(lookahead_idx).copied()
    }

    #[inline]
    pub fn finalized_randao_mixes(&self) -> &'a [B256] {
        &self.base.randao_mixes
    }

    #[inline]
    pub fn finalized_slashings(&self) -> &'a [u64] {
        &self.base.slashings
    }

    #[inline]
    pub fn delta_randao_mixes(&self) -> &'a [B256] {
        self.delta.map_or(&[][..], |d| &d.randao_mixes)
    }

    #[inline]
    pub fn delta_slashings(&self) -> &'a [u64] {
        self.delta.map_or(&[][..], |d| &d.slashings)
    }

    /// `randao_mix(epoch)` with the epoch-delta overlay (see
    /// [`ring_overlay_at`]).
    pub fn randao_mix_at_epoch(&self, epoch: Epoch, fin_epoch: Epoch) -> B256 {
        ring_overlay_at(&self.base.randao_mixes, self.delta_randao_mixes(), epoch, fin_epoch)
    }

    /// Per-completed-epoch slashings sum, with the delta overlay (see
    /// [`ring_overlay_at`]).
    pub fn slashings_at(&self, epoch: Epoch, fin_epoch: Epoch) -> u64 {
        ring_overlay_at(&self.base.slashings, self.delta_slashings(), epoch, fin_epoch)
    }
}

/// Circular-buffer read at `epoch` with the fork-delta overlay, walked in
/// reverse so a wrapped position hits the most recent override. Convention:
/// delta entry `k` is the final value for epoch `fin_epoch + k`, at position
/// `(fin_epoch + k) % cap`.
fn ring_overlay_at<T: Copy>(base_ring: &[T], delta_log: &[T], epoch: Epoch, fin_epoch: Epoch) -> T {
    let cap = base_ring.len();
    let target_pos = epoch as usize % cap;
    for (k, v) in delta_log.iter().enumerate().rev() {
        if (fin_epoch as usize + k) % cap == target_pos {
            return *v;
        }
    }
    base_ring[target_pos]
}

pub struct EpochWriteView<'a> {
    base: &'a EpochStateFinalized,
    fork: RingSlot<'a, EpochGroup, EpochStateDelta>,
}

impl<'a> EpochWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a EpochStateFinalized,
        fork: RingSlot<'a, EpochGroup, EpochStateDelta>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> EpochId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> EpochView<'_> {
        EpochView::new(self.base, Some(&self.fork))
    }

    #[inline]
    pub fn state_mut(&mut self) -> &mut EpochState {
        &mut self.fork.state
    }

    /// Seed the fresh fork's scalar `EpochState` from the finalized base; the
    /// per-completed-epoch logs stay empty (cleared by `reset`).
    #[inline]
    pub(super) fn seed_from_base(&mut self) {
        self.fork.state = self.base.state;
    }

    #[inline]
    pub fn push_randao_mix(&mut self, m: B256) {
        self.fork.randao_mixes.push(m);
    }

    #[inline]
    pub fn push_slashings(&mut self, s: u64) {
        self.fork.slashings.push(s);
    }
}
