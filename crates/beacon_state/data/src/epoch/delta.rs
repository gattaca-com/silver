use super::{EpochGroup, EpochId, finalized::EpochStateFinalized};
use crate::{
    buffer::{Reset, Slot as RingSlot},
    types::{B256, Epoch, EpochState},
};

/// Per-fork epoch-tier delta: the working [`EpochState`] scalars plus the
/// per-completed-epoch `randao_mixes`/`slashings` log appended since
/// finalization.
// size: ~696 B stack (2 × Vec header + EpochState ~648 B); logs on the heap.
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
        let drop_r = promoted.randao_mixes.len().min(self.randao_mixes.len());
        self.randao_mixes.drain(..drop_r);
        let drop_s = promoted.slashings.len().min(self.slashings.len());
        self.slashings.drain(..drop_s);
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

    /// Effective `EpochState` — the fork's if it has a delta, else the base.
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

    /// Finalized circular buffer of randao mixes (length
    /// `EPOCHS_PER_HISTORICAL_VECTOR`).
    #[inline]
    pub fn finalized_randao_mixes(&self) -> &'a [B256] {
        &self.base.randao_mixes
    }

    /// Finalized circular buffer of per-epoch slashings totals (length
    /// `EPOCHS_PER_SLASHINGS_VECTOR`).
    #[inline]
    pub fn finalized_slashings(&self) -> &'a [u64] {
        &self.base.slashings
    }

    /// Randao mixes appended on the fork delta (empty if no delta).
    #[inline]
    pub fn delta_randao_mixes(&self) -> &'a [B256] {
        self.delta.map_or(&[][..], |d| &d.randao_mixes)
    }

    /// Per-epoch slashings appended on the fork delta (empty if no delta).
    #[inline]
    pub fn delta_slashings(&self) -> &'a [u64] {
        self.delta.map_or(&[][..], |d| &d.slashings)
    }

    /// `randao_mix(epoch)` with the epoch-delta overlay (walked in reverse so a
    /// wrapped position hits the most recent override). Convention: delta entry
    /// `k` is the final mix for epoch `fin_epoch + k`, at circular-buffer
    /// position `(fin_epoch + k) % HV`.
    pub fn randao_mix_at_epoch(&self, epoch: Epoch, fin_epoch: Epoch) -> B256 {
        let cap = self.base.randao_mixes.len();
        if let Some(delta) = self.delta {
            let target_pos = epoch as usize % cap;
            for (k, m) in delta.randao_mixes.iter().enumerate().rev() {
                let pos = (fin_epoch as usize + k) % cap;
                if pos == target_pos {
                    return *m;
                }
            }
        }
        self.base.randao_mixes[epoch as usize % cap]
    }

    /// Per-completed-epoch slashings sum, with the delta overlay (reverse-walk,
    /// same convention as [`Self::randao_mix_at_epoch`]).
    pub fn slashings_at(&self, epoch: Epoch, fin_epoch: Epoch) -> u64 {
        let cap = self.base.slashings.len();
        if let Some(delta) = self.delta {
            let target_pos = epoch as usize % cap;
            for (k, s) in delta.slashings.iter().enumerate().rev() {
                let pos = (fin_epoch as usize + k) % cap;
                if pos == target_pos {
                    return *s;
                }
            }
        }
        self.base.slashings[epoch as usize % cap]
    }
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

    /// Read view over the same fork — mirrors `SlotStateWriteView::reader`.
    #[inline]
    pub fn reader(&self) -> EpochView<'_> {
        EpochView::new(self.base, Some(&self.fork))
    }

    /// Mutable handle to the fork's scalar [`EpochState`].
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
