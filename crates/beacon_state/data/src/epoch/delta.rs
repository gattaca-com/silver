use super::{EpochGroup, EpochId, finalized::EpochStateFinalized, ptc_window::PtcWindow};
use crate::{
    gloas::{PTC_WINDOW_LEN, PtcCommittee},
    ring::{Reset, Slot as RingSlot},
    types::{B256, Epoch, EpochState, Fork, SLOTS_PER_EPOCH, Slot, Version},
};

#[derive(Clone, Default)]
pub(crate) struct EpochStateDelta {
    pub(super) state: EpochState,
    // [New in Gloas]
    pub(super) ptc_window: PtcWindow,
}

impl Reset for EpochStateDelta {
    fn reset(&mut self) {
        self.state = Default::default();
        // `ptc_window` is left as-is: every roll overwrites it (`fresh` copies
        // the base's, `reset_from` the parent's), so zeroing the 393 KB box
        // here would be redundant work.
    }

    fn reset_from(&mut self, other: &Self) {
        self.state = other.state;
        self.ptc_window.clone_from(&other.ptc_window);
    }
}

/// Value-layer read over the epoch tier (base + optional per-fork delta). The
/// delta is `Some` for a fork that crossed an epoch boundary, else `None` and
/// reads fall through to the base.
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

    /// The block the finalized checkpoint names. Zero is the placeholder a
    /// chain carries until its first finalization, and names none.
    pub fn finalized_block_root(&self) -> Option<B256> {
        let root = self.state().finalized_checkpoint.root;
        (root != [0u8; 32]).then_some(root)
    }

    /// Whether finalization covers a block of this chain at `slot`: the
    /// finalized checkpoint names the newest block at or before its epoch's
    /// first slot, so every block at or below that slot is that one or an
    /// ancestor.
    pub fn finalizes_slot(&self, slot: Slot) -> bool {
        slot <= self.state().finalized_checkpoint.epoch.saturating_mul(SLOTS_PER_EPOCH)
    }

    #[inline]
    pub fn ptc_window(&self) -> &'a PtcWindow {
        self.delta.map_or(&self.base.ptc_window, |d| &d.ptc_window)
    }

    /// Expected proposer at `lookahead_idx` (slots since the lookahead's
    /// anchor epoch start; the window covers current + next epoch), `None`
    /// outside the window.
    #[inline]
    pub fn proposer_at(&self, lookahead_idx: usize) -> Option<u64> {
        self.state().proposer_lookahead.get(lookahead_idx).copied()
    }

    #[inline]
    pub fn fork(&self) -> &'a Fork {
        &self.state().fork
    }

    #[inline]
    pub fn is_gloas(&self, gloas_fork_version: Version) -> bool {
        self.state().fork.current_version == gloas_fork_version
    }

    #[inline]
    pub fn fork_version_at(&self, block_epoch: Epoch) -> Version {
        let f = &self.state().fork;
        if block_epoch >= f.epoch { f.current_version } else { f.previous_version }
    }

    #[inline]
    pub fn fork_descriptor(&self) -> (Epoch, Version, Version) {
        let f = &self.state().fork;
        (f.epoch, f.previous_version, f.current_version)
    }
}

pub struct EpochWriteView<'a> {
    base: &'a EpochStateFinalized,
    fork: RingSlot<'a, EpochGroup>,
}

impl<'a> EpochWriteView<'a> {
    /// Fresh fork: a full working copy of the base's scalars and PTC window.
    #[inline]
    pub(super) fn fresh(base: &'a EpochStateFinalized, mut fork: RingSlot<'a, EpochGroup>) -> Self {
        fork.state = base.state;
        fork.ptc_window.clone_from(&base.ptc_window);
        Self { base, fork }
    }

    /// Fork whose delta already carries its state (roll_from).
    #[inline]
    pub(super) fn derived(base: &'a EpochStateFinalized, fork: RingSlot<'a, EpochGroup>) -> Self {
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

    #[inline]
    pub fn set_ptc_window(&mut self, committees: Box<[PtcCommittee; PTC_WINDOW_LEN]>) {
        self.fork.ptc_window = PtcWindow::new(committees);
    }

    #[inline]
    pub fn rotate_ptc_window(&mut self, new_last_epoch: &[PtcCommittee]) {
        self.fork.ptc_window.rotate(new_last_epoch);
    }
}
