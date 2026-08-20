use super::{EpochGroup, EpochId, finalized::EpochStateFinalized};
use crate::{
    gloas::{PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    ring::{Reset, Slot as RingSlot},
    types::{Epoch, EpochState, Fork, SLOTS_PER_EPOCH, Version},
};

#[derive(Clone)]
pub(crate) struct EpochStateDelta {
    pub(super) state: EpochState,
    // [New in Gloas]
    pub(super) ptc_window: Box<[PtcCommittee; PTC_WINDOW_LEN]>,
}

impl Default for EpochStateDelta {
    fn default() -> Self {
        Self { state: EpochState::default(), ptc_window: zeroed_ptc_window() }
    }
}

impl Reset for EpochStateDelta {
    fn reset(&mut self) {
        self.state = Default::default();
        // `ptc_window` is left as-is: every roll re-seeds it via
        // `seed_from_base` (roll_fresh) or `reset_from`, so zeroing the 393 KB
        // box here would be redundant work.
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

    #[inline]
    pub fn ptc_window(&self) -> &'a [PtcCommittee; PTC_WINDOW_LEN] {
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
    #[inline]
    pub(super) fn new(base: &'a EpochStateFinalized, fork: RingSlot<'a, EpochGroup>) -> Self {
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
    pub fn set_ptc_window(&mut self, window: Box<[PtcCommittee; PTC_WINDOW_LEN]>) {
        self.fork.ptc_window = window;
    }

    #[inline]
    pub fn rotate_ptc_window(&mut self, new_last_epoch: &[PtcCommittee]) {
        const SPE: usize = SLOTS_PER_EPOCH as usize;
        debug_assert_eq!(new_last_epoch.len(), SPE);
        self.fork.ptc_window.copy_within(SPE.., 0);
        self.fork.ptc_window[PTC_WINDOW_LEN - SPE..].copy_from_slice(new_last_epoch);
    }

    /// Seed the fresh fork's scalar `EpochState` + `ptc_window` from the
    /// finalized base.
    #[inline]
    pub(super) fn seed_from_base(&mut self) {
        self.fork.state = self.base.state;
        self.fork.ptc_window.clone_from(&self.base.ptc_window);
    }
}
