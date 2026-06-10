use super::{InactivityId, InactivityScoresGroup, finalized::FinalizedInactivityScores};
use crate::{
    buffer::{Reset, Slot},
    sparse::{
        SparseLayer, install_against, lookup_sparse, rebase_and_prune_sparse, replace_against,
        set_against, sweep,
    },
};

/// Per-fork sparse overlay of `inactivity_scores` over the finalized base.
/// Sorted by index; entries equal to the base are elided. `total` is the fork's
/// list length, grown in lockstep with the validator registry.
#[derive(Default, Clone)]
pub(crate) struct InactivityScoresDelta {
    edits: Vec<(u32, u64)>,
    total: usize,
}

impl InactivityScoresDelta {
    #[inline]
    pub(super) fn edits(&self) -> &[(u32, u64)] {
        &self.edits
    }

    #[inline]
    pub(super) fn total(&self) -> usize {
        self.total
    }

    /// Anchor a freshly-rolled (reset) delta at `base`'s length. `edits` is
    /// already empty; only the length needs seeding. Mirrors `BalancesDelta`.
    pub(super) fn anchor_at(&mut self, base: &FinalizedInactivityScores) {
        self.total = base.count();
    }

    /// Fill `out` (a fresh slot) with `self` (a survivor) finalized against a
    /// promoted `winner`, pre-promotion. `self` is only read (stays frozen).
    /// `valid_below` (old base count) and `new_count` (winner's length) are
    /// both intrinsic. See [`rebase_and_prune_sparse`].
    pub(super) fn rebase_and_prune(
        &self,
        out: &mut InactivityScoresDelta,
        base: &FinalizedInactivityScores,
        winner: &InactivityScoresDelta,
    ) {
        out.total = self.total;
        out.edits = rebase_and_prune_sparse(
            &self.edits,
            &winner.edits,
            base.count() as u32,
            winner.total as u32,
            |idx| base.get(idx as usize),
            |idx| lookup_sparse(&winner.edits, idx).unwrap_or_else(|| base.get(idx as usize)),
        );
    }
}

impl Reset for InactivityScoresDelta {
    fn reset(&mut self) {
        self.edits.clear();
        self.total = 0;
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.total = other.total;
    }
}

impl SparseLayer for InactivityScoresDelta {
    type Base = FinalizedInactivityScores;
    type Val = u64;
    const APPENDED_DEFAULT: u64 = 0;
    fn edits_mut(&mut self) -> &mut Vec<(u32, u64)> {
        &mut self.edits
    }
    fn base_get(base: &FinalizedInactivityScores, i: usize) -> u64 {
        base.get(i)
    }
    fn base_data(base: &FinalizedInactivityScores) -> &[u64] {
        &base.data
    }
    fn base_count(base: &FinalizedInactivityScores) -> usize {
        base.count()
    }
    fn total(&self) -> usize {
        self.total
    }
}

/// Read-only view over the inactivity base + a frozen fork delta.
#[derive(Clone, Copy)]
pub struct InactivityView<'a> {
    base: &'a FinalizedInactivityScores,
    delta: &'a InactivityScoresDelta,
}

impl<'a> InactivityView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedInactivityScores,
        delta: &'a InactivityScoresDelta,
    ) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> u64 {
        if let Some(v) = lookup_sparse(self.delta.edits(), ix as u32) {
            return v;
        }
        if ix < self.base.count() { self.base.get(ix) } else { 0 }
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = u64> + 'a {
        sweep(self.delta.edits(), &self.base.data[..self.base.count()], 0, self.delta.total())
    }
}

/// Writer over the inactivity group's base + a per-fork delta. Length is
/// intrinsic (no external counts), mirroring [`BalancesWriteView`].
pub struct InactivityWriteView<'a> {
    base: &'a FinalizedInactivityScores,
    fork: Slot<'a, InactivityScoresGroup, InactivityScoresDelta>,
}

impl<'a> InactivityWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedInactivityScores,
        fork: Slot<'a, InactivityScoresGroup, InactivityScoresDelta>,
    ) -> Self {
        Self { base, fork }
    }

    /// Consume the writer and surface the fork's typed id (see
    /// [`Slot::commit`]).
    #[inline]
    pub fn commit(self) -> InactivityId {
        self.fork.commit()
    }

    /// Grow the list by one (new validator → score 0, the base default, so no
    /// edit). Mirrors `BalancesWriteView::append`; the two move in lockstep.
    #[inline]
    pub fn append(&mut self) -> u32 {
        let idx = self.fork.total as u32;
        self.fork.total += 1;
        idx
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: u64) {
        set_against(&mut *self.fork, self.base, idx, v);
    }

    #[inline]
    pub fn install(&mut self, dense: &mut Vec<(u32, u64)>) {
        install_against(&mut *self.fork, self.base, dense);
    }

    #[inline]
    pub fn replace<F: FnMut(usize, u64) -> u64>(&mut self, scratch: &mut Vec<(u32, u64)>, f: F) {
        replace_against(&mut *self.fork, self.base, scratch, f);
    }

    /// Read-only view over the same base + fork — mirrors
    /// `BalancesWriteView::reader`.
    #[inline]
    pub fn reader(&self) -> InactivityView<'_> {
        InactivityView::new(self.base, &self.fork)
    }

    #[inline]
    pub fn get(&self, ix: usize) -> u64 {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.reader().iter()
    }
}
