use std::marker::PhantomData;

use super::{ParticipationGroup, finalized::FinalizedParticipation};
use crate::{
    buffer::{Id, Reset, Slot},
    sparse::{
        SparseLayer, install_against, lookup_sparse, rebase_and_prune_sparse, replace_against,
        set_against, sparse_merge_into, sweep,
    },
};

/// Per-fork sparse overlay of a participation column over the finalized base.
/// Sorted by index; entries equal to the base are elided. `total` is the fork's
/// length, grown in lockstep with the validator registry. Shared by both the
/// previous and current columns — the marker lives on [`ParticipationGroup`].
#[derive(Default, Clone)]
pub(crate) struct ParticipationDelta {
    edits: Vec<(u32, u8)>,
    total: usize,
}

impl ParticipationDelta {
    #[inline]
    pub(super) fn edits(&self) -> &[(u32, u8)] {
        &self.edits
    }

    #[inline]
    pub(super) fn total(&self) -> usize {
        self.total
    }

    pub(super) fn anchor_at(&mut self, base: &FinalizedParticipation) {
        self.total = base.count();
    }

    /// Fill `out` (a fresh slot) with `self` (a survivor) finalized against a
    /// promoted `winner`, pre-promotion. See [`rebase_and_prune_sparse`].
    pub(super) fn rebase_and_prune(
        &self,
        out: &mut ParticipationDelta,
        base: &FinalizedParticipation,
        winner: &ParticipationDelta,
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

impl Reset for ParticipationDelta {
    fn reset(&mut self) {
        self.edits.clear();
        self.total = 0;
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.total = other.total;
    }
}

impl SparseLayer for ParticipationDelta {
    type Base = FinalizedParticipation;
    type Val = u8;
    const APPENDED_DEFAULT: u8 = 0;
    fn edits_mut(&mut self) -> &mut Vec<(u32, u8)> {
        &mut self.edits
    }
    fn base_get(base: &FinalizedParticipation, i: usize) -> u8 {
        base.get(i)
    }
    fn base_data(base: &FinalizedParticipation) -> &[u8] {
        &base.data
    }
}

/// Read-only view over one participation column's base + a frozen fork delta.
/// Generic over the column marker `M` (previous / current).
pub struct ParticipationView<'a, M> {
    base: &'a FinalizedParticipation,
    delta: &'a ParticipationDelta,
    _marker: PhantomData<fn() -> M>,
}

impl<'a, M> Clone for ParticipationView<'a, M> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, M> Copy for ParticipationView<'a, M> {}

impl<'a, M> ParticipationView<'a, M> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedParticipation, delta: &'a ParticipationDelta) -> Self {
        Self { base, delta, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> u8 {
        if let Some(v) = lookup_sparse(self.delta.edits(), ix as u32) {
            return v;
        }
        if ix < self.base.count() { self.base.get(ix) } else { 0 }
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = u8> + 'a {
        sweep(self.delta.edits(), &self.base.data[..self.base.count()], 0, self.delta.total())
    }
}

/// Writer over one participation column's base + a per-fork delta. Generic over
/// the column marker `M` (previous / current). Length is intrinsic.
pub struct ParticipationWriteView<'a, M> {
    base: &'a FinalizedParticipation,
    fork: Slot<'a, ParticipationGroup<M>, ParticipationDelta>,
}

impl<'a, M> ParticipationWriteView<'a, M> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedParticipation,
        fork: Slot<'a, ParticipationGroup<M>, ParticipationDelta>,
    ) -> Self {
        Self { base, fork }
    }

    /// Consume the writer and surface the fork's typed id (see
    /// [`Slot::commit`]).
    #[inline]
    pub fn commit(self) -> Id<ParticipationGroup<M>> {
        self.fork.commit()
    }

    /// Grow the list by one (new validator → flags 0, the base default).
    #[inline]
    pub fn append(&mut self) -> u32 {
        let idx = self.fork.total as u32;
        self.fork.total += 1;
        idx
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: u8) {
        let base_count = self.base.count();
        set_against(&mut *self.fork, self.base, base_count, idx, v);
    }

    /// Merge a sorted, distinct-index batch in O(|edits| + |batch|), keeping
    /// base-equal entries (the read sweep / rebase tolerate redundant edits).
    #[inline]
    pub fn merge(&mut self, sorted: &[(u32, u8)]) {
        sparse_merge_into(self.fork.edits_mut(), sorted);
    }

    #[inline]
    pub fn install(&mut self, dense: &mut Vec<(u32, u8)>) {
        let base_count = self.base.count();
        install_against(&mut *self.fork, self.base, base_count, dense);
    }

    #[inline]
    pub fn replace<F: FnMut(usize, u8) -> u8>(&mut self, scratch: &mut Vec<(u32, u8)>, f: F) {
        let base_count = self.base.count();
        let total = self.fork.total;
        replace_against(&mut *self.fork, self.base, base_count, total, scratch, f);
    }

    /// Read-only view over the same base + fork — mirrors
    /// `BalancesWriteView::reader`.
    #[inline]
    pub fn reader(&self) -> ParticipationView<'_, M> {
        ParticipationView::new(self.base, &self.fork)
    }

    #[inline]
    pub fn get(&self, ix: usize) -> u8 {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.reader().iter()
    }
}
