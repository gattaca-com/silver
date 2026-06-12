use std::marker::PhantomData;

use super::{ColumnGroup, ColumnSpec, ColumnVal, finalized::FinalizedColumn};
use crate::{
    buffer::{Id, Reset, Slot},
    sparse::{
        SparseLayer, install_against, lookup_sparse, rebase_and_prune_sparse, replace_against,
        set_against, sparse_merge_into, sweep,
    },
};

/// Sorted by index; entries equal to the base are elided on the bulk paths.
/// `total` is the fork's list length, grown in lockstep with the validator
/// registry.
#[derive(Clone)]
pub(crate) struct ColumnDelta<V> {
    edits: Vec<(u32, V)>,
    total: usize,
}

// Manual impl: the derive would spuriously bind `V: Default` (an empty edit
// vec needs no element default).
impl<V> Default for ColumnDelta<V> {
    fn default() -> Self {
        Self { edits: Vec::new(), total: 0 }
    }
}

impl<V: ColumnVal> ColumnDelta<V> {
    #[inline]
    pub(super) fn edits(&self) -> &[(u32, V)] {
        &self.edits
    }

    #[inline]
    pub(super) fn total(&self) -> usize {
        self.total
    }

    /// Anchor a freshly-rolled (reset) delta at `base`'s length. `edits` is
    /// already empty; only the length needs seeding.
    pub(super) fn anchor_at(&mut self, base: &FinalizedColumn<V>) {
        self.total = base.count();
    }

    /// Fill `out` (a fresh slot) with `self` (a survivor) finalized against a
    /// promoted `winner`, pre-promotion. `self` is only read (stays frozen).
    /// `valid_below` (old base count) and `new_count` (winner's length) are
    /// both intrinsic. See [`rebase_and_prune_sparse`].
    pub(super) fn rebase_and_prune(
        &self,
        out: &mut ColumnDelta<V>,
        base: &FinalizedColumn<V>,
        winner: &ColumnDelta<V>,
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

impl<V: ColumnVal> Reset for ColumnDelta<V> {
    fn reset(&mut self) {
        self.edits.clear();
        self.total = 0;
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.total = other.total;
    }
}

impl<V: ColumnVal> SparseLayer for ColumnDelta<V> {
    type Base = FinalizedColumn<V>;
    type Val = V;
    const APPENDED_DEFAULT: V = V::APPENDED_DEFAULT;
    fn edits_mut(&mut self) -> &mut Vec<(u32, V)> {
        &mut self.edits
    }
    fn base_get(base: &FinalizedColumn<V>, i: usize) -> V {
        base.get(i)
    }
    fn base_data(base: &FinalizedColumn<V>) -> &[V] {
        base.data()
    }
    fn base_count(base: &FinalizedColumn<V>) -> usize {
        base.count()
    }
    fn total(&self) -> usize {
        self.total
    }
}

pub struct ColumnView<'a, C: ColumnSpec> {
    base: &'a FinalizedColumn<C::Val>,
    delta: &'a ColumnDelta<C::Val>,
    _marker: PhantomData<fn() -> C>,
}

// Manual impls: deriving would spuriously bind `C: Clone`.
impl<C: ColumnSpec> Clone for ColumnView<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ColumnSpec> Copy for ColumnView<'_, C> {}

impl<'a, C: ColumnSpec> ColumnView<'a, C> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedColumn<C::Val>, delta: &'a ColumnDelta<C::Val>) -> Self {
        Self { base, delta, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        if let Some(v) = lookup_sparse(self.delta.edits(), ix as u32) {
            return v;
        }
        if ix < self.base.count() { self.base.get(ix) } else { C::Val::APPENDED_DEFAULT }
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        sweep(
            self.delta.edits(),
            &self.base.data()[..self.base.count()],
            C::Val::APPENDED_DEFAULT,
            self.delta.total(),
        )
    }
}

/// Length is intrinsic (no external counts).
pub struct ColumnWriteView<'a, C: ColumnSpec> {
    base: &'a FinalizedColumn<C::Val>,
    fork: Slot<'a, ColumnGroup<C>, ColumnDelta<C::Val>>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedColumn<C::Val>,
        fork: Slot<'a, ColumnGroup<C>, ColumnDelta<C::Val>>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.fork.commit()
    }

    /// Grow the list by one (new validator → the appended default, so no
    /// edit).
    #[inline]
    pub fn append(&mut self) -> u32 {
        let idx = self.fork.total as u32;
        self.fork.total += 1;
        idx
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        set_against(&mut *self.fork, self.base, idx, v);
    }

    /// Merge a sorted, distinct-index batch in O(|edits| + |batch|), keeping
    /// base-equal entries (the read sweep / rebase tolerate redundant edits).
    #[inline]
    pub fn merge(&mut self, sorted: &[(u32, C::Val)]) {
        sparse_merge_into(self.fork.edits_mut(), sorted);
    }

    #[inline]
    pub fn install(&mut self, dense: &mut Vec<(u32, C::Val)>) {
        install_against(&mut *self.fork, self.base, dense);
    }

    #[inline]
    pub fn replace<F: FnMut(usize, C::Val) -> C::Val>(
        &mut self,
        scratch: &mut Vec<(u32, C::Val)>,
        f: F,
    ) {
        replace_against(&mut *self.fork, self.base, scratch, f);
    }

    #[inline]
    pub fn reader(&self) -> ColumnView<'_, C> {
        ColumnView::new(self.base, &self.fork)
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = C::Val> + '_ {
        self.reader().iter()
    }
}
