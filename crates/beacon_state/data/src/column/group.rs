use std::marker::PhantomData;

use silver_common_macros::timed;

use super::{
    ColumnReader, ColumnSpec, ColumnWriteView, delta::ColumnDelta, finalized::FinalizedColumn,
};
use crate::{
    buffer::{Id, Ring, reanchor_survivors},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

pub struct ColumnGroup<C: ColumnSpec> {
    finalized: FinalizedColumn<C::Val>,
    deltas: Ring<Self, ColumnDelta<C::Val>, SLOTS_RING_N>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> ColumnGroup<C> {
    #[inline]
    pub(crate) fn finalized(&self) -> &FinalizedColumn<C::Val> {
        &self.finalized
    }

    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            finalized: FinalizedColumn::new(cap, count, ssz_bytes)?,
            deltas: Ring::default(),
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnReader<'_, C> {
        ColumnReader::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        ColumnWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        ColumnWriteView::new(finalized, deltas.roll_from(parent))
    }

    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        let (mut new, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut new, finalized, winner_delta);
        ColumnWriteView::new(finalized, new)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the
    /// finalized state.
    #[timed]
    pub fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas, .. } = self;
        deltas.get(winner).promote_into_base(finalized);

        deltas.free_outdated(&fresh);

        fresh
    }
}
