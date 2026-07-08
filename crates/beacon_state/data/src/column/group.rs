use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;

use super::{ColumnReader, ColumnSpec, ColumnWriteView, tree::ColumnTree};
use crate::{
    buffer::{Id, Reset, Ring},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

pub struct ColumnGroup<C: ColumnSpec> {
    finalized: ColumnTree,
    deltas: Ring<Self, ColumnTree, SLOTS_RING_N>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> ColumnGroup<C> {
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            finalized: ColumnTree::new::<C::Val>(cap, count, ssz_bytes)?,
            deltas: Ring::default(),
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnReader<'_, C> {
        ColumnReader::new(self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        let mut slot = deltas.roll_fresh();
        slot.reset_from(finalized);
        ColumnWriteView::new(slot)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        ColumnWriteView::new(self.deltas.roll_from(parent))
    }

    /// Promote the winner's whole tree into the finalized base and reclaim the
    /// non-survivor slots. Survivors are standalone trees that read nothing
    /// through the base, so there is no rebase and their ids are unchanged.
    #[timed]
    pub fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        let Self { finalized, deltas, .. } = self;
        finalized.reset_from(deltas.get(winner));
        deltas.free_outdated(survivors);
        survivors.to_vec()
    }

    #[inline]
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.finalized.write_ssz::<C::Val, W>(w)
    }
}
