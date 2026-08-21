mod delta;
mod epoch_balances;
mod finalized;
#[cfg(test)]
mod tests;

use delta::SlotStateDelta;
pub use delta::{SlotStateView, SlotStateWriteView};
pub use epoch_balances::{EpochBalances, EpochBalancesRow};
pub use finalized::SlotStateFinalized;
use flux_profiler::timed;

use crate::{
    reanchor::finalize_full_copies,
    ring::{Id, Ring, RingGroup},
    types::SLOTS_RING_N,
};

pub type SlotStateId = Id<SlotStateGroup>;

pub struct SlotStateGroup {
    finalized: SlotStateFinalized,
    deltas: Ring<Self>,
}

impl RingGroup for SlotStateGroup {
    type Entry = SlotStateDelta;
}

impl SlotStateGroup {
    #[inline]
    pub(crate) fn finalized(&self) -> &SlotStateFinalized {
        &self.finalized
    }

    pub fn new(finalized: SlotStateFinalized) -> Self {
        Self { finalized, deltas: Ring::new(SLOTS_RING_N) }
    }

    #[inline]
    pub fn view(&self, id: SlotStateId) -> SlotStateView<'_> {
        SlotStateView::new(&self.finalized, Some(self.deltas.get(id)))
    }

    /// Read-only view over the finalized state with no active fork — the
    /// pre-fork surface (freshly decomposed / checkpoint-loaded state, and
    /// the cross-thread reader before any slot delta is published).
    #[inline]
    pub fn finalized_view(&self) -> SlotStateView<'_> {
        SlotStateView::new(&self.finalized, None)
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> SlotStateWriteView<'_> {
        let Self { finalized, deltas } = self;
        let mut fork = deltas.roll_fresh();
        // Anchor the fresh fork's full `SlotState` at the finalized state. The slot
        // delta is a full working copy (not a sparse overlay), so an un-seeded
        // fork would shadow the finalized state with zeros; block/state-root
        // tails stay empty.
        fork.slot.clone_from(&finalized.slot);
        fork.epoch_balances = finalized.epoch_balances;
        SlotStateWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { finalized, deltas } = self;
        SlotStateWriteView::new(finalized, deltas.roll_from(parent))
    }

    #[timed]
    pub fn finalize(&mut self, winner: SlotStateId, survivors: &[SlotStateId]) -> Vec<SlotStateId> {
        let Self { finalized, deltas } = self;
        finalize_full_copies(deltas, winner, survivors, |w| finalized.promote(w))
    }
}
