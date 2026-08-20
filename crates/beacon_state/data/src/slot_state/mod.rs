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
    reanchor::reanchor_survivors,
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

    /// Copy a survivor into a fresh slot so finalization can free the ring
    /// below it. The delta is a full working copy of `SlotState`, so nothing
    /// rebases against the new base.
    fn reanchor(&mut self, survivor: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { finalized, deltas } = self;
        SlotStateWriteView::new(finalized, deltas.roll_from(survivor))
    }

    /// Re-anchor each survivor into a fresh slot (deduped), then adopt the
    /// winner's `SlotState` as the finalized base.
    #[timed]
    pub fn finalize(&mut self, winner: SlotStateId, survivors: &[SlotStateId]) -> Vec<SlotStateId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s).commit());

        let Self { finalized, deltas } = self;
        finalized.promote(deltas.get(winner));

        deltas.free_outdated(&fresh);

        fresh
    }
}
