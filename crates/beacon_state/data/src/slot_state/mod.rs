mod delta;
mod finalized;
#[cfg(test)]
mod tests;

use delta::SlotStateDelta;
pub use delta::{SlotStateView, SlotStateWriteView};
pub use finalized::SlotStateFinalized;
use flux_profiler::timed;

use crate::{
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring},
    types::SLOTS_RING_N,
};

pub type SlotStateId = Id<SlotStateGroup>;

pub struct SlotStateGroup {
    finalized: SlotStateFinalized,
    deltas: Ring<Self, SlotStateDelta>,
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
        SlotStateWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { finalized, deltas } = self;
        SlotStateWriteView::new(finalized, deltas.roll_from(parent))
    }

    /// Copy a survivor into a fresh slot and drop the promoted root prefix
    /// (pre-promotion). The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: SlotStateId, winner: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        SlotStateWriteView::new(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the finalized state
    /// (circular-buffer write).
    #[timed]
    pub fn finalize(&mut self, winner: SlotStateId, survivors: &[SlotStateId]) -> Vec<SlotStateId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        finalized.promote(deltas.get(winner));

        deltas.free_outdated(&fresh);

        fresh
    }
}
