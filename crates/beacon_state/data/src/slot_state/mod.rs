//! Slot-tier group: the canonical `SlotState` scalars + block/state-root
//! circular buffers as one finalized base ([`SlotStateFinalized`]) plus a
//! per-fork delta ([`SlotStateDelta`]), bundled with the ring. The heaviest
//! tier (~145 KB `SlotState`); read by both the writer-thread `StateReadView`
//! and the cross-thread reader via [`SlotStateView`].

mod delta;
mod finalized;
#[cfg(test)]
mod tests;

use delta::SlotStateDelta;
pub use delta::{SlotStateView, SlotStateWriteView};
pub use finalized::SlotStateFinalized;

use crate::{
    buffer::{Id, Reset, Ring, reanchor_survivors},
    types::SLOTS_RING_N,
};

/// Typed ring-slot handle into a [`SlotStateGroup`] (see [`Id`]).
pub type SlotStateId = Id<SlotStateGroup>;

pub struct SlotStateGroup {
    base: SlotStateFinalized,
    forks: Ring<Self, SlotStateDelta, SLOTS_RING_N>,
}

impl SlotStateGroup {
    /// The finalized base (checkpoint encoding).
    #[inline]
    pub(crate) fn base(&self) -> &SlotStateFinalized {
        &self.base
    }

    pub fn new(base: SlotStateFinalized) -> Self {
        Self { base, forks: Ring::default() }
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: SlotStateId) -> SlotStateView<'_> {
        SlotStateView::new(&self.base, Some(self.forks.get(id)))
    }

    /// Read-only view over the finalized base with no active fork — the
    /// pre-fork surface (freshly decomposed / checkpoint-loaded state, and
    /// the cross-thread reader before any slot delta is published).
    #[inline]
    pub fn base_view(&self) -> SlotStateView<'_> {
        SlotStateView::new(&self.base, None)
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> SlotStateWriteView<'_> {
        let Self { base, forks } = self;
        let mut fork = forks.roll_fresh();
        // Anchor the fresh fork's full `SlotState` at the base. The slot delta
        // is a full working copy (not a sparse overlay), so an un-seeded fork
        // would shadow the base with zeros; block/state-root tails stay empty.
        fork.slot.clone_from(&base.slot);
        SlotStateWriteView::new(base, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { base, forks } = self;
        SlotStateWriteView::new(base, forks.roll_from(parent))
    }

    /// Copy a survivor into a fresh slot and drop the promoted root prefix
    /// (pre-promotion). The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: SlotStateId, winner: SlotStateId) -> SlotStateWriteView<'_> {
        let Self { base, forks } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        SlotStateWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the base (circular-buffer
    /// write). Mirrors [`BalancesGroup::finalize`](crate::BalancesGroup).
    pub fn finalize(&mut self, winner: SlotStateId, survivors: &[SlotStateId]) -> Vec<SlotStateId> {
        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { base, forks } = self;
        base.promote(forks.get(winner));

        forks.free_stale(&fresh);

        fresh
    }
}
