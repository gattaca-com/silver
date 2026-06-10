//! Epoch-tier group: the canonical [`EpochState`](crate::EpochState) scalars +
//! the `randao_mixes`/`slashings` circular buffers as one finalized base
//! ([`EpochStateFinalized`]) plus a per-fork delta ([`EpochStateDelta`]),
//! bundled with the ring. Read by both the writer-thread `StateReadView` and
//! the cross-thread reader via [`EpochView`]. Unlike the slot
//! tier the fork is rolled lazily — only when a fork crosses an epoch boundary
//! — so the slot id resolves to a fork delta or, when absent, the base.

mod delta;
mod finalized;
#[cfg(test)]
mod tests;

pub(crate) use delta::EpochStateDelta;
pub use delta::{EpochView, EpochWriteView};
pub use finalized::EpochStateFinalized;

use crate::{
    buffer::{Id, Reset, Ring, reanchor_survivors},
    types::EPOCHS_RING_N,
};

/// Typed ring-slot handle into an [`EpochGroup`] (see [`Id`]).
pub type EpochId = Id<EpochGroup>;

pub struct EpochGroup {
    base: EpochStateFinalized,
    forks: Ring<Self, EpochStateDelta, EPOCHS_RING_N>,
}

impl EpochGroup {
    pub fn new(base: EpochStateFinalized) -> Self {
        Self { base, forks: Ring::default() }
    }

    #[inline]
    pub fn base(&self) -> &EpochStateFinalized {
        &self.base
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: EpochId) -> EpochView<'_> {
        EpochView::new(&self.base, Some(self.forks.get(id)))
    }

    /// Read-only view over the finalized base with no active fork — the surface
    /// for a fork that hasn't crossed an epoch boundary (and the cross-thread
    /// reader before any epoch delta is published).
    #[inline]
    pub fn base_view(&self) -> EpochView<'_> {
        EpochView::new(&self.base, None)
    }

    /// Resolve a fork's optional id ([`Self::base_view`] on `None`) — the one
    /// helper every reader of a slot delta's `epoch_idx` goes through.
    #[inline]
    pub fn view_opt(&self, id: Option<EpochId>) -> EpochView<'_> {
        id.map_or_else(|| self.base_view(), |id| self.view(id))
    }

    /// Roll a fresh fork seeded from the base scalars (empty logs) — the
    /// epoch-boundary roll. The id surfaces from the writer's `commit`.
    #[inline]
    pub fn roll_fresh(&mut self) -> EpochWriteView<'_> {
        let Self { base, forks } = self;
        let mut wv = EpochWriteView::new(base, forks.roll_fresh());
        wv.seed_from_base();
        wv
    }

    #[inline]
    pub fn roll_from(&mut self, parent: EpochId) -> EpochWriteView<'_> {
        let Self { base, forks } = self;
        EpochWriteView::new(base, forks.roll_from(parent))
    }

    /// Roll derived from the inherited `parent` entry, or fresh off the base
    /// when no ancestor owns one.
    #[inline]
    pub fn roll_inheriting(&mut self, parent: Option<EpochId>) -> EpochWriteView<'_> {
        match parent {
            Some(p) => self.roll_from(p),
            None => self.roll_fresh(),
        }
    }

    /// Copy a survivor into a fresh slot and drop the promoted log prefix
    /// (pre-promotion). The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: EpochId, winner: EpochId) -> EpochWriteView<'_> {
        let Self { base, forks } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        EpochWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the base (circular-buffer write
    /// at `old_fin_epoch`). Mirrors [`SlotStateGroup::finalize`](crate::
    /// SlotStateGroup), with the extra `old_fin_epoch` offset the epoch
    /// circular buffers need.
    pub fn finalize(
        &mut self,
        winner: EpochId,
        survivors: &[EpochId],
        old_fin_epoch: usize,
    ) -> Vec<EpochId> {
        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { base, forks } = self;
        base.promote(forks.get(winner), old_fin_epoch);

        forks.free_stale(&fresh);

        fresh
    }
}
