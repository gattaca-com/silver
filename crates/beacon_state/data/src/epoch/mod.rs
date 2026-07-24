mod delta;
mod finalized;
#[cfg(test)]
mod tests;

pub(crate) use delta::EpochStateDelta;
pub use delta::{EpochView, EpochWriteView};
pub use finalized::EpochStateFinalized;
use flux_profiler::timed;

use crate::{
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring, RingGroup},
    types::EPOCHS_RING_N,
};

pub type EpochId = Id<EpochGroup>;

pub struct EpochGroup {
    finalized: EpochStateFinalized,
    deltas: Ring<Self>,
}

impl RingGroup for EpochGroup {
    type Entry = EpochStateDelta;
}

impl EpochGroup {
    pub fn new(finalized: EpochStateFinalized) -> Self {
        Self { finalized, deltas: Ring::new(EPOCHS_RING_N) }
    }

    #[inline]
    pub fn finalized(&self) -> &EpochStateFinalized {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: EpochId) -> EpochView<'_> {
        EpochView::new(&self.finalized, Some(self.deltas.get(id)))
    }

    /// Read-only view over the finalized state with no active fork — the
    /// surface for a fork that hasn't crossed an epoch boundary (and the
    /// cross-thread reader before any epoch delta is published).
    #[inline]
    pub fn finalized_view(&self) -> EpochView<'_> {
        EpochView::new(&self.finalized, None)
    }

    /// Resolve a fork's optional id ([`Self::finalized_view`] on `None`) — the
    /// one helper every reader of a slot delta's `epoch_idx` goes through.
    #[inline]
    pub fn view_opt(&self, id: Option<EpochId>) -> EpochView<'_> {
        id.map_or_else(|| self.finalized_view(), |id| self.view(id))
    }

    /// Roll a fresh fork seeded from the finalized scalars (empty logs) — the
    /// epoch-boundary roll. The id surfaces from the writer's `commit`.
    #[inline]
    pub fn roll_fresh(&mut self) -> EpochWriteView<'_> {
        let Self { finalized, deltas } = self;
        let mut wv = EpochWriteView::new(finalized, deltas.roll_fresh());
        wv.seed_from_base();
        wv
    }

    #[inline]
    pub fn roll_from(&mut self, parent: EpochId) -> EpochWriteView<'_> {
        let Self { finalized, deltas } = self;
        EpochWriteView::new(finalized, deltas.roll_from(parent))
    }

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
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        EpochWriteView::new(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the finalized state
    /// (circular-buffer write at `old_fin_epoch`). Mirrors
    /// [`SlotStateGroup::finalize`](crate:: SlotStateGroup), with the extra
    /// `old_fin_epoch` offset the epoch circular buffers need.
    #[timed]
    pub fn finalize(
        &mut self,
        winner: EpochId,
        survivors: &[EpochId],
        old_fin_epoch: usize,
    ) -> Vec<EpochId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        finalized.promote(deltas.get(winner), old_fin_epoch);

        deltas.free_outdated(&fresh);

        fresh
    }
}
