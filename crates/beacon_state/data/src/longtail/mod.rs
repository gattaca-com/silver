mod delta;
mod finalized;
mod sync_committees;
#[cfg(test)]
mod tests;

pub use delta::{LongtailView, LongtailWriteView};
pub use finalized::LongtailState;
use flux_profiler::timed;
use parking_lot::Mutex;
pub use sync_committees::SyncCommittees;

use crate::{
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring, RingGroup},
    types::LONGTAILS_RING_N,
};

pub type LongtailId = Id<LongtailGroup>;

pub struct LongtailGroup {
    finalized: Box<LongtailState>,
    deltas: Ring<Self>,
    /// Promote barrier: the finalized state's `historical_summaries` log grows
    /// on promote, so the checkpoint persist (storage thread) must not read it
    /// mid-`finalize` (realloc would dangle the read). Writer-thread view
    /// reads never race promote (same thread) and stay lock-free.
    persist_lock: Mutex<()>,
}

impl RingGroup for LongtailGroup {
    type Entry = LongtailState;
}

impl LongtailGroup {
    pub fn new(finalized: LongtailState) -> Self {
        Self {
            finalized: Box::new(finalized),
            deltas: Ring::new(LONGTAILS_RING_N),
            persist_lock: Mutex::new(()),
        }
    }

    /// Run `f` over the finalized state under the promote barrier — the
    /// checkpoint encoder's (only) way in. Keep `f` to a bounded memcpy.
    #[inline]
    pub(crate) fn with_finalized_locked<R>(&self, f: impl FnOnce(&LongtailState) -> R) -> R {
        let _g = self.persist_lock.lock();
        f(&self.finalized)
    }

    #[inline]
    pub fn finalized(&self) -> &LongtailState {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: LongtailId) -> LongtailView<'_> {
        LongtailView::new(&self.finalized, Some(self.deltas.get(id)))
    }

    /// The surface for a fork that hasn't crossed a rotation (and the
    /// cross-thread reader before any longtail delta is published).
    #[inline]
    pub fn finalized_view(&self) -> LongtailView<'_> {
        LongtailView::new(&self.finalized, None)
    }

    /// Resolve a fork's optional id ([`Self::finalized_view`] on `None`) — the
    /// one helper every reader of a slot delta's `longtail_idx` goes
    /// through.
    #[inline]
    pub fn view_opt(&self, id: Option<LongtailId>) -> LongtailView<'_> {
        id.map_or_else(|| self.finalized_view(), |id| self.view(id))
    }

    /// Roll a fresh fork seeded from the finalized sync committees (empty
    /// `historical_summaries`) — the rotation roll. The caller records the
    /// new id on its slot delta.
    #[inline]
    pub fn roll_fresh(&mut self) -> LongtailWriteView<'_> {
        let Self { finalized, deltas, .. } = self;
        LongtailWriteView::fresh(finalized, deltas.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: LongtailId) -> LongtailWriteView<'_> {
        let Self { finalized, deltas, .. } = self;
        LongtailWriteView::derived(finalized, deltas.roll_from(parent))
    }

    /// Roll derived from the inherited `parent` entry, or fresh off the
    /// finalized state when no ancestor owns one.
    #[inline]
    pub fn roll_inheriting(&mut self, parent: Option<LongtailId>) -> LongtailWriteView<'_> {
        match parent {
            Some(p) => self.roll_from(p),
            None => self.roll_fresh(),
        }
    }

    /// Copy a survivor into a fresh slot and drop the promoted
    /// `historical_summaries` prefix (pre-promotion). The survivor stays
    /// frozen — append-only.
    fn reanchor(&mut self, survivor: LongtailId, winner: LongtailId) -> LongtailWriteView<'_> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        LongtailWriteView::derived(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the finalized state.
    #[timed]
    pub fn finalize(&mut self, winner: LongtailId, survivors: &[LongtailId]) -> Vec<LongtailId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas, persist_lock } = self;
        {
            let _g = persist_lock.lock();
            finalized.promote(deltas.get(winner));
        }

        deltas.free_outdated(&fresh);

        fresh
    }
}
