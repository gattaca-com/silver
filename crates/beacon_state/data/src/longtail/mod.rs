//! Longtail-tier group: sync committees + their resolved validator indices +
//! the cumulative `historical_summaries` log as one finalized base
//! ([`LongtailState`]) plus a per-fork delta (the same [`LongtailState`] type,
//! holding only the post-finalization `historical_summaries` appends), bundled
//! with the ring. Read by both the writer-thread `StateReadView` and the
//! cross-thread reader via [`LongtailView`]. Rolled lazily — only
//! when a fork crosses a sync-committee / historical-summary rotation — so the
//! slot id resolves to a fork delta or, when absent, the base.

mod delta;
mod finalized;
#[cfg(test)]
mod tests;

pub use delta::{LongtailView, LongtailWriteView};
pub use finalized::LongtailState;
use parking_lot::Mutex;

use crate::{
    buffer::{Id, Reset, Ring},
    types::LONGTAILS_RING_N,
};

/// Typed ring-slot handle into a [`LongtailGroup`] (see [`Id`]).
pub type LongtailId = Id<LongtailGroup>;

pub struct LongtailGroup {
    base: LongtailState,
    forks: Ring<Self, LongtailState, LONGTAILS_RING_N>,
    /// Promote barrier: the base's `historical_summaries` log grows on
    /// promote, so the checkpoint persist (storage thread) must not read it
    /// mid-`finalize` (realloc would dangle the read). Writer-thread view
    /// reads never race promote (same thread) and stay lock-free.
    persist_lock: Mutex<()>,
}

impl LongtailGroup {
    pub fn new(base: LongtailState) -> Self {
        Self { base, forks: Ring::default(), persist_lock: Mutex::new(()) }
    }

    /// Run `f` over the finalized base under the promote barrier — the
    /// checkpoint encoder's (only) way in. Keep `f` to a bounded memcpy.
    #[inline]
    pub(crate) fn with_base_locked<R>(&self, f: impl FnOnce(&LongtailState) -> R) -> R {
        let _g = self.persist_lock.lock();
        f(&self.base)
    }

    #[inline]
    pub fn base(&self) -> &LongtailState {
        &self.base
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: LongtailId) -> LongtailView<'_> {
        LongtailView::new(&self.base, Some(self.forks.get(id)))
    }

    /// Read-only view over the finalized base with no active fork — the surface
    /// for a fork that hasn't crossed a rotation (and the cross-thread reader
    /// before any longtail delta is published).
    #[inline]
    pub fn base_view(&self) -> LongtailView<'_> {
        LongtailView::new(&self.base, None)
    }

    /// Resolve a fork's optional id ([`Self::base_view`] on `None`) — the one
    /// helper every reader of a slot delta's `longtail_idx` goes through.
    #[inline]
    pub fn view_opt(&self, id: Option<LongtailId>) -> LongtailView<'_> {
        id.map_or_else(|| self.base_view(), |id| self.view(id))
    }

    /// Roll a fresh fork seeded from the base sync committees (empty
    /// `historical_summaries`) — the rotation roll. The caller records the
    /// new id on its slot delta.
    #[inline]
    pub fn roll_fresh(&mut self) -> LongtailWriteView<'_> {
        let Self { base, forks, .. } = self;
        let mut wv = LongtailWriteView::new(base, forks.roll_fresh());
        wv.seed_from_base();
        wv
    }

    #[inline]
    pub fn roll_from(&mut self, parent: LongtailId) -> LongtailWriteView<'_> {
        let Self { base, forks, .. } = self;
        LongtailWriteView::new(base, forks.roll_from(parent))
    }

    /// Copy a survivor into a fresh slot and drop the promoted
    /// `historical_summaries` prefix (pre-promotion). The survivor stays
    /// frozen — append-only.
    fn reanchor(&mut self, survivor: LongtailId, winner: LongtailId) -> LongtailWriteView<'_> {
        let Self { base, forks, .. } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.prune_to_base(winner_delta);
        LongtailWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the base. Mirrors
    /// [`SlotStateGroup::finalize`](crate::SlotStateGroup).
    pub fn finalize(&mut self, winner: LongtailId, survivors: &[LongtailId]) -> Vec<LongtailId> {
        let mut fresh: Vec<LongtailId> = Vec::with_capacity(survivors.len());
        for (i, &s) in survivors.iter().enumerate() {
            let new_id = match survivors[..i].iter().position(|&p| p == s) {
                Some(seen) => fresh[seen],
                None => self.reanchor(s, winner).commit(),
            };
            fresh.push(new_id);
        }

        let Self { base, forks, persist_lock } = self;
        {
            let _g = persist_lock.lock();
            base.promote(forks.get(winner));
        }

        if let Some(&oldest) = fresh.iter().min() {
            forks.free(oldest);
        }

        fresh
    }
}
