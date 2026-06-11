mod delta;
mod finalized;

use delta::{OldBaseLens, PendingQueuesDelta};
pub use delta::{PendingView, PendingWriteView};
pub use finalized::PendingQueues;
use parking_lot::Mutex;

use crate::{
    buffer::{Id, Reset, Ring, reanchor_survivors},
    types::SLOTS_RING_N,
};

/// Typed ring-slot handle into a [`PendingGroup`] (see [`Id`]).
pub type PendingId = Id<PendingGroup>;

pub struct PendingGroup {
    base: PendingQueues,
    forks: Ring<Self, PendingQueuesDelta, SLOTS_RING_N>,
    /// Promote barrier: the base queues are growable `Vec`s, so the checkpoint
    /// persist (storage thread) must not read them while `finalize` promotes
    /// into them (realloc would dangle the read). Writer-thread view reads
    /// never race promote (same thread) and stay lock-free.
    persist_lock: Mutex<()>,
}

impl PendingGroup {
    pub fn new(base: PendingQueues) -> Self {
        Self { base, forks: Ring::default(), persist_lock: Mutex::new(()) }
    }

    /// Run `f` over the finalized base under the promote barrier — the
    /// checkpoint encoder's (only) way in. Keep `f` to a bounded memcpy.
    #[inline]
    pub(crate) fn with_base_locked<R>(&self, f: impl FnOnce(&PendingQueues) -> R) -> R {
        let _g = self.persist_lock.lock();
        f(&self.base)
    }

    /// Read-only view over a fork — for the read views (`StateReadView`).
    #[inline]
    pub fn view(&self, id: PendingId) -> PendingView<'_> {
        PendingView::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PendingWriteView<'_> {
        let Self { base, forks, .. } = self;
        PendingWriteView::new(base, forks.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PendingId) -> PendingWriteView<'_> {
        let Self { base, forks, .. } = self;
        PendingWriteView::new(base, forks.roll_from(parent))
    }

    /// Copy a survivor into a fresh slot and re-base it against the promoted
    /// `winner` (pre-promotion, with the old base lengths). The survivor stays
    /// frozen — append-only.
    fn reanchor(
        &mut self,
        survivor: PendingId,
        winner: PendingId,
        old_base_lens: &OldBaseLens,
    ) -> PendingWriteView<'_> {
        let Self { base, forks, .. } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.rebase(winner_delta, old_base_lens);
        PendingWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the base.
    /// Self-contained — `old_base_lens` is snapshotted from the still-old base.
    /// Mirrors [`BalancesGroup::finalize`](crate::BalancesGroup).
    pub fn finalize(&mut self, winner: PendingId, survivors: &[PendingId]) -> Vec<PendingId> {
        let old_base_lens = OldBaseLens::snapshot(&self.base);

        let fresh =
            reanchor_survivors(survivors, |s| self.reanchor(s, winner, &old_base_lens).commit());

        let Self { base, forks, persist_lock } = self;
        {
            let _g = persist_lock.lock();
            base.promote(forks.get(winner));
        }

        forks.free_stale(&fresh);

        fresh
    }
}
