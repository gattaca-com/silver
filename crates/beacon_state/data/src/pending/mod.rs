//! Pending-queues group: the three FIFO queues (`pending_deposits`,
//! `pending_partial_withdrawals`, `pending_consolidations`) as one finalized
//! base ([`PendingQueues`]) plus a per-fork delta ([`PendingQueuesDelta`]) of
//! drain offsets + appended tails, bundled with the ring. Mirrors the balances
//! group; read on the writer thread (`StateReadView`/`StateWriterView`) but not
//! the cross-thread reader.

mod delta;
mod finalized;

use delta::{OldBaseLens, PendingQueuesDelta};
pub use delta::{PendingView, PendingWriteView};
pub use finalized::PendingQueues;

use crate::{
    buffer::{Id, Reset, Ring},
    types::SLOTS_RING_N,
};

/// Typed ring-slot handle into a [`PendingGroup`] (see [`Id`]).
pub type PendingId = Id<PendingGroup>;

pub struct PendingGroup {
    base: PendingQueues,
    forks: Ring<Self, PendingQueuesDelta, SLOTS_RING_N>,
}

impl PendingGroup {
    pub fn new(base: PendingQueues) -> Self {
        Self { base, forks: Ring::default() }
    }

    /// Read-only view over a fork — for the read views (`StateReadView`).
    #[inline]
    pub fn view(&self, id: PendingId) -> PendingView<'_> {
        PendingView::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PendingWriteView<'_> {
        let Self { base, forks } = self;
        PendingWriteView::new(base, forks.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PendingId) -> PendingWriteView<'_> {
        let Self { base, forks } = self;
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
        let Self { base, forks } = self;
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

        let mut fresh: Vec<PendingId> = Vec::with_capacity(survivors.len());
        for (i, &s) in survivors.iter().enumerate() {
            let new_id = match survivors[..i].iter().position(|&p| p == s) {
                Some(seen) => fresh[seen],
                None => self.reanchor(s, winner, &old_base_lens).commit(),
            };
            fresh.push(new_id);
        }

        let Self { base, forks } = self;
        base.promote(forks.get(winner));

        if let Some(&oldest) = fresh.iter().min() {
            forks.free(oldest);
        }

        fresh
    }
}
