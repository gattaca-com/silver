//! Inactivity-scores group: one finalized base ([`FinalizedInactivityScores`])
//! plus a per-fork sparse delta ([`InactivityScoresDelta`]), bundled with the
//! ring in [`InactivityScoresGroup`]. Mirrors the balances group; read/written
//! only on the write path (epoch transition + state-root hashing), so there is
//! no lock-free reader split.

mod delta;
mod finalized;

use delta::InactivityScoresDelta;
pub use delta::{InactivityView, InactivityWriteView};
pub use finalized::FinalizedInactivityScores;

use crate::{
    buffer::{Id, Ring},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

/// Typed ring-slot handle into an [`InactivityScoresGroup`] (see [`Id`]).
pub type InactivityId = Id<InactivityScoresGroup>;

pub struct InactivityScoresGroup {
    base: FinalizedInactivityScores,
    forks: Ring<Self, InactivityScoresDelta, SLOTS_RING_N>,
}

impl InactivityScoresGroup {
    /// The finalized base (checkpoint encoding).
    #[inline]
    pub(crate) fn base(&self) -> &FinalizedInactivityScores {
        &self.base
    }

    /// Group over a base decoded from the SSZ `inactivity_scores` byte range
    /// (little-endian `u64`s); `new(cap, &[])` is the empty group.
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            base: FinalizedInactivityScores::new(cap, count, ssz_bytes)?,
            forks: Ring::default(),
        })
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: InactivityId) -> InactivityView<'_> {
        InactivityView::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> InactivityWriteView<'_> {
        let Self { base, forks } = self;
        let mut fork = forks.roll_fresh();
        fork.anchor_at(base);
        InactivityWriteView::new(base, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: InactivityId) -> InactivityWriteView<'_> {
        let Self { base, forks } = self;
        InactivityWriteView::new(base, forks.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot
    /// (pin + prune), pre-promotion. The survivor stays frozen — append-only.
    fn reanchor(
        &mut self,
        survivor: InactivityId,
        winner: InactivityId,
    ) -> InactivityWriteView<'_> {
        let Self { base, forks } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, base, winner_delta);
        InactivityWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the base.
    /// Self-contained — the rebase bounds come from the base/winner lengths.
    /// Mirrors [`BalancesGroup::finalize`](crate::BalancesGroup).
    pub fn finalize(
        &mut self,
        winner: InactivityId,
        survivors: &[InactivityId],
    ) -> Vec<InactivityId> {
        let mut fresh: Vec<InactivityId> = Vec::with_capacity(survivors.len());
        for (i, &s) in survivors.iter().enumerate() {
            let new_id = match survivors[..i].iter().position(|&p| p == s) {
                Some(seen) => fresh[seen],
                None => self.reanchor(s, winner).commit(),
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
