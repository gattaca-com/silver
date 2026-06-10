//! Participation-flags groups: the `previous_epoch_participation` and
//! `current_epoch_participation` columns (`List[ParticipationFlags, …]`). Both
//! share one delta/base impl
//! ([`ParticipationDelta`]/[`FinalizedParticipation`]); a zero-size marker
//! ([`Previous`]/[`Current`]) distinguishes the two rings so their [`Id`]s
//! can't be confused. Read/written only on the write path, so no
//! lock-free reader split — mirrors the balances group.

mod delta;
mod finalized;

use std::marker::PhantomData;

use delta::ParticipationDelta;
pub use delta::{ParticipationView, ParticipationWriteView};
pub use finalized::FinalizedParticipation;

use crate::{
    buffer::{Id, Ring},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

/// Column markers — keep `previous`/`current` ring ids distinct.
pub struct Previous;
pub struct Current;

pub type PreviousParticipationId = Id<ParticipationGroup<Previous>>;
pub type CurrentParticipationId = Id<ParticipationGroup<Current>>;
pub type PreviousParticipationGroup = ParticipationGroup<Previous>;
pub type CurrentParticipationGroup = ParticipationGroup<Current>;

pub struct ParticipationGroup<M> {
    base: FinalizedParticipation,
    forks: Ring<Self, ParticipationDelta, SLOTS_RING_N>,
    _marker: PhantomData<fn() -> M>,
}

impl<M> ParticipationGroup<M> {
    /// Group over a base decoded from the SSZ participation byte range (one
    /// flag byte per validator); `new(cap, &[])` is the empty group.
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            base: FinalizedParticipation::new(cap, count, ssz_bytes)?,
            forks: Ring::default(),
            _marker: PhantomData,
        })
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: Id<Self>) -> ParticipationView<'_, M> {
        ParticipationView::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ParticipationWriteView<'_, M> {
        let Self { base, forks, .. } = self;
        let mut fork = forks.roll_fresh();
        fork.anchor_at(base);
        ParticipationWriteView::new(base, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: Id<Self>) -> ParticipationWriteView<'_, M> {
        let Self { base, forks, .. } = self;
        ParticipationWriteView::new(base, forks.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot
    /// (pin + prune), pre-promotion. The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> ParticipationWriteView<'_, M> {
        let Self { base, forks, .. } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, base, winner_delta);
        ParticipationWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the base.
    /// Self-contained. Mirrors
    /// [`BalancesGroup::finalize`](crate::BalancesGroup).
    pub fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        let mut fresh: Vec<Id<Self>> = Vec::with_capacity(survivors.len());
        for (i, &s) in survivors.iter().enumerate() {
            let new_id = match survivors[..i].iter().position(|&p| p == s) {
                Some(seen) => fresh[seen],
                None => self.reanchor(s, winner).commit(),
            };
            fresh.push(new_id);
        }

        let Self { base, forks, .. } = self;
        base.promote(forks.get(winner));

        if let Some(&oldest) = fresh.iter().min() {
            forks.free(oldest);
        }

        fresh
    }
}
