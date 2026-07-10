mod delta;
mod finalized;
#[cfg(test)]
mod tests;

use delta::Eth1VotesDelta;
pub use delta::{Eth1View, Eth1WriteView};
pub use finalized::Eth1Votes;
use flux_profiler::timed;

use crate::{
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring},
    types::SLOTS_RING_N,
};

pub type Eth1Id = Id<Eth1Group>;

/// Eth1 vote list as its own always-rolled tier. The finalized side is an
/// inline fixed-capacity list (never reallocates — the lock-free checkpoint
/// read can't dangle); forks carry only their appends since finalization.
pub struct Eth1Group {
    finalized: Eth1Votes,
    deltas: Ring<Self, Eth1VotesDelta, SLOTS_RING_N>,
}

impl Eth1Group {
    pub fn new(finalized: Eth1Votes) -> Self {
        Self { finalized, deltas: Ring::default() }
    }

    #[inline]
    pub fn finalized(&self) -> &Eth1Votes {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: Eth1Id) -> Eth1View<'_> {
        Eth1View::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> Eth1WriteView<'_> {
        let Self { finalized, deltas } = self;
        Eth1WriteView::new(finalized, deltas.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: Eth1Id) -> Eth1WriteView<'_> {
        let Self { finalized, deltas } = self;
        Eth1WriteView::new(finalized, deltas.roll_from(parent))
    }

    /// Copy a survivor into a fresh slot and re-base it against the promoted
    /// `winner` (pre-promotion). The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: Eth1Id, winner: Eth1Id) -> Eth1WriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.rebase(winner_delta);
        Eth1WriteView::new(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), then promote the winner into the finalized state.
    #[timed]
    pub fn finalize(&mut self, winner: Eth1Id, survivors: &[Eth1Id]) -> Vec<Eth1Id> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        finalized.promote(deltas.get(winner));

        deltas.free_outdated(&fresh);

        fresh
    }
}
