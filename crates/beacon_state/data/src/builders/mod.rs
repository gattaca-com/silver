mod delta;
mod finalized;

use delta::BuildersDelta;
pub use delta::{BuildersView, BuildersWriteView};
pub use finalized::FinalizedBuilders;
use silver_common_macros::timed;

use crate::{
    buffer::{Id, Reset, Ring, reanchor_survivors},
    types::SLOTS_RING_N,
};

pub type BuildersId = Id<BuildersGroup>;

pub struct BuildersGroup {
    finalized: FinalizedBuilders,
    deltas: Ring<Self, BuildersDelta, SLOTS_RING_N>,
}

impl BuildersGroup {
    pub fn new(finalized: FinalizedBuilders) -> Self {
        Self { finalized, deltas: Ring::default() }
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedBuilders {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: BuildersId) -> BuildersView<'_> {
        BuildersView::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> BuildersWriteView<'_> {
        let Self { finalized, deltas } = self;
        BuildersWriteView::new(finalized, deltas.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: BuildersId) -> BuildersWriteView<'_> {
        let Self { finalized, deltas } = self;
        BuildersWriteView::new(finalized, deltas.roll_from(parent))
    }

    fn reanchor(&mut self, survivor: BuildersId, winner: BuildersId) -> BuildersWriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.rebase(winner_delta);
        BuildersWriteView::new(finalized, fork)
    }

    #[timed]
    pub fn finalize(&mut self, winner: BuildersId, survivors: &[BuildersId]) -> Vec<BuildersId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        finalized.promote(deltas.get(winner));

        deltas.free_outdated(&fresh);

        fresh
    }
}
