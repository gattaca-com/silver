mod delta;
mod finalized;

#[cfg(test)]
mod tests;

use delta::BuildersDelta;
pub use delta::{BuildersView, BuildersWriteView};
pub use finalized::FinalizedBuilders;
use flux_profiler::timed;

use crate::{
    gloas::Builder,
    merkle::{hash_fixed_bytes, merkleize, uint64_chunk},
    reanchor::reanchor_survivors,
    ring::{Id, Ring},
    types::{B256, SLOTS_RING_N},
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
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        BuildersWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: BuildersId) -> BuildersWriteView<'_> {
        let Self { finalized, deltas } = self;
        BuildersWriteView::new(finalized, deltas.roll_from(parent))
    }

    fn reanchor(&mut self, survivor: BuildersId, winner: BuildersId) -> BuildersWriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.rebase_and_prune_from(old, finalized, winner_delta);
        BuildersWriteView::new(finalized, fork)
    }

    #[timed]
    pub fn finalize(&mut self, winner: BuildersId, survivors: &[BuildersId]) -> Vec<BuildersId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        deltas.get(winner).promote_into_base(finalized);

        deltas.free_outdated(&fresh);

        fresh
    }
}

#[inline]
pub(crate) fn builder_hash(b: &Builder) -> B256 {
    merkleize(&[
        hash_fixed_bytes(&b.pubkey),
        uint64_chunk(b.version as u64),
        hash_fixed_bytes(&b.execution_address),
        uint64_chunk(b.balance),
        uint64_chunk(b.deposit_epoch),
        uint64_chunk(b.withdrawable_epoch),
    ])
}
