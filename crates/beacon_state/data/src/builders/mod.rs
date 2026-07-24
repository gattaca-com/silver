mod delta;
mod finalized;

#[cfg(test)]
mod tests;

use delta::BuildersDelta;
pub use delta::{BuildersView, BuildersWriteView};
pub use finalized::FinalizedBuilders;
use flux_profiler::timed;

use crate::{
    column::{BuildersHash, ColumnGroup},
    gloas::Builder,
    merkle::{hash_fixed_bytes, merkleize, uint64_chunk},
    reanchor::reanchor_survivors,
    ring::{Id, Ring},
    types::{B256, HashFormat, SLOTS_RING_N},
};

/// The data ring reanchors survivors into fresh slots at finalize while the
/// paged hash column keeps survivor ids stable, so the two rings can't share
/// one seq — a fork's id is the pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BuildersId {
    data: Id<BuildersGroup>,
    hash: Id<ColumnGroup<BuildersHash>>,
}

pub struct BuildersGroup {
    finalized: FinalizedBuilders,
    deltas: Ring<Self, BuildersDelta, SLOTS_RING_N>,
    hash: ColumnGroup<BuildersHash>,
}

impl BuildersGroup {
    pub fn new(finalized: FinalizedBuilders) -> Self {
        let leaf_bytes: Vec<u8> = finalized.as_slice().iter().flat_map(builder_hash).collect();
        let hash =
            ColumnGroup::new(finalized.capacity(), finalized.len(), &leaf_bytes, HashFormat::Gloas)
                .expect("leaf bytes sized from the registry");
        Self { finalized, deltas: Ring::default(), hash }
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedBuilders {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: BuildersId) -> BuildersView<'_> {
        BuildersView::new(&self.finalized, self.deltas.get(id.data), self.hash.view(id.hash))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> BuildersWriteView<'_> {
        let Self { finalized, deltas, hash } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        BuildersWriteView::new(finalized, fork, hash.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: BuildersId) -> BuildersWriteView<'_> {
        let Self { finalized, deltas, hash } = self;
        BuildersWriteView::new(
            finalized,
            deltas.roll_from(parent.data),
            hash.roll_from(parent.hash),
        )
    }

    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> Id<Self> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.rebase_and_prune_from(old, finalized, winner_delta);
        fork.commit()
    }

    #[timed]
    pub fn finalize(&mut self, winner: BuildersId, survivors: &[BuildersId]) -> Vec<BuildersId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        let data_ids: Vec<_> = survivors.iter().map(|s| s.data).collect();
        self.deltas.free_outdated(&data_ids);

        let fresh = reanchor_survivors(survivors, |s| BuildersId {
            data: self.reanchor(s.data, winner.data),
            hash: s.hash,
        });

        let Self { finalized, deltas, hash } = self;
        deltas.get(winner.data).promote_into_base(finalized);

        let hash_ids: Vec<_> = survivors.iter().map(|s| s.hash).collect();
        hash.finalize(winner.hash, &hash_ids);

        let fresh_data: Vec<_> = fresh.iter().map(|f| f.data).collect();
        deltas.free_outdated(&fresh_data);

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
