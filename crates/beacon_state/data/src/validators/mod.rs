mod delta;
mod finalized;

#[cfg(test)]
mod tests;

use delta::ValidatorsDelta;
pub use delta::{ValidatorsView, ValidatorsWriteView};
pub use finalized::{FinalizedValidators, ValSeed, ValidatorsDecodeError};
use flux_profiler::timed;

use crate::{
    Withdrawals,
    column::{ColumnGroup, ValidatorsHash},
    merkle::{hash_fixed_bytes, merkleize, uint64_chunk},
    reanchor::reanchor_survivors,
    ring::{Id, Ring},
    types::{B256, BLSPubkey, Epoch, HashFormat, SLOTS_RING_N},
};

/// The data ring reanchors survivors into fresh slots at finalize while the
/// paged hash column keeps survivor ids stable, so the two rings can't share
/// one seq — a fork's id is the pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ValidatorsId {
    data: Id<ValidatorsGroup>,
    hash: Id<ColumnGroup<ValidatorsHash>>,
}

/// The validator registry as one coupled unit: the finalized columns + pubkey
/// index + persistent hash tree ([`FinalizedValidators`]) plus a per-fork delta
/// ([`ValidatorsDelta`]) ring. Logically identical to [`BalancesGroup`] —
/// finalized columns + sparse edits + a hash overlay — so finalization uses the
/// same reanchor-against-the-winner model. Read by both views; its finalized
/// index/hash grow, so the checkpoint-persist snapshot read on the storage
/// thread must be lock-guarded.
///
/// [`BalancesGroup`]: crate::BalancesGroup
pub struct ValidatorsGroup {
    finalized: FinalizedValidators,
    deltas: Ring<Self, ValidatorsDelta, SLOTS_RING_N>,
    hash: ColumnGroup<ValidatorsHash>,
}

impl ValidatorsGroup {
    pub fn new(finalized: FinalizedValidators, format: HashFormat) -> Self {
        let n = finalized.validator_count();
        let leaf_bytes: Vec<u8> = (0..n).flat_map(|i| finalized.leaf_hash(i)).collect();
        let hash = ColumnGroup::new(finalized.capacity(), n, &leaf_bytes, format)
            .expect("leaf bytes sized from the registry");
        Self { finalized, deltas: Ring::default(), hash }
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedValidators {
        &self.finalized
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: ValidatorsId) -> ValidatorsView<'_> {
        ValidatorsView::new(&self.finalized, self.deltas.get(id.data), self.hash.view(id.hash))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ValidatorsWriteView<'_> {
        let Self { finalized, deltas, hash } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        ValidatorsWriteView::new(finalized, fork, hash.roll_fresh())
    }

    #[inline]
    pub fn roll_from(&mut self, parent: ValidatorsId) -> ValidatorsWriteView<'_> {
        let Self { finalized, deltas, hash } = self;
        ValidatorsWriteView::new(
            finalized,
            deltas.roll_from(parent.data),
            hash.roll_from(parent.hash),
        )
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot,
    /// pre-promotion (mirror of `BalancesGroup::reanchor`). Data ring only —
    /// the paged hash column finalizes by page adoption, no rebase.
    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> Id<Self> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.rebase_and_prune_from(old, finalized, winner_delta);
        fork.commit()
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), promote the winner into the finalized state, then free the
    /// oldest. Mirrors [`BalancesGroup::finalize`](crate::BalancesGroup).
    #[timed]
    pub fn finalize(
        &mut self,
        winner: ValidatorsId,
        survivors: &[ValidatorsId],
    ) -> Vec<ValidatorsId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        let data_ids: Vec<_> = survivors.iter().map(|s| s.data).collect();
        self.deltas.free_outdated(&data_ids);

        let fresh = reanchor_survivors(survivors, |s| ValidatorsId {
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

#[allow(clippy::too_many_arguments)]
#[inline]
pub fn validator_hash(
    pubkey: &BLSPubkey,
    credentials: &Withdrawals,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: Epoch,
    activation_epoch: Epoch,
    exit_epoch: Epoch,
    withdrawable_epoch: Epoch,
) -> B256 {
    let mut slashed_chunk = [0u8; 32];
    slashed_chunk[0] = u8::from(slashed);

    let chunks = [
        hash_fixed_bytes(pubkey),
        credentials.0,
        uint64_chunk(effective_balance),
        slashed_chunk,
        uint64_chunk(activation_eligibility_epoch),
        uint64_chunk(activation_epoch),
        uint64_chunk(exit_epoch),
        uint64_chunk(withdrawable_epoch),
    ];
    merkleize(&chunks)
}
