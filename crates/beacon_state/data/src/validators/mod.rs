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
    buffer::{Id, Ring, reanchor_survivors},
    ssz_hash::{hash_fixed_bytes, merkleize, uint64_chunk},
    types::{B256, BLSPubkey, Epoch, SLOTS_RING_N},
};

/// Typed ring-slot handle into a [`ValidatorsGroup`] (see [`Id`]).
pub type ValidatorsId = Id<ValidatorsGroup>;

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
}

impl ValidatorsGroup {
    pub fn new(finalized: FinalizedValidators) -> Self {
        Self { finalized, deltas: Ring::default() }
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedValidators {
        &self.finalized
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: ValidatorsId) -> ValidatorsView<'_> {
        ValidatorsView::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ValidatorsWriteView<'_> {
        let Self { finalized, deltas } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        ValidatorsWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: ValidatorsId) -> ValidatorsWriteView<'_> {
        let Self { finalized, deltas } = self;
        ValidatorsWriteView::new(finalized, deltas.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot,
    /// pre-promotion (mirror of `BalancesGroup::reanchor`).
    fn reanchor(
        &mut self,
        survivor: ValidatorsId,
        winner: ValidatorsId,
    ) -> ValidatorsWriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.rebase_and_prune_from(old, finalized, winner_delta);
        ValidatorsWriteView::new(finalized, fork)
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
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        deltas.get(winner).promote_into_base(finalized);

        deltas.free_outdated(&fresh);

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
