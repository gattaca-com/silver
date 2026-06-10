mod delta;
mod finalized;

#[cfg(test)]
mod tests;

pub use delta::{AppendedValidator, ValidatorsDelta, ValidatorsView, ValidatorsWriteView};
pub use finalized::{FinalizedValidators, ValSeed, ValidatorsDecodeError};

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
/// ([`ValidatorsDelta`]) ring. Logically identical to [`BalancesGroup`] — base
/// columns + sparse edits + a hash overlay — so finalization uses the same
/// reanchor-against-the-winner model. Read by both views; its base index/hash
/// grow, so the checkpoint-persist snapshot read on the storage thread must be
/// lock-guarded.
///
/// [`BalancesGroup`]: crate::BalancesGroup
pub struct ValidatorsGroup {
    base: FinalizedValidators,
    forks: Ring<Self, ValidatorsDelta, SLOTS_RING_N>,
}

impl ValidatorsGroup {
    pub fn new(base: FinalizedValidators) -> Self {
        Self { base, forks: Ring::default() }
    }

    #[inline]
    pub fn base(&self) -> &FinalizedValidators {
        &self.base
    }

    /// Read-only view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: ValidatorsId) -> ValidatorsView<'_> {
        ValidatorsView::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ValidatorsWriteView<'_> {
        let Self { base, forks } = self;
        let mut fork = forks.roll_fresh();
        fork.anchor_at(base);
        ValidatorsWriteView::new(base, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: ValidatorsId) -> ValidatorsWriteView<'_> {
        let Self { base, forks } = self;
        ValidatorsWriteView::new(base, forks.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot,
    /// pre-promotion (mirror of `BalancesGroup::reanchor`).
    fn reanchor(
        &mut self,
        survivor: ValidatorsId,
        winner: ValidatorsId,
    ) -> ValidatorsWriteView<'_> {
        let Self { base, forks } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, base, winner_delta);
        ValidatorsWriteView::new(base, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped), promote the winner into the base, then free the oldest.
    /// Mirrors [`BalancesGroup::finalize`](crate::BalancesGroup).
    pub fn finalize(
        &mut self,
        winner: ValidatorsId,
        survivors: &[ValidatorsId],
    ) -> Vec<ValidatorsId> {
        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { base, forks } = self;
        forks.get(winner).promote_into_base(base);

        forks.free_stale(&fresh);

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
