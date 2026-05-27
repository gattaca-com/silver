mod delta;
mod finalised;

#[cfg(test)]
mod tests;

pub use delta::{AppendedValidator, ValidatorsDelta};
pub use finalised::{FinalisedValidators, ValidatorRow};

use crate::{
    Withdrawals,
    beacon_state::types::{B256, BLSPubkey, Epoch},
    ssz_hash::{hash_fixed_bytes, merkleize, uint64_chunk},
};

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
