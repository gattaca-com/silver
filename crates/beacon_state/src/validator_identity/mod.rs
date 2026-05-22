mod delta;
mod finalized;
mod state;
mod withdrawals;

#[cfg(test)]
mod tests;

use silver_common::ssz_hash::{ZERO_HASHES, hash_fixed_bytes, merkleize};

pub use delta::{AppendedValidator, ValidatorsDelta};
pub use finalized::{FinalizedValidators, PubkeyIndex};
pub use state::ValidatorsState;
pub use withdrawals::Withdrawals;

use crate::types::{B256, BLSPubkey};

// TODO: add more fields when they will be migrated to validator identity layer
pub fn validator_hash(pubkey: &BLSPubkey, credentials: &Withdrawals) -> B256 {
    let chunks = [hash_fixed_bytes(pubkey, &ZERO_HASHES), credentials.0];
    merkleize(&chunks, &ZERO_HASHES)
}
