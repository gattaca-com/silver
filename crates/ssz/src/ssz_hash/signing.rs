//! Signing-root helpers computed from typed fields (not a serialized
//! container's bytes), so they stay free functions rather than view methods.

use flux_profiler::timed;

use crate::merkle::{B256, hash_concat, merkleize, sha256, uint64_chunk};

/// hash_tree_root(ForkData(current_version, genesis_validators_root)).
/// 2-chunk container → single sha256 of the concatenated chunks (the
/// 4-byte version is right-zero-padded into a 32-byte chunk per SSZ).
#[timed]
pub fn hash_tree_root_fork_data(version: [u8; 4], genesis_validators_root: &B256) -> B256 {
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&version);
    hash_concat(&version_chunk, genesis_validators_root)
}

/// SSZ root of `VoluntaryExit { epoch, validator_index }`. Two uint64 fields
/// merkleized in order.
#[timed]
pub fn hash_tree_root_voluntary_exit(epoch: u64, validator_index: u64) -> B256 {
    merkleize(&[uint64_chunk(epoch), uint64_chunk(validator_index)])
}

/// SSZ root of `BLSToExecutionChange { validator_index, from_bls_pubkey,
/// to_execution_address }`. The pubkey is a 48-byte vector → packed into two
/// 32-byte chunks (`pad_to_64(pubkey)` then sha256). The address is 20 bytes
/// in the low end of a 32-byte chunk.
#[timed]
pub fn hash_tree_root_bls_change(
    validator_index: u64,
    from_pubkey: &[u8; 48],
    to_address: &[u8; 20],
) -> B256 {
    let mut pk_chunk = [0u8; 64];
    pk_chunk[..48].copy_from_slice(from_pubkey);
    let pk_root = sha256(&pk_chunk);

    let mut addr_chunk = [0u8; 32];
    addr_chunk[..20].copy_from_slice(to_address);

    merkleize(&[uint64_chunk(validator_index), pk_root, addr_chunk])
}
