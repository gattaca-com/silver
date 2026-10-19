//! `B256`, chunk encoders and merkle-branch verification, over the `hashtree`
//! backend and zero-subtree table of `silver_hashing`.

use flux_profiler::timed;
use sha2::{Digest, Sha256};
pub use silver_hashing::merkle::{ZERO_HASHES, hash_concat, hash_concat_many, mix_in_length};

pub type B256 = [u8; 32];

#[inline]
pub fn sha256(data: &[u8]) -> B256 {
    Sha256::digest(data).into()
}

/// Spec: is_valid_merkle_branch. `branch` is `depth * 32` bytes of siblings,
/// ascending from leaf-level. Bit `i` of `index` selects which side the
/// running hash takes at level `i`.
#[timed]
pub fn is_valid_merkle_branch(
    leaf: &B256,
    branch: &[u8],
    depth: u32,
    index: u64,
    root: &B256,
) -> bool {
    if branch.len() < (depth as usize) * 32 {
        return false;
    }
    let mut value = *leaf;
    for i in 0..depth {
        let sib: &B256 = branch[(i as usize) * 32..((i + 1) as usize) * 32].try_into().unwrap();
        value =
            if (index >> i) & 1 == 0 { hash_concat(&value, sib) } else { hash_concat(sib, &value) };
    }
    value == *root
}

#[inline]
pub fn uint64_chunk(v: u64) -> B256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

pub const ZERO_HASH: B256 = [0u8; 32];

/// Max SSZ depth we ever hit is 40 (VALIDATOR_REGISTRY_LIMIT = 2^40);
pub const fn const_hash_concat(a: &B256, b: &B256) -> B256 {
    sha2_const_stable::Sha256::new().update(a).update(b).finalize()
}
