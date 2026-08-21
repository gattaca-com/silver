//! Hashing primitives and the zero-subtree table: the `hashtree` backend calls,
//! `B256`, chunk encoders, length mix-in, and merkle-branch verification.

use std::sync::LazyLock;

use flux_profiler::timed;
use sha2::{Digest, Sha256};

/// One-time hashtree backend selection (SHA-NI / AVX-512 / AVX2 / SSE).
/// Forced on the first `hash_concat` call; result is `1` on success.
static HASHTREE_READY: LazyLock<()> = LazyLock::new(|| {
    let rc = hashtree_rs::init();
    debug_assert_eq!(rc, 1, "hashtree_rs::init() failed");
});

pub type B256 = [u8; 32];

#[inline]
pub fn sha256(data: &[u8]) -> B256 {
    Sha256::digest(data).into()
}

#[inline]
pub fn hash_concat(a: &B256, b: &B256) -> B256 {
    LazyLock::force(&HASHTREE_READY);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    let mut out = [0u8; 32];
    hashtree_rs::hash(&mut out, &buf, 1);
    out
}

#[inline]
pub fn hash_concat_many(out: &mut [B256], pairs: &[B256]) {
    debug_assert_eq!(pairs.len(), 2 * out.len());
    LazyLock::force(&HASHTREE_READY);
    let n = out.len();
    let out_bytes = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, n * 32) };
    let in_bytes = unsafe { std::slice::from_raw_parts(pairs.as_ptr() as *const u8, n * 64) };
    hashtree_rs::hash(out_bytes, in_bytes, n);
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

#[inline]
pub fn mix_in_length(root: &B256, length: usize) -> B256 {
    hash_concat(root, &uint64_chunk(length as u64))
}

pub const ZERO_HASH: B256 = [0u8; 32];

/// Max SSZ depth we ever hit is 40 (VALIDATOR_REGISTRY_LIMIT = 2^40);
pub const ZERO_HASHES_LEN: usize = 48;

pub const ZERO_HASHES: [B256; ZERO_HASHES_LEN] = {
    let mut zh = [ZERO_HASH; ZERO_HASHES_LEN];
    let mut i = 1;
    while i < ZERO_HASHES_LEN {
        zh[i] = const_hash_concat(&zh[i - 1], &zh[i - 1]);
        i += 1;
    }
    zh
};

pub const fn const_hash_concat(a: &B256, b: &B256) -> B256 {
    sha2_const_stable::Sha256::new().update(a).update(b).finalize()
}
