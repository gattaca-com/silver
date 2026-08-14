//! Chunk → root: byte-chunk packing and the `merkleize*` family (inline
//! batched fast path, stack-machine fallback, fixed-limit padding).

use super::{
    hash::{B256, ZERO_HASH, hash_concat_many},
    stack::MerkleStack,
};

/// Regroup `data` into 32-byte chunks (tail zero-padded), feeding each to
/// `push`. The aligned prefix is cast as `&[B256]` (alignment 1, so any byte
/// pointer is valid); no per-element copy.
pub fn pack_byte_chunks(data: &[u8], mut push: impl FnMut(B256)) {
    let aligned = data.len() & !31;
    let chunks: &[B256] =
        unsafe { core::slice::from_raw_parts(data.as_ptr().cast::<B256>(), aligned / 32) };
    for c in chunks {
        push(*c);
    }
    let tail = data.len() - aligned;
    if tail != 0 {
        let mut last = [0u8; 32];
        last[..tail].copy_from_slice(&data[aligned..]);
        push(last);
    }
}

/// hash_tree_root of `bytes` packed into 32-byte chunks and merkleized to a
/// `chunk_capacity`-leaf tree (rounded to the next power of two). No length
/// mix-in — callers that hash a `List` wrap the result in
/// [`mix_in_length`](super::hash::mix_in_length).
pub fn merkleize_bytes(bytes: &[u8], chunk_capacity: usize) -> B256 {
    let mut stack = MerkleStack::new(chunk_capacity);
    pack_byte_chunks(bytes, |c| stack.push(c));
    stack.finalize()
}

/// hash_tree_root of a fixed-size byte vector (e.g. BLSSignature, Bitvector).
pub fn hash_fixed_bytes(data: &[u8]) -> B256 {
    merkleize_bytes(data, data.len().div_ceil(32))
}

/// Upper bound for `merkleize`'s stack-based fast path (covers small fixed
/// containers like the 8-field `Validator`).
pub(crate) const MERKLE_INLINE_CHUNKS: usize = 32;

/// Merkleize `chunks` into a caller-chosen `leaf_count`-leaf tree (power of
/// two, zero-padded) — a fixed list limit or progressive segment width, not
/// derived from `chunks.len()` like [`merkleize`].
#[inline]
pub fn merkleize_to(chunks: &[B256], leaf_count: usize) -> B256 {
    if leaf_count <= MERKLE_INLINE_CHUNKS {
        merkleize_inline(chunks, leaf_count)
    } else {
        merkleize_padded(chunks, leaf_count)
    }
}

/// Merkleize a slice of 32-byte chunks, padding to the next power of two.
#[inline]
pub fn merkleize(chunks: &[B256]) -> B256 {
    merkleize_to(chunks, chunks.len().next_power_of_two().max(1))
}

/// Merkleize `chunks` into a `leaf_count`-leaf tree, zero-padding missing
/// leaves and reducing a layer at a time with batched hashing. Ping-pongs `a`
/// and `b` so each `hash_concat_many` has disjoint in/out.
#[inline]
pub fn merkleize_inline(chunks: &[B256], leaf_count: usize) -> B256 {
    debug_assert!(leaf_count.is_power_of_two() && leaf_count <= MERKLE_INLINE_CHUNKS);
    debug_assert!(chunks.len() <= leaf_count);
    let mut a = [ZERO_HASH; MERKLE_INLINE_CHUNKS];
    a[..chunks.len()].copy_from_slice(chunks);
    if leaf_count == 1 {
        return a[0];
    }
    let mut b = [ZERO_HASH; MERKLE_INLINE_CHUNKS / 2];
    let mut width = leaf_count;
    let mut in_a = true; // current layer lives in `a` (else `b`)
    while width > 1 {
        let half = width / 2;
        if in_a {
            hash_concat_many(&mut b[..half], &a[..width]);
        } else {
            hash_concat_many(&mut a[..half], &b[..width]);
        }
        in_a = !in_a;
        width = half;
    }
    if in_a { a[0] } else { b[0] }
}

/// Merkleize with a fixed leaf count (power of two, for list limits).
pub fn merkleize_padded(chunks: &[B256], leaf_count: usize) -> B256 {
    debug_assert!(leaf_count.is_power_of_two());
    debug_assert!(chunks.len() <= leaf_count);

    let mut stack = MerkleStack::new(leaf_count);
    for c in chunks {
        stack.push(*c);
    }
    stack.finalize()
}
