use crate::merkle::{B256, ZERO_HASHES, hash_concat};

pub const PROGRESSIVE_SEGMENTS: usize = 22;

/// Start chunk of progressive-tree segment k: `(4^k - 1) / 3` (EIP-7916).
/// Segment k is a binary subtree of `4^k` chunks at depth `2k`; the root is
/// `hash(segment 0, hash(segment 1, ... hash(segment K, Bytes32(0))))`.
/// 22 segments cover `(4^22 - 1)/3 > 2^42` chunks, beyond any list we hash.
///
/// Chunk gindices are stable in list length: chunk `c` in segment `k` at
/// local offset `i = c - start(k)` has gindex `((0b10 << k | ((1 << k) - 1))
/// << 2k) + i` from the progressive root (remerkleable
/// `to_gindex_progressive`).
pub const PROGRESSIVE_SEGMENT_START: [usize; PROGRESSIVE_SEGMENTS] = {
    let mut t = [0usize; PROGRESSIVE_SEGMENTS];
    let mut k = 1;
    while k < PROGRESSIVE_SEGMENTS {
        t[k] = t[k - 1] * 4 + 1;
        k += 1;
    }
    t
};

/// Segment holding chunk `c`: `floor(log4(3c + 1))`.
#[inline]
pub fn progressive_segment_of_chunk(c: usize) -> u32 {
    (63 - (3 * c as u64 + 1).leading_zeros()) >> 1
}

/// Spine node count covering `n` chunks (segments above the terminator).
#[inline]
pub fn progressive_segments_for(n: usize) -> usize {
    if n == 0 { 0 } else { progressive_segment_of_chunk(n - 1) as usize + 1 }
}

/// EIP-7916's right-to-left spine fold:
/// `hash(seg_0, hash(seg_1, ... hash(seg_last, Bytes32(0))))`.
pub fn fold_progressive_spine(segments: usize, mut seg_root: impl FnMut(usize) -> B256) -> B256 {
    let mut acc = ZERO_HASHES[0];
    for k in (0..segments).rev() {
        acc = hash_concat(&seg_root(k), &acc);
    }
    acc
}
