//! EIP-7916 / EIP-7495 progressive Merkleization: `merkleize_progressive`,
//! the streaming [`ProgressiveHasher`], and the ProgressiveContainer
//! `active_fields` mix-in. Activates with EIP-7688 (gloas). `ProgressiveList`
//! roots go through the generic list hashers in [`crate::merkle`] with a
//! [`ProgressiveHasher`] as the [`Merkleizer`](crate::merkle::Merkleizer).

use flux::utils::ArrayVec;

use crate::merkle::{B256, MerkleStack, Merkleizer, ZERO_HASH, hash_concat, merkleize_to};

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
    let mut acc = ZERO_HASH;
    for k in (0..segments).rev() {
        acc = hash_concat(&seg_root(k), &acc);
    }
    acc
}

/// EIP-7916 `merkleize_progressive` over a chunk slice. Empty input is
/// `ZERO_HASH`.
pub fn merkleize_progressive(chunks: &[B256]) -> B256 {
    fold_progressive_spine(progressive_segments_for(chunks.len()), |k| {
        let start = PROGRESSIVE_SEGMENT_START[k];
        let leaf_count = 1usize << (2 * k);
        let end = chunks.len().min(start + leaf_count);
        merkleize_to(&chunks[start..end], leaf_count)
    })
}

#[derive(Clone, Copy, Default)]
pub struct ProgressiveHasher {
    stack: MerkleStack,
    seg_roots: ArrayVec<B256, PROGRESSIVE_SEGMENTS>,
    filled: usize,
}

impl ProgressiveHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, c: B256) {
        self.stack.push(c);
        self.filled += 1;
        let k = self.seg_roots.len();
        if self.filled == 1usize << (2 * k) {
            // Segment k holds 4^k chunks; the next holds 4^(k+1).
            let full = std::mem::replace(&mut self.stack, MerkleStack::new(1 << (2 * (k + 1))));
            self.seg_roots.push(full.finalize());
            self.filled = 0;
        }
    }

    /// Progressive root without consuming the accumulated frontier — for
    /// callers that keep pushing after reading the root (queue frontiers).
    #[inline]
    pub fn root(&self) -> B256 {
        (*self).finalize()
    }

    /// Progressive root (no length mix-in).
    pub fn finalize(mut self) -> B256 {
        if self.filled > 0 {
            self.seg_roots.push(self.stack.finalize());
        }
        let roots = self.seg_roots;
        fold_progressive_spine(roots.len(), |k| roots.as_slice()[k])
    }
}

impl Merkleizer for ProgressiveHasher {
    #[inline]
    fn push(&mut self, chunk: B256) {
        self.push_chunk(chunk);
    }
    #[inline]
    fn finalize(self) -> B256 {
        ProgressiveHasher::finalize(self)
    }
}

/// EIP-7495 ProgressiveContainer mix-in:
/// `hash(root, pack_bits(active_fields))`.
#[inline]
pub fn mix_in_active_fields(root: &B256, active_fields: &B256) -> B256 {
    hash_concat(root, active_fields)
}

/// An EIP-7495 ProgressiveContainer type, identified by its `active_fields`
/// mask. A deactivated field keeps its slot as a zero chunk (stable gindex)
/// with its bit cleared, so the mask is a property of the type, not derived
/// from the field count — see [`packed_active_fields`] for the all-active case.
pub trait ProgressiveContainer {
    const ACTIVE_FIELDS: B256;

    /// Root over already-merkleized `field_roots` (inactive slots hold
    /// `ZERO_HASH`), with this type's `active_fields` mixed in. The per-type
    /// `hash_tree_root` that extracts the fields calls this as its final step.
    fn progressive_root(field_roots: &[B256]) -> B256 {
        debug_assert!(field_roots.len() <= 256);
        debug_assert!(
            field_roots.iter().enumerate().all(|(i, f)| {
                (Self::ACTIVE_FIELDS[i / 8] >> (i % 8)) & 1 == 1 || *f == ZERO_HASH
            }),
            "inactive field must occupy its slot as a zero chunk",
        );
        mix_in_active_fields(&merkleize_progressive(field_roots), &Self::ACTIVE_FIELDS)
    }
}

/// `pack_bits([1] * n)` as a `Bitvector[256]` chunk — the `active_fields`
/// mask of a ProgressiveContainer whose fields are all active (every EIP-7688
/// type at its first fork).
pub const fn packed_active_fields(n: usize) -> B256 {
    let mut chunk = [0u8; 32];
    let mut i = 0;
    while i < n {
        chunk[i / 8] |= 1 << (i % 8);
        i += 1;
    }
    chunk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{ZERO_HASHES, hash_bitlist, hash_uint64_list, merkleize_padded, uint64_chunk},
        scalar::SszScalar,
    };

    /// Element: 28 bytes of 0xFF + 4-byte LE int. Matches spec's e(v).
    fn e(v: u32) -> B256 {
        let mut chunk = [0xFF; 32];
        chunk[28..32].copy_from_slice(&v.to_le_bytes());
        chunk
    }

    fn z(i: usize) -> B256 {
        ZERO_HASHES[i]
    }

    fn h(a: B256, b: B256) -> B256 {
        hash_concat(&a, &b)
    }

    fn hex_b32(s: &str) -> B256 {
        assert_eq!(s.len(), 64);
        let b = s.as_bytes();
        let n = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!(),
            }
        };
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (n(b[i * 2]) << 4) | n(b[i * 2 + 1]);
        }
        out
    }

    #[test]
    fn segment_table_and_chunk_lookup() {
        assert_eq!(&PROGRESSIVE_SEGMENT_START[..5], &[0, 1, 5, 21, 85]);
        let seg_starts = [(0, 0), (1, 1), (4, 1), (5, 2), (20, 2), (21, 3), (84, 3), (85, 4)];
        for (c, k) in seg_starts {
            assert_eq!(progressive_segment_of_chunk(c), k, "chunk {c}");
        }
    }

    /// Hand-composed EIP-7916 roots at every segment boundary, in the style
    /// of `ssz_hash::tests::spec_merkleize_vectors`. Segment subtree left,
    /// spine right, `Bytes32(0)` terminator.
    #[test]
    fn spec_merkleize_progressive_vectors() {
        let m1_full = h(h(e(1), e(2)), h(e(3), e(4)));
        let m2_of_e5 = h(h(h(h(e(5), z(0)), z(1)), z(2)), z(3));
        let chunks: Vec<B256> = (0..22).map(e).collect();
        let m2_full = merkleize_padded(&chunks[5..21], 16);
        let m3_of_e21 = merkleize_padded(&chunks[21..22], 64);

        let cases: Vec<(usize, B256)> = vec![
            (0, ZERO_HASH),
            (1, h(e(0), ZERO_HASH)),
            (2, h(e(0), h(h(h(e(1), z(0)), z(1)), ZERO_HASH))),
            (5, h(e(0), h(m1_full, ZERO_HASH))),
            (6, h(e(0), h(m1_full, h(m2_of_e5, ZERO_HASH)))),
            (21, h(e(0), h(m1_full, h(m2_full, ZERO_HASH)))),
            (22, h(e(0), h(m1_full, h(m2_full, h(m3_of_e21, ZERO_HASH))))),
        ];
        for (count, expected) in cases {
            assert_eq!(merkleize_progressive(&chunks[..count]), expected, "count={count}");
        }
    }

    /// Verbatim transcription of the EIP-7916 pseudocode.
    fn merkleize_progressive_ref(chunks: &[B256], num_leaves: usize) -> B256 {
        if chunks.is_empty() {
            return ZERO_HASH;
        }
        let split = chunks.len().min(num_leaves);
        hash_concat(
            &merkleize_padded(&chunks[..split], num_leaves),
            &merkleize_progressive_ref(&chunks[split..], num_leaves * 4),
        )
    }

    #[test]
    fn progressive_matches_reference_recursion() {
        let chunks: Vec<B256> = (0..200).map(e).collect();
        for n in 0..=200usize {
            let expected = merkleize_progressive_ref(&chunks[..n], 1);
            assert_eq!(merkleize_progressive(&chunks[..n]), expected, "slice n={n}");

            let mut hasher = ProgressiveHasher::new();
            for c in &chunks[..n] {
                hasher.push_chunk(*c);
            }
            assert_eq!(hasher.finalize(), expected, "streaming n={n}");
        }
    }

    #[test]
    fn packed_active_fields_bytes() {
        let mut body = [0u8; 32];
        body[..2].copy_from_slice(&[0xff, 0x1f]);
        assert_eq!(packed_active_fields(13), body);

        let mut state = [0u8; 32];
        state[..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]);
        assert_eq!(packed_active_fields(46), state);
    }

    /// Roots pinned from the consensus-specs reference implementation
    /// (eth-remerkleable 0.1.31):
    /// ```python
    /// from remerkleable.progressive import ProgressiveList, ProgressiveBitlist, ProgressiveContainer
    /// from remerkleable.basic import uint64
    /// ProgressiveList[uint64](1,2,3,4,5).hash_tree_root().hex()
    /// ProgressiveList[uint64](*range(1, 101)).hash_tree_root().hex()
    /// ProgressiveList[uint64]().hash_tree_root().hex()
    /// ProgressiveBitlist(*([True]*10)).hash_tree_root().hex()
    /// ProgressiveBitlist(*([True, False]*150)).hash_tree_root().hex()
    /// class Gapped(ProgressiveContainer(active_fields=[1, 0, 1])):
    ///     a: uint64
    ///     b: uint64
    /// Gapped(a=7, b=9).hash_tree_root().hex()
    /// ```
    #[test]
    fn remerkleable_pins() {
        let v5: Vec<u64> = (1..=5).collect();
        assert_eq!(
            hash_uint64_list(ProgressiveHasher::new(), &u64::as_ssz_bytes(&v5), 5),
            hex_b32("29918e0447260511bc5be0f7dbb9817201e16e30c56af228b9cb931a16e8799d"),
        );
        let v100: Vec<u64> = (1..=100).collect();
        assert_eq!(
            hash_uint64_list(ProgressiveHasher::new(), &u64::as_ssz_bytes(&v100), 100),
            hex_b32("3fea5b85e30e0416810839a91ea3767e65b04890709db74997109f50213b3375"),
        );
        assert_eq!(
            hash_uint64_list(ProgressiveHasher::new(), &[], 0),
            hex_b32("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        );

        // 10 one-bits + delimiter at bit 10.
        assert_eq!(
            hash_bitlist(ProgressiveHasher::new(), &[0xff, 0x07], 10),
            hex_b32("e41f8e72e544f68368824f9ee40fb8f8e70b6e11e0cae82769c1e042deb3befa"),
        );
        // (true, false) * 150 + delimiter at bit 300.
        let mut alternating = [0x55u8; 38];
        alternating[37] = 0x15;
        assert_eq!(
            hash_bitlist(ProgressiveHasher::new(), &alternating, 300),
            hex_b32("afa0fd3f9e5c0423bdf5339ad8c90effe12e2b5640cb6f219afe4f40aed02f27"),
        );

        // ProgressiveContainer(active_fields=[1,0,1]): the inactive field
        // leaves a zero chunk at its bit position (gindex gap).
        let mut active = [0u8; 32];
        active[0] = 0b101;
        assert_eq!(
            mix_in_active_fields(
                &merkleize_progressive(&[uint64_chunk(7), ZERO_HASH, uint64_chunk(9)]),
                &active,
            ),
            hex_b32("aedfb2d01919beeb8a2cf250f421d1aaefcffc16cb74d54056ce9e98099f0616"),
        );
    }
}
