//! Generic SSZ collection hashers over byte slices: `List` / `Vector` /
//! `Bitlist`, the [`FixedContainer`] element trait, and the offset-table
//! iterator for variable-size elements. Each takes a [`Merkleizer`] so the same
//! code serves fixed-limit and progressive trees.

use flux_profiler::timed;

use super::{
    hash::{B256, ZERO_HASH, mix_in_length},
    merkleize::{merkleize, merkleize_bytes, pack_byte_chunks},
    stack::Merkleizer,
};
use crate::scalar::SszScalar;

/// Pack a Bitlist's content bytes into 32-byte chunks, clearing the sentinel
/// (length-delimiter) bit. Shared core of the fixed-limit and progressive
/// bitlist hashers; pushes nothing for `bit_len == 0`.
pub fn pack_bitlist_chunks(data: &[u8], bit_len: usize, mut push: impl FnMut(B256)) {
    if bit_len == 0 {
        return;
    }
    let content_bytes = bit_len.div_ceil(8);
    // Byte-aligned bitlists carry the sentinel in the next (excluded) byte, so
    // the content bytes are clean and bulk-push straight through.
    if bit_len.is_multiple_of(8) {
        pack_byte_chunks(&data[..content_bytes], push);
        return;
    }
    // Otherwise the sentinel sits in the final content byte: bulk-push every
    // preceding full chunk, then mask it in the padded tail chunk.
    let tail_start = (content_bytes - 1) & !31;
    pack_byte_chunks(&data[..tail_start], &mut push);
    let mut tail = [0u8; 32];
    tail[..content_bytes - tail_start].copy_from_slice(&data[tail_start..content_bytes]);
    tail[content_bytes - 1 - tail_start] &= !(1u8 << (bit_len % 8));
    push(tail);
}

/// Iterate a variable-size SSZ list's elements through its offset table,
/// yielding `None` for a malformed offset pair; empty or malformed input
/// yields nothing. Callers map each element (and any `None`) to a leaf and feed
/// the result to [`hash_list`].
pub fn variable_containers(data: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
    let count = if data.len() < 4 {
        0
    } else {
        let first_offset = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
            0
        } else {
            first_offset / 4
        }
    };
    (0..count).map(move |i| {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        (start <= end && end <= data.len()).then(|| &data[start..end])
    })
}

/// Hash a `uint64` list from its LE-packed SSZ bytes, mixing in `count`. The
/// `merkleizer` fixes the tree: `MerkleStack::new(limit.div_ceil(4))` for
/// `List[uint64, limit]`, `ProgressiveHasher` for `ProgressiveList[uint64]`.
#[timed]
pub fn hash_uint64_list(mut merkleizer: impl Merkleizer, data: &[u8], count: usize) -> B256 {
    pack_byte_chunks(data, |c| merkleizer.push(c));
    mix_in_length(&merkleizer.finalize(), count)
}

#[timed]
pub fn hash_b256_vector(values: &[B256]) -> B256 {
    merkleize(values)
}

#[timed]
pub fn hash_uint64_vector(values: &[u64]) -> B256 {
    merkleize_bytes(&u64::as_ssz_bytes(values), values.len().div_ceil(4))
}

/// hash_tree_root of a `List`/`ProgressiveList`: merkleize the per-element
/// `leaves` and mix in the count. Callers map elements to leaves, so the
/// element hasher lives at the call site, not as a parameter.
pub fn hash_list(mut merkleizer: impl Merkleizer, leaves: impl Iterator<Item = B256>) -> B256 {
    let mut count = 0;
    for leaf in leaves {
        merkleizer.push(leaf);
        count += 1;
    }
    mix_in_length(&merkleizer.finalize(), count)
}

/// A fixed-size SSZ type: its serialized byte length is a property of the type,
/// paired with its hasher — so a list of them hashes off the type rather than a
/// literal at the call site (see [`FixedContainer::hash_list`]).
pub trait FixedContainer {
    const SSZ_SIZE: usize;
    fn hash_tree_root(bytes: &[u8]) -> B256;

    /// hash_tree_root of a `List[Self, N]` / `ProgressiveList[Self]` from its
    /// concatenated element bytes. The `merkleizer` fixes the tree —
    /// `MerkleStack::new(limit)` for a bounded list, `ProgressiveHasher` for a
    /// progressive one.
    fn hash_list(merkleizer: impl Merkleizer, bytes: &[u8]) -> B256 {
        // `hash_list` here is the leaves-iterator primitive above, not this
        // method (an unqualified call can't reach an associated fn).
        hash_list(merkleizer, bytes.chunks_exact(Self::SSZ_SIZE).map(Self::hash_tree_root))
    }
}

/// [`FixedContainer::hash_list`] for variable-size elements: walk the offset
/// table instead of fixed chunks, hashing each with `hash_elem` (a malformed
/// offset pair contributes a zero leaf).
pub fn hash_variable_list(
    merkleizer: impl Merkleizer,
    data: &[u8],
    hash_elem: impl Fn(&[u8]) -> B256,
) -> B256 {
    hash_list(merkleizer, variable_containers(data).map(|e| e.map_or(ZERO_HASH, |b| hash_elem(b))))
}

/// [`hash_list`] for a fixed `Vector[T, len]` — merkleize the leaves with no
/// length mix-in.
pub fn hash_vector(mut merkleizer: impl Merkleizer, leaves: impl Iterator<Item = B256>) -> B256 {
    for leaf in leaves {
        merkleizer.push(leaf);
    }
    merkleizer.finalize()
}

/// hash_tree_root for a Bitlist. Streams content bytes into 32-byte chunks,
/// masking the delimiter bit on the last content byte. The `merkleizer` fixes
/// the tree: `MerkleStack::new(max_bits.div_ceil(256).next_power_of_two())` for
/// `Bitlist[max_bits]`, `ProgressiveHasher` for `ProgressiveBitlist`.
#[timed]
pub fn hash_bitlist(mut merkleizer: impl Merkleizer, data: &[u8], bit_len: usize) -> B256 {
    pack_bitlist_chunks(data, bit_len, |c| merkleizer.push(c));
    mix_in_length(&merkleizer.finalize(), bit_len)
}

pub fn bitlist_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let last = data[data.len() - 1];
    if last == 0 {
        return 0;
    }
    let bits_before_last = (data.len() - 1) * 8;
    bits_before_last + 7 - last.leading_zeros() as usize
}
