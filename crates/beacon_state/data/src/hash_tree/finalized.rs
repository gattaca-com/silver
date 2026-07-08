//! Finalized layer — 1-indexed flat segment tree of `B256` leaves
//! (`nodes[1]` root, `left(i) = 2i`, `right(i) = 2i+1`). Built once at
//! checkpoint load, then mutated only via `promote_delta` copying the
//! delta's precomputed hashes. Reads are O(1); per-leaf `set` belongs on
//! the delta layer.

use flux_profiler::timed;

use crate::{
    ssz_hash::{ZERO_HASHES, hash_concat_many},
    types::B256,
};

/// Generic finalized segment tree of `B256` leaves.
///
/// Owns a heap-allocated `Box<[B256]>` of length `2 * max_elements`.
/// `max_elements` is fixed at construction; the caller picks a
/// power-of-two large enough to cover the worst-case populated count.
pub struct FinalizedHashTree {
    /// 1-indexed flat tree. `nodes[0]` is unused. `nodes[1]` is the
    /// root of the physical tree. Leaves occupy
    /// `nodes[max_elements..2*max_elements]`. Length is exactly `2 *
    /// max_elements`.
    nodes: Box<[B256]>,
    /// Power-of-two leaf capacity.
    max_elements: usize,
}

impl FinalizedHashTree {
    #[inline]
    pub const fn root() -> u32 {
        1
    }

    #[inline]
    pub const fn left(node: u32) -> u32 {
        2 * node
    }

    #[inline]
    pub const fn right(node: u32) -> u32 {
        2 * node + 1
    }

    /// Bottom-up O(N) build. The leaf capacity is derived as
    /// `max(1, capacity_hint.next_power_of_two())`; trailing nodes up to that
    /// capacity stay at the zero hash (and propagate as zero subtrees).
    #[timed]
    #[inline]
    pub fn from_leaves(leaves: impl ExactSizeIterator<Item = B256>, capacity_hint: usize) -> Self {
        let leaf_count = leaves.len();
        let max_elements = capacity_hint.next_power_of_two().max(1);
        debug_assert!(leaf_count <= max_elements);

        let mut nodes: Box<[B256]> = vec![[0u8; 32]; 2 * max_elements].into_boxed_slice();
        for (slot, leaf) in nodes[max_elements..].iter_mut().zip(leaves) {
            *slot = leaf;
        }

        let depth = max_elements.trailing_zeros() as usize;
        let mut left_level_node = max_elements;
        let mut right_level_node = 2 * max_elements;
        let mut right_real_level_node = max_elements + leaf_count;
        for zero_hash in ZERO_HASHES.iter().take(depth + 1).skip(1) {
            left_level_node >>= 1;
            right_level_node >>= 1;
            right_real_level_node = right_real_level_node.div_ceil(2);
            let real_count = right_real_level_node - left_level_node;

            // Skip empty levels: `hashtree_rs::hash` rejects a count of 0.
            if real_count > 0 {
                // split_at_mut: children `[2*left .. 2*right_real)` and output
                // `[left .. right_real)` are disjoint.
                let (out_side, in_side) = nodes.split_at_mut(2 * left_level_node);
                hash_concat_many(
                    &mut out_side[left_level_node..right_real_level_node],
                    &in_side[..2 * real_count],
                );
            }
            nodes[right_real_level_node..right_level_node].fill(*zero_hash);
        }

        Self { nodes, max_elements }
    }

    /// Power-of-two leaf capacity. Fixed at construction.
    pub fn max_elements(&self) -> usize {
        self.max_elements
    }

    #[inline]
    fn debug_assert_node(&self, node: u32) {
        debug_assert!(node >= 1, "node is 1-indexed; 0 is unused");
        debug_assert!(
            (node as usize) < 2 * self.max_elements,
            "node out of range: node={node}, 2*max_elements={}",
            2 * self.max_elements,
        );
    }

    /// Read an arbitrary node by its 1-indexed node. Also serves as
    /// the leaf-read entrypoint: a leaf at index `i` sits at
    /// `node = max_elements() + i`.
    pub fn node_hash(&self, node: u32) -> &B256 {
        self.debug_assert_node(node);
        &self.nodes[node as usize]
    }

    /// Root hash of the tree — equivalent to `self.node_hash(Self::root())`.
    /// Caller wraps with `mix_in_length` / extra zero-hash folding for SSZ
    /// semantics.
    pub fn root_hash(&self) -> &B256 {
        &self.nodes[Self::root() as usize]
    }

    /// Write `hash` into the flat-array node `node` *without* propagating
    /// upward. Used by `FinalizedHashTree::promote_delta` to copy the
    /// delta's precomputed internal-node hashes straight into the base
    pub fn write_node(&mut self, node: u32, hash: B256) {
        self.debug_assert_node(node);
        self.nodes[node as usize] = hash;
    }
}
