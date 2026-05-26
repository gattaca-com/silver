//! Finalized layer — flat segment tree of `B256` leaves.
//!
//! 1-indexed segment-tree layout:
//!
//! ```text
//!     nodes[0]                 unused
//!     nodes[1]                 root
//!     nodes[i]                 internal,   parent  = i / 2
//!     nodes[leaves .. 2*leaves] leaves,    left(i) = 2i, right(i) = 2i+1
//! ```
//!
//! Lifecycle:
//!
//! - **Build once** via `new(leaves)` (O(N) bottom-up build at checkpoint load;
//!   `leaves.len()` is rounded up to the next power of two and uses that as the
//!   max_elements.
//! - **Mutate only via delta promotion on finalization.**
//!   `FinalizedHashTree::promote_delta` walks its delta and calls
//!   `write_node(node, hash)` per dirty internal node, copying the delta's
//!   precomputed hashes straight into the flat array — no SHA-256 work at the
//!   base layer during promotion.
//!
//! Reads are O(1). The base never exposes a single-leaf `set` that
//! recomputes the path upward — that operation belongs on the delta,
//! where the cached hashes feed the next promotion.

use silver_common::ssz_hash::{ZERO_HASHES, hash_concat_many};

use crate::types::B256;

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

    /// Allocate and populate a tree from `leaves`. The leaf capacity is
    /// derived as `max(1, leaves.len().next_power_of_two())`; trailing
    /// nodes up to that capacity stay at the zero hash (and propagate
    /// as zero subtrees).
    ///
    /// Bottom-up O(N) build
    pub fn new(leaves: &[B256], capacity_hint: usize) -> Self {
        let max_elements = capacity_hint.next_power_of_two().max(1);
        debug_assert!(leaves.len() <= max_elements);

        let mut nodes: Box<[B256]> = vec![[0u8; 32]; 2 * max_elements].into_boxed_slice();
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[max_elements + i] = *leaf;
        }

        let depth = max_elements.trailing_zeros() as usize;
        let mut left_level_node = max_elements;
        let mut right_level_node = 2 * max_elements;
        let mut right_real_level_node = max_elements + leaves.len();
        for zero_hash in ZERO_HASHES.iter().take(depth + 1).skip(1) {
            left_level_node >>= 1;
            right_level_node >>= 1;
            right_real_level_node = right_real_level_node.div_ceil(2);
            let real_count = right_real_level_node - left_level_node;

            // `real_count == 0` when `leaves.is_empty()` — skip the call so we
            // don't hand `hashtree_rs::hash` a count of 0 with empty slices.
            if real_count > 0 {
                // children at `[2*left .. 2*right_real)`, output at `[left .. right_real)`;
                // the two ranges are disjoint, so split_at_mut isolates them for borrow
                // checker.
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

    /// Root hash of the tree — equivalent to `self.node(Self::root())`. Caller
    /// wraps with `mix_in_length` / extra zero-hash folding for SSZ semantics.
    pub fn root_hash(&self) -> &B256 {
        &self.nodes[Self::root() as usize]
    }

    /// Write `hash` into the flat-array node `node` *without* propagating
    /// upward. Used by `HashTreeState::promote_delta` to copy the
    /// delta's precomputed internal-node hashes straight into the base
    pub fn write_node(&mut self, node: u32, hash: B256) {
        self.debug_assert_node(node);
        self.nodes[node as usize] = hash;
    }
}
