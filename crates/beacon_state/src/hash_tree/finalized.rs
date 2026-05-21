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
//!   `leaves.len()` is rounded up to the next power of two and uses that as the max_elements.
//! - **Mutate only via delta promotion on finalization.** `FinalizedHashTree::promote_delta`
//!   walks its delta and calls `write_node(node, hash)` per dirty internal
//!   node, copying the delta's precomputed hashes straight into the flat array
//!   — no SHA-256 work at the base layer during promotion.
//!
//! Reads are O(1). The base never exposes a single-leaf `set` that
//! recomputes the path upward — that operation belongs on the delta,
//! where the cached hashes feed the next promotion.
//!
//! Length tracking lives in the caller (e.g. `ValidatorsState::
//! validator_cnt`). The tree only knows its `max_elements`. nodes
//! above the caller's logical length stay at zero hashes and
//! propagate upward as zero subtrees — correct by construction
//! without any length bookkeeping here.

use silver_common::ssz_hash::hash_concat;

use crate::types::B256;

/// Generic finalized segment tree of `B256` leaves.
///
/// Owns a heap-allocated `Box<[B256]>` of length `2 * max_elements`.
/// `max_elements` is fixed at construction; the caller picks a
/// power-of-two large enough to cover the worst-case populated count.
pub struct FinalizedHashTree {
    /// 1-indexed flat tree. `nodes[0]` is unused. `nodes[1]` is the
    /// root of the physical tree. Leaves occupy `nodes[max_elements..2*max_elements]`. 
    /// Length is exactly `2 * max_elements`.
    nodes: Box<[B256]>,
    /// Power-of-two leaf capacity.
    max_elements: usize,
}

impl FinalizedHashTree {
    /// Root node in the 1-indexed segment-tree layout.
    #[inline]
    pub const fn root() -> u32 {
        1
    }

    /// Left child node in the 1-indexed segment-tree layout.
    #[inline]
    pub const fn left(node: u32) -> u32 {
        2 * node
    }

    /// Right child node in the 1-indexed segment-tree layout.
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
    pub fn new(leaves: Vec<B256>) -> Self {
        let max_elements = leaves.len().next_power_of_two().max(1);
        debug_assert!(max_elements.is_power_of_two());
        debug_assert!(max_elements >= 1);
        debug_assert!(leaves.len() <= max_elements);

        let mut nodes: Box<[B256]> = vec![[0u8; 32]; 2 * max_elements].into_boxed_slice();
        for (i, leaf) in leaves.into_iter().enumerate() {
            nodes[max_elements + i] = leaf;
        }

        for node in (1..max_elements).rev() {
            nodes[node] = hash_concat(&nodes[2 * node], &nodes[2 * node + 1]);
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
