//! Finalized layer — 1-indexed flat segment tree of `B256` leaves
//! (`nodes[1]` root, `left(i) = 2i`, `right(i) = 2i+1`). Built once at
//! checkpoint load, then mutated only via `promote_delta` copying the
//! delta's precomputed hashes. Reads are O(1); per-leaf `set` belongs on
//! the delta layer.

use crate::{
    beacon_state::types::B256,
    ssz_hash::{ZERO_HASHES, hash_concat},
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

    /// Allocate and populate a tree from `leaves`. The leaf capacity is
    /// derived as `max(1, capacity_hint.next_power_of_two())`; trailing
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

        let elements_count = leaves.len();
        let depth = max_elements.trailing_zeros() as usize;

        for node in (1..max_elements).rev() {
            // Leaves are level 0; root (node=1) sits at level `depth`. Node n at
            // level L covers leaves `[(n << L) - max_elements, (n+1 << L) - max_elements)`.
            let node_level = depth - node.ilog2() as usize;
            let subtree_first_leaf = (node << node_level) - max_elements;
            if subtree_first_leaf >= elements_count {
                nodes[node] = ZERO_HASHES[node_level];
            } else {
                nodes[node] = hash_concat(&nodes[2 * node], &nodes[2 * node + 1]);
            }
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
