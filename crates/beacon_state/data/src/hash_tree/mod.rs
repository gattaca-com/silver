//! Two-layer persistent hash tree for big SSZ `List[T, N]` fields:
//! `FinalizedHashTree` (flat segment tree on the finalized base) +
//! `DeltaHashTree` (per-fork sparse `Arc<DeltaNode>` overlay). The view
//! layer composes them ephemerally via the helpers below.

mod delta;
mod finalized;

#[cfg(test)]
mod tests;

pub use delta::DeltaHashTree;
pub use finalized::FinalizedHashTree;

use crate::{
    ssz_hash::{ZERO_HASHES, hash_concat, mix_in_length},
    types::B256,
};

impl FinalizedHashTree {
    /// Write `leaf` to position `i` of the delta. Sparse: only the path
    /// from leaf `i` up to the root is materialised on the delta; sibling
    /// subtrees remain `DeltaHashTree::Base(...)` pointers into the
    /// finalized array.
    #[inline]
    pub fn set_delta_leaf(&self, delta: &mut DeltaHashTree, i: usize, leaf: B256) {
        debug_assert!(
            i < self.max_elements(),
            "leaf index out of range: i={i}, max_elements={}",
            self.max_elements()
        );
        *delta = self.set_delta_leaf_in_range(delta, i as u32, 0, self.max_elements() as u32, leaf);
    }

    /// Effective root of the (finalized + delta) merged tree.
    #[inline]
    pub fn delta_root(&self, delta: &DeltaHashTree) -> B256 {
        self.resolve_delta_hash(delta)
    }

    /// Fold `delta`'s precomputed internal-node hashes into the finalized
    /// flat array (no SHA-256 work). Caller is expected to follow up with
    /// `prune_delta` on every surviving descendant so unused chains drop.
    #[inline]
    pub fn promote_delta(&mut self, delta: &DeltaHashTree) {
        self.promote_delta_at(delta, Self::root());
    }

    /// Collapse `delta` nodes whose cached hash equals the new base hash
    /// back to `Base(...)`. Frees the redundant `Arc<DeltaNode>` chains.
    #[inline]
    pub fn prune_delta(&self, delta: &mut DeltaHashTree) {
        self.prune_delta_at(delta, Self::root());
    }

    /// SSZ `hash_tree_root` for a `List[T, 1<<list_depth]` backed by this
    /// tree + `delta`. Pads the physical root with zero subtrees up to
    /// `list_depth`, then mixes in `len`.
    #[inline]
    pub fn ssz_list_root(&self, delta: &DeltaHashTree, list_depth: u32, len: usize) -> B256 {
        let mut root = self.delta_root(delta);
        for h in self.max_elements().trailing_zeros()..list_depth {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, len)
    }
}
