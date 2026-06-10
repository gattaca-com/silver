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

impl DeltaHashTree {
    /// Write `leaf` to position `i` of this overlay over `base`. Sparse: only
    /// the path from leaf `i` up to the root is materialised; sibling subtrees
    /// remain `Base(..)` pointers into the finalized array.
    #[inline]
    pub fn set_leaf(&mut self, base: &FinalizedHashTree, i: usize, leaf: B256) {
        debug_assert!(
            i < base.max_elements(),
            "leaf index out of range: i={i}, max_elements={}",
            base.max_elements()
        );
        *self = base.set_delta_leaf_in_range(self, i as u32, 0, base.max_elements() as u32, leaf);
    }

    /// The hash this overlay resolves to over `base` — its merged root (for a
    /// subtree node, that subtree's root).
    #[inline]
    pub fn root(&self, base: &FinalizedHashTree) -> B256 {
        match self {
            DeltaHashTree::Base(node) => *base.node_hash(*node),
            DeltaHashTree::Leaf(hash) => *hash,
            DeltaHashTree::Node(node) => node.hash,
        }
    }

    /// SSZ `hash_tree_root` for a `List[T, 1<<list_depth]` backed by `base` +
    /// this overlay. Pads the physical root with zero subtrees up to
    /// `list_depth`, then mixes in `len`.
    #[inline]
    pub fn ssz_list_root(&self, base: &FinalizedHashTree, list_depth: u32, len: usize) -> B256 {
        let mut root = self.root(base);
        for h in base.max_elements().trailing_zeros()..list_depth {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, len)
    }
}

impl FinalizedHashTree {
    /// Advance the base to `winner`, re-anchoring every `survivor`. Bakes in
    /// the only correct order — rebase each survivor, fold `winner` in,
    /// then prune — so callers can't run the `pub(crate)` steps out of
    /// order. See `DeltaHashTree::rebase` and
    /// `docs/delta-rebase-invariant.md`.
    pub fn finalize(&mut self, winner: &DeltaHashTree, survivors: &mut [&mut DeltaHashTree]) {
        for survivor in survivors.iter_mut() {
            survivor.rebase(self, winner);
        }
        self.promote_delta(winner);
        for survivor in survivors.iter_mut() {
            self.prune_delta(survivor);
        }
    }

    /// Fold `delta`'s precomputed internal-node hashes into the finalized flat
    /// array (no SHA-256 work). A finalization building block — drive it via
    /// [`Self::finalize`], which rebases survivors first.
    #[inline]
    pub(crate) fn promote_delta(&mut self, delta: &DeltaHashTree) {
        self.promote_delta_at(delta, Self::root());
    }

    /// Collapse `delta` nodes whose cached hash equals the new base hash back
    /// to `Base(...)`, freeing redundant `Arc<DeltaNode>` chains. A
    /// finalization building block — drive it via [`Self::finalize`].
    #[inline]
    pub(crate) fn prune_delta(&self, delta: &mut DeltaHashTree) {
        self.prune_delta_at(delta, Self::root());
    }

    /// Pre-promote counterpart of [`Self::prune_delta`]: collapse `delta` nodes
    /// that already equal the **new** base — `self` with `winner` promoted into
    /// it — letting a survivor finalize its hash overlay in one pass with
    /// `rebase`, before `winner` is folded into the base.
    #[inline]
    pub(crate) fn prune_delta_against(&self, delta: &mut DeltaHashTree, winner: &DeltaHashTree) {
        self.prune_delta_against_at(delta, winner, Self::root());
    }
}
