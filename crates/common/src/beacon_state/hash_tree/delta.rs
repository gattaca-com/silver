//! Persistent delta over `FinalizedHashTree`. Mutation clones a fresh
//! `Arc<DeltaNode>` along the path to the touched leaf; sibling subtrees
//! stay as `Base(n)` pointers into the finalized array.
//!
//! Promotion safety: every survivor is a descendant of the promoted fork,
//! so unchanged subtrees still point at base and modified ones already
//! cache the post-promotion hash. `prune_delta_at` collapses redundant
//! `Arc<DeltaNode>` chains whose cached hash matches base.

use std::sync::Arc;

use super::finalized::FinalizedHashTree;
use crate::{
    beacon_state::{buffer::Reset, types::B256},
    ssz_hash::hash_concat,
};

/// Per-fork delta on top of a [`FinalizedHashTree`]. Three states:
/// - `Base(node)`: subtree lives in the finalized base at `node`.
/// - `Leaf(value)`: a delta leaf (depth = leaf row); `value` IS the hash.
/// - `Node(Arc<DeltaNode>)`: a delta internal node with cached hash + children.
///
/// `Clone` is O(1): `Base` copies a u32, `Leaf` copies 32 B, `Node` bumps
/// the `Arc` refcount. Used by `Reset::reset_from`
/// so per-slot ring rolls don't deep-copy the dirty overlay.
///
/// TODO(perf): replace `Arc<DeltaNode>` with a `TierPool`-style slab
/// (`silver_common::arena`). Turns each `set_leaf`'s ~22 mallocs into pointer
/// bumps and co-locates delta nodes. Gated on generational free-tracking for
/// safe ring-wrap.
#[derive(Clone)]
pub enum DeltaHashTree {
    Base(u32),
    Leaf(B256),
    Node(Arc<DeltaNode>),
}

impl DeltaHashTree {
    pub fn new_at(_base: &FinalizedHashTree) -> Self {
        Self::Base(FinalizedHashTree::root())
    }
}

impl Default for DeltaHashTree {
    fn default() -> Self {
        // The root node is index 1 (1-indexed segment tree).
        Self::Base(FinalizedHashTree::root())
    }
}

impl Reset for DeltaHashTree {
    fn reset(&mut self) {
        *self = Self::Base(FinalizedHashTree::root());
    }

    fn reset_from(&mut self, other: &Self) {
        // Arc::clone makes this O(1) regardless of overlay depth.
        *self = other.clone();
    }
}

#[derive(Clone)]
pub struct DeltaNode {
    pub hash: B256,
    pub left: DeltaHashTree,
    pub right: DeltaHashTree,
}

impl FinalizedHashTree {
    #[inline]
    pub(super) fn resolve_delta_hash(&self, delta: &DeltaHashTree) -> B256 {
        match delta {
            DeltaHashTree::Base(node) => *self.node_hash(*node),
            DeltaHashTree::Leaf(hash) => *hash,
            DeltaHashTree::Node(node) => node.hash,
        }
    }

    /// `[subtree_left, subtree_right)` is the leaf-index range covered by node
    /// subtree.
    pub(super) fn set_delta_leaf_in_range(
        &self,
        delta: &DeltaHashTree,
        index: u32,
        subtree_left: u32,
        subtree_right: u32,
        leaf: B256,
    ) -> DeltaHashTree {
        debug_assert!(subtree_left <= index && index < subtree_right);

        if subtree_right - subtree_left == 1 {
            return DeltaHashTree::Leaf(leaf);
        }

        let (mut left_node, mut right_node) = match delta {
            DeltaHashTree::Base(b) => {
                (DeltaHashTree::Base(Self::left(*b)), DeltaHashTree::Base(Self::right(*b)))
            }
            DeltaHashTree::Node(arc) => (arc.left.clone(), arc.right.clone()),
            DeltaHashTree::Leaf(_) => {
                unreachable!("Leaf possible only when subtree_right - subtree_left == 1")
            }
        };

        let subtree_mid = (subtree_left + subtree_right) / 2;
        if index < subtree_mid {
            left_node =
                self.set_delta_leaf_in_range(&left_node, index, subtree_left, subtree_mid, leaf);
        } else {
            right_node =
                self.set_delta_leaf_in_range(&right_node, index, subtree_mid, subtree_right, leaf);
        }

        let hash = hash_concat(
            &self.resolve_delta_hash(&left_node),
            &self.resolve_delta_hash(&right_node),
        );
        DeltaHashTree::Node(Arc::new(DeltaNode { hash, left: left_node, right: right_node }))
    }

    pub(super) fn prune_delta_at(&self, delta: &mut DeltaHashTree, node: u32) {
        match delta {
            DeltaHashTree::Base(_) => {}
            DeltaHashTree::Leaf(hash) => {
                if hash == self.node_hash(node) {
                    *delta = DeltaHashTree::Base(node);
                }
            }
            DeltaHashTree::Node(arc) => {
                if arc.hash == *self.node_hash(node) {
                    *delta = DeltaHashTree::Base(node);
                    return;
                }
                // We must clone-on-write because the Arc may still be shared with sibling
                // forks.
                let mut delta_node = (**arc).clone();
                self.prune_delta_at(&mut delta_node.left, Self::left(node));
                self.prune_delta_at(&mut delta_node.right, Self::right(node));
                *arc = Arc::new(delta_node);
            }
        }
    }

    /// Zero SHA-256 invocations: reuses cached delta hashes.
    /// Cost: O(delta node count) ≈ O(k · log(max_elements / k)) for `k` dirty
    /// leaves.
    pub(super) fn promote_delta_at(&mut self, delta: &DeltaHashTree, node: u32) {
        match delta {
            DeltaHashTree::Base(_) => {}
            DeltaHashTree::Leaf(hash) => {
                self.write_node(node, *hash);
            }
            DeltaHashTree::Node(delta_node) => {
                self.write_node(node, delta_node.hash);
                self.promote_delta_at(&delta_node.left, Self::left(node));
                self.promote_delta_at(&delta_node.right, Self::right(node));
            }
        }
    }
}
