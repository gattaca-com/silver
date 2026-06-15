//! Persistent delta over `FinalizedHashTree`. Mutation clones a fresh
//! `Arc<DeltaNode>` along the path to the touched leaf; sibling subtrees
//! stay as `Base(n)` pointers into the finalized array.
//!
//! A `Base` symlink follows the base when it is promoted
//! (see documentation for more details in `docs/delta-rebase-invariant.md`).

use std::sync::Arc;

use super::finalized::FinalizedHashTree;
use crate::{buffer::Reset, ssz_hash::hash_concat, types::B256};

/// Per-fork delta on top of a [`FinalizedHashTree`]. Three states:
/// - `Base(node)`: a lazy **symlink** to the finalized base at `node` —
///   resolves to the base's *current* value, so it follows the base when it
///   moves (see the module-level promote hazard).
/// - `Leaf(value)`: a *frozen* delta leaf (depth = leaf row); `value` IS the
///   hash.
/// - `Node(Arc<DeltaNode>)`: a *frozen* internal node with cached hash +
///   children.
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

    fn same(&self, other: &DeltaHashTree) -> bool {
        match (self, other) {
            (DeltaHashTree::Base(x), DeltaHashTree::Base(y)) => x == y,
            (DeltaHashTree::Leaf(x), DeltaHashTree::Leaf(y)) => x == y,
            (DeltaHashTree::Node(x), DeltaHashTree::Node(y)) => Arc::ptr_eq(x, y),
            _ => false,
        }
    }

    /// Re-pin every leaf the `winner` overrides so the survivor's symlinks
    /// don't follow the base when it moves. A `Base` entry is a *symlink*:
    /// it reads the base's value live, so when the base changes under it,
    /// its value changes too. One-leaf walk-through:
    ///
    /// ```text
    /// start:  base leaf = A,  survivor overlay = Base   (symlink, reads A)
    /// winner overwrites the leaf to B, then is promoted  ->  base leaf = B
    ///   no rebase:  survivor still Base       -> now reads B   (wrong, wanted A)
    ///   rebase:     survivor frozen to Leaf(A) -> still reads A (correct)
    /// ```
    ///
    /// Full invariant: `docs/delta-rebase-invariant.md`.
    pub(crate) fn rebase(&mut self, base: &FinalizedHashTree, winner: &DeltaHashTree) {
        self.rebase_at(base, winner, FinalizedHashTree::root())
    }

    fn rebase_at(&mut self, base: &FinalizedHashTree, winner: &DeltaHashTree, node: u32) {
        // Survivor already equals the winner here → it matches the new base too,
        // so no symlink can drift; nothing to pin.
        if self.same(winner) {
            return;
        }

        match winner {
            // Base doesn't move here → the survivor's symlinks stay valid.
            DeltaHashTree::Base(_) => (),
            // Base moves here → freeze the survivor's value, else its symlink
            // would follow the base to the winner's new value.
            DeltaHashTree::Leaf(_) => *self = DeltaHashTree::Leaf(self.root(base)),
            // Base moves below → descend to the symlinks at risk.
            DeltaHashTree::Node(winner_node) => {
                let (mut left, mut right) = match self {
                    DeltaHashTree::Base(_) => (
                        DeltaHashTree::Base(FinalizedHashTree::left(node)),
                        DeltaHashTree::Base(FinalizedHashTree::right(node)),
                    ),
                    DeltaHashTree::Node(n) => (n.left.clone(), n.right.clone()),
                    DeltaHashTree::Leaf(_) => unreachable!("Leaf only at a single-leaf range"),
                };
                left.rebase_at(base, &winner_node.left, FinalizedHashTree::left(node));
                right.rebase_at(base, &winner_node.right, FinalizedHashTree::right(node));

                *self =
                    DeltaHashTree::Node(Arc::new(DeltaNode { hash: self.root(base), left, right }));
            }
        }
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
    /// Apply all `leaves` (sorted, distinct, within `[lo, hi)`; `node` is the
    /// 1-indexed tree node for that range) in one recursive divide & conquer
    /// that hashes each touched internal node exactly once — instead of one
    /// root→leaf rebuild per leaf re-hashing shared upper nodes. A
    /// single-element batch is the per-leaf write. Subtrees with no dirty leaf
    /// are never entered; auxiliary memory is just the recursion stack.
    ///
    /// Collapse-to-base: when a written leaf equals the base leaf, or both
    /// children end up symlinking to this node's own base children, the
    /// subtree provably equals the base, so we store a `Base(node)` symlink
    /// instead of hashing/allocating a `Node`. A clear over an empty base
    /// collapses every leaf and propagates to the root — no SHA, no `Arc`;
    /// a non-empty base stays correct since differing subtrees build normally.
    /// This is an eager prune — the finalize-time `rebase` re-pins these
    /// symlinks on base advance.
    pub(super) fn set_delta_leaves_collapse(
        &self,
        delta: &DeltaHashTree,
        leaves: &[(u32, B256)],
        node: u32,
        lo: u32,
        hi: u32,
    ) -> DeltaHashTree {
        debug_assert!(!leaves.is_empty());

        if hi - lo == 1 {
            let leaf = leaves[0].1;
            if leaf == *self.node_hash(node) {
                return DeltaHashTree::Base(node);
            }
            return DeltaHashTree::Leaf(leaf);
        }

        let (mut left_node, mut right_node) = match delta {
            DeltaHashTree::Base(_) => {
                (DeltaHashTree::Base(Self::left(node)), DeltaHashTree::Base(Self::right(node)))
            }
            DeltaHashTree::Node(arc) => (arc.left.clone(), arc.right.clone()),
            DeltaHashTree::Leaf(_) => unreachable!("Leaf possible only when hi - lo == 1"),
        };

        let mid = (lo + hi) / 2;
        let split = leaves.partition_point(|(i, _)| *i < mid);
        let (left_leaves, right_leaves) = leaves.split_at(split);
        if !left_leaves.is_empty() {
            left_node =
                self.set_delta_leaves_collapse(&left_node, left_leaves, Self::left(node), lo, mid);
        }
        if !right_leaves.is_empty() {
            right_node = self.set_delta_leaves_collapse(
                &right_node,
                right_leaves,
                Self::right(node),
                mid,
                hi,
            );
        }

        // Both children symlink to this node's base children ⇒ node == base.
        // Collapse without hashing or allocating.
        if let (DeltaHashTree::Base(l), DeltaHashTree::Base(r)) = (&left_node, &right_node) {
            if *l == Self::left(node) && *r == Self::right(node) {
                return DeltaHashTree::Base(node);
            }
        }

        let hash = hash_concat(&left_node.root(self), &right_node.root(self));
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

    /// Like [`prune_delta_at`](Self::prune_delta_at) but against the **new**
    /// base *before* it is promoted: the new base hash at a node is `winner`'s
    /// override there, else the old base (`self`). Lets a survivor collapse its
    /// redundant nodes pre-promote — its winner-pinned leaves (frozen by
    /// `rebase`) differ from the new base, so they survive; only edits that
    /// already equal the new base fold back to `Base` symlinks (which then
    /// follow the base once `winner` is promoted).
    pub(super) fn prune_delta_against_at(
        &self,
        delta: &mut DeltaHashTree,
        winner: &DeltaHashTree,
        node: u32,
    ) {
        let new_base_hash = match winner {
            DeltaHashTree::Base(_) => *self.node_hash(node),
            DeltaHashTree::Leaf(hash) => *hash,
            DeltaHashTree::Node(arc) => arc.hash,
        };
        match delta {
            // A symlink reads the (new) base live — already collapsed. `rebase`
            // froze every winner-moved leaf first, so a surviving `Base` here is
            // a node the winner left untouched: following the base stays correct.
            DeltaHashTree::Base(_) => {}
            DeltaHashTree::Leaf(hash) => {
                if *hash == new_base_hash {
                    *delta = DeltaHashTree::Base(node);
                }
            }
            DeltaHashTree::Node(arc) => {
                if arc.hash == new_base_hash {
                    *delta = DeltaHashTree::Base(node);
                    return;
                }
                // `delta` is a `Node`, so this range spans >1 leaf and `winner`
                // is `Base`/`Node` here (never `Leaf`); descend its children.
                let (winner_left, winner_right) = match winner {
                    DeltaHashTree::Base(_) => (
                        DeltaHashTree::Base(Self::left(node)),
                        DeltaHashTree::Base(Self::right(node)),
                    ),
                    DeltaHashTree::Node(w) => (w.left.clone(), w.right.clone()),
                    DeltaHashTree::Leaf(_) => {
                        unreachable!("Leaf spans a single leaf, delta is Node")
                    }
                };
                // COW: the Arc may still be shared with sibling forks.
                let mut delta_node = (**arc).clone();
                self.prune_delta_against_at(&mut delta_node.left, &winner_left, Self::left(node));
                self.prune_delta_against_at(
                    &mut delta_node.right,
                    &winner_right,
                    Self::right(node),
                );
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
