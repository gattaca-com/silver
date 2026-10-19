use super::{
    TreeSpec,
    format::TreeFormat,
    store::NodeStore,
    subtree::{build_subtree_hashes, rehash_subtree},
};
use crate::{
    B256,
    merkle::{ZERO_HASHES, hash_concat},
};

pub struct ListTree<C: TreeSpec> {
    pub(super) store: NodeStore<C>,
    pub(super) max_elements: usize,
}

impl<C: TreeSpec> Default for ListTree<C> {
    fn default() -> Self {
        Self { store: NodeStore::default(), max_elements: 0 }
    }
}

impl<C: TreeSpec> ListTree<C> {
    pub(super) fn new(cap: usize, count: usize, leaves: impl Iterator<Item = B256>) -> Self {
        let max_elements = cap.div_ceil(C::VALS_PER_CHUNK).next_power_of_two().max(1);
        let store = NodeStore::with_leaves(TreeFormat::Fixed { max_elements }, count, leaves);
        let mut tree = Self { store, max_elements };
        tree.build(count.div_ceil(C::VALS_PER_CHUNK));
        tree
    }

    fn build(&mut self, non_zero: usize) {
        let (internal, leaves) = self.store.nodes.split_at_mut(self.max_elements);
        build_subtree_hashes(internal, leaves, non_zero);
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        TreeFormat::Fixed { max_elements: self.max_elements }
    }

    pub(super) fn rehash(&mut self) {
        let (nodes, unhashed) = self.store.take_unhashed();
        let (internal, leaves) = nodes.split_at_mut(self.max_elements);
        rehash_subtree(internal, leaves, unhashed);
    }

    /// The old tree becomes the new root's left child, so only the new root is
    /// hashed.
    #[cold]
    pub(super) fn grow_one(&mut self) {
        let old_max = self.max_elements;
        let new_max = 2 * old_max;
        let depth = old_max.ilog2();

        let nodes = &mut self.store.nodes;
        nodes.resize(2 * new_max, ZERO_HASHES[0]);
        nodes.copy_within(old_max..2 * old_max, new_max);
        // Deepest level first: each destination lies past every source not yet
        // moved.
        for level in (0..depth).rev() {
            let start = 1usize << level;
            nodes.copy_within(start..2 * start, 2 * start);
            nodes[3 * start..4 * start].fill(ZERO_HASHES[(depth - level) as usize]);
        }
        nodes[1] = hash_concat(&nodes[2], &nodes[3]);

        self.max_elements = new_max;
        self.store.writes.resize(new_max);
        self.store.writes.mark_all_hashed();
    }

    pub(super) fn fill_zero(&mut self) {
        let (internal, leaves) = self.store.nodes.split_at_mut(self.max_elements);
        leaves.fill(ZERO_HASHES[0]);
        build_subtree_hashes(internal, leaves, 0);
    }
}
