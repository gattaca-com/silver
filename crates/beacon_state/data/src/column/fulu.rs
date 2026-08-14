use silver_ssz::scalar::SszScalar;

use super::{
    format::TreeFormat,
    store::NodeStore,
    subtree::{build_subtree_hashes, rehash_subtree},
};
use crate::{merkle::ZERO_HASHES, types::B256};

#[derive(Default)]
pub(super) struct FuluTree {
    pub(super) store: NodeStore,
    pub(super) max_elements: usize,
}

impl FuluTree {
    pub(super) fn new<V: SszScalar>(
        cap: usize,
        count: usize,
        leaves: impl Iterator<Item = B256>,
    ) -> Self {
        let max_elements = cap.div_ceil(V::VALS_PER_CHUNK).next_power_of_two().max(1);
        let store = NodeStore::with_leaves(2 * max_elements, count, max_elements, leaves);
        let mut tree = Self { store, max_elements };
        tree.build(count.div_ceil(V::VALS_PER_CHUNK));
        tree
    }

    fn build(&mut self, non_zero: usize) {
        let (internal, leaves) = self.store.nodes.split_at_mut(self.max_elements);
        build_subtree_hashes(internal, leaves, non_zero);
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        TreeFormat::Fulu { max_elements: self.max_elements }
    }

    pub(super) fn rehash(&mut self) {
        let max_elements = self.max_elements;
        let NodeStore { nodes, dirty_chunks, .. } = &mut self.store;
        let (internal, leaves) = nodes.split_at_mut(max_elements);
        rehash_subtree(internal, leaves, dirty_chunks);
        dirty_chunks.clear();
    }

    pub(super) fn fill_zero(&mut self) {
        let (internal, leaves) = self.store.nodes.split_at_mut(self.max_elements);
        leaves.fill(ZERO_HASHES[0]);
        build_subtree_hashes(internal, leaves, 0);
    }
}
