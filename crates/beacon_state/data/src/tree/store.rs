use std::marker::PhantomData;

use super::{
    TreeSpec,
    chunk_writes::ChunkWrites,
    format::TreeFormat,
    page_format::{PagePos, Subtree},
    pool::{PageId, PagePool},
    snapshot::PageSnapshot,
    subtree::NodeRange,
};
use crate::{merkle::ZERO_HASHES, types::B256};

pub(super) struct NodeStore<C: TreeSpec> {
    pub(super) nodes: Vec<B256>,
    pub(super) count: usize,
    pub(super) writes: ChunkWrites,
    _marker: PhantomData<fn() -> C>,
}

impl<C: TreeSpec> Default for NodeStore<C> {
    fn default() -> Self {
        Self { nodes: Vec::new(), count: 0, writes: ChunkWrites::default(), _marker: PhantomData }
    }
}

impl<C: TreeSpec> NodeStore<C> {
    pub(super) fn with_leaves(
        format: TreeFormat,
        count: usize,
        leaves: impl Iterator<Item = B256>,
    ) -> Self {
        let mut store =
            Self { nodes: vec![[0u8; 32]; format.num_nodes::<C>()], count, ..Self::default() };
        store.writes.resize(format.data_capacity());
        for (slot, leaf) in store.nodes[format.data_start::<C>()..].iter_mut().zip(leaves) {
            *slot = leaf;
        }
        store
    }

    pub(super) fn take_unhashed(&mut self) -> (&mut [B256], &mut [NodeRange]) {
        (&mut self.nodes, self.writes.take_unhashed())
    }

    /// Copy `target` into the flat tree, skipping what it already holds:
    /// `loaded` is the snapshot it matches outside the written chunks.
    /// A format change copies every page.
    pub(super) fn load(
        &mut self,
        pool: &PagePool<C::Page>,
        loaded: &PageSnapshot,
        target: &PageSnapshot,
    ) {
        let format = target.format;
        self.nodes.resize(format.num_nodes::<C>(), [0u8; 32]);
        let same_format = loaded.format == format;
        for (s, sub) in format.subtrees::<C>().enumerate() {
            let loaded = loaded.roots.get(s).copied().filter(|_| same_format);
            self.load_page(pool, sub, sub.root::<C>(), loaded, target.roots[s]);
        }

        self.count = target.count;
        self.writes.clear();
        self.writes.resize(format.data_capacity());
    }

    fn load_page(
        &mut self,
        pool: &PagePool<C::Page>,
        sub: Subtree,
        at: PagePos,
        loaded: Option<PageId>,
        target: PageId,
    ) {
        if loaded == Some(target) && !self.writes.touches(sub.chunks_under::<C>(at)) {
            return;
        }
        let page = pool.page(target);
        for (node, len) in sub.rows_of::<C>(at) {
            self.nodes[node..node + len].copy_from_slice(&page[len..2 * len]);
        }
        for j in 0..sub.child_count::<C>(at) {
            let loaded = loaded.map(|l| pool.child(l, j));
            self.load_page(pool, sub, sub.child::<C>(at, j), loaded, pool.child(target, j));
        }
    }

    /// Commit the flat tree into `dst`, reusing `dst`'s allocations: clean
    /// pages are `parent`'s, dirty ones get fresh pages, except all-zero
    /// subtrees, which share the pool's zero page of their depth. A parent in
    /// another format, or none, shares nothing.
    pub(super) fn commit(
        &mut self,
        format: TreeFormat,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: Option<&PageSnapshot>,
    ) {
        debug_assert!(!self.writes.has_unhashed(), "commit before rehash");
        let parent = parent.filter(|parent| parent.format == format);
        dst.roots.clear();
        dst.allocated.clear();
        let mut committer = PageCommitter::<C> {
            writes: &self.writes,
            nodes: &self.nodes,
            pool,
            allocated: &mut dst.allocated,
        };
        for (s, sub) in format.subtrees::<C>().enumerate() {
            let root =
                committer.commit_page(sub, sub.root::<C>(), parent.map(|parent| parent.roots[s]));
            dst.roots.push(root);
        }
        dst.format = format;
        dst.count = self.count;
        self.writes.clear();
    }
}

struct PageCommitter<'a, C: TreeSpec> {
    writes: &'a ChunkWrites,
    nodes: &'a [B256],
    pool: &'a mut PagePool<C::Page>,
    allocated: &'a mut Vec<(u32, PageId)>,
}

impl<C: TreeSpec> PageCommitter<'_, C> {
    fn commit_page(&mut self, sub: Subtree, at: PagePos, parent: Option<PageId>) -> PageId {
        if let Some(parent) = parent &&
            !self.writes.touches(sub.chunks_under::<C>(at))
        {
            return parent;
        }
        // A subtree is all zero iff its root is the zero hash of its depth:
        // the collision resistance the Merkle tree already rests on.
        let nodes = self.nodes;
        let (top_node, depth) = (sub.top_node::<C>(at), sub.depth::<C>(at));
        if nodes[top_node] == ZERO_HASHES[depth as usize] {
            return self.pool.zero_page(depth);
        }

        let rows = sub.rows_of::<C>(at).map(|(node, len)| &nodes[node..node + len]);
        let id = self.pool.alloc(sub.child_count::<C>(at), rows);
        for j in 0..sub.child_count::<C>(at) {
            let parent = parent.map(|parent| self.pool.child(parent, j));
            let child = self.commit_page(sub, sub.child::<C>(at, j), parent);
            self.pool.set_child(id, j, child);
        }

        self.allocated.push((top_node as u32, id));
        id
    }
}
