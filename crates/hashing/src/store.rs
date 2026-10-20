use std::marker::PhantomData;

use super::{
    TreeSpec,
    chunk_writes::ChunkWrites,
    format::TreeFormat,
    page_format::{PagePos, Subtree},
    storage::{PageAlloc, PageId, PageStore},
    subtree::NodeRange,
    table::PageTable,
};
use crate::{B256, merkle::ZERO_HASHES};

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
    /// `loaded` is the table it matches outside the written chunks.
    /// A format change copies every page.
    pub(super) fn load(&mut self, pages: &impl PageStore, loaded: &PageTable, target: &PageTable) {
        let format = target.format();
        self.nodes.resize(format.num_nodes::<C>(), [0u8; 32]);
        let same_format = loaded.format() == format;
        for (s, sub) in format.subtrees::<C>().enumerate() {
            let loaded = loaded.roots().get(s).copied().filter(|_| same_format);
            self.load_page(pages, sub, sub.root::<C>(), loaded, target.roots()[s]);
        }

        self.count = target.len();
        self.writes.clear();
        self.writes.resize(format.data_capacity());
    }

    fn load_page(
        &mut self,
        pages: &impl PageStore,
        sub: Subtree,
        at: PagePos,
        loaded: Option<PageId>,
        target: PageId,
    ) {
        if loaded == Some(target) && !self.writes.touches(sub.chunks_under::<C>(at)) {
            return;
        }
        let page = pages.page(target);
        for (node, len) in sub.rows_of::<C>(at) {
            self.nodes[node..node + len].copy_from_slice(&page[len..2 * len]);
        }
        for j in 0..sub.child_count::<C>(at) {
            let loaded = loaded.map(|l| pages.child(l, j));
            self.load_page(pages, sub, sub.child::<C>(at, j), loaded, pages.child(target, j));
        }
    }

    /// Commit the flat tree into `dst`, reusing its `roots` buffer. Clean pages
    /// are `parent`'s, dirty ones are new, and all-zero subtrees share the zero
    /// page of their depth. A parent in another format, or none, shares
    /// nothing.
    pub(super) fn commit(
        &mut self,
        format: TreeFormat,
        alloc: &mut impl PageAlloc,
        dst: &mut PageTable,
        parent: Option<&PageTable>,
        allocated: Option<&mut Vec<(u32, PageId)>>,
    ) {
        debug_assert!(!self.writes.has_unhashed(), "commit before rehash");
        let parent = parent.filter(|parent| parent.format() == format);
        let mut committer =
            PageCommitter { writes: &self.writes, nodes: &self.nodes, alloc, allocated };
        let roots = format.subtrees::<C>().enumerate().map(|(s, sub)| {
            let parent = parent.map(|parent| parent.roots()[s]);
            committer.commit_page::<C>(sub, sub.root::<C>(), parent)
        });
        dst.set(format, self.count, roots);
        self.writes.clear();
    }
}

struct PageCommitter<'a, Alloc: PageAlloc> {
    writes: &'a ChunkWrites,
    nodes: &'a [B256],
    alloc: &'a mut Alloc,
    /// `(flat-tree node in slot 1, page)` per page `alloc` gave.
    allocated: Option<&'a mut Vec<(u32, PageId)>>,
}

impl<Alloc: PageAlloc> PageCommitter<'_, Alloc> {
    fn commit_page<C: TreeSpec>(
        &mut self,
        sub: Subtree,
        at: PagePos,
        parent: Option<PageId>,
    ) -> PageId {
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
            return self.alloc.zero_page(depth);
        }

        let rows = sub.rows_of::<C>(at).map(|(node, len)| &nodes[node..node + len]);
        let id = self.alloc.alloc(sub.child_count::<C>(at), rows);
        if let Some(allocated) = self.allocated.as_deref_mut() {
            allocated.push((top_node as u32, id));
        }
        for j in 0..sub.child_count::<C>(at) {
            let parent = parent.map(|parent| self.alloc.child(parent, j));
            let child = self.commit_page::<C>(sub, sub.child::<C>(at, j), parent);
            self.alloc.set_child(id, j, child);
        }
        id
    }
}
