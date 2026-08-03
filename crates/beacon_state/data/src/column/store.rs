use super::{
    format::TreeFormat,
    pool::{PAGE_NODES, PagePool},
    snapshot::PageSnapshot,
    subtree::NodeRange,
};
use crate::types::B256;

#[derive(Default)]
pub(super) struct NodeStore {
    pub(super) nodes: Vec<B256>,
    pub(super) count: usize,
    pub(super) dirty_pages: Vec<bool>,
    pub(super) dirty_chunks: Vec<NodeRange>,
}

impl NodeStore {
    pub(super) fn with_leaves(
        num_nodes: usize,
        count: usize,
        data_start: usize,
        leaves: impl Iterator<Item = B256>,
    ) -> Self {
        let mut store = Self {
            nodes: vec![[0u8; 32]; num_nodes],
            count,
            dirty_pages: vec![false; num_pages_for(num_nodes)],
            dirty_chunks: Vec::new(),
        };
        for (slot, leaf) in store.nodes[data_start..].iter_mut().zip(leaves) {
            *slot = leaf;
        }
        store
    }

    #[inline]
    pub(super) fn num_pages(&self) -> usize {
        num_pages_for(self.nodes.len())
    }

    #[inline]
    pub(super) fn node(&self, n: usize) -> &B256 {
        &self.nodes[n]
    }

    #[inline]
    pub(super) fn page(&self, pi: usize) -> &[B256] {
        let end = ((pi + 1) * PAGE_NODES).min(self.nodes.len());
        &self.nodes[pi * PAGE_NODES..end]
    }

    #[inline]
    fn page_mut(&mut self, pi: usize) -> &mut [B256] {
        let end = ((pi + 1) * PAGE_NODES).min(self.nodes.len());
        &mut self.nodes[pi * PAGE_NODES..end]
    }

    /// Copy in only the pages that differ from `target`. `loaded` is the
    /// table our nodes already match: an equal page id with a clean dirty
    /// bit means the bytes are already right (pool pages never change while
    /// referenced). Everything else — mismatched, dirtied, or past the old
    /// table after a resize — gets copied.
    pub(super) fn load_diff(
        &mut self,
        pool: &PagePool,
        loaded: &PageSnapshot,
        target: &PageSnapshot,
        num_nodes: usize,
    ) {
        self.nodes.resize(num_nodes, [0u8; 32]);
        self.count = target.len();
        for pi in 0..target.num_pages() {
            let same = self.dirty_pages.get(pi).is_some_and(|&dirty| !dirty) &&
                loaded.pages.get(pi) == Some(&target.pages[pi]);
            if !same {
                let dst = self.page_mut(pi);
                dst.copy_from_slice(&target.page(pool, pi)[..dst.len()]);
            }
        }
        self.reset_dirty_mask();
    }

    pub(super) fn to_snapshot(&self, pool: &mut PagePool, format: TreeFormat) -> PageSnapshot {
        let pages = (0..self.num_pages()).map(|pi| pool.alloc_from_slice(self.page(pi))).collect();
        PageSnapshot { pages, format, count: self.count, is_released: false }
    }

    /// Commit the scratch into `dst`, reusing `dst`'s page-table allocation: it
    /// shares `parent`'s clean pages (bumping their refcounts) and claims fresh
    /// pages for the ones this block dirtied — plus every page past `parent`'s
    /// table when this block changed the format (migration or segment growth).
    pub(super) fn commit_into(
        &self,
        pool: &mut PagePool,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
        format: TreeFormat,
    ) {
        dst.pages.clear();
        dst.pages.extend((0..self.num_pages()).map(|pi| match parent.pages.get(pi) {
            Some(&id) if !self.dirty_pages[pi] => {
                pool.retain(id);
                id
            }
            _ => pool.alloc_from_slice(self.page(pi)),
        }));
        dst.format = format;
        dst.count = self.count;
        dst.is_released = false;
    }

    /// Start a fresh write session: no dirty pages, and no dirty chunks — an
    /// abandoned fork can leave an unhashed `add_at` batch behind, and its ids
    /// may not even be in range of the tree loaded since.
    pub(super) fn reset_dirty_mask(&mut self) {
        let num_pages = self.num_pages();
        self.dirty_pages.clear();
        self.dirty_pages.resize(num_pages, false);
        self.dirty_chunks.clear();
    }

    pub(super) fn mark_all_dirty(&mut self) {
        let num_pages = self.num_pages();
        self.dirty_pages.clear();
        self.dirty_pages.resize(num_pages, true);
    }

    pub(super) fn copy_changed_pages_from(&mut self, src: &NodeStore) {
        debug_assert_eq!(self.count, src.count, "rotate needs a same-length source");
        let len = self.nodes.len();
        let Self { nodes, dirty_pages, .. } = self;
        for (pi, dirty) in dirty_pages.iter_mut().enumerate() {
            let range = pi * PAGE_NODES..((pi + 1) * PAGE_NODES).min(len);
            if nodes[range.clone()].as_flattened() != src.nodes[range.clone()].as_flattened() {
                nodes[range.clone()].copy_from_slice(&src.nodes[range]);
                *dirty = true;
            }
        }
    }

    #[inline]
    pub(super) fn mark_dirty_page(&mut self, node: usize) {
        self.dirty_pages[node / PAGE_NODES] = true;
    }

    #[inline]
    pub(super) fn push_dirty(&mut self, chunk: u32) {
        match self.dirty_chunks.last_mut() {
            Some(last) if last.contains(chunk) => {}
            Some(last) if chunk == last.end => last.end += 1,
            _ => self.dirty_chunks.push(NodeRange::single(chunk)),
        }
    }

    /// Sort the dirty ranges and merge any that touch, restoring the
    /// ascending-disjoint invariant `rehash` relies on.
    pub(super) fn sort_merge_dirty(&mut self) {
        self.dirty_chunks.sort_unstable_by_key(|r| r.start);
        let mut n = 0;
        for j in 0..self.dirty_chunks.len() {
            let r = self.dirty_chunks[j];
            if n > 0 && self.dirty_chunks[n - 1].try_merge(r) {
                continue;
            }
            self.dirty_chunks[n] = r;
            n += 1;
        }
        self.dirty_chunks.truncate(n);
    }

    /// `seg_off` is the internal node's subtree block offset (0 for fulu's
    /// single tree); the walk is subtree-local.
    #[inline]
    pub(super) fn mark_dirty_node(&mut self, node: usize, seg_off: usize) {
        let mut local = node - seg_off;
        debug_assert!(PAGE_NODES.is_power_of_two(), "PAGE_NODES must be a power of two");
        debug_assert!(seg_off.is_multiple_of(PAGE_NODES), "subtree regions must be page-aligned");
        // We can skip already-marked pages: local top bits (the page) halve the
        // same way for every node on a page, so a dirty page means every page
        // above it is dirty too. Example (top bits | last PAGE_NODES bits):
        // Node1 110|0101011 -> 11|0010101
        // Node2 110|1010100 -> 11|0101010
        // The page-aligned seg_off only shifts pages by a constant.
        while local >= 1 && !self.dirty_pages[(seg_off + local) / PAGE_NODES] {
            self.dirty_pages[(seg_off + local) / PAGE_NODES] = true;
            local >>= 1;
        }
    }
}

fn num_pages_for(num_nodes: usize) -> usize {
    num_nodes.div_ceil(PAGE_NODES).max(1)
}
