use super::{
    ColumnVal,
    pool::{PAGE_NODES, PagePool},
    snapshot::PageSnapshot,
};
use crate::{ColumnLenMismatch, ssz_hash::hash_concat_many, types::B256};

#[derive(Default)]
pub struct ColumnTree {
    nodes: Vec<B256>,
    max_elements: usize,
    count: usize,
    dirty_mark: Vec<bool>,
}

impl ColumnTree {
    pub fn new<V: ColumnVal>(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * size_of::<V>() {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        let cap = cap.next_multiple_of(V::VALS_PER_CHUNK);
        let max_elements = (cap / V::VALS_PER_CHUNK).next_power_of_two().max(1);

        let mut nodes = vec![[0u8; 32]; 2 * max_elements];
        nodes[max_elements..].as_flattened_mut()[..ssz_bytes.len()].copy_from_slice(ssz_bytes);

        let mut level = max_elements;
        while level > 1 {
            let parent = level >> 1;
            let (parents, children) = nodes.split_at_mut(level);
            hash_concat_many(&mut parents[parent..level], &children[..level]);
            level = parent;
        }
        let num_pages = (2 * max_elements).div_ceil(PAGE_NODES).max(1);
        Ok(Self { nodes, max_elements, count, dirty_mark: vec![false; num_pages] })
    }

    #[inline]
    pub(super) fn max_elements(&self) -> usize {
        self.max_elements
    }

    #[inline]
    pub(super) fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub(super) fn num_pages(&self) -> usize {
        (2 * self.max_elements).div_ceil(PAGE_NODES).max(1)
    }

    #[inline]
    pub(super) fn node(&self, n: usize) -> &B256 {
        &self.nodes[n]
    }

    #[inline]
    fn page(&self, pi: usize) -> &[B256] {
        let end = ((pi + 1) * PAGE_NODES).min(self.nodes.len());
        &self.nodes[pi * PAGE_NODES..end]
    }

    #[inline]
    fn page_mut(&mut self, pi: usize) -> &mut [B256] {
        let end = ((pi + 1) * PAGE_NODES).min(self.nodes.len());
        &mut self.nodes[pi * PAGE_NODES..end]
    }

    fn reset_to(&mut self, max_elements: usize, count: usize) {
        self.nodes.resize(2 * max_elements, [0u8; 32]);
        self.max_elements = max_elements;
        self.count = count;
    }

    pub(super) fn gather_from(&mut self, pool: &PagePool, snapshot: &PageSnapshot) {
        self.reset_to(snapshot.max_elements(), snapshot.len());
        for pi in 0..snapshot.num_pages() {
            let dst = self.page_mut(pi);
            dst.copy_from_slice(&snapshot.page(pool, pi)[..dst.len()]);
        }
    }

    pub(super) fn to_snapshot(&self, pool: &mut PagePool) -> PageSnapshot {
        let pages = (0..self.num_pages()).map(|pi| pool.alloc_from_slice(self.page(pi))).collect();
        PageSnapshot {
            pages,
            max_elements: self.max_elements,
            count: self.count,
            is_released: false,
        }
    }

    /// Commit the scratch into `dst`, reusing `dst`'s page-table allocation: it
    /// shares `parent`'s clean pages (bumping their refcounts) and claims fresh
    /// pages for the ones this block dirtied.
    pub(super) fn commit_into(
        &self,
        pool: &mut PagePool,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
    ) {
        dst.pages.clear();
        dst.pages.extend(parent.pages.iter().enumerate().map(|(pi, &id)| {
            if self.dirty_mark[pi] {
                pool.alloc_from_slice(self.page(pi))
            } else {
                pool.retain(id);
                id
            }
        }));
        dst.max_elements = self.max_elements;
        dst.count = self.count;
        dst.is_released = false;
    }

    pub(super) fn reset_dirty_mask(&mut self) {
        let num_pages = self.num_pages();
        self.dirty_mark.clear();
        self.dirty_mark.resize(num_pages, false);
    }

    #[inline]
    fn mark_dirty_node(&mut self, leaf: u32) {
        let mut node = leaf as usize;
        debug_assert!(PAGE_NODES.is_power_of_two(), "PAGE_NODES must be a power of two");
        // We can skip already marked pages as top bids will always be the same after
        // division by 2 Example (top bits | last PAGE_NODES bits):
        // Leaf1 110|0101011 -> 11|0010101
        // Leaf2 110|1010100 -> 11|0101010
        while node >= 1 && !self.dirty_mark[node / PAGE_NODES] {
            self.dirty_mark[node / PAGE_NODES] = true;
            node >>= 1;
        }
    }

    pub fn set_vals<V: ColumnVal>(&mut self, changes: &[(u32, V)]) {
        if changes.is_empty() {
            return;
        }
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_vals needs ascending, distinct indices",
        );
        let k = V::VALS_PER_CHUNK as u32;

        let mut dirty: Vec<u32> = Vec::with_capacity(changes.len());
        for group in changes.chunk_by(|a, b| a.0 / k == b.0 / k) {
            let node = self.max_elements as u32 + group[0].0 / k;
            debug_assert!((node as usize) < 2 * self.max_elements, "index out of range");
            let leaf = &mut self.nodes[node as usize];
            for &(idx, v) in group {
                V::set_lane(leaf, (idx % k) as usize, v);
            }
            self.mark_dirty_node(node);
            dirty.push(node);
        }
        self.rehash(&mut dirty);
    }

    fn rehash(&mut self, dirty: &mut Vec<u32>) {
        let mut level = self.max_elements as u32;
        while level > 1 {
            let mut n = 0;
            for i in 0..dirty.len() {
                let parent = dirty[i] >> 1;
                if n == 0 || dirty[n - 1] != parent {
                    dirty[n] = parent;
                    n += 1;
                }
            }
            dirty.truncate(n);

            let (parents, children) = self.nodes.split_at_mut(level as usize);
            let mut i = 0;
            while i < dirty.len() {
                let start = i;
                while i + 1 < dirty.len() && dirty[i + 1] == dirty[i] + 1 {
                    i += 1;
                }
                i += 1;
                let (lo, hi) = (dirty[start], dirty[i - 1] + 1);
                hash_concat_many(
                    &mut parents[lo as usize..hi as usize],
                    &children[(2 * lo - level) as usize..(2 * hi - level) as usize],
                );
            }
            level >>= 1;
        }
    }

    pub fn append_empty<V: ColumnVal>(&mut self) -> u32 {
        let idx = self.count as u32;
        self.count += 1;
        debug_assert!(
            self.count <= self.max_elements * V::VALS_PER_CHUNK,
            "append past leaf capacity — cap headroom exhausted",
        );

        let k = V::VALS_PER_CHUNK;
        debug_assert!(
            V::lane(&self.nodes[self.max_elements + idx as usize / k], idx as usize % k) ==
                V::default(),
            "append over a non-zero leaf slot",
        );

        idx
    }
}
