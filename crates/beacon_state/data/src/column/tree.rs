use flux_profiler::timed;
use silver_ssz::scalar::SszScalar;

use super::{
    ColumnSpec,
    format::{TreeFormat, progressive_internal_parent},
    list::ListTree,
    pool::PagePool,
    progressive_list::ProgressiveListTree,
    snapshot::PageSnapshot,
    store::NodeStore,
};
use crate::types::{B256, HashFormat};

pub enum ColumnTree<C: ColumnSpec> {
    List(ListTree<C>),
    ProgressiveList(ProgressiveListTree<C>),
}

impl<C: ColumnSpec> Default for ColumnTree<C> {
    fn default() -> Self {
        ColumnTree::List(ListTree::default())
    }
}

impl<C: ColumnSpec> ColumnTree<C> {
    #[timed]
    pub fn from_leaves(
        cap: usize,
        count: usize,
        leaves: impl Iterator<Item = B256>,
        format: HashFormat,
    ) -> Self {
        match format {
            HashFormat::Fixed => ColumnTree::List(ListTree::new(cap, count, leaves)),
            HashFormat::Progressive => {
                ColumnTree::ProgressiveList(ProgressiveListTree::from_leaves(cap, count, leaves))
            }
        }
    }

    pub fn migrate_to_progressive(&mut self) {
        let ColumnTree::List(list) = self else { return };
        *self = ColumnTree::ProgressiveList(ProgressiveListTree::from_list(list));
    }

    #[inline]
    fn store(&self) -> &NodeStore<C> {
        match self {
            ColumnTree::List(t) => &t.store,
            ColumnTree::ProgressiveList(t) => &t.store,
        }
    }

    #[inline]
    fn store_mut(&mut self) -> &mut NodeStore<C> {
        match self {
            ColumnTree::List(t) => &mut t.store,
            ColumnTree::ProgressiveList(t) => &mut t.store,
        }
    }

    #[inline]
    fn data_start(&self) -> usize {
        self.format().data_start::<C>()
    }

    #[inline]
    fn leaf_pos(&self, chunk: usize) -> usize {
        self.format().leaf_pos::<C>(chunk)
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        match self {
            ColumnTree::List(t) => t.format(),
            ColumnTree::ProgressiveList(t) => t.format(),
        }
    }

    #[inline]
    pub(super) fn count(&self) -> usize {
        self.store().count
    }

    #[inline]
    pub(super) fn num_pages(&self) -> usize {
        self.store().num_pages()
    }

    #[inline]
    pub(super) fn node(&self, n: usize) -> &B256 {
        self.store().node(n)
    }

    /// Load `target`'s content, switching tree variant if its format differs.
    /// `loaded` is the table our content already matches, so only mismatched
    /// or dirtied pages get copied. Clears the dirty mask.
    #[timed]
    pub(super) fn load(
        &mut self,
        pool: &PagePool<C::Page>,
        loaded: &PageSnapshot,
        target: &PageSnapshot,
    ) {
        let format = target.format();
        if self.format() != format {
            let store = std::mem::take(self.store_mut());
            *self = match format {
                TreeFormat::Fixed { max_elements } => {
                    ColumnTree::List(ListTree { store, max_elements })
                }
                TreeFormat::Progressive { last_seg } => {
                    ColumnTree::ProgressiveList(ProgressiveListTree { store, last_seg })
                }
            };
        }
        self.store_mut().load_diff(pool, loaded, target, format.num_nodes::<C>());
    }

    #[timed]
    pub(super) fn to_snapshot(&self, pool: &mut PagePool<C::Page>) -> PageSnapshot {
        self.store().to_snapshot(pool, self.format())
    }

    pub(super) fn commit_into(
        &self,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
    ) {
        self.store().commit_into(pool, dst, parent, self.format());
    }

    pub(super) fn reset_dirty_mask(&mut self) {
        self.store_mut().reset_dirty_mask();
    }

    pub(super) fn mark_all_dirty(&mut self) {
        self.store_mut().mark_all_dirty();
    }

    pub(super) fn copy_changed_pages_from<D>(&mut self, src: &ColumnTree<D>)
    where
        D: ColumnSpec<Val = C::Val, Page = C::Page>,
    {
        debug_assert_eq!(self.format(), src.format(), "rotate needs a same-format source");
        self.store_mut().copy_changed_pages_from(src.store());
    }

    pub fn fill_zero(&mut self) {
        match self {
            ColumnTree::List(t) => t.fill_zero(),
            ColumnTree::ProgressiveList(t) => t.fill_zero(),
        }
        self.mark_all_dirty();
    }

    pub fn iter_vals(&self) -> impl Iterator<Item = C::Val> + '_ {
        let sz = size_of::<C::Val>();
        let count = self.count();
        let data_start = self.data_start();
        let bytes = &self.store().nodes[data_start..].as_flattened()[..count * sz];
        (0..count).map(move |i| {
            let mut out = [C::Val::default()];
            <C::Val>::read_ssz_slice(&mut out, &bytes[i * sz..i * sz + sz]);
            out[0]
        })
    }

    /// Record chunk `chunk` as dirty and mark the pages its rehash will touch.
    /// A list's leaf is an in-tree node, so its page walk starts there; a
    /// progressive list's leaf is flat data, so its data page is marked plus
    /// the internal ancestors in its segment block (segment 0's lone leaf is
    /// its own root — no internal pages).
    fn seed_write(&mut self, chunk: usize, data_node: usize) {
        let format = self.format();
        let store = self.store_mut();
        store.push_dirty(chunk as u32);
        match format {
            TreeFormat::Fixed { .. } => store.mark_dirty_node(data_node, 0),
            TreeFormat::Progressive { .. } => {
                store.mark_dirty_page(data_node);
                if let Some((parent, seg_off)) = progressive_internal_parent::<C>(chunk) {
                    store.mark_dirty_node(parent, seg_off);
                }
            }
        }
    }

    /// Write one value without rehashing; queue its chunk for a later
    /// [`rehash_unsorted`](Self::rehash_unsorted).
    pub fn set_val_deferred(&mut self, idx: u32, v: C::Val) {
        let k = C::VALS_PER_CHUNK as u32;
        let chunk = (idx / k) as usize;
        let data_node = self.leaf_pos(chunk);
        {
            let store = self.store_mut();
            debug_assert!(data_node < store.nodes.len(), "index out of range");
            let leaf = &mut store.nodes[data_node];
            let lane = (idx % k) as usize;
            if <C::Val>::lane(leaf, lane) == v {
                return;
            }
            <C::Val>::set_lane(leaf, lane, v);
        }
        self.seed_write(chunk, data_node);
    }

    #[inline]
    pub(super) fn has_pending_rehash(&self) -> bool {
        !self.store().dirty_chunks.is_empty()
    }

    pub fn set_vals(&mut self, changes: &[(u32, C::Val)]) {
        if changes.is_empty() {
            return;
        }
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_vals needs ascending, distinct indices",
        );
        debug_assert!(self.store().dirty_chunks.is_empty(), "unhashed add_at batch pending");
        let k = C::VALS_PER_CHUNK as u32;
        let format = self.format();
        for group in changes.chunk_by(|a, b| a.0 / k == b.0 / k) {
            let chunk = (group[0].0 / k) as usize;
            let data_node = format.leaf_pos::<C>(chunk);
            {
                let store = self.store_mut();
                debug_assert!(data_node < store.nodes.len(), "index out of range");
                let leaf = &mut store.nodes[data_node];
                for &(idx, v) in group {
                    <C::Val>::set_lane(leaf, (idx % k) as usize, v);
                }
            }
            self.seed_write(chunk, data_node);
        }
        self.rehash();
    }

    pub fn rehash_unsorted(&mut self) {
        self.store_mut().sort_merge_dirty();
        self.rehash();
    }

    pub fn rehash(&mut self) {
        debug_assert!(
            self.store().dirty_chunks.iter().all(|r| r.start < r.end) &&
                self.store().dirty_chunks.windows(2).all(|w| w[0].end <= w[1].start),
            "rehash needs sorted disjoint dirty ranges; use rehash_unsorted",
        );
        match self {
            ColumnTree::List(t) => t.rehash(),
            ColumnTree::ProgressiveList(t) => t.rehash(),
        }
    }

    pub fn append_empty(&mut self) -> u32 {
        let idx = self.count() as u32;
        self.store_mut().count += 1;
        if self.count().div_ceil(C::VALS_PER_CHUNK) > self.format().data_capacity() {
            match self {
                ColumnTree::List(_) => {
                    debug_assert!(false, "append past leaf capacity — cap headroom exhausted")
                }
                ColumnTree::ProgressiveList(t) => t.append_progressive_segment(),
            }
        }

        let k = C::VALS_PER_CHUNK;
        let data_node = self.leaf_pos(idx as usize / k);
        debug_assert!(
            <C::Val>::lane(self.node(data_node), idx as usize % k) == C::Val::default(),
            "append over a non-zero leaf slot",
        );

        idx
    }
}

impl<C: ColumnSpec<Val = u64>> ColumnTree<C> {
    pub fn add_at(&mut self, idx: u32, delta: i64) {
        let k = C::VALS_PER_CHUNK as u32;
        let chunk = (idx / k) as usize;
        let data_node = self.leaf_pos(chunk);
        {
            let store = self.store_mut();
            debug_assert!(data_node < store.nodes.len(), "index out of range");
            let leaf = &mut store.nodes[data_node];
            let lane = (idx % k) as usize;
            let old = u64::lane(leaf, lane);
            let new = old.saturating_add_signed(delta);
            if new == old {
                return;
            }
            u64::set_lane(leaf, lane, new);
        }
        self.seed_write(chunk, data_node);
    }
}
