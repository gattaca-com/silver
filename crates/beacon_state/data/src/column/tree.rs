use flux_profiler::timed;
use silver_ssz::scalar::SszScalar;

use super::{
    ColumnSpec, format::TreeFormat, list::ListTree, pool::PagePool,
    progressive_list::ProgressiveListTree, snapshot::PageSnapshot, store::NodeStore,
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
    pub(super) fn node(&self, n: usize) -> &B256 {
        &self.store().nodes[n]
    }

    /// Load `target`'s content, switching tree variant if its format differs.
    /// `loaded` is the snapshot our content already matches, so only
    /// mismatched or dirtied pages get copied.
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
        self.store_mut().load(pool, loaded, target);
    }

    #[timed]
    pub(super) fn to_snapshot(&mut self, pool: &mut PagePool<C::Page>) -> PageSnapshot {
        let mut snapshot = PageSnapshot::default();
        self.commit(pool, &mut snapshot, None);
        snapshot.allocated.clear();
        snapshot
    }

    pub(super) fn commit(
        &mut self,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: Option<&PageSnapshot>,
    ) {
        let format = self.format();
        self.store_mut().commit(format, pool, dst, parent);
    }

    pub(super) fn copy_from<D>(&mut self, src: &ColumnTree<D>)
    where
        D: ColumnSpec<Val = C::Val, Page = C::Page>,
    {
        debug_assert_eq!(self.format(), src.format(), "rotate needs a same-format source");
        debug_assert_eq!(self.count(), src.count(), "rotate needs a same-length source");
        let store = self.store_mut();
        store.nodes.copy_from_slice(&src.store().nodes);
        store.writes.mark_all_hashed();
    }

    pub fn fill_zero(&mut self) {
        match self {
            ColumnTree::List(t) => t.fill_zero(),
            ColumnTree::ProgressiveList(t) => t.fill_zero(),
        }
        let writes = &mut self.store_mut().writes;
        writes.clear();
        writes.mark_all_hashed();
    }

    pub fn iter_vals(&self) -> impl Iterator<Item = C::Val> + '_ {
        let sz = size_of::<C::Val>();
        let count = self.count();
        let data_start = self.format().data_start::<C>();
        let bytes = &self.store().nodes[data_start..].as_flattened()[..count * sz];
        (0..count).map(move |i| {
            let mut out = [C::Val::default()];
            <C::Val>::read_ssz_slice(&mut out, &bytes[i * sz..i * sz + sz]);
            out[0]
        })
    }

    pub fn set_val(&mut self, idx: u32, v: C::Val) {
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
        self.store_mut().writes.mark(chunk);
    }

    #[inline]
    pub(super) fn has_pending_rehash(&self) -> bool {
        self.store().writes.has_unhashed()
    }

    #[timed]
    pub fn rehash(&mut self) {
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
                ColumnTree::List(t) => t.grow_one(),
                ColumnTree::ProgressiveList(t) => t.grow_one(),
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
        self.store_mut().writes.mark(chunk);
    }
}
