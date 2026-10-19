use std::marker::PhantomData;

use flux_profiler::timed;
use silver_ssz::scalar::SszScalar;

use super::{
    TreeGroup, TreeSpec, flat::FlatTree, format::TreeFormat, pool::PagePool, snapshot::PageSnapshot,
};
use crate::{ring::Id, types::B256};

/// The node array a column read walks: the flat tree (the live, still-
/// writable head — hot path) or a committed fork's paged snapshot. The read
/// algorithms (`get`/`hash_root`) are written once here over
/// [`node`](Self::node); only node addressing differs between backings.
enum Nodes<'a, C: TreeSpec> {
    Flat(&'a FlatTree<C>),
    Paged(&'a PagePool<C::Page>, &'a PageSnapshot),
}

// Derived by hand: `#[derive]` would demand `C: Clone + Copy`, and a column
// marker is a zero-sized tag that need not be either.
impl<C: TreeSpec> Clone for Nodes<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: TreeSpec> Copy for Nodes<'_, C> {}

impl<'a, C: TreeSpec> Nodes<'a, C> {
    #[inline]
    fn node(&self, n: usize) -> &B256 {
        match self {
            Nodes::Flat(t) => t.node(n),
            Nodes::Paged(pool, snap) => snap.node::<C>(pool, n),
        }
    }

    #[inline]
    fn count(&self) -> usize {
        match self {
            Nodes::Flat(t) => t.count(),
            Nodes::Paged(_, snap) => snap.len(),
        }
    }
}

/// Read handle over a fork's column: value reads (`get`/`iter`) plus the SSZ
/// list root, whether the fork is the live flat head or a committed paged
/// snapshot.
pub struct TreeReader<'a, C: TreeSpec> {
    nodes: Nodes<'a, C>,
    /// Resolved once at construction so per-element reads pay a single
    /// layout match.
    format: TreeFormat,
    _marker: PhantomData<fn() -> C>,
}

// By hand for the same reason as `Nodes`.
impl<C: TreeSpec> Clone for TreeReader<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: TreeSpec> Copy for TreeReader<'_, C> {}

impl<'a, C: TreeSpec> TreeReader<'a, C> {
    #[inline]
    pub(super) fn flat(tree: &'a FlatTree<C>) -> Self {
        Self { nodes: Nodes::Flat(tree), format: tree.format(), _marker: PhantomData }
    }

    #[inline]
    pub(super) fn paged(pool: &'a PagePool<C::Page>, snap: &'a PageSnapshot) -> Self {
        Self { nodes: Nodes::Paged(pool, snap), format: snap.format(), _marker: PhantomData }
    }

    #[inline]
    fn leaf_pos(&self, chunk: usize) -> usize {
        self.format.leaf_pos::<C>(chunk)
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        let k = C::VALS_PER_CHUNK;
        <C::Val>::lane(self.nodes.node(self.leaf_pos(ix / k)), ix % k)
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        if let Nodes::Flat(t) = self.nodes {
            debug_assert!(!t.has_pending_rehash(), "deferred writes not rehashed before root");
        }
        self.format.hash_root::<C>(self.nodes.count(), |n| *self.nodes.node(n))
    }
}

/// Write handle over the flat tree. Values are written flat (fast
/// path); `commit` pages the result into the ring, sharing the parent's
/// unchanged pages.
pub struct TreeWriteView<'a, C: TreeSpec> {
    group: &'a mut TreeGroup<C>,
    parent: Option<Id<TreeGroup<C>>>,
}

impl<'a, C: TreeSpec> TreeWriteView<'a, C> {
    #[inline]
    pub(super) fn new(group: &'a mut TreeGroup<C>, parent: Option<Id<TreeGroup<C>>>) -> Self {
        Self { group, parent }
    }

    #[inline]
    pub fn commit(self) -> Id<TreeGroup<C>> {
        self.group.commit_writer(self.parent)
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.group.tree_mut().set_val(idx, v);
    }

    #[inline]
    pub fn append_empty(&mut self) -> u32 {
        debug_assert!(C::IS_LIST, "a vector tree has fixed length");
        self.group.tree_mut().append_empty()
    }

    pub fn copy_from<D: TreeSpec<Val = C::Val, Page = C::Page>>(
        &mut self,
        other: &mut TreeWriteView<'_, D>,
    ) {
        other.group.tree_mut().rehash();
        self.group.tree_mut().copy_from(other.group.tree());
    }

    #[inline]
    pub fn clear_to_zero(&mut self) {
        self.group.tree_mut().fill_zero();
    }

    #[timed]
    pub fn migrate_to_progressive(&mut self) {
        debug_assert!(C::IS_LIST, "vectors are fork-invariant under EIP-7688");
        self.group.tree_mut().migrate_to_progressive();
    }

    #[inline]
    pub fn reader(&self) -> TreeReader<'_, C> {
        TreeReader::flat(self.group.tree())
    }

    pub fn hashed_reader(&mut self) -> TreeReader<'_, C> {
        self.group.tree_mut().rehash();
        self.reader()
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = C::Val> + '_ {
        self.group.tree().iter_vals()
    }

    #[inline]
    pub fn hash_root(&mut self) -> B256 {
        self.hashed_reader().hash_root()
    }
}

impl<C: TreeSpec<Val = u64>> TreeWriteView<'_, C> {
    #[inline]
    pub fn add_at(&mut self, idx: u32, delta: i64) {
        self.group.tree_mut().add_at(idx, delta);
    }
}
