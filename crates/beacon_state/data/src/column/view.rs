use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;
use silver_ssz::scalar::SszScalar;

use super::{
    ColumnGroup, ColumnSpec, format::TreeFormat, pool::PagePool, snapshot::PageSnapshot,
    tree::ColumnTree,
};
use crate::{ring::Id, types::B256};

/// The node array a column read walks: the flat scratch (the live, still-
/// writable head — hot path) or a committed fork's paged snapshot. The read
/// algorithms (`get`/`iter`/`hash_root`/`write_ssz`) are written once here over
/// [`node`](Self::node); only node addressing differs between backings.
enum Nodes<'a, C: ColumnSpec> {
    Flat(&'a ColumnTree<C>),
    Paged(&'a PagePool<C::Page>, &'a PageSnapshot),
}

// Derived by hand: `#[derive]` would demand `C: Clone + Copy`, and a column
// marker is a zero-sized tag that need not be either.
impl<C: ColumnSpec> Clone for Nodes<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ColumnSpec> Copy for Nodes<'_, C> {}

impl<'a, C: ColumnSpec> Nodes<'a, C> {
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
pub struct ColumnReader<'a, C: ColumnSpec> {
    nodes: Nodes<'a, C>,
    /// Resolved once at construction so per-element reads pay a single
    /// layout match.
    format: TreeFormat,
    _marker: PhantomData<fn() -> C>,
}

// By hand for the same reason as `Nodes`.
impl<C: ColumnSpec> Clone for ColumnReader<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ColumnSpec> Copy for ColumnReader<'_, C> {}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn flat(tree: &'a ColumnTree<C>) -> Self {
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

    #[inline]
    pub(super) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let (k, size) = (C::VALS_PER_CHUNK, size_of::<C::Val>());
        let (full, rem) = (self.nodes.count() / k, self.nodes.count() % k);
        for chunk in 0..full {
            w.write_all(self.nodes.node(self.leaf_pos(chunk)))?;
        }
        if rem > 0 {
            w.write_all(&self.nodes.node(self.leaf_pos(full))[..rem * size])?;
        }
        Ok(())
    }
}

/// Write handle over the flat scratch head. Values are written flat (fast
/// path); `commit` pages the result into the ring, sharing the parent's
/// unchanged pages.
pub struct ColumnWriteView<'a, C: ColumnSpec> {
    group: &'a mut ColumnGroup<C>,
    parent: Option<Id<ColumnGroup<C>>>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(group: &'a mut ColumnGroup<C>, parent: Option<Id<ColumnGroup<C>>>) -> Self {
        Self { group, parent }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.group.commit_scratch(self.parent)
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.set_many(&[(idx, v)]);
    }

    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        self.group.scratch_mut().set_vals(changes);
    }

    /// Write without rehashing; the owner must call
    /// [`rehash_unsorted`](Self::rehash_unsorted) before reading the root or
    /// committing.
    #[inline]
    pub fn set_deferred(&mut self, idx: u32, v: C::Val) {
        self.group.scratch_mut().set_val_deferred(idx, v);
    }

    #[timed]
    pub fn rehash(&mut self) {
        self.group.scratch_mut().rehash();
    }

    #[timed]
    pub fn rehash_unsorted(&mut self) {
        self.group.scratch_mut().rehash_unsorted();
    }

    #[inline]
    pub fn append_empty(&mut self) -> u32 {
        debug_assert!(C::IS_LIST, "a vector column has fixed length");
        self.group.scratch_mut().append_empty()
    }

    pub fn copy_changed_from<D: ColumnSpec<Val = C::Val, Page = C::Page>>(
        &mut self,
        other: &ColumnWriteView<'_, D>,
    ) {
        let src = other.group.scratch();
        self.group.scratch_mut().copy_changed_pages_from(src);
    }

    #[inline]
    pub fn clear_to_zero(&mut self) {
        self.group.scratch_mut().fill_zero();
    }

    #[timed]
    pub fn migrate_to_progressive(&mut self) {
        debug_assert!(C::IS_LIST, "vectors are fork-invariant under EIP-7688");
        self.group.scratch_mut().migrate_to_progressive();
    }

    #[inline]
    pub fn reader(&self) -> ColumnReader<'_, C> {
        ColumnReader::flat(self.group.scratch())
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = C::Val> + '_ {
        self.group.scratch().iter_vals()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.reader().hash_root()
    }
}

impl<C: ColumnSpec<Val = u64>> ColumnWriteView<'_, C> {
    #[inline]
    pub fn add_at(&mut self, idx: u32, delta: i64) {
        self.group.scratch_mut().add_at(idx, delta);
    }
}
