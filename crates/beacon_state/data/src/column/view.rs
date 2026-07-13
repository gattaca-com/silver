use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;

use super::{
    ColumnGroup, ColumnSpec, ColumnVal, pool::PagePool, snapshot::PageSnapshot, tree::ColumnTree,
};
use crate::{
    ring::Id,
    ssz_hash::{ZERO_HASHES, hash_concat, mix_in_length},
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

/// The node array a column read walks: the flat scratch (the live, still-
/// writable head — hot path) or a committed fork's paged snapshot. The read
/// algorithms (`get`/`iter`/`hash_root`/`write_ssz`) are written once here over
/// [`node`](Self::node); only node addressing differs between backings.
#[derive(Clone, Copy)]
enum Nodes<'a> {
    Flat(&'a ColumnTree),
    Paged(&'a PagePool, &'a PageSnapshot),
}

impl<'a> Nodes<'a> {
    #[inline]
    fn node(&self, n: usize) -> &B256 {
        match self {
            Nodes::Flat(t) => t.node(n),
            Nodes::Paged(pool, snap) => snap.node(pool, n),
        }
    }

    #[inline]
    fn count(&self) -> usize {
        match self {
            Nodes::Flat(t) => t.count(),
            Nodes::Paged(_, snap) => snap.len(),
        }
    }

    #[inline]
    fn max_elements(&self) -> usize {
        match self {
            Nodes::Flat(t) => t.max_elements(),
            Nodes::Paged(_, snap) => snap.max_elements(),
        }
    }

    #[inline]
    fn get<V: ColumnVal>(&self, i: usize) -> V {
        let k = V::VALS_PER_CHUNK;
        V::lane(self.node(self.max_elements() + i / k), i % k)
    }

    #[inline]
    fn iter<V: ColumnVal>(self) -> impl Iterator<Item = V> + 'a {
        (0..self.count()).map(move |i| self.get::<V>(i))
    }

    #[inline]
    fn hash_root<V: ColumnVal>(&self) -> B256 {
        let list_depth = (VALIDATOR_REGISTRY_LIMIT / V::VALS_PER_CHUNK).trailing_zeros();
        let mut root = *self.node(1);
        for h in self.max_elements().trailing_zeros()..list_depth {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, self.count())
    }

    fn write_ssz<V: ColumnVal, W: Write>(&self, w: &mut W) -> io::Result<()> {
        let (k, size) = (V::VALS_PER_CHUNK, size_of::<V>());
        let (full, rem) = (self.count() / k, self.count() % k);
        for chunk in 0..full {
            w.write_all(self.node(self.max_elements() + chunk))?;
        }
        if rem > 0 {
            w.write_all(&self.node(self.max_elements() + full)[..rem * size])?;
        }
        Ok(())
    }
}

/// Read handle over a fork's column: value reads (`get`/`iter`) plus the SSZ
/// list root, whether the fork is the live flat head or a committed paged
/// snapshot.
#[derive(Clone, Copy)]
pub struct ColumnReader<'a, C: ColumnSpec> {
    nodes: Nodes<'a>,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn flat(tree: &'a ColumnTree) -> Self {
        Self { nodes: Nodes::Flat(tree), _marker: PhantomData }
    }

    #[inline]
    pub(super) fn paged(pool: &'a PagePool, snap: &'a PageSnapshot) -> Self {
        Self { nodes: Nodes::Paged(pool, snap), _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.nodes.get::<C::Val>(ix)
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        self.nodes.iter::<C::Val>()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.nodes.hash_root::<C::Val>()
    }

    #[inline]
    pub(super) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.nodes.write_ssz::<C::Val, W>(w)
    }
}

/// Write handle over the flat scratch head. Values are written flat (fast
/// path); `commit` pages the result into the ring, sharing the parent's
/// unchanged pages.
pub struct ColumnWriteView<'a, C: ColumnSpec> {
    group: &'a mut ColumnGroup<C>,
    parent: Option<Id<ColumnGroup<C>>>,
    id: Id<ColumnGroup<C>>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(
        group: &'a mut ColumnGroup<C>,
        parent: Option<Id<ColumnGroup<C>>>,
        id: Id<ColumnGroup<C>>,
    ) -> Self {
        Self { group, parent, id }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.group.commit_scratch(self.id, self.parent);
        self.id
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.set_many(&[(idx, v)]);
    }

    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        self.group.scratch_mut().set_vals::<C::Val>(changes);
    }

    #[timed]
    pub fn rehash(&mut self) {
        self.group.scratch_mut().rehash();
    }

    #[inline]
    pub fn append_empty(&mut self) -> u32 {
        self.group.scratch_mut().append_empty::<C::Val>()
    }

    pub fn copy_changed_from<D: ColumnSpec<Val = C::Val>>(
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
        self.reader().iter()
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
