use std::marker::PhantomData;

use flux_profiler::timed;

use super::{ColumnGroup, ColumnSpec, ColumnVal, tree::ColumnTree};
use crate::{
    buffer::{Id, Slot},
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

pub struct ColumnReader<'a, C: ColumnSpec> {
    tree: &'a ColumnTree,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn new(tree: &'a ColumnTree) -> Self {
        Self { tree, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.tree.get::<C::Val>(ix)
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        self.tree.iter::<C::Val>()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        let list_depth = (VALIDATOR_REGISTRY_LIMIT / C::Val::VALS_PER_CHUNK).trailing_zeros();
        self.tree.hash_root(list_depth)
    }
}

pub struct ColumnWriteView<'a, C: ColumnSpec> {
    tree: Slot<'a, ColumnGroup<C>, ColumnTree>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(tree: Slot<'a, ColumnGroup<C>, ColumnTree>) -> Self {
        Self { tree }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.tree.commit()
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.set_many(&[(idx, v)]);
    }

    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        self.tree.set_vals::<C::Val>(changes);
    }

    #[inline]
    pub fn append(&mut self, v: C::Val) -> u32 {
        self.tree.append(v)
    }

    #[inline]
    pub fn reader(&self) -> ColumnReader<'_, C> {
        ColumnReader::new(&self.tree)
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
