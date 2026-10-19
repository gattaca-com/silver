use std::ops::Deref;

use flux_profiler::timed;
use silver_hashing::{FlatTree, PagePool, PageSnapshot, TreeReader};

use super::{TreeGroup, TreeSpec};
use crate::{ring::Id, types::B256};

/// A read over a group's pool. A local type, so groups add their own reads
/// (`at_slot`, `at_epoch`).
pub struct TreeView<'a, C: TreeSpec>(TreeReader<'a, C>);

// Derived by hand: `#[derive]` would demand `C: Clone + Copy`.
impl<C: TreeSpec> Clone for TreeView<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: TreeSpec> Copy for TreeView<'_, C> {}

impl<'a, C: TreeSpec> TreeView<'a, C> {
    #[inline]
    pub(super) fn flat(tree: &'a FlatTree<C>) -> Self {
        Self(TreeReader::flat(tree))
    }

    #[inline]
    pub(super) fn paged(pool: &'a PagePool<C::Page>, snapshot: &'a PageSnapshot) -> Self {
        Self(TreeReader::paged(pool, snapshot))
    }
}

impl<'a, C: TreeSpec> Deref for TreeView<'a, C> {
    type Target = TreeReader<'a, C>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Writes into the group's flat tree. `commit` pages the result into the
/// ring, sharing the parent's unchanged pages.
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
    pub fn reader(&self) -> TreeView<'_, C> {
        TreeView::flat(self.group.tree())
    }

    pub fn hashed_reader(&mut self) -> TreeView<'_, C> {
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
