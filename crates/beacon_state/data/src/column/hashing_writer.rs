use super::{ColumnSpec, pool::PagePool, snapshot::PageSnapshot, tree::ColumnTree};

/// A flat writable copy of one fork. `mirror` is what `tree` holds outside its
/// dirty pages, so a load copies only the pages that differ. It keeps its own
/// refcounts, so finalize releasing the mirrored fork doesn't invalidate it.
pub(super) struct HashingWriter<C: ColumnSpec> {
    tree: ColumnTree<C>,
    mirror: PageSnapshot,
}

impl<C: ColumnSpec> HashingWriter<C> {
    /// The writer, and `tree` committed as the base it mirrors.
    pub(super) fn new(tree: ColumnTree<C>, pool: &mut PagePool<C::Page>) -> (Self, PageSnapshot) {
        let base = tree.to_snapshot(pool);
        let mut mirror = PageSnapshot::new_released();
        pool.share_into(&mut mirror, &base);
        (Self { tree, mirror }, base)
    }

    #[inline]
    pub(super) fn tree(&self) -> &ColumnTree<C> {
        &self.tree
    }

    #[inline]
    pub(super) fn tree_mut(&mut self) -> &mut ColumnTree<C> {
        &mut self.tree
    }

    pub(super) fn load(&mut self, pool: &mut PagePool<C::Page>, target: &PageSnapshot) {
        self.tree.load(pool, &self.mirror, target);
        pool.share_into(&mut self.mirror, target);
    }

    pub(super) fn commit(
        &mut self,
        pool: &mut PagePool<C::Page>,
        dst: &mut PageSnapshot,
        parent: &PageSnapshot,
    ) {
        self.tree.commit_into(pool, dst, parent);
        pool.share_into(&mut self.mirror, dst);
        self.tree.reset_dirty_mask();
    }
}
