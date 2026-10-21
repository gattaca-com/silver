use flux_profiler::timed;

use crate::{
    FlatTree, TreeSpec,
    single_owner::pool::PagePool,
    storage::{PageId, PageTable},
};

/// A committed fork's tree in a [`PagePool`].
///
/// Ownership: the base owns every page reachable from its roots, and a fork
/// owns exactly its `allocated` pages.
#[derive(Default)]
pub struct PageSnapshot {
    table: PageTable,
    /// `(flat-tree node in slot 1, page)` per page this commit allocated.
    allocated: Vec<(u32, PageId)>,
}

impl PageSnapshot {
    /// `tree` committed as a base: it owns every page.
    #[timed]
    pub fn from_tree<C: TreeSpec>(tree: &mut FlatTree<C>, pool: &mut PagePool<C::Page>) -> Self {
        let mut snapshot = Self::default();
        tree.commit(pool, &mut snapshot.table, None, None);
        snapshot
    }

    /// Commit `tree` over `parent`, owning the pages it allocates.
    pub fn commit<C: TreeSpec>(
        &mut self,
        tree: &mut FlatTree<C>,
        pool: &mut PagePool<C::Page>,
        parent: &PageSnapshot,
    ) {
        debug_assert!(!self.owns_pages(), "recycled slot still owns pages: not released");
        tree.commit(pool, &mut self.table, Some(&parent.table), Some(&mut self.allocated));
    }

    #[inline]
    pub fn table(&self) -> &PageTable {
        &self.table
    }

    #[inline]
    pub fn owns_pages(&self) -> bool {
        !self.allocated.is_empty()
    }

    /// Only correct when the original is retired and never released: ownership
    /// of its allocated pages moves to the copy.
    pub fn clone_for_grow(&self) -> Self {
        Self { table: self.table.clone(), allocated: self.allocated.clone() }
    }

    /// Make this base `winner`'s tree, freeing the base pages the winner does
    /// not share.
    pub fn promote<C: TreeSpec>(&mut self, pool: &mut PagePool<C::Page>, winner: &PageSnapshot) {
        let same_format = self.table.format() == winner.table.format();
        for (s, sub) in self.table.format().subtrees::<C>().enumerate() {
            let new = winner.table.roots().get(s).copied().filter(|_| same_format);
            pool.free_unshared::<C>(sub, sub.root::<C>(), self.table.roots()[s], new);
        }
        self.table.clone_from(&winner.table);
    }

    /// Free this fork's allocated pages, except those `base` holds. Idempotent,
    /// as it clears `allocated`; `roots` stay, so racing readers stay in
    /// bounds.
    pub fn release<C: TreeSpec>(&mut self, pool: &mut PagePool<C::Page>, base: &PageSnapshot) {
        let same_format = self.table.format() == base.table.format();
        for &(n, id) in &self.allocated {
            if !same_format || base.table.page_of::<C>(pool, n as usize).0 != id {
                pool.free(id);
            }
        }
        self.allocated.clear();
    }
}
