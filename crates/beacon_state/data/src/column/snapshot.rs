use super::{
    ColumnSpec,
    format::TreeFormat,
    page_format::Subtree,
    pool::{PageId, PagePool},
};
use crate::types::B256;

/// A committed fork's column tree: one root page per subtree. A page id names
/// its whole subtree, so forks share every page they did not write.
///
/// Ownership: the base owns every page reachable from its roots, and a fork
/// owns exactly its `allocated` pages.
#[derive(Default)]
pub struct PageSnapshot {
    pub(super) roots: Vec<PageId>,
    /// `(flat-tree node in slot 1, page)` per page this commit allocated.
    pub(super) allocated: Vec<(u32, PageId)>,
    pub(super) format: TreeFormat,
    pub(super) count: usize,
}

impl PageSnapshot {
    /// Only correct during the ring's copy-grow: the original is retired and
    /// never released, so ownership of its allocated pages moves to the copy.
    pub(super) fn clone_for_grow(&self) -> Self {
        Self { roots: self.roots.clone(), allocated: self.allocated.clone(), ..*self }
    }

    /// Take `src`'s content without taking ownership of any page.
    pub(super) fn mirror(&mut self, src: &PageSnapshot) {
        self.roots.clone_from(&src.roots);
        self.format = src.format;
        self.count = src.count;
    }

    /// Forget the mirrored content, so a load against this copies every page.
    pub(super) fn unmirror(&mut self) {
        self.roots.clear();
    }

    #[inline]
    pub(super) fn same_pages(&self, other: &PageSnapshot) -> bool {
        self.format == other.format && self.roots == other.roots
    }

    /// Make this base `winner`'s tree, freeing the base pages the winner does
    /// not share.
    pub(super) fn promote<C: ColumnSpec>(
        &mut self,
        pool: &mut PagePool<C::Page>,
        winner: &PageSnapshot,
    ) {
        let same_format = self.format == winner.format;
        for (s, sub) in self.format.subtrees::<C>().enumerate() {
            let new = winner.roots.get(s).copied().filter(|_| same_format);
            pool.free_unshared::<C>(sub, sub.root::<C>(), self.roots[s], new);
        }
        self.mirror(winner);
    }

    /// Free this fork's allocated pages, except those `base` holds. Idempotent,
    /// as it clears `allocated`; `roots` stay, so racing readers stay in
    /// bounds.
    pub(super) fn release<C: ColumnSpec>(
        &mut self,
        pool: &mut PagePool<C::Page>,
        base: &PageSnapshot,
    ) {
        let same_format = self.format == base.format;
        for &(n, id) in &self.allocated {
            if !same_format || base.page_of::<C>(pool, n as usize).0 != id {
                pool.free(id);
            }
        }
        self.allocated.clear();
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        self.format
    }

    #[inline]
    pub(super) fn node<'a, C: ColumnSpec>(
        &self,
        pool: &'a PagePool<C::Page>,
        n: usize,
    ) -> &'a B256 {
        let (id, slot) = self.page_of::<C>(pool, n);
        &pool.page(id)[slot]
    }

    /// The page holding flat-tree node `n`, and its slot there.
    #[inline]
    fn page_of<C: ColumnSpec>(&self, pool: &PagePool<C::Page>, n: usize) -> (PageId, usize) {
        let (s, level, pos) = self.format.locate::<C>(n);
        let (children, slot) = Subtree::of::<C>(self.format, s).path_to::<C>(level, pos);
        let root = self.roots.get(s).copied().unwrap_or(0);
        (children.fold(root, |id, j| pool.child(id, j)), slot)
    }
}
