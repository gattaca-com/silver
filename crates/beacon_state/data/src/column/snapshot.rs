use super::{
    ColumnSpec,
    format::TreeFormat,
    pool::{PageArray, PageId, PagePool},
};
use crate::types::B256;

/// A committed fork's whole column tree as a page table: `pages[i]` is the pool
/// id of node-page `i`.
pub struct PageSnapshot {
    pub(super) pages: Vec<PageId>,
    pub(super) format: TreeFormat,
    pub(super) count: usize,
    pub(super) is_released: bool,
}

impl PageSnapshot {
    #[inline]
    pub(super) fn new_released() -> Self {
        Self { pages: Vec::new(), format: TreeFormat::default(), count: 0, is_released: true }
    }

    /// Copy that points at the same pool pages without bumping their
    /// refcounts. This is only correct during the ring's copy-grow: the
    /// original is retired and never released again, so the pages' single
    /// reference effectively moves over to the copy.
    pub(super) fn clone_for_grow(&self) -> Self {
        Self {
            pages: self.pages.clone(),
            format: self.format,
            count: self.count,
            is_released: self.is_released,
        }
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
    pub(super) fn num_pages(&self) -> usize {
        self.pages.len()
    }

    #[inline]
    pub(super) fn page<'a, P: PageArray>(&self, pool: &'a PagePool<P>, pi: usize) -> &'a [B256] {
        pool.page(self.pages[pi])
    }

    #[inline]
    pub(super) fn node<'a, C: ColumnSpec>(
        &self,
        pool: &'a PagePool<C::Page>,
        n: usize,
    ) -> &'a B256 {
        let p = C::PAGE_NODES;
        &pool.page(self.pages[n / p])[n % p]
    }
}
