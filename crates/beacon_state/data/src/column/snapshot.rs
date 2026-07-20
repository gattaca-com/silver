use super::{
    format::TreeFormat,
    pool::{PAGE_NODES, PageId, PagePool},
};
use crate::types::B256;

/// A committed fork's whole column tree as a page table: `pages[i]` is the pool
/// id of node-page `i`. Built and read by
/// [`ColumnTree`](super::tree::ColumnTree) (the data), shared/released by
/// [`PagePool`](PagePool) (the refcounts).
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
    pub(super) fn page<'a>(&self, pool: &'a PagePool, pi: usize) -> &'a [B256] {
        pool.page(self.pages[pi])
    }

    #[inline]
    pub(super) fn node<'a>(&self, pool: &'a PagePool, n: usize) -> &'a B256 {
        &pool.page(self.pages[n / PAGE_NODES])[n % PAGE_NODES]
    }
}
