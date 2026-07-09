use super::pool::{PAGE_NODES, PageId, PagePool};
use crate::types::B256;

/// A committed fork's whole column tree as a page table: `pages[i]` is the pool
/// id of node-page `i`. Built and read by
/// [`ColumnTree`](super::tree::ColumnTree) (the data), shared/released by
/// [`PagePool`](PagePool) (the refcounts).
#[derive(Default)]
pub struct PageSnapshot {
    pub(super) pages: Vec<PageId>,
    pub(super) max_elements: usize,
    pub(super) count: usize,
}

impl PageSnapshot {
    #[inline]
    pub(super) fn is_released(&self) -> bool {
        self.pages.is_empty()
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub(super) fn max_elements(&self) -> usize {
        self.max_elements
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
