mod table;

pub use table::PageTable;

use crate::B256;

pub type PageId = u32;

/// A list's page, carried as a type rather than a `const PAGE_NODES` because
/// an associated const may not be an array length in a generic context
/// (`error: generic parameters may not be used in const operations`).
pub trait PageArray: 'static {
    const LEN: usize;
    /// What a racing reader sees for an id the pool can't resolve yet; its
    /// retry discards the read.
    const UNRESOLVED: &'static [B256];
}

impl<const N: usize> PageArray for [B256; N] {
    /// The check sits inside the value so any use of `LEN` const-evals it —
    /// an assert in its own associated const is never evaluated unless forced.
    /// Power-of-two keeps page-relative `/` and `%` folding to shift/mask.
    const LEN: usize = {
        assert!(N.is_power_of_two(), "PageArray: page size must be a power of two");
        N
    };
    const UNRESOLVED: &'static [B256] = &[[0u8; 32]; N];
}

/// Committed pages, as loads and readers see them. Both methods are total: a
/// stale or freed id yields some page and some child, never a panic, so an
/// optimistic reader can race a writer and retry on its own version check.
pub trait PageStore {
    fn page(&self, id: PageId) -> &[B256];
    fn child(&self, id: PageId, j: usize) -> PageId;
}

/// What one commit needs from storage.
pub trait PageAlloc: PageStore {
    /// A new page holding `rows` from slot 1 on.
    fn alloc<'a>(&mut self, children: usize, rows: impl Iterator<Item = &'a [B256]>) -> PageId;
    fn set_child(&mut self, id: PageId, j: usize, child: PageId);
    /// The page of an all-zero subtree of merkle depth `depth`.
    fn zero_page(&mut self, depth: u32) -> PageId;
}
