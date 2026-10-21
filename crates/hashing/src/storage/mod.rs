mod table;

use std::{iter, slice};

use bytesize::ByteSize;
pub use table::PageTable;

use crate::{B256, merkle::ZERO_HASHES};

pub type PageId = u32;

pub(crate) const SEGMENT_BYTES: usize = ByteSize::mib(1).as_u64() as usize;

/// Pages of `page_len` nodes per segment.
pub(crate) const fn segment_pages(page_len: usize) -> usize {
    let page_bytes = page_len * size_of::<B256>();
    assert!(page_bytes <= SEGMENT_BYTES, "a page must fit in one segment");
    let pages = SEGMENT_BYTES / page_bytes;
    assert!(pages.is_power_of_two(), "segment pages must be a power of two");
    pages
}

/// Fill a fresh page's rows from slot 1 on.
#[inline]
pub(crate) fn write_rows<'a>(mut page: &mut [B256], rows: impl Iterator<Item = &'a [B256]>) {
    for row in rows {
        page[..row.len()].copy_from_slice(row);
        page = &mut page[row.len()..];
    }
}

/// The all-zero subtree's page per depth, like `ZERO_HASHES`. Pages are cut
/// from the leaves up, so a depth fixes the row count and whether the page has
/// children, which are zero pages themselves.
pub(crate) fn zero_pages<P: PageArray>(alloc: &mut impl PageAlloc) -> [PageId; ZERO_HASHES.len()] {
    let levels_per_page = P::LEN.trailing_zeros() as usize;
    let mut pages = [0; ZERO_HASHES.len()];
    for depth in 0..pages.len() {
        let rows = depth % levels_per_page + 1;
        let hashes = (0..rows)
            .flat_map(|r| iter::repeat_n(slice::from_ref(&ZERO_HASHES[depth - r]), 1 << r));
        let children = if depth < levels_per_page { 0 } else { 1 << rows };
        let id = alloc.alloc(children, hashes);
        for j in 0..children {
            let child = pages[depth - rows];
            alloc.reuse(child);
            alloc.set_child(id, j, child);
        }
        pages[depth] = id;
    }
    pages
}

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

/// What one commit needs from storage. Every page the new tree holds comes
/// from exactly one of `alloc`, `reuse` or `zero_page`.
pub trait PageAlloc: PageStore {
    /// A new page holding `rows` from slot 1 on.
    fn alloc<'a>(&mut self, children: usize, rows: impl Iterator<Item = &'a [B256]>) -> PageId;
    fn set_child(&mut self, id: PageId, j: usize, child: PageId);
    /// Reuses `id`'s whole subtree too.
    fn reuse(&mut self, id: PageId);
    /// The page of an all-zero subtree of merkle depth `depth`.
    fn zero_page(&mut self, depth: u32) -> PageId;
}
