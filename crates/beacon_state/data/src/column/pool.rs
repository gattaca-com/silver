use std::{iter, marker::PhantomData, slice};

use bytesize::ByteSize;

use super::{
    ColumnSpec,
    page_format::{PagePos, Subtree},
};
use crate::{
    merkle::{ZERO_HASHES, ZERO_HASHES_LEN},
    types::B256,
};

pub type PageId = u32;

/// A column's page, carried as a type rather than a `const PAGE_NODES` because
/// an associated const may not be an array length in a generic context
/// (`error: generic parameters may not be used in const operations`).
pub trait PageArray: 'static {
    const LEN: usize;
    /// What a racing reader sees for an id the pool can't resolve yet; the
    /// seqlock retry discards the read.
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

const SEGMENT_BYTES: usize = ByteSize::mib(1).as_u64() as usize;
const MAX_POOL_BYTES: usize = ByteSize::gib(4).as_u64() as usize;

/// Reserved up front, so the segment list a reader indexes never moves.
const MAX_SEGMENTS: usize = MAX_POOL_BYTES / SEGMENT_BYTES;

/// `SEGMENT_BYTES` of pages of one kind, fixed when the segment is created:
///
/// - with children: pages above the bottom page level, each with `P::LEN` child
///   ids in `children_pages`;
/// - without children: bottom-level pages, which hold the leaves;
///   `children_pages` stays empty.
///
/// Allocated zeroed at full size, so neither buffer moves under a reader.
struct Segment {
    page_data: Box<[B256]>,
    children_pages: Box<[PageId]>,
    used: usize,
}

pub(super) struct PagePool<P: PageArray> {
    segments: Vec<Segment>,
    /// Freed ids per segment kind: `[without children, with children]`.
    free: [Vec<PageId>; 2],
    /// The segment each kind takes fresh ids from, indexed as `free`.
    filling: [Option<usize>; 2],
    /// The all-zero subtree's page per depth, like `ZERO_HASHES`. Never freed:
    /// no fork owns it.
    zero_pages: [PageId; ZERO_HASHES_LEN],
    _page: PhantomData<fn() -> P>,
}

impl<P: PageArray> PagePool<P> {
    const SEGMENT_PAGES: usize = {
        let page_bytes = P::LEN * size_of::<B256>();
        assert!(page_bytes <= SEGMENT_BYTES, "PagePool: a page must fit in one segment");
        let pages = SEGMENT_BYTES / page_bytes;
        assert!(pages.is_power_of_two(), "PagePool: segment pages must be a power of two");
        pages
    };

    pub(super) fn new() -> Self {
        let mut pool = Self {
            segments: Vec::with_capacity(MAX_SEGMENTS),
            free: [Vec::new(), Vec::new()],
            filling: [None, None],
            zero_pages: [0; ZERO_HASHES_LEN],
            _page: PhantomData,
        };
        for depth in 0..ZERO_HASHES_LEN {
            pool.zero_pages[depth] = pool.alloc_zero(depth);
        }
        pool
    }

    /// Pages are cut from the leaves up, so `depth` fixes the row count and
    /// whether the page has children, which are zero pages themselves.
    fn alloc_zero(&mut self, depth: usize) -> PageId {
        let levels_per_page = P::LEN.trailing_zeros() as usize;
        let rows = depth % levels_per_page + 1;
        let hashes = (0..rows)
            .flat_map(|r| iter::repeat_n(slice::from_ref(&ZERO_HASHES[depth - r]), 1 << r));
        let children = if depth < levels_per_page { 0 } else { 1 << rows };
        let id = self.alloc(children, hashes);
        for j in 0..children {
            self.set_child(id, j, self.zero_pages[depth - rows]);
        }
        id
    }

    #[inline]
    pub(super) fn zero_page(&self, depth: u32) -> PageId {
        self.zero_pages[depth as usize]
    }

    #[inline]
    pub(super) fn alloc<'a>(
        &mut self,
        children: usize,
        rows: impl Iterator<Item = &'a [B256]>,
    ) -> PageId {
        let inner = children != 0;
        let id = match self.free[inner as usize].pop() {
            Some(id) => id,
            None => self.fresh_id(inner),
        };
        let (segment, i) = Self::split(id);
        let mut page = &mut self.segments[segment].page_data[i * P::LEN + 1..];
        for row in rows {
            page[..row.len()].copy_from_slice(row);
            page = &mut page[row.len()..];
        }
        id
    }

    fn fresh_id(&mut self, inner: bool) -> PageId {
        let segment = match self.filling[inner as usize] {
            Some(s) if self.segments[s].used < Self::SEGMENT_PAGES => s,
            _ => self.push_segment(inner),
        };
        let used = &mut self.segments[segment].used;
        *used += 1;
        (segment * Self::SEGMENT_PAGES + *used - 1) as PageId
    }

    fn push_segment(&mut self, inner: bool) -> usize {
        assert!(self.segments.len() < MAX_SEGMENTS, "PagePool: exceeds MAX_POOL_BYTES");
        let child_slots = if inner { Self::SEGMENT_PAGES * P::LEN } else { 0 };
        self.segments.push(Segment {
            page_data: vec![[0u8; 32]; Self::SEGMENT_PAGES * P::LEN].into_boxed_slice(),
            children_pages: vec![0; child_slots].into_boxed_slice(),
            used: 0,
        });
        self.filling[inner as usize] = Some(self.segments.len() - 1);
        self.segments.len() - 1
    }

    #[inline]
    pub(super) fn free(&mut self, id: PageId) {
        let inner = !self.segments[Self::split(id).0].children_pages.is_empty();
        self.free[inner as usize].push(id);
    }

    /// Free `old`'s pages down to where they meet `new`'s. Zero pages are the
    /// pool's, never a fork's.
    pub(super) fn free_unshared<C: ColumnSpec<Page = P>>(
        &mut self,
        sub: Subtree,
        at: PagePos,
        old: PageId,
        new: Option<PageId>,
    ) {
        if new == Some(old) || old == self.zero_page(sub.depth::<C>(at)) {
            return;
        }
        self.free(old);
        for j in 0..sub.child_count::<C>(at) {
            let new = new.map(|new| self.child(new, j));
            self.free_unshared::<C>(sub, sub.child::<C>(at, j), self.child(old, j), new);
        }
    }

    #[inline]
    fn split(id: PageId) -> (usize, usize) {
        let id = id as usize;
        (id / Self::SEGMENT_PAGES, id % Self::SEGMENT_PAGES)
    }

    #[inline]
    pub(super) fn page(&self, id: PageId) -> &[B256] {
        let (segment, i) = Self::split(id);
        self.segments
            .get(segment)
            .and_then(|s| s.page_data.get(i * P::LEN..(i + 1) * P::LEN))
            .unwrap_or(P::UNRESOLVED)
    }

    #[inline]
    pub(super) fn child(&self, id: PageId, j: usize) -> PageId {
        let (segment, i) = Self::split(id);
        self.segments
            .get(segment)
            .and_then(|s| s.children_pages.get(i * P::LEN + j))
            .copied()
            .unwrap_or(0)
    }

    #[inline]
    pub(super) fn set_child(&mut self, id: PageId, j: usize, child: PageId) {
        let (segment, i) = Self::split(id);
        self.segments[segment].children_pages[i * P::LEN + j] = child;
    }
}

#[cfg(test)]
mod tests;
