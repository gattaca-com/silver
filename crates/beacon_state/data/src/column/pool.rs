use std::marker::PhantomData;

use bytesize::ByteSize;

use super::snapshot::PageSnapshot;
use crate::types::B256;

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

/// `SEGMENT_BYTES` of pages. Allocated zeroed at full size, so its buffer
/// never moves under a reader.
struct Segment {
    nodes: Box<[B256]>,
    used: usize,
}

pub(super) struct PagePool<P: PageArray> {
    segments: Vec<Segment>,
    refs: Vec<u32>,
    free: Vec<PageId>,
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
        Self {
            segments: Vec::with_capacity(MAX_SEGMENTS),
            refs: Vec::new(),
            free: Vec::new(),
            _page: PhantomData,
        }
    }

    #[inline]
    pub(super) fn retain(&mut self, id: PageId) {
        self.refs[id as usize] += 1;
    }

    #[inline]
    fn release_page(&mut self, id: PageId) {
        let r = &mut self.refs[id as usize];
        *r -= 1;
        if *r == 0 {
            self.free.push(id);
        }
    }

    /// Re-point `dst` at `src`'s pages, reusing `dst`'s page-table allocation:
    /// release `dst`'s current pages, then adopt `src`'s (bumping their
    /// refcounts). Identical entries — typically the bulk — cancel their
    /// release+retain and cost only the compare. A released `dst` comes back
    /// live: its refs are already gone, so its table counts as empty and
    /// everything in `src` is retained.
    pub(super) fn share_into(&mut self, dst: &mut PageSnapshot, src: &PageSnapshot) {
        let owned = if dst.is_released { &[] } else { dst.pages.as_slice() };
        for i in 0..owned.len().max(src.pages.len()) {
            let (d, s) = (owned.get(i).copied(), src.pages.get(i).copied());
            if d == s {
                continue;
            }
            if let Some(d) = d {
                self.release_page(d);
            }
            if let Some(s) = s {
                self.retain(s);
            }
        }
        dst.pages.clear();
        dst.pages.extend_from_slice(&src.pages);
        dst.format = src.format;
        dst.count = src.count;
        dst.is_released = false;
    }

    /// Free the snapshot's pages; does nothing if already released. The page
    /// table is kept, so parallel readers stay in bounds and retry via
    /// seqlock.
    pub(super) fn release(&mut self, snapshot: &mut PageSnapshot) {
        if snapshot.is_released {
            return;
        }
        for &id in &snapshot.pages {
            self.release_page(id);
        }
        snapshot.is_released = true;
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
            .and_then(|s| s.nodes.get(i * P::LEN..(i + 1) * P::LEN))
            .unwrap_or(P::UNRESOLVED)
    }

    /// Claim a fresh private page seeded from a flat node slice (the writable
    /// scratch's page). `src` may be shorter than a full page (the tail leaf
    /// page of a small tree); the remainder is zeroed.
    #[inline]
    pub(super) fn alloc_from_slice(&mut self, src: &[B256]) -> PageId {
        debug_assert!(src.len() <= P::LEN);
        let id = match self.free.pop() {
            Some(id) => {
                self.refs[id as usize] = 1;
                id
            }
            None => self.fresh_id(),
        };
        let (segment, i) = Self::split(id);
        let page = &mut self.segments[segment].nodes[i * P::LEN..(i + 1) * P::LEN];
        page[..src.len()].copy_from_slice(src);
        page[src.len()..].fill([0u8; 32]);
        id
    }

    fn fresh_id(&mut self) -> PageId {
        if self.segments.last().is_none_or(|s| s.used == Self::SEGMENT_PAGES) {
            assert!(self.segments.len() < MAX_SEGMENTS, "PagePool: exceeds MAX_POOL_BYTES");
            self.segments.push(Segment {
                nodes: vec![[0u8; 32]; Self::SEGMENT_PAGES * P::LEN].into_boxed_slice(),
                used: 0,
            });
        }
        self.refs.push(1);
        let segment = self.segments.len() - 1;
        let used = &mut self.segments[segment].used;
        *used += 1;
        (segment * Self::SEGMENT_PAGES + *used - 1) as PageId
    }
}

#[cfg(test)]
mod tests {
    use super::{super::format::TreeFormat, B256, PagePool, PageSnapshot};

    fn snapshot(pages: Vec<u32>) -> PageSnapshot {
        PageSnapshot { pages, format: TreeFormat::default(), count: 1, is_released: false }
    }

    /// Release the same snapshot twice; between the two calls the page got a
    /// new owner. The second release must not free it again.
    #[test]
    fn double_release_does_not_free_reallocated_page() {
        let mut pool = PagePool::<[B256; 32]>::new();

        // Fork a owns one page, then loses and is released.
        let mut a = snapshot(vec![pool.alloc_from_slice(&[[1u8; 32]])]);
        let p = a.pages[0];
        pool.release(&mut a); // p is free now, but a still names it

        // A new fork takes p.
        let b = snapshot(vec![pool.alloc_from_slice(&[[2u8; 32]])]);
        assert_eq!(b.pages[0], p, "free page should be reused");

        // Later, finalize releases a's slot a second time (a dropped write
        // view left it behind).
        pool.release(&mut a);

        // p belongs to b: a new alloc must not hand it out again.
        assert_ne!(pool.alloc_from_slice(&[]), p, "second release freed a live page");
    }
}
