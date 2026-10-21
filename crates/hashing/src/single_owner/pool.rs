use std::marker::PhantomData;

use bytesize::ByteSize;

use crate::{
    B256, TreeSpec,
    flat_hashing::page_format::{PagePos, Subtree},
    merkle::ZERO_HASHES,
    storage::{
        PageAlloc, PageArray, PageId, PageStore, SEGMENT_BYTES, segment_pages, write_rows,
        zero_pages,
    },
};

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

pub struct PagePool<P: PageArray> {
    segments: Vec<Segment>,
    /// Freed ids per segment kind: `[without children, with children]`.
    free: [Vec<PageId>; 2],
    /// The segment each kind takes fresh ids from, indexed as `free`.
    filling: [Option<usize>; 2],
    /// The all-zero subtree's page per depth, like `ZERO_HASHES`. Never freed:
    /// no fork owns it.
    zero_pages: [PageId; ZERO_HASHES.len()],
    _page: PhantomData<fn() -> P>,
}

impl<P: PageArray> PagePool<P> {
    const SEGMENT_PAGES: usize = segment_pages(P::LEN);

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

    /// Pages handed out and not freed, the zero pages included.
    #[cfg(test)]
    pub(crate) fn live_pages(&self) -> usize {
        let used: usize = self.segments.iter().map(|segment| segment.used).sum();
        used - self.free.iter().map(Vec::len).sum::<usize>()
    }

    #[inline]
    pub(super) fn free(&mut self, id: PageId) {
        let inner = !self.segments[Self::split(id).0].children_pages.is_empty();
        self.free[inner as usize].push(id);
    }

    /// Free `old`'s pages down to where they meet `new`'s. Zero pages are the
    /// pool's, never a fork's.
    pub(super) fn free_unshared<C: TreeSpec<Page = P>>(
        &mut self,
        sub: Subtree,
        at: PagePos,
        old: PageId,
        new: Option<PageId>,
    ) {
        if new == Some(old) || old == self.zero_pages[sub.depth::<C>(at) as usize] {
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
}

impl<P: PageArray> Default for PagePool<P> {
    fn default() -> Self {
        let mut pool = Self {
            segments: Vec::with_capacity(MAX_SEGMENTS),
            free: [Vec::new(), Vec::new()],
            filling: [None, None],
            zero_pages: [0; ZERO_HASHES.len()],
            _page: PhantomData,
        };
        pool.zero_pages = zero_pages::<P>(&mut pool);
        pool
    }
}

impl<P: PageArray> PageStore for PagePool<P> {
    #[inline]
    fn page(&self, id: PageId) -> &[B256] {
        let (segment, i) = Self::split(id);
        self.segments
            .get(segment)
            .and_then(|s| s.page_data.get(i * P::LEN..(i + 1) * P::LEN))
            .unwrap_or(P::UNRESOLVED)
    }

    #[inline]
    fn child(&self, id: PageId, j: usize) -> PageId {
        let (segment, i) = Self::split(id);
        self.segments
            .get(segment)
            .and_then(|s| s.children_pages.get(i * P::LEN + j))
            .copied()
            .unwrap_or(0)
    }
}

/// Creator-owned: a fork owns the pages it allocated, and a shared page stays
/// its creator's.
impl<P: PageArray> PageAlloc for PagePool<P> {
    #[inline]
    fn alloc<'a>(&mut self, children: usize, rows: impl Iterator<Item = &'a [B256]>) -> PageId {
        let inner = children != 0;
        let id = match self.free[inner as usize].pop() {
            Some(id) => id,
            None => self.fresh_id(inner),
        };
        let (segment, i) = Self::split(id);
        write_rows(&mut self.segments[segment].page_data[i * P::LEN + 1..], rows);
        id
    }

    #[inline]
    fn set_child(&mut self, id: PageId, j: usize, child: PageId) {
        let (segment, i) = Self::split(id);
        self.segments[segment].children_pages[i * P::LEN + j] = child;
    }

    #[inline]
    fn zero_page(&mut self, depth: u32) -> PageId {
        self.zero_pages[depth as usize]
    }
}

#[cfg(test)]
mod tests;
