use std::{
    marker::PhantomData,
    slice,
    sync::atomic::{Ordering, fence},
    thread,
};

use crate::{
    B256,
    merkle::ZERO_HASHES,
    multi_owner::arena::{Arena, MAX_SEGMENTS, Segment},
    storage::{PageAlloc, PageArray, PageId, PageStore, segment_pages, write_rows, zero_pages},
};

/// Set on ids of pages with children, which live in their own arena.
const INNER: PageId = 1 << 31;

/// Pages shared by any number of trees, on any thread.
///
/// A page's count is how many table roots and parent child slots point at it.
/// A commit takes one count per page its tree holds. A page whose count
/// reaches zero frees itself and releases its children, on whichever thread
/// dropped the last reference.
///
/// Lock-free: the count is the allocation state.
pub struct SharedPool<P: PageArray> {
    arenas: [Arena; 2],
    /// The all-zero subtree's page per depth, like `ZERO_HASHES`. The pool
    /// holds one reference to each, so they are never freed.
    zero_pages: [PageId; ZERO_HASHES.len()],
    _page: PhantomData<fn() -> P>,
}

// SAFETY: page data is written only through `alloc`, on a page no reference
// reaches yet; every other shared state is atomic.
unsafe impl<P: PageArray> Send for SharedPool<P> {}
unsafe impl<P: PageArray> Sync for SharedPool<P> {}

impl<P: PageArray> SharedPool<P> {
    const SEGMENT_PAGES: usize = {
        let pages = segment_pages(P::LEN);
        assert!(MAX_SEGMENTS * pages <= INNER as usize, "SharedPool: indices must fit below INNER");
        pages
    };

    #[inline]
    fn arena(&self, id: PageId) -> &Arena {
        &self.arenas[(id & INNER != 0) as usize]
    }

    #[inline]
    fn segment(&self, id: PageId) -> Option<(&Segment, usize)> {
        self.arena(id).segment(id & !INNER)
    }

    #[inline]
    fn alloc<'a>(&self, children: usize, rows: impl Iterator<Item = &'a [B256]>) -> PageId {
        let inner = children != 0;
        let arena = &self.arenas[inner as usize];
        let index = arena.alloc();
        let id = index | if inner { INNER } else { 0 };

        let (segment, i) = self.segment(id).expect("allocated page has a segment");
        // SAFETY: the page is free, so no reference reaches it and no other
        // thread reads or writes it until this id is published.
        let page = unsafe { slice::from_raw_parts_mut(segment.page_ptr(i, P::LEN), P::LEN) };
        write_rows(&mut page[1..], rows);
        if inner {
            segment.child_counts[i].store(children as u32, Ordering::Relaxed);
        }
        segment.refs[i].store(1, Ordering::Relaxed);
        id
    }

    #[inline]
    fn set_child(&self, id: PageId, j: usize, child: PageId) {
        let (segment, i) = self.segment(id).expect("allocated page has a segment");
        segment.children_pages[i * P::LEN + j].store(child, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn retain(&self, id: PageId) {
        let (segment, i) = self.segment(id).expect("retained page has a segment");
        let old = segment.refs[i].fetch_add(1, Ordering::Relaxed);
        debug_assert!(old != 0, "retained a free page");
    }

    /// Drop one reference to `id`, freeing it and releasing its children when
    /// it was the last.
    pub(super) fn release(&self, id: PageId) {
        let (segment, i) = self.segment(id).expect("released page has a segment");
        let old = segment.refs[i].fetch_sub(1, Ordering::Release);
        debug_assert!(old != 0, "released a free page");
        if old != 1 {
            return;
        }
        // Every other holder's writes and reads happen before the free.
        fence(Ordering::Acquire);
        if id & INNER != 0 {
            for j in 0..segment.child_counts[i].load(Ordering::Relaxed) as usize {
                self.release(segment.children_pages[i * P::LEN + j].load(Ordering::Relaxed));
            }
        }
        self.arena(id).free(id & !INNER, segment, i);
    }
}

impl<P: PageArray> Default for SharedPool<P> {
    fn default() -> Self {
        let mut pool = Self {
            arenas: [false, true].map(|inner| Arena::new(Self::SEGMENT_PAGES, P::LEN, inner)),
            zero_pages: [0; ZERO_HASHES.len()],
            _page: PhantomData,
        };
        pool.zero_pages = zero_pages::<P>(&mut &pool);
        pool
    }
}

/// Every tree over the pool keeps it alive, so a page still referenced here
/// leaked.
impl<P: PageArray> Drop for SharedPool<P> {
    fn drop(&mut self) {
        if cfg!(debug_assertions) && !thread::panicking() {
            for id in self.zero_pages {
                self.release(id);
            }
            let leaked: usize = self.arenas.iter().map(Arena::referenced_pages).sum();
            debug_assert_eq!(leaked, 0, "SharedPool dropped with leaked pages");
        }
    }
}

impl<P: PageArray> PageStore for SharedPool<P> {
    #[inline]
    fn page(&self, id: PageId) -> &[B256] {
        match self.segment(id) {
            // SAFETY: a referenced page is not written; see `alloc`.
            Some((segment, i)) => unsafe {
                slice::from_raw_parts(segment.page_ptr(i, P::LEN), P::LEN)
            },
            None => P::UNRESOLVED,
        }
    }

    #[inline]
    fn child(&self, id: PageId, j: usize) -> PageId {
        self.segment(id)
            .and_then(|(segment, i)| segment.children_pages.get(i * P::LEN + j))
            .map_or(0, |child| child.load(Ordering::Relaxed))
    }
}

/// The allocator is a shared reference, as every clone of a list commits
/// into the same pool; `PageAlloc` needs it to read pages too.
impl<P: PageArray> PageStore for &SharedPool<P> {
    #[inline]
    fn page(&self, id: PageId) -> &[B256] {
        SharedPool::page(self, id)
    }

    #[inline]
    fn child(&self, id: PageId, j: usize) -> PageId {
        SharedPool::child(self, id, j)
    }
}

/// A commit takes one reference per page its tree holds.
impl<P: PageArray> PageAlloc for &SharedPool<P> {
    #[inline]
    fn alloc<'a>(&mut self, children: usize, rows: impl Iterator<Item = &'a [B256]>) -> PageId {
        SharedPool::alloc(self, children, rows)
    }

    #[inline]
    fn set_child(&mut self, id: PageId, j: usize, child: PageId) {
        SharedPool::set_child(self, id, j, child);
    }

    #[inline]
    fn reuse(&mut self, id: PageId) {
        self.retain(id);
    }

    #[inline]
    fn zero_page(&mut self, depth: u32) -> PageId {
        let id = self.zero_pages[depth as usize];
        self.retain(id);
        id
    }
}
