use std::{
    cell::UnsafeCell,
    iter,
    marker::PhantomData,
    ptr, slice,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering, fence},
};

use bytesize::ByteSize;

use crate::{
    B256,
    merkle::ZERO_HASHES,
    storage::{
        PageAlloc, PageArray, PageId, PageStore, SEGMENT_BYTES, segment_pages, write_rows,
        zero_pages,
    },
};

const MAX_ARENA_BYTES: usize = ByteSize::gib(4).as_u64() as usize;
const MAX_SEGMENTS: usize = MAX_ARENA_BYTES / SEGMENT_BYTES;

/// Set on ids of pages with children, which live in their own arena.
const INNER: PageId = 1 << 31;

/// Pages shared by any number of trees, on any thread.
///
/// A page's count is how many table roots and parent child slots point at it.
/// A commit takes one count per page its tree holds. A page whose count
/// reaches zero frees itself and releases its children, on whichever thread
/// dropped the last reference.
///
/// Lock-free: the count is the allocation state, and free pages form a tagged
/// Treiber stack.
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

/// Pages of one kind: leaf pages, or pages with a child slot per node.
struct Arena {
    segment_pages: usize,
    page_nodes: usize,
    inner: bool,
    segments: Box<[AtomicPtr<Segment>]>,
    /// First never-handed-out index.
    next: AtomicU32,
    /// `(tag << 32) | (index + 1)` of the top free page, zero when empty. The
    /// tag makes a pop fail if the top was popped and pushed again meanwhile.
    free: AtomicU64,
}

/// Allocated zeroed at full size, so no buffer moves once published.
struct Segment {
    page_data: Box<[UnsafeCell<B256>]>,
    children_pages: Box<[AtomicU32]>,
    child_counts: Box<[AtomicU32]>,
    refs: Box<[AtomicU32]>,
    next_free: Box<[AtomicU32]>,
}

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
        let index = arena.pop().unwrap_or_else(|| arena.fresh());
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
        self.arena(id).push(id & !INNER, segment, i);
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

impl Arena {
    fn new(segment_pages: usize, page_nodes: usize, inner: bool) -> Self {
        Self {
            segment_pages,
            page_nodes,
            inner,
            segments: iter::repeat_with(|| AtomicPtr::new(ptr::null_mut()))
                .take(MAX_SEGMENTS)
                .collect(),
            next: AtomicU32::new(0),
            free: AtomicU64::new(0),
        }
    }

    #[inline]
    fn segment(&self, index: PageId) -> Option<(&Segment, usize)> {
        let index = index as usize;
        let segment = self.segments.get(index / self.segment_pages)?.load(Ordering::Acquire);
        // SAFETY: published segments live until the pool drops.
        (!segment.is_null()).then(|| (unsafe { &*segment }, index % self.segment_pages))
    }

    fn fresh(&self) -> PageId {
        let index = self.next.fetch_add(1, Ordering::Relaxed) as usize;
        let segment = self
            .segments
            .get(index / self.segment_pages)
            .expect("SharedPool: exceeds MAX_ARENA_BYTES");
        if segment.load(Ordering::Acquire).is_null() {
            let fresh = Segment::new(self.segment_pages, self.page_nodes, self.inner);
            let fresh = Box::into_raw(Box::new(fresh));
            let lost = segment
                .compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire)
                .is_err();
            if lost {
                // SAFETY: never published.
                drop(unsafe { Box::from_raw(fresh) });
            }
        }
        index as PageId
    }

    fn pop(&self) -> Option<PageId> {
        let mut head = self.free.load(Ordering::Acquire);
        loop {
            let top = head as u32;
            if top == 0 {
                return None;
            }
            let (segment, i) = self.segment(top - 1).expect("a free page has a segment");
            let next = segment.next_free[i].load(Ordering::Relaxed);
            let tagged = ((head >> 32) + 1) << 32 | next as u64;
            match self.free.compare_exchange_weak(
                head,
                tagged,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(top - 1),
                Err(now) => head = now,
            }
        }
    }

    fn push(&self, index: PageId, segment: &Segment, i: usize) {
        let mut head = self.free.load(Ordering::Relaxed);
        loop {
            segment.next_free[i].store(head as u32, Ordering::Relaxed);
            let tagged = ((head >> 32) + 1) << 32 | (index + 1) as u64;
            match self.free.compare_exchange_weak(
                head,
                tagged,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(now) => head = now,
            }
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        for segment in &mut self.segments {
            let segment = *segment.get_mut();
            if !segment.is_null() {
                // SAFETY: published by `fresh`, and the pool is gone.
                drop(unsafe { Box::from_raw(segment) });
            }
        }
    }
}

impl Segment {
    #[inline]
    fn page_ptr(&self, i: usize, page_nodes: usize) -> *mut B256 {
        UnsafeCell::raw_get(self.page_data[i * page_nodes..(i + 1) * page_nodes].as_ptr())
    }

    /// Zeroed by the allocator, so untouched pages cost no memory.
    fn new(pages: usize, page_nodes: usize, inner: bool) -> Self {
        let page_data = vec![[0u8; 32]; pages * page_nodes].into_boxed_slice();
        // SAFETY: `UnsafeCell<T>` has the same layout as `T`.
        let page_data =
            unsafe { Box::from_raw(Box::into_raw(page_data) as *mut [UnsafeCell<B256>]) };
        let atomics = |n: usize| {
            let zeros = vec![0u32; n].into_boxed_slice();
            // SAFETY: `AtomicU32` has the same layout as `u32`.
            unsafe { Box::from_raw(Box::into_raw(zeros) as *mut [AtomicU32]) }
        };
        Self {
            page_data,
            children_pages: atomics(if inner { pages * page_nodes } else { 0 }),
            child_counts: atomics(if inner { pages } else { 0 }),
            refs: atomics(pages),
            next_free: atomics(pages),
        }
    }
}
