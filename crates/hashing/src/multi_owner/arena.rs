use std::{
    cell::UnsafeCell,
    iter, ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering},
};

use bytesize::ByteSize;

use crate::{
    B256,
    storage::{PageId, SEGMENT_BYTES},
};

const MAX_ARENA_BYTES: usize = ByteSize::gib(4).as_u64() as usize;
pub(super) const MAX_SEGMENTS: usize = MAX_ARENA_BYTES / SEGMENT_BYTES;

/// Pages of one kind: leaf pages, or pages with a child slot per node. Free
/// pages form a tagged Treiber stack.
pub(super) struct Arena {
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
pub(super) struct Segment {
    page_data: Box<[UnsafeCell<B256>]>,
    pub(super) children_pages: Box<[AtomicU32]>,
    pub(super) child_counts: Box<[AtomicU32]>,
    pub(super) refs: Box<[AtomicU32]>,
    next_free: Box<[AtomicU32]>,
}

impl Arena {
    pub(super) fn new(segment_pages: usize, page_nodes: usize, inner: bool) -> Self {
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
    pub(super) fn segment(&self, index: PageId) -> Option<(&Segment, usize)> {
        let index = index as usize;
        let segment = self.segments.get(index / self.segment_pages)?.load(Ordering::Acquire);
        // SAFETY: published segments live until the pool drops.
        (!segment.is_null()).then(|| (unsafe { &*segment }, index % self.segment_pages))
    }

    #[inline]
    pub(super) fn alloc(&self) -> PageId {
        self.pop().unwrap_or_else(|| self.fresh())
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

    pub(super) fn free(&self, index: PageId, segment: &Segment, i: usize) {
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
    pub(super) fn page_ptr(&self, i: usize, page_nodes: usize) -> *mut B256 {
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
