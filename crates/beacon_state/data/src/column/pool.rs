use super::snapshot::PageSnapshot;
use crate::types::B256;

/// 4 KiB page = one OS virtual page (128 × 32-byte nodes).
pub(super) const PAGE_NODES: usize = 4096 / size_of::<B256>();

pub(super) type Page = [B256; PAGE_NODES];
pub(super) type PageId = u32;

pub(super) struct PagePool {
    pages: Vec<Box<Page>>,
    refs: Vec<u32>,
    free: Vec<PageId>,
}

impl PagePool {
    pub(super) fn new(hint: usize) -> Self {
        Self { pages: Vec::with_capacity(hint), refs: Vec::with_capacity(hint), free: Vec::new() }
    }

    #[inline]
    pub(super) fn alloc(&mut self) -> PageId {
        if let Some(id) = self.free.pop() {
            self.refs[id as usize] = 1;
            return id;
        }
        let id = self.pages.len();
        self.pages.push(Box::new([[0u8; 32]; PAGE_NODES]));
        self.refs.push(1);
        id as PageId
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
    /// refcounts). The finalized base adopting a survivor. Identical entries —
    /// the bulk, since the two differ only in pages dirtied since the last
    /// finalize — cancel their release+retain and cost only the compare.
    pub(super) fn share_into(&mut self, dst: &mut PageSnapshot, src: &PageSnapshot) {
        debug_assert!(!dst.is_released, "share_into over a released snapshot double-frees");
        for i in 0..dst.pages.len().max(src.pages.len()) {
            let (d, s) = (dst.pages.get(i).copied(), src.pages.get(i).copied());
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

    /// Drop `snapshot`'s hold on its pages (freeing any that hit refcount 0)
    /// and empty it, so a later release of the same slot is a no-op.
    pub(super) fn release(&mut self, snapshot: &mut PageSnapshot) {
        for &id in &snapshot.pages {
            self.release_page(id);
        }
        snapshot.is_released = true;
    }

    #[inline]
    pub(super) fn page(&self, id: PageId) -> &Page {
        &self.pages[id as usize]
    }

    /// Claim a fresh private page seeded from a flat node slice (the writable
    /// scratch's page). `src` may be shorter than a full page (the tail leaf
    /// page of a small tree); the remainder is zeroed.
    #[inline]
    pub(super) fn alloc_from_slice(&mut self, src: &[B256]) -> PageId {
        debug_assert!(src.len() <= PAGE_NODES);
        let id = self.alloc();
        let p = &mut self.pages[id as usize];
        p[..src.len()].copy_from_slice(src);
        p[src.len()..].fill([0u8; 32]);
        id
    }
}
