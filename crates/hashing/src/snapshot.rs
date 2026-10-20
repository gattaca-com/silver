use std::io::{self, Write};

use super::{
    TreeSpec,
    format::TreeFormat,
    page_format::Subtree,
    pool::{PageId, PagePool},
};
use crate::B256;

/// A committed fork's tree in a [`PagePool`]: one root page per subtree. A
/// page id names its whole subtree, so forks share every page they did not
/// write.
///
/// Ownership: the base owns every page reachable from its roots, and a fork
/// owns exactly its `allocated` pages.
#[derive(Default)]
pub struct PageSnapshot {
    pub(super) roots: Vec<PageId>,
    /// `(flat-tree node in slot 1, page)` per page this commit allocated.
    pub(super) allocated: Vec<(u32, PageId)>,
    pub(super) format: TreeFormat,
    pub(super) count: usize,
}

impl PageSnapshot {
    /// Only correct during the ring's copy-grow: the original is retired and
    /// never released, so ownership of its allocated pages moves to the copy.
    pub fn clone_for_grow(&self) -> Self {
        Self { roots: self.roots.clone(), allocated: self.allocated.clone(), ..*self }
    }

    /// Take `src`'s content without taking ownership of any page.
    pub fn mirror(&mut self, src: &PageSnapshot) {
        self.roots.clone_from(&src.roots);
        self.format = src.format;
        self.count = src.count;
    }

    #[inline]
    pub fn same_pages(&self, other: &PageSnapshot) -> bool {
        self.format == other.format && self.roots == other.roots
    }

    /// Make this base `winner`'s tree, freeing the base pages the winner does
    /// not share.
    pub fn promote<C: TreeSpec>(&mut self, pool: &mut PagePool<C::Page>, winner: &PageSnapshot) {
        let same_format = self.format == winner.format;
        for (s, sub) in self.format.subtrees::<C>().enumerate() {
            let new = winner.roots.get(s).copied().filter(|_| same_format);
            pool.free_unshared::<C>(sub, sub.root::<C>(), self.roots[s], new);
        }
        self.mirror(winner);
    }

    /// Free this fork's allocated pages, except those `base` holds. Idempotent,
    /// as it clears `allocated`; `roots` stay, so racing readers stay in
    /// bounds.
    pub fn release<C: TreeSpec>(&mut self, pool: &mut PagePool<C::Page>, base: &PageSnapshot) {
        let same_format = self.format == base.format;
        for &(n, id) in &self.allocated {
            if !same_format || base.page_of::<C>(pool, n as usize).0 != id {
                pool.free(id);
            }
        }
        self.allocated.clear();
    }

    #[inline]
    pub fn owns_pages(&self) -> bool {
        !self.allocated.is_empty()
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        self.format
    }

    /// One root-to-page walk per leaf row, not per chunk.
    pub fn write_ssz<C: TreeSpec, W: Write>(
        &self,
        pool: &PagePool<C::Page>,
        w: &mut W,
    ) -> io::Result<()> {
        let chunks = self.count.div_ceil(C::VALS_PER_CHUNK);
        let mut bytes_left = self.count * size_of::<C::Val>();
        let mut chunk = 0;
        while chunk < chunks {
            let (id, slot) = self.page_of::<C>(pool, self.format.leaf_pos::<C>(chunk));
            let row = &pool.page(id)[slot..(2 << slot.ilog2()).min(slot + chunks - chunk)];
            let bytes = row.as_flattened();
            let bytes = &bytes[..bytes.len().min(bytes_left)];
            w.write_all(bytes)?;
            bytes_left -= bytes.len();
            chunk += row.len();
        }
        Ok(())
    }

    #[inline]
    pub(super) fn node<'a, C: TreeSpec>(&self, pool: &'a PagePool<C::Page>, n: usize) -> &'a B256 {
        let (id, slot) = self.page_of::<C>(pool, n);
        &pool.page(id)[slot]
    }

    /// The page holding flat-tree node `n`, and its slot there. A node this
    /// format can't place, as a racing reader may ask, resolves to the first
    /// root slot.
    #[inline]
    fn page_of<C: TreeSpec>(&self, pool: &PagePool<C::Page>, n: usize) -> (PageId, usize) {
        let (s, level, pos) = self.format.locate::<C>(n).unwrap_or_default();
        let (children, slot) = Subtree::of::<C>(self.format, s).path_to::<C>(level, pos);
        let root = self.roots.get(s).copied().unwrap_or(0);
        (children.fold(root, |id, j| pool.child(id, j)), slot)
    }
}
