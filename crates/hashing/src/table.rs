use std::{
    io::{self, Write},
    iter,
};

use crate::{
    B256, TreeSpec,
    format::TreeFormat,
    page_format::Subtree,
    storage::{PageId, PageStore},
};

/// A committed tree: one root page per subtree, the rest reached through each
/// page's children. A page id names its whole subtree, so trees share every
/// page they did not write. Owns no page: who frees what is the storage's
/// business.
#[derive(Clone, Default)]
pub struct PageTable {
    pub(super) roots: Vec<PageId>,
    pub(super) format: TreeFormat,
    pub(super) count: usize,
}

impl PageTable {
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn format(&self) -> TreeFormat {
        self.format
    }

    #[inline]
    pub fn same_pages(&self, other: &PageTable) -> bool {
        self.format == other.format && self.roots == other.roots
    }

    pub fn write_ssz<C: TreeSpec, W: Write>(
        &self,
        store: &impl PageStore,
        w: &mut W,
    ) -> io::Result<()> {
        let mut bytes_left = self.count * size_of::<C::Val>();
        for row in self.leaf_rows::<C, _>(store) {
            let bytes = row.as_flattened();
            let bytes = &bytes[..bytes.len().min(bytes_left)];
            w.write_all(bytes)?;
            bytes_left -= bytes.len();
        }
        Ok(())
    }

    /// The leaf chunks in order, walking from the root once per leaf row.
    pub(super) fn leaf_rows<'a, C: TreeSpec, Store: PageStore>(
        &'a self,
        store: &'a Store,
    ) -> impl Iterator<Item = &'a [B256]> {
        let chunks = self.count.div_ceil(C::VALS_PER_CHUNK);
        let mut chunk = 0;
        iter::from_fn(move || {
            (chunk < chunks).then(|| {
                let (id, slot) = self.page_of::<C>(store, self.format.leaf_pos::<C>(chunk));
                let row = &store.page(id)[slot..(2 << slot.ilog2()).min(slot + chunks - chunk)];
                chunk += row.len();
                row
            })
        })
    }

    #[inline]
    pub(super) fn node<'a, C: TreeSpec>(&self, store: &'a impl PageStore, n: usize) -> &'a B256 {
        let (id, slot) = self.page_of::<C>(store, n);
        &store.page(id)[slot]
    }

    /// The page holding flat-tree node `n`, and its slot there. A node this
    /// format can't place, as a racing reader may ask, resolves to the first
    /// root slot.
    #[inline]
    pub(super) fn page_of<C: TreeSpec>(&self, store: &impl PageStore, n: usize) -> (PageId, usize) {
        let (s, level, pos) = self.format.locate::<C>(n).unwrap_or_default();
        let (children, slot) = Subtree::of::<C>(self.format, s).path_to::<C>(level, pos);
        let root = self.roots.get(s).copied().unwrap_or(0);
        (children.fold(root, |id, j| store.child(id, j)), slot)
    }
}
