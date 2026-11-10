use std::{
    io::{self, Write},
    iter,
};

use crate::{
    B256, TreeSpec,
    flat_hashing::{MAX_SEGS, format::TreeFormat, page_format::Subtree},
    storage::{PageId, PageStore},
};

const MAX_ROOTS: usize = 32;
const _: () = assert!(MAX_ROOTS >= MAX_SEGS);

/// A committed tree: one root page per subtree, the rest reached through each
/// page's children. A page id names its whole subtree, so trees share every
/// page they did not write. Owns no page: who frees what is the storage's
/// business.
#[derive(Clone, Default)]
pub struct PageTable {
    roots: [PageId; MAX_ROOTS],
    root_count: usize,
    pub(super) format: TreeFormat,
    pub(super) count: usize,
}

impl PageTable {
    pub(crate) fn set(
        &mut self,
        format: TreeFormat,
        count: usize,
        roots: impl Iterator<Item = PageId>,
    ) {
        let mut root_count = 0;
        for root in roots {
            self.roots[root_count] = root;
            root_count += 1;
        }
        self.root_count = root_count;
        self.format = format;
        self.count = count;
    }

    #[inline]
    pub(crate) fn roots(&self) -> &[PageId] {
        &self.roots[..self.root_count]
    }

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
        self.format == other.format && self.roots() == other.roots()
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
    pub(crate) fn leaf_rows<'a, C: TreeSpec, Store: PageStore>(
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
    pub(crate) fn node<'a, C: TreeSpec>(&self, store: &'a impl PageStore, n: usize) -> &'a B256 {
        let (id, slot) = self.page_of::<C>(store, n);
        &store.page(id)[slot]
    }

    /// The page holding flat-tree node `n`, and its slot there. A node this
    /// format can't place, as a racing reader may ask, resolves to the first
    /// root slot.
    #[inline]
    pub(crate) fn page_of<C: TreeSpec>(&self, store: &impl PageStore, n: usize) -> (PageId, usize) {
        let (s, level, pos) = self.format.locate::<C>(n).unwrap_or_default();
        let (children, slot) = Subtree::of::<C>(self.format, s).path_to::<C>(level, pos);
        let root = self.roots().get(s).copied().unwrap_or(0);
        (children.fold(root, |id, j| store.child(id, j)), slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VALIDATOR_REGISTRY_LIMIT, progressive::progressive_segments_for};

    #[test]
    fn set_and_clone_from_reuse_inline_roots() {
        let fixed = TreeFormat::Fixed { max_elements: 1024 };
        let progressive = TreeFormat::Progressive { last_seg: MAX_SEGS as u32 - 1 };
        let mut table = PageTable::default();
        let roots = table.roots().as_ptr();
        table.set(fixed, 1, [7].into_iter());
        table.set(progressive, 100, 0..MAX_SEGS as PageId);
        assert_eq!(roots, table.roots().as_ptr());
        assert_eq!(table.roots().len(), MAX_SEGS);

        table.set(fixed, 1, [9].into_iter());
        assert_eq!(table.roots(), &[9]);

        let mut source = PageTable::default();
        source.set(fixed, 1, [9].into_iter());
        assert!(table.same_pages(&source), "unused root slots do not affect equality");

        source.set(progressive, 200, (0..MAX_SEGS as PageId).rev());
        table.clone_from(&source);
        assert_eq!(roots, table.roots().as_ptr());
        assert_eq!(table.roots(), source.roots());
        assert_eq!(table.format(), progressive);
        assert_eq!(table.len(), 200);
        drop(source);
        assert_eq!(table.roots()[0], MAX_SEGS as PageId - 1);
    }

    #[test]
    fn inline_capacity_covers_the_full_registry_limit() {
        let roots = progressive_segments_for(VALIDATOR_REGISTRY_LIMIT);
        assert_eq!(roots, 21);
        assert!(roots <= MAX_ROOTS);
    }
}
