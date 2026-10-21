use std::{
    io::{self, Write},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicPtr, Ordering},
    },
};

use crate::{
    B256, FlatTree, HashFormat, SszScalar, TreeFormat, TreeReader, TreeSpec, merkle::byte_chunks,
    multi_owner::pool::SharedPool, storage::PageTable,
};

/// A list whose committed tree lives in refcounted pages. Clones share every
/// page, and dropping the last list over a page frees it.
///
/// Writes go to a private flat tree. `commit` hashes them, shares the pages
/// they did not touch, and parks the flat tree for the next writer among the
/// clones.
pub struct SharedList<C: TreeSpec> {
    pool: Arc<ListPool<C>>,
    /// Holds one reference per root.
    table: PageTable,
    /// Matches `table` outside its uncommitted writes.
    flat: Option<Box<FlatTree<C>>>,
}

type Reader<'a, C> = TreeReader<'a, C, SharedPool<<C as TreeSpec>::Page>>;

impl<C: TreeSpec> SharedList<C> {
    pub fn new(vals: &[C::Val], format: HashFormat) -> Self {
        let pool = Arc::new(ListPool::default());
        let bytes = C::Val::as_ssz_bytes(vals);
        let mut flat = FlatTree::from_leaves(vals.len(), vals.len(), byte_chunks(&bytes), format);
        let mut table = PageTable::default();
        flat.commit(&mut &pool.pages, &mut table, None, None);
        Self { pool, table, flat: Some(Box::new(flat)) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.reader().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        debug_assert!(ix < self.len(), "index out of range");
        self.reader().get(ix)
    }

    /// One tree walk per leaf row, not per value.
    pub fn iter(&self) -> impl Iterator<Item = C::Val> + '_ {
        let (flat, paged) = match &self.flat {
            Some(flat) => (Some(flat.leaves()), None),
            None => (None, Some(self.table.leaf_rows::<C, _>(&self.pool.pages))),
        };
        flat.into_iter()
            .chain(paged.into_iter().flatten())
            .flatten()
            .flat_map(|chunk| (0..C::VALS_PER_CHUNK).map(|lane| C::Val::lane(chunk, lane)))
            .take(self.len())
    }

    #[inline]
    pub fn set(&mut self, ix: usize, v: C::Val) {
        debug_assert!(ix < self.len(), "index out of range");
        self.flat_mut().set_val(ix as u32, v);
    }

    pub fn push(&mut self, v: C::Val) {
        debug_assert!(C::IS_LIST, "a vector has fixed length");
        let flat = self.flat_mut();
        let ix = flat.append_empty();
        flat.set_val(ix, v);
    }

    pub fn format(&self) -> HashFormat {
        match self.reader().format() {
            TreeFormat::Fixed { .. } => HashFormat::Fixed,
            TreeFormat::Progressive { .. } => HashFormat::Progressive,
        }
    }

    pub fn migrate_to_progressive(&mut self) {
        debug_assert!(C::IS_LIST, "vectors are fork-invariant under EIP-7688");
        self.flat_mut().migrate_to_progressive();
    }

    pub fn hash_root(&self) -> B256 {
        debug_assert!(self.is_committed(), "commit before hash_root");
        self.reader().hash_root()
    }

    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match &self.flat {
            Some(flat) => w.write_all(flat.ssz_bytes()),
            None => self.table.write_ssz::<C, W>(&self.pool.pages, w),
        }
    }

    fn reader(&self) -> Reader<'_, C> {
        match &self.flat {
            Some(flat) => TreeReader::flat(flat),
            None => TreeReader::paged(&self.pool.pages, &self.table),
        }
    }

    fn flat_mut(&mut self) -> &mut FlatTree<C> {
        let (pool, table) = (&self.pool, &self.table);
        self.flat.get_or_insert_with(|| pool.flat_tree_for(table))
    }

    /// Hash the writes and commit them into the pool, sharing every page they
    /// did not touch. The flat tree is parked for the next writer.
    pub fn commit(&mut self) {
        let Some(mut flat) = self.flat.take() else { return };
        if holds_writes(&flat, &self.table) {
            flat.rehash();
            let mut table = PageTable::default();
            flat.commit(&mut &self.pool.pages, &mut table, Some(&self.table), None);
            self.pool.release(&self.table);
            self.table = table;
        }
        self.pool.park(flat, &self.table);
    }

    pub fn is_committed(&self) -> bool {
        self.flat.as_ref().is_none_or(|flat| !holds_writes(flat, &self.table))
    }
}

/// An append of a zero value writes no chunk, so the length counts too.
fn holds_writes<C: TreeSpec>(flat: &FlatTree<C>, table: &PageTable) -> bool {
    flat.has_writes() || flat.count() != table.len()
}

/// The pages of a list and its clones, and the flat tree of their last commit.
/// The spare lets a clone's first write reload only the pages that changed,
/// instead of every page.
struct ListPool<C: TreeSpec> {
    pages: SharedPool<C::Page>,
    spare: AtomicPtr<Spare<C>>,
}

/// `flat` matches `table`, which holds one reference per root.
struct Spare<C: TreeSpec> {
    flat: Box<FlatTree<C>>,
    table: PageTable,
}

impl<C: TreeSpec> Default for ListPool<C> {
    fn default() -> Self {
        Self { pages: SharedPool::default(), spare: AtomicPtr::new(ptr::null_mut()) }
    }
}

impl<C: TreeSpec> ListPool<C> {
    fn park(&self, flat: Box<FlatTree<C>>, table: &PageTable) {
        self.retain(table);
        let spare = Box::into_raw(Box::new(Spare { flat, table: table.clone() }));
        if let Some(old) = self.take(self.spare.swap(spare, Ordering::AcqRel)) {
            self.release(&old.table);
        }
    }

    /// A concurrent writer that finds no spare builds its tree from every page.
    fn flat_tree_for(&self, table: &PageTable) -> Box<FlatTree<C>> {
        let Some(spare) = self.take(self.spare.swap(ptr::null_mut(), Ordering::AcqRel)) else {
            let mut flat = Box::<FlatTree<C>>::default();
            flat.load(&self.pages, &PageTable::default(), table);
            return flat;
        };
        let Spare { mut flat, table: parked } = *spare;
        flat.load(&self.pages, &parked, table);
        self.release(&parked);
        flat
    }

    fn take(&self, spare: *mut Spare<C>) -> Option<Box<Spare<C>>> {
        // SAFETY: a non-null `spare` came from `Box::into_raw` in `park`, and
        // the swap that returned it removed it from `self.spare`.
        (!spare.is_null()).then(|| unsafe { Box::from_raw(spare) })
    }

    fn retain(&self, table: &PageTable) {
        for &root in table.roots() {
            self.pages.retain(root);
        }
    }

    fn release(&self, table: &PageTable) {
        for &root in table.roots() {
            self.pages.release(root);
        }
    }
}

impl<C: TreeSpec> Drop for ListPool<C> {
    fn drop(&mut self) {
        let spare = *self.spare.get_mut();
        if let Some(spare) = self.take(spare) {
            self.release(&spare.table);
        }
    }
}

/// Shares every committed page. A clone of an uncommitted list also copies
/// the flat tree that holds its writes.
impl<C: TreeSpec> Clone for SharedList<C> {
    fn clone(&self) -> Self {
        self.pool.retain(&self.table);
        let flat = if self.is_committed() {
            None
        } else {
            self.flat.as_ref().map(|flat| Box::new(flat.duplicate()))
        };
        Self { pool: self.pool.clone(), table: self.table.clone(), flat }
    }
}

impl<C: TreeSpec> Drop for SharedList<C> {
    fn drop(&mut self) {
        self.pool.release(&self.table);
    }
}

#[cfg(test)]
mod tests;
