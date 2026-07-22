use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;

use super::{
    ColumnReader, ColumnSpec, ColumnWriteView, pool::PagePool, snapshot::PageSnapshot,
    tree::ColumnTree,
};
use crate::{
    ring::{Id, Ring},
    types::{ColumnLenMismatch, HashFormat, SLOTS_RING_N},
};

pub struct ColumnGroup<C: ColumnSpec> {
    pool: PagePool,
    finalized: PageSnapshot,
    ring: Ring<Self, PageSnapshot>,
    /// Flat writable head — the hot write path stays flat; committed forks are
    /// paged.
    scratch: ColumnTree,
    /// The committed fork whose content `scratch` currently holds. While it
    /// matches a roll's parent the scratch is reused in place and the full-tree
    /// snapshot load is skipped; set on commit, cleared on every roll.
    scratch_at: Option<Id<Self>>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> ColumnGroup<C> {
    pub fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
        format: HashFormat,
    ) -> Result<Self, ColumnLenMismatch> {
        let flat = ColumnTree::new::<C::Val>(cap, count, ssz_bytes, format)?;
        // Grow-hint for the base's pages; the pool grows lazily beyond it.
        let mut pool = PagePool::new(flat.num_pages() * 2);
        let finalized = flat.to_snapshot(&mut pool);
        Ok(Self {
            pool,
            finalized,
            ring: Ring::filled(SLOTS_RING_N, PageSnapshot::new_released),
            scratch: flat,
            scratch_at: None,
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnReader<'_, C> {
        ColumnReader::paged(&self.pool, self.ring.get(id))
    }

    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let Self { pool, finalized, scratch, .. } = self;
        scratch.load_snapshot(pool, finalized);
        scratch.reset_dirty_mask();
        self.scratch_at = None;
        ColumnWriteView::new(self, None)
    }

    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { pool, ring, scratch, .. } = self;
        if self.scratch_at != Some(parent) {
            scratch.load_snapshot(pool, ring.get(parent));
        }
        scratch.reset_dirty_mask();
        self.scratch_at = None;
        ColumnWriteView::new(self, Some(parent))
    }

    pub(super) fn commit_scratch(&mut self, parent: Option<Id<Self>>) -> Id<Self> {
        let Self { pool, finalized, ring, scratch, .. } = self;
        debug_assert!(!scratch.has_pending_rehash(), "deferred writes not rehashed before commit");

        ring.grow_if_full_with(PageSnapshot::new_released, |src, dst| *dst = src.clone_for_grow());
        let (id, dst, parent_snap) = ring.roll_deriving(parent);

        debug_assert!(dst.is_released, "recycled slot not freed by finalize or clear");
        scratch.commit_into(pool, dst, parent_snap.unwrap_or(finalized));
        self.scratch_at = Some(id);
        id
    }

    #[inline]
    pub(super) fn scratch(&self) -> &ColumnTree {
        &self.scratch
    }

    #[inline]
    pub(super) fn scratch_mut(&mut self) -> &mut ColumnTree {
        &mut self.scratch
    }

    /// Promote the winner into the base and free everything below the oldest
    /// survivor. Survivor ids stay valid unchanged — columns never reanchor.
    #[timed]
    pub fn finalize<S>(&mut self, promoted: &S, survivors: &[S], idx: impl Fn(&S) -> Id<Self>) {
        let winner = idx(promoted);
        debug_assert!(
            survivors.iter().any(|s| idx(s) == winner),
            "winner must be among the survivors"
        );
        let Self { pool, finalized, ring, .. } = self;
        pool.share_into(finalized, ring.get(winner));
        ring.free_outdated_with(survivors.iter().map(idx), |snapshot| pool.release(snapshot));
    }

    #[inline]
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        ColumnReader::<C>::paged(&self.pool, &self.finalized).write_ssz(w)
    }
}
