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
    ring::{Id, RingIndex},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

pub struct ColumnGroup<C: ColumnSpec> {
    pool: PagePool,
    finalized: PageSnapshot,
    ring: Box<[PageSnapshot]>,
    /// Flat writable head — the hot write path stays flat; committed forks are
    /// paged.
    scratch: ColumnTree,
    /// The committed fork whose content `scratch` currently holds. While it
    /// matches a roll's parent the scratch is reused in place and the full-tree
    /// gather is skipped; set on commit, cleared on every roll.
    scratch_at: Option<Id<Self>>,
    index: RingIndex<Self, SLOTS_RING_N>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> ColumnGroup<C> {
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        let flat = ColumnTree::new::<C::Val>(cap, count, ssz_bytes)?;
        // Grow-hint for the base's pages; the pool grows lazily beyond it.
        let mut pool = PagePool::new(flat.num_pages() * 2);
        let finalized = flat.to_snapshot(&mut pool);
        let ring = (0..SLOTS_RING_N).map(|_| PageSnapshot::default()).collect();
        Ok(Self {
            pool,
            finalized,
            ring,
            scratch: flat,
            scratch_at: None,
            index: RingIndex::default(),
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnReader<'_, C> {
        ColumnReader::paged(&self.pool, &self.ring[self.index.pos(id)])
    }

    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let (id, pos) = self.index.roll();
        let Self { pool, finalized, ring, scratch, .. } = self;
        debug_assert!(ring[pos].is_released(), "recycled slot not freed by finalize");
        scratch.gather_from(pool, finalized);
        scratch.reset_dirty_mask();
        self.scratch_at = None;
        ColumnWriteView::new(self, None, id)
    }

    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        let (id, pos) = self.index.roll();
        let reuse_scratch = self.scratch_at == Some(parent);
        let parent_pos = self.index.pos(parent);
        let Self { pool, ring, scratch, .. } = self;
        debug_assert!(ring[pos].is_released(), "recycled slot not freed by finalize");
        if !reuse_scratch {
            scratch.gather_from(pool, &ring[parent_pos]);
        }
        scratch.reset_dirty_mask();
        self.scratch_at = None;
        ColumnWriteView::new(self, Some(parent), id)
    }

    /// Commit the flat scratch into the new fork's ring slot: a paged snapshot
    /// sharing the parent's pages except the ones this block dirtied. `parent`
    /// is `None` for a fork rolled off the base. Called by the write view's
    /// `commit`.
    pub(super) fn commit_scratch(&mut self, id: Id<Self>, parent: Option<Id<Self>>) {
        let pos = self.index.pos(id);
        let parent_pos = parent.map(|p| self.index.pos(p));
        let Self { pool, finalized, ring, scratch, .. } = self;
        let parent = match parent_pos {
            None => &*finalized,
            Some(ppos) => &ring[ppos],
        };
        ring[pos] = scratch.commit_from(pool, parent);
        self.scratch_at = Some(id);
    }

    #[inline]
    pub(super) fn scratch(&self) -> &ColumnTree {
        &self.scratch
    }

    #[inline]
    pub(super) fn scratch_mut(&mut self) -> &mut ColumnTree {
        &mut self.scratch
    }

    #[timed]
    pub fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        let winner_pos = self.index.pos(winner);
        {
            let Self { pool, finalized, ring, .. } = self;
            pool.release(finalized);
            *finalized = pool.share(&ring[winner_pos]);
        }
        for seq in self.index.free_outdated(survivors) {
            let pos = self.index.slot(seq);
            self.pool.release(&mut self.ring[pos]);
        }
        survivors.to_vec()
    }

    #[inline]
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        ColumnReader::<C>::paged(&self.pool, &self.finalized).write_ssz(w)
    }
}
