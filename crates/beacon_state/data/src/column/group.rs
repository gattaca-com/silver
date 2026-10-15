use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;

use super::{
    ColumnReader, ColumnSpec, ColumnWriteView, hashing_writer::HashingWriter, pool::PagePool,
    snapshot::PageSnapshot, tree::ColumnTree,
};
use crate::{
    ring::{Id, Ring, RingGroup},
    types::{B256, ColumnLenMismatch, HashFormat, SLOTS_RING_N},
};

fn byte_chunks(bytes: &[u8]) -> impl Iterator<Item = B256> + '_ {
    bytes.chunks(32).map(|c| {
        let mut chunk = [0u8; 32];
        chunk[..c.len()].copy_from_slice(c);
        chunk
    })
}

pub struct ColumnGroup<C: ColumnSpec> {
    pool: PagePool<C::Page>,
    finalized: PageSnapshot,
    /// The last winner: its ring slot is freed, and its id now names
    /// `finalized`.
    finalized_id: Option<Id<Self>>,
    ring: Ring<Self>,
    /// Flat writable head — the hot write path stays flat; committed forks are
    /// paged.
    writer: HashingWriter<C>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> RingGroup for ColumnGroup<C> {
    type Entry = PageSnapshot;
}

impl<C: ColumnSpec> ColumnGroup<C> {
    pub fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
        format: HashFormat,
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * size_of::<C::Val>() {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        Ok(Self::from_leaves(cap, count, byte_chunks(ssz_bytes), format))
    }

    pub fn vector(ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        debug_assert!(!C::IS_LIST, "vector constructor on a list column");
        Self::new(C::SSZ_LIMIT, C::SSZ_LIMIT, ssz_bytes, HashFormat::Fixed)
    }

    pub fn zeroed_vector() -> Self {
        Self::vector(&vec![0u8; C::SSZ_LIMIT * size_of::<C::Val>()])
            .expect("a zeroed buffer is exactly the vector length")
    }

    pub fn from_leaves(
        cap: usize,
        count: usize,
        leaves: impl Iterator<Item = B256>,
        format: HashFormat,
    ) -> Self {
        let mut pool = PagePool::new();
        let flat = ColumnTree::from_leaves(cap, count, leaves, format);
        let (writer, finalized) = HashingWriter::new(flat, &mut pool);
        Self {
            writer,
            pool,
            finalized,
            finalized_id: None,
            ring: Ring::filled(SLOTS_RING_N, PageSnapshot::default),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnReader<'_, C> {
        let snapshot =
            if self.finalized_id == Some(id) { &self.finalized } else { self.ring.get(id) };
        ColumnReader::paged(&self.pool, snapshot)
    }

    #[timed]
    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let Self { pool, finalized, writer, .. } = self;
        writer.load(pool, finalized, None);
        ColumnWriteView::new(self, None)
    }

    #[timed]
    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { pool, finalized, finalized_id, ring, writer, .. } = self;
        if *finalized_id == Some(parent) {
            writer.load(pool, finalized, None);
        } else {
            writer.load(pool, ring.get(parent), Some(parent));
        }
        ColumnWriteView::new(self, Some(parent))
    }

    pub(super) fn commit_writer(&mut self, parent: Option<Id<Self>>) -> Id<Self> {
        let Self { pool, finalized, finalized_id, ring, writer, .. } = self;
        writer.tree_mut().rehash();

        ring.grow_if_full_with(PageSnapshot::default, |src, dst| *dst = src.clone_for_grow());
        let parent_in_ring = parent.filter(|&p| Some(p) != *finalized_id);
        let (id, dst, parent_snap) = ring.roll_deriving(parent_in_ring);

        debug_assert!(dst.allocated.is_empty(), "recycled slot still owns pages: not released");
        writer.commit(pool, dst, parent_snap.unwrap_or(finalized), id);
        id
    }

    #[inline]
    pub(super) fn tree(&self) -> &ColumnTree<C> {
        self.writer.tree()
    }

    #[inline]
    pub(super) fn tree_mut(&mut self) -> &mut ColumnTree<C> {
        self.writer.tree_mut()
    }

    /// Promote the winner into the base and free its ring slot and everything
    /// older. The winner's id then names the base; the other survivor ids stay
    /// valid unchanged — columns never reanchor.
    #[timed]
    pub fn finalize<S>(&mut self, winner: Id<Self>, survivors: &[S], idx: impl Fn(&S) -> Id<Self>) {
        debug_assert!(
            survivors.iter().any(|s| idx(s) == winner),
            "winner must be among the survivors"
        );
        debug_assert!(survivors.iter().all(|s| idx(s) >= winner), "a survivor predates the winner");
        let Self { pool, finalized, finalized_id, ring, writer, .. } = self;
        if *finalized_id == Some(winner) {
            return;
        }
        finalized.promote::<C>(pool, ring.get(winner));
        ring.free_through_with(winner, |snapshot| snapshot.release::<C>(pool, finalized));
        *finalized_id = Some(winner);
        writer.unmirror_dead(finalized, |id| survivors.iter().any(|s| idx(s) == id));
    }

    #[inline]
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        ColumnReader::<C>::paged(&self.pool, &self.finalized).write_ssz(w)
    }
}
