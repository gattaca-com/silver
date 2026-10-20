use std::{
    io::{self, Write},
    marker::PhantomData,
};

use flux_profiler::timed;
use silver_hashing::{FlatTree, PagePool, PageSnapshot};

use super::{
    TreeSpec, TreeView, TreeWriteView,
    hashing_writer::{Committed, HashingWriter},
};
use crate::{
    ring::{Id, Ring, RingGroup},
    types::{B256, HashFormat, SLOTS_RING_N, TreeLenMismatch},
};

fn byte_chunks(bytes: &[u8]) -> impl Iterator<Item = B256> + '_ {
    bytes.chunks(32).map(|c| {
        let mut chunk = [0u8; 32];
        chunk[..c.len()].copy_from_slice(c);
        chunk
    })
}

pub struct TreeGroup<C: TreeSpec> {
    pool: PagePool<C::Page>,
    finalized: PageSnapshot,
    /// The last winner: its ring slot is freed, and its id now names
    /// `finalized`.
    finalized_id: Option<Id<Self>>,
    ring: Ring<Self>,
    /// Writes go to this flat tree; committed forks live in pages.
    writer: HashingWriter<C>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: TreeSpec> RingGroup for TreeGroup<C> {
    type Entry = PageSnapshot;
}

impl<C: TreeSpec> TreeGroup<C> {
    pub fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
        format: HashFormat,
    ) -> Result<Self, TreeLenMismatch> {
        if ssz_bytes.len() != count * size_of::<C::Val>() {
            return Err(TreeLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        Ok(Self::from_leaves(cap, count, byte_chunks(ssz_bytes), format))
    }

    pub fn vector(ssz_bytes: &[u8]) -> Result<Self, TreeLenMismatch> {
        debug_assert!(!C::IS_LIST, "vector constructor on a list tree");
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
        let mut pool = PagePool::default();
        let flat = FlatTree::from_leaves(cap, count, leaves, format);
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
    pub fn view(&self, id: Id<Self>) -> TreeView<'_, C> {
        let snapshot =
            if self.finalized_id == Some(id) { &self.finalized } else { self.ring.get(id) };
        TreeView::paged(&self.pool, snapshot.table())
    }

    #[timed]
    pub fn roll_fresh(&mut self) -> TreeWriteView<'_, C> {
        let Self { pool, finalized, ring, writer, .. } = self;
        writer.load(pool, finalized, ring, Committed::Base);
        TreeWriteView::new(self, None)
    }

    #[timed]
    pub fn roll_from(&mut self, parent: Id<Self>) -> TreeWriteView<'_, C> {
        let Self { pool, finalized, finalized_id, ring, writer, .. } = self;
        let target =
            if *finalized_id == Some(parent) { Committed::Base } else { Committed::Entry(parent) };
        writer.load(pool, finalized, ring, target);
        TreeWriteView::new(self, Some(parent))
    }

    pub(super) fn commit_writer(&mut self, parent: Option<Id<Self>>) -> Id<Self> {
        let Self { pool, finalized, finalized_id, ring, writer, .. } = self;
        writer.tree_mut().rehash();

        ring.grow_if_full_with(PageSnapshot::default, |src, dst| *dst = src.clone_for_grow());
        let parent_in_ring = parent.filter(|&p| Some(p) != *finalized_id);
        let (id, dst, parent_snap) = ring.roll_deriving(parent_in_ring);
        writer.commit(pool, dst, parent_snap.unwrap_or(finalized), id);
        id
    }

    #[inline]
    pub(super) fn tree(&self) -> &FlatTree<C> {
        self.writer.tree()
    }

    #[inline]
    pub(super) fn tree_mut(&mut self) -> &mut FlatTree<C> {
        self.writer.tree_mut()
    }

    /// Promote the winner into the base and free its ring slot and everything
    /// older. The winner's id then names the base; the other survivor ids stay
    /// valid unchanged — trees never reanchor.
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
        let base_kept = finalized.table().same_pages(ring.get(winner).table());
        finalized.promote::<C>(pool, ring.get(winner));
        ring.free_through_with(winner, |snapshot| snapshot.release::<C>(pool, finalized));
        *finalized_id = Some(winner);
        writer.forget_dead(winner, base_kept, |id| survivors.iter().any(|s| idx(s) == id));
    }

    #[inline]
    pub fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.finalized.table().write_ssz::<C, W>(&self.pool, w)
    }
}
