use std::marker::PhantomData;

use flux_profiler::timed;

use super::{ColumnGroup, ColumnSpec, ColumnVal, tree::ColumnTree};
use crate::{
    buffer::{Id, Slot},
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

/// Read handle over a fork's whole column tree: value reads (`get`/`iter`) plus
/// the SSZ list root. Values are unpacked straight from the (fixed, committed)
/// leaf row, so lock-free cross-thread readers can't race the writer.
pub struct ColumnReader<'a, C: ColumnSpec> {
    tree: &'a ColumnTree,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn new(tree: &'a ColumnTree) -> Self {
        Self { tree, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.tree.get::<C::Val>(ix)
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        self.tree.iter::<C::Val>()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        let list_depth = (VALIDATOR_REGISTRY_LIMIT / C::Val::VALS_PER_CHUNK).trailing_zeros();
        self.tree.ssz_list_root(list_depth)
    }
}

pub struct ColumnWriteView<'a, C: ColumnSpec> {
    tree: Slot<'a, ColumnGroup<C>, ColumnTree>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(tree: Slot<'a, ColumnGroup<C>, ColumnTree>) -> Self {
        Self { tree }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.tree.commit()
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.set_many(&[(idx, v)]);
    }

    /// Repack each touched chunk's leaf (seeded from its current value) and
    /// write them through [`ColumnTree::set_leaves`], which recomputes the
    /// touched ancestor paths in place.
    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_many input must be ascending with distinct indices",
        );
        let k = C::Val::VALS_PER_CHUNK as u32;

        let mut leaves: Vec<(u32, B256)> = Vec::with_capacity(changes.len());
        for group in changes.chunk_by(|a, b| a.0 / k == b.0 / k) {
            let chunk = group[0].0 / k;
            let mut leaf = *self.tree.leaf(chunk);
            for &(idx, v) in group {
                C::Val::set_lane(&mut leaf, (idx % k) as usize, v);
            }
            leaves.push((chunk, leaf));
        }
        self.tree.set_leaves(&leaves);
    }

    /// Append a value for a newly-registered validator (+1 length) — columns
    /// move in lockstep with the registry so the lengths stay aligned.
    #[inline]
    pub fn append(&mut self, v: C::Val) -> u32 {
        self.tree.append(v)
    }

    #[inline]
    pub fn reader(&self) -> ColumnReader<'_, C> {
        ColumnReader::new(&self.tree)
    }

    // Read-through conveniences (a `Deref` to `ColumnReader` is impossible —
    // the reader borrows the tree shared while we hold it `&mut`).
    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = C::Val> + '_ {
        self.reader().iter()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.reader().hash_root()
    }
}
