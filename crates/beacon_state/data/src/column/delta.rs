use std::marker::PhantomData;

use silver_common_macros::timed;

use super::{ColumnGroup, ColumnSpec, ColumnVal, finalized::FinalizedColumn};
use crate::{
    buffer::{Id, Reset, Slot},
    hash_tree::DeltaHashTree,
    sparse::Edits,
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

/// Per-fork delta of one column: sparse value edits over the finalized base
/// plus the hash overlay over the same chunks. `total` is the fork's list
/// length, grown in lockstep with the validator registry.
#[derive(Default)]
pub(crate) struct ColumnDelta<V> {
    edits: Edits<V>,
    hash: DeltaHashTree,
    total: usize,
}

impl<V: ColumnVal> ColumnDelta<V> {
    /// Seed the fork length from `base` after a ring roll — `edits`/`hash` are
    /// already empty, so only the length needs setting.
    pub(super) fn anchor_at(&mut self, base: &FinalizedColumn<V>) {
        self.total = base.count;
    }

    pub(super) fn rebase_and_prune_from(
        &mut self,
        old: &Self,
        base: &FinalizedColumn<V>,
        winner: &Self,
    ) {
        self.total = old.total;
        self.edits.rebase_and_prune_from(&old.edits, &winner.edits, winner.total as u32, |idx| {
            base.data[idx as usize]
        });

        // Don't rebase hash part as it is slow because:
        // * Rebase is slow as almost all elements are updated
        // * We don't use finalize part of hash tree
        self.hash = old.hash.clone();
    }

    /// Fold the delta into `base`: edits into `data`, fork length into the
    /// count, and the overlay's cached hashes into the tree (zero SHA).
    pub(super) fn promote_into_base(&self, base: &mut FinalizedColumn<V>) {
        for &(idx, v) in self.edits.iter() {
            base.data[idx as usize] = v;
        }
        base.count = self.total;
        base.hash.promote_delta(&self.hash);
    }
}

impl<V: Copy> Reset for ColumnDelta<V> {
    fn reset(&mut self) {
        self.edits.clear();
        self.hash.reset();
        self.total = 0;
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.hash.reset_from(&other.hash);
        self.total = other.total;
    }
}

/// Resolve chunk's 32-byte leaf from the merged base+edits values.
fn chunk_leaf<V: ColumnVal>(data: &[V], edits: &Edits<V>, chunk: u32) -> B256 {
    let per_chunk = V::VALS_PER_CHUNK;
    let b = chunk as usize * per_chunk;
    let mut vals = [V::default(); 32];
    let vals = &mut vals[..per_chunk];
    vals.copy_from_slice(&data[b..b + per_chunk]);

    for &(k, v) in edits.iter_from(b as u32).take_while(|(k, _)| (*k as usize) < b + per_chunk) {
        vals[k as usize - b] = v;
    }
    V::pack_leaf(vals)
}

/// Read handle over base + delta: value reads (`get`/`iter`) plus the SSZ list
/// root. `get`/`iter` never touch the hash overlay, so lock-free value readers
/// can't race the writer; `hash_root` reads it and stays writer-side.
pub struct ColumnReader<'a, C: ColumnSpec> {
    finalized: &'a FinalizedColumn<C::Val>,
    delta: &'a ColumnDelta<C::Val>,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedColumn<C::Val>, delta: &'a ColumnDelta<C::Val>) -> Self {
        Self { finalized: base, delta, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        if let Some(v) = self.delta.edits.get(ix as u32).copied() {
            return v;
        }
        if ix < self.finalized.count { self.finalized.data[ix] } else { C::Val::default() }
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        self.delta.edits.sweep(
            self.finalized.count,
            self.delta.total,
            |i| self.finalized.data[i],
            |_| C::Val::default(),
        )
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        let chunk_depth = (VALIDATOR_REGISTRY_LIMIT / C::Val::VALS_PER_CHUNK).trailing_zeros();
        self.delta.hash.ssz_list_root(&self.finalized.hash, chunk_depth, self.delta.total)
    }
}

pub struct ColumnWriteView<'a, C: ColumnSpec> {
    finalized: &'a FinalizedColumn<C::Val>,
    delta: Slot<'a, ColumnGroup<C>, ColumnDelta<C::Val>>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(
        finalized: &'a FinalizedColumn<C::Val>,
        delta: Slot<'a, ColumnGroup<C>, ColumnDelta<C::Val>>,
    ) -> Self {
        Self { finalized, delta }
    }

    #[inline]
    pub fn commit(self) -> Id<ColumnGroup<C>> {
        self.delta.commit()
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: C::Val) {
        self.set_many(&[(idx, v)]);
    }

    /// Merge a sorted, distinct-index batch in O(|edits| + |batch|), keeping
    /// base-equal entries (the read sweep / rebase tolerate redundant edits),
    /// then recompute each dirty chunk's leaf in the hash overlay.
    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_many input must be ascending with distinct indices",
        );
        let ColumnDelta { edits, hash, .. } = &mut *self.delta;
        edits.merge_in_place(changes);

        let per_chunk = C::Val::VALS_PER_CHUNK as u32;
        let mut leaves: Vec<(u32, B256)> = Vec::with_capacity(changes.len());
        for group in changes.chunk_by(|a, b| a.0 / per_chunk == b.0 / per_chunk) {
            let chunk = group[0].0 / per_chunk;
            leaves.push((chunk, chunk_leaf(&self.finalized.data, edits, chunk)));
        }
        hash.set_leaves(&self.finalized.hash, &leaves);
    }

    /// Append a value for a newly-registered validator (+1 length) — columns
    /// move in lockstep with the registry so the lengths stay aligned.
    pub fn append(&mut self, v: C::Val) -> u32 {
        let idx = self.delta.total as u32;
        self.delta.total += 1;
        self.set(idx, v);
        idx
    }

    #[inline]
    pub fn reader(&self) -> ColumnReader<'_, C> {
        ColumnReader::new(self.finalized, &self.delta)
    }

    // Read-through conveniences (a `Deref` to `ColumnReader` is impossible —
    // the reader borrows the delta shared while we hold it `&mut`).
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
