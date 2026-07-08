use std::marker::PhantomData;

use flux_profiler::timed;

use super::{ColumnGroup, finalized::FinalizedColumn};
use crate::{
    buffer::{Id, Reset, Slot},
    column::{ColumnSpec, ColumnVal},
    hash_tree::DeltaHashTree,
    sparse::Edits,
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

#[derive(Default)]
pub(super) struct ColumnDelta {
    /// Keyed by chunk index, not element index: a stored group holds the
    /// chunk's every lane (dirty ones the fork's value, clean ones the base
    /// value at materialisation), so it doubles as the merkle leaf and the
    /// hash overlay shares its index.
    edits: Edits<B256>,
    hash: DeltaHashTree,
    /// Element count, grown in lockstep with the validator registry.
    total: usize,
}

impl ColumnDelta {
    /// Seed the fork length from `base` after a ring roll — `edits`/`hash` are
    /// already empty, so only the length needs setting.
    pub(super) fn anchor_at<V: ColumnVal>(&mut self, base: &FinalizedColumn<V>) {
        self.total = base.count;
    }

    pub(super) fn rebase_and_prune_from<V: ColumnVal>(
        &mut self,
        old: &Self,
        base: &FinalizedColumn<V>,
        winner: &Self,
    ) {
        self.total = old.total;
        let base_chunks = winner.total.div_ceil(V::VALS_PER_CHUNK) as u32;
        self.edits.rebase_and_prune_from(&old.edits, &winner.edits, base_chunks, |chunk| {
            base.group(chunk)
        });

        // Don't rebase hash part as it is slow because:
        // * Rebase is slow as almost all elements are updated
        // * We don't use finalize part of hash tree
        self.hash = old.hash.clone();
    }

    /// Zero SHA: stored groups and the overlay's cached hashes fold in as-is.
    pub(super) fn promote_into_base<V: ColumnVal>(&self, base: &mut FinalizedColumn<V>) {
        let k = V::VALS_PER_CHUNK;
        for &(chunk, group) in self.edits.iter() {
            let b = chunk as usize * k;
            V::read_ssz_slice(&mut base.data[b..b + k], &group);
        }
        base.count = self.total;
        base.hash.promote_delta(&self.hash);
    }
}

impl Reset for ColumnDelta {
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

/// Read handle over base + delta: value reads (`get`/`iter`) plus the SSZ list
/// root. `get`/`iter` never touch the hash overlay, so lock-free value readers
/// can't race the writer; `hash_root` reads it and stays writer-side.
pub struct ColumnReader<'a, C: ColumnSpec> {
    finalized: &'a FinalizedColumn<C::Val>,
    delta: &'a ColumnDelta,
    _marker: PhantomData<fn() -> C>,
}

impl<'a, C: ColumnSpec> ColumnReader<'a, C> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedColumn<C::Val>, delta: &'a ColumnDelta) -> Self {
        Self { finalized: base, delta, _marker: PhantomData }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> C::Val {
        let k = C::Val::VALS_PER_CHUNK;
        if let Some(group) = self.delta.edits.get((ix / k) as u32) {
            return C::Val::lane(group, ix % k);
        }
        if ix < self.finalized.count { self.finalized.data[ix] } else { C::Val::default() }
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = C::Val> + 'a {
        let k = C::Val::VALS_PER_CHUNK;
        let edits = self.delta.edits.as_slice();
        let base = self.finalized;
        let mut cursor = 0usize;
        (0..self.delta.total).map(move |i| {
            let chunk = (i / k) as u32;
            while cursor < edits.len() && edits[cursor].0 < chunk {
                cursor += 1;
            }
            if cursor < edits.len() && edits[cursor].0 == chunk {
                C::Val::lane(&edits[cursor].1, i % k)
            } else if i < base.count {
                base.data[i]
            } else {
                C::Val::default()
            }
        })
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        let chunk_depth = (VALIDATOR_REGISTRY_LIMIT / C::Val::VALS_PER_CHUNK).trailing_zeros();
        self.delta.hash.ssz_list_root(&self.finalized.hash, chunk_depth, self.delta.total)
    }
}

pub struct ColumnWriteView<'a, C: ColumnSpec> {
    finalized: &'a FinalizedColumn<C::Val>,
    delta: Slot<'a, ColumnGroup<C>, ColumnDelta>,
}

impl<'a, C: ColumnSpec> ColumnWriteView<'a, C> {
    #[inline]
    pub(super) fn new(
        finalized: &'a FinalizedColumn<C::Val>,
        delta: Slot<'a, ColumnGroup<C>, ColumnDelta>,
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

    /// Each touched chunk's group is rebuilt (seeded from its prior edit, else
    /// the base) and, being both value edit and hash leaf, feeds `edits` and
    /// the hash overlay alike.
    #[timed]
    pub fn set_many(&mut self, changes: &[(u32, C::Val)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_many input must be ascending with distinct indices",
        );
        let k = C::Val::VALS_PER_CHUNK as u32;
        let ColumnDelta { edits, hash, .. } = &mut *self.delta;

        let mut leaves: Vec<(u32, B256)> = Vec::with_capacity(changes.len());
        let mut cursor = 0;
        for group in changes.chunk_by(|a, b| a.0 / k == b.0 / k) {
            let chunk = group[0].0 / k;
            let mut leaf = edits
                .get_from(&mut cursor, chunk)
                .copied()
                .unwrap_or_else(|| self.finalized.group(chunk));
            for &(idx, v) in group {
                C::Val::set_lane(&mut leaf, (idx % k) as usize, v);
            }
            leaves.push((chunk, leaf));
        }

        edits.merge_in_place(&leaves);
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
