use super::{BalancesGroup, BalancesId, finalized::FinalizedBalances, pack_chunk};
use crate::{
    buffer::{Reset, Slot},
    hash_tree::DeltaHashTree,
    sparse::Edits,
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

#[derive(Default, Clone)]
pub(crate) struct BalancesDelta {
    edits: Edits<u64>,
    hash_delta: DeltaHashTree,
    total: usize,
}

impl BalancesDelta {
    /// Anchor a freshly [`reset`](Reset::reset) delta at `base`'s finalized
    /// count, in place. Called right after a ring roll, so `edits`/`hash_delta`
    /// are already empty (and keep their allocated capacity for reuse); only
    /// the length needs seeding. Mirrors `ValidatorsDelta::new_at`.
    pub(super) fn anchor_at(&mut self, base: &FinalizedBalances) {
        self.total = base.count();
    }

    /// Fill `out` (a fresh, just-rolled slot) with `self` (a survivor)
    /// finalized against a promoted `winner`. `self` is only read — it
    /// stays frozen for lock-free readers. Run against the still-**old**
    /// `base`, before [`promote_into_base`](Self::promote_into_base). Both
    /// halves rebase pins + prune redundancy in one pass against the
    /// *logical* new base (the winner's override else the old base): values
    /// via [`Edits::rebase_and_prune`], the hash overlay via `rebase`
    /// (freeze winner-moved leaves) then `prune_delta_against` (collapse
    /// leaves that already equal the new base).
    ///
    /// The two count bounds are intrinsic: `valid_below` (the indices that
    /// existed in the pre-promote base, so a winner override there pins the old
    /// value) is `base.count()`, still the old count since promotion is later;
    /// the new count below which an edit is redundant is the winner's length,
    /// which [`promote_into_base`](Self::promote_into_base) writes into the
    /// base.
    pub(super) fn rebase_and_prune(
        &self,
        out: &mut BalancesDelta,
        base: &FinalizedBalances,
        winner: &BalancesDelta,
    ) {
        out.total = self.total;
        out.edits = self.edits.rebase_and_prune(
            &winner.edits,
            base.count() as u32,
            winner.total as u32,
            |idx| base.data[idx as usize],
            |idx| winner.edits.get(idx).copied().unwrap_or(base.data[idx as usize]),
        );
        out.hash_delta = self.hash_delta.clone();
        out.hash_delta.rebase(&base.hash, &winner.hash_delta);
        base.hash.prune_delta_against(&mut out.hash_delta, &winner.hash_delta);
    }

    /// Fold this delta into `base`: edits into `data`, the fork length into the
    /// base count, then promote the hash overlay's cached hashes (zero SHA).
    pub(super) fn promote_into_base(&self, base: &mut FinalizedBalances) {
        base.apply_edits(&self.edits);
        base.count = self.total;
        base.hash.promote_delta(&self.hash_delta);
    }
}

impl Reset for BalancesDelta {
    fn reset(&mut self) {
        self.edits.clear();
        self.hash_delta = DeltaHashTree::default();
        self.total = 0;
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.hash_delta = other.hash_delta.clone();
        self.total = other.total;
    }
}

/// Value-only read over base + delta — never touches the hash overlay, so a
/// concurrent reader holding one cannot race the writer's hash mutations. The
/// length is intrinsic: the finalized count lives in `base`, the fork's count
/// in the delta — no external length is supplied.
#[derive(Clone, Copy)]
pub struct BalancesView<'a> {
    delta: &'a BalancesDelta,
    base: &'a FinalizedBalances,
}

impl<'a> BalancesView<'a> {
    #[inline]
    pub fn get(&self, ix: usize) -> u64 {
        if let Some(v) = self.delta.edits.get(ix as u32).copied() {
            return v;
        }
        if ix < self.base.count { self.base.data[ix] } else { 0 }
    }

    pub fn iter(self) -> impl Iterator<Item = u64> + 'a {
        let mut edit_iter = self.delta.edits.iter().peekable();
        let base = &self.base.data[..self.base.count];
        (0..self.delta.total).map(move |i| {
            if edit_iter.peek().is_some_and(|(idx, _)| *idx as usize == i) {
                edit_iter.next().unwrap().1
            } else if i < base.len() {
                base[i]
            } else {
                0
            }
        })
    }
}

/// Reader handed out by the writer's view: the value reads of [`BalancesView`]
/// **plus** the SSZ list root. `hash_root` reads the hash overlay, so this is
/// writer-side only — the concurrent read path takes the value-only
/// [`BalancesView`] (via [`values`](Self::values)) and can never reach it.
#[derive(Clone, Copy)]
pub struct BalancesReader<'a> {
    view: BalancesView<'a>,
}

impl<'a> BalancesReader<'a> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedBalances, delta: &'a BalancesDelta) -> Self {
        Self { view: BalancesView { delta, base } }
    }

    #[inline]
    pub fn get(&self, ix: usize) -> u64 {
        self.view.get(ix)
    }

    #[inline]
    pub fn iter(self) -> impl Iterator<Item = u64> + 'a {
        self.view.iter()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        const CHUNK_DEPTH: u32 = (VALIDATOR_REGISTRY_LIMIT / 4).trailing_zeros();
        let v = &self.view;
        v.delta.hash_delta.ssz_list_root(&v.base.hash, CHUNK_DEPTH, v.delta.total)
    }

    #[inline]
    pub fn values(self) -> BalancesView<'a> {
        self.view
    }
}

pub struct BalancesWriteView<'a> {
    base: &'a FinalizedBalances,
    fork: Slot<'a, BalancesGroup, BalancesDelta>,
}

impl<'a> BalancesWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedBalances,
        fork: Slot<'a, BalancesGroup, BalancesDelta>,
    ) -> Self {
        Self { base, fork }
    }

    /// Consume the writer and surface the fork's typed id — the read handle to
    /// store and to feed back into rolling children / finalize. Delegates to
    /// [`Slot::commit`]: taking `self` by value ends this writer's borrow, so
    /// the slot can't be mutated through it after publishing.
    #[inline]
    pub fn commit(self) -> BalancesId {
        self.fork.commit()
    }

    #[inline]
    pub fn set(&mut self, idx: u32, v: u64) {
        self.set_many(&[(idx, v)]);
    }

    pub fn set_many(&mut self, changes: &[(u32, u64)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_many input must be ascending with distinct indices",
        );
        self.fork.edits.merge_in_place(changes);

        for group in changes.chunk_by(|a, b| a.0 / 4 == b.0 / 4) {
            self.recompute_chunk(group[0].0 / 4);
        }
    }

    /// Append a balance for a newly-registered validator, growing the fork's
    /// length by one. Mirrors `ValidatorsDelta::append`; the two must move in
    /// lockstep so the lengths agree.
    pub fn append(&mut self, v: u64) -> u32 {
        let idx = self.fork.total as u32;
        self.fork.total += 1;
        self.set(idx, v);
        idx
    }

    #[inline]
    pub fn reader(&self) -> BalancesReader<'_> {
        BalancesReader::new(self.base, &self.fork)
    }

    // Read-through conveniences (a `Deref` to `BalancesReader` is impossible —
    // the reader borrows the delta shared while we hold it `&mut`).
    #[inline]
    pub fn get(&self, ix: usize) -> u64 {
        self.reader().get(ix)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.reader().iter()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.reader().hash_root()
    }

    fn recompute_chunk(&mut self, chunk: u32) {
        let base = self.base;
        let b = (chunk * 4) as usize;
        let mut vals = [base.data[b], base.data[b + 1], base.data[b + 2], base.data[b + 3]];

        let start = self.fork.edits.partition_point(|(k, _)| (*k as usize) < b);
        for &(k, v) in self.fork.edits.iter_from(start).take_while(|(k, _)| (*k as usize) < b + 4) {
            vals[k as usize - b] = v;
        }
        self.fork.hash_delta.set_leaf(&base.hash, chunk as usize, pack_chunk(vals));
    }
}
