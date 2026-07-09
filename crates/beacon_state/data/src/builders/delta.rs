use super::{BuildersGroup, builder_hash, finalized::FinalizedBuilders};
use crate::{
    B256,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder},
    hash_tree::DeltaHashTree,
    ring::{Reset, Slot},
    sparse::Edits,
};

/// Per-fork delta over [`FinalizedBuilders`]. `appended` holds the immutable
/// creation content of new tail indices (absolute index `base_count + p`);
/// `edits` overlays mutations/replacements at any absolute index (base or
/// appended). All mutation routes through `edits` so the winner-prefix drop in
/// `rebase_and_prune_from` stays safe.
#[derive(Clone, Default)]
pub(super) struct BuildersDelta {
    base_count: usize,
    appended: Vec<Builder>,
    edits: Edits<Builder>,
    hash_overlay: DeltaHashTree,
}

impl BuildersDelta {
    pub(super) fn anchor_at(&mut self, base: &FinalizedBuilders) {
        self.base_count = base.len();
        self.hash_overlay = DeltaHashTree::new_at(base.hash());
    }

    pub(super) fn promote_into_base(&self, base: &mut FinalizedBuilders) {
        debug_assert_eq!(
            base.len(),
            self.base_count,
            "promote_into_base: delta.base_count must match the current base count",
        );
        let end = self.base_count + self.appended.len();
        base.builders[self.base_count..end].copy_from_slice(&self.appended);
        self.edits.scatter(&mut base.builders[..end]);
        base.count = end;
        base.hash.promote_delta(&self.hash_overlay);
    }

    pub(super) fn rebase_and_prune_from(
        &mut self,
        old: &Self,
        base: &FinalizedBuilders,
        winner: &Self,
    ) {
        let new_count = winner.base_count + winner.appended.len();

        let promoted = (new_count - old.base_count).min(old.appended.len());
        self.appended = old.appended[promoted..].to_vec();
        self.base_count = new_count;

        self.edits.rebase_and_prune_from(&old.edits, &winner.edits, new_count as u32, |i| {
            base.builders[i as usize]
        });

        self.hash_overlay = old.hash_overlay.clone();
        self.hash_overlay.rebase(base.hash(), &winner.hash_overlay);
        base.hash().prune_delta_against(&mut self.hash_overlay, &winner.hash_overlay);
    }
}

impl Reset for BuildersDelta {
    fn reset(&mut self) {
        self.base_count = 0;
        self.appended.clear();
        self.edits.clear();
        self.hash_overlay = DeltaHashTree::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.base_count = other.base_count;
        self.appended.clone_from(&other.appended);
        self.edits.clone_from(&other.edits);
        self.hash_overlay = other.hash_overlay.clone();
    }
}

#[derive(Clone, Copy)]
pub struct BuildersView<'a> {
    base: &'a FinalizedBuilders,
    delta: &'a BuildersDelta,
}

impl<'a> BuildersView<'a> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedBuilders, delta: &'a BuildersDelta) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.delta.base_count + self.delta.appended.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&'a Builder> {
        if let Some(b) = self.delta.edits.get(i as u32) {
            return Some(b);
        }
        if i < self.delta.base_count {
            self.base.get(i)
        } else {
            self.delta.appended.get(i - self.delta.base_count)
        }
    }

    /// Single forward-cursor merge of the base/appended slots with the sparse
    /// `edits` overlay (no per-element lookup). `Builder` is `Copy`, so this
    /// yields by value.
    pub fn iter(self) -> impl Iterator<Item = Builder> + 'a {
        let base_count = self.delta.base_count;
        let base = self.base.as_slice();
        let appended = self.delta.appended.as_slice();
        self.delta.edits.sweep(
            base_count,
            self.len(),
            move |i| base[i],
            move |i| appended[i - base_count],
        )
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        const LIST_DEPTH: u32 = BUILDER_REGISTRY_LIMIT.trailing_zeros();
        let len = self.len();
        self.delta.hash_overlay.ssz_list_root(self.base.hash(), LIST_DEPTH, len)
    }

    // TODO: replace the linear scan
    pub fn find_by_pubkey(&self, pubkey: &[u8; 48]) -> Option<usize> {
        (0..self.len()).find(|&i| self.get(i).unwrap().pubkey == *pubkey)
    }

    #[inline]
    fn recompute_leaf(&self, i: usize) -> B256 {
        builder_hash(self.get(i).unwrap())
    }
}

pub struct BuildersWriteView<'a> {
    base: &'a FinalizedBuilders,
    fork: Slot<'a, BuildersGroup, BuildersDelta>,
}

impl<'a> BuildersWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedBuilders,
        fork: Slot<'a, BuildersGroup, BuildersDelta>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> super::BuildersId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> BuildersView<'_> {
        BuildersView { base: self.base, delta: &self.fork }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.reader().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.reader().is_empty()
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.reader().hash_root()
    }

    fn refresh_leaf(&mut self, i: usize) {
        let leaf = self.reader().recompute_leaf(i);
        self.fork.hash_overlay.set_leaf(self.base.hash(), i, leaf);
    }

    #[inline]
    pub fn push(&mut self, builder: Builder) {
        assert!(self.len() < BUILDER_REGISTRY_LIMIT, "builders exceeded BUILDER_REGISTRY_LIMIT");
        let idx = self.fork.base_count + self.fork.appended.len();
        self.fork.appended.push(builder);
        self.refresh_leaf(idx);
    }

    #[inline]
    pub fn set_builder(&mut self, i: usize, builder: Builder) {
        self.fork.edits.merge_in_place(&[(i as u32, builder)]);
        self.refresh_leaf(i);
    }

    #[inline]
    pub fn add_balance(&mut self, builder_index: usize, amount: u64) {
        let mut b = *self.reader().get(builder_index).expect("add_balance: index out of range");
        b.balance += amount;
        self.fork.edits.merge_in_place(&[(builder_index as u32, b)]);
        self.refresh_leaf(builder_index);
    }

    #[inline]
    pub fn sub_balance(&mut self, builder_index: usize, amount: u64) {
        let mut b = *self.reader().get(builder_index).expect("sub_balance: index out of range");
        b.balance -= amount.min(b.balance);
        self.set_builder(builder_index, b);
    }

    #[inline]
    pub fn set_withdrawable_epoch(&mut self, builder_index: usize, epoch: u64) {
        let mut b =
            *self.reader().get(builder_index).expect("set_withdrawable_epoch: index out of range");
        b.withdrawable_epoch = epoch;
        self.set_builder(builder_index, b);
    }
}
