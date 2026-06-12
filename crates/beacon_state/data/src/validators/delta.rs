use blst::min_pk::PublicKey;

use super::{FinalizedValidators, ValidatorsGroup, ValidatorsId, validator_hash};
use crate::{
    B256, Withdrawals,
    buffer::{Reset, Slot as RingSlot},
    hash_tree::DeltaHashTree,
    sparse::Edits,
    types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH, VALIDATOR_REGISTRY_LIMIT},
};

#[derive(Clone, PartialEq)]
pub struct AppendedValidator {
    pub pubkey: BLSPubkey,
    pub pubkey_decompressed: PublicKey,
    pub credentials: Withdrawals,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl AppendedValidator {
    #[inline]
    pub fn new(
        pubkey: BLSPubkey,
        pubkey_decompressed: PublicKey,
        credentials: Withdrawals,
    ) -> Self {
        Self {
            pubkey,
            pubkey_decompressed,
            credentials,
            effective_balance: 0,
            slashed: false,
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// Per-fork delta over [`FinalizedValidators`]. Sparse edits per mutable
/// Validator-container field + appended new-validator records + a hash
/// overlay keyed by leaf index.
///
/// `appended[p]`'s absolute validator index is `base_count + p`. The `_edits`
/// vecs are sparse, sorted by absolute index. Edits may target either a
/// base validator (idx < base_count) or an appended one (idx >= base_count).
#[derive(Default, Clone)]
pub struct ValidatorsDelta {
    pub base_count: usize,
    pub appended: Vec<AppendedValidator>,
    pub credentials_edits: Edits<Withdrawals>,
    pub effective_balance_edits: Edits<u64>,
    pub slashed_edits: Edits<bool>,
    pub activation_eligibility_epoch_edits: Edits<Epoch>,
    pub activation_epoch_edits: Edits<Epoch>,
    pub exit_epoch_edits: Edits<Epoch>,
    pub withdrawable_epoch_edits: Edits<Epoch>,
    pub hash_overlay: DeltaHashTree,
}

impl ValidatorsDelta {
    /// Empty delta over `base`.
    pub fn new_at(base: &FinalizedValidators) -> Self {
        let mut d = Self::default();
        d.anchor_at(base);
        d
    }

    /// Absolute index of an appended validator matching `pubkey`.
    /// Linear scan — `appended` is bounded by deposits-since-finalization.
    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.appended.iter().position(|a| &a.pubkey == pubkey).map(|p| self.base_count + p)
    }

    #[inline]
    pub fn effective_credentials<'a>(
        &'a self,
        base: &'a FinalizedValidators,
        idx: u32,
    ) -> &'a Withdrawals {
        if let Some(v) = self.credentials_edits.get(idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_count {
            base.withdrawal_credentials(i)
        } else {
            &self.appended[i - self.base_count].credentials
        }
    }

    #[inline]
    pub fn effective_pubkey<'a>(
        &'a self,
        base: &'a FinalizedValidators,
        idx: u32,
    ) -> &'a BLSPubkey {
        let i = idx as usize;
        if i < self.base_count {
            base.pubkey(i)
        } else {
            &self.appended[i - self.base_count].pubkey
        }
    }

    #[inline]
    pub fn effective_pubkey_decompressed<'a>(
        &'a self,
        base: &'a FinalizedValidators,
        idx: u32,
    ) -> &'a PublicKey {
        let i = idx as usize;
        if i < self.base_count {
            base.pubkey_decompressed(i)
        } else {
            &self.appended[i - self.base_count].pubkey_decompressed
        }
    }

    /// Effective value of a `Copy` field at `idx`: base column when
    /// `idx < base_count`, otherwise the appended record's field.
    #[inline]
    fn base_field<T>(
        &self,
        base: &FinalizedValidators,
        idx: u32,
        from_base: impl Fn(&FinalizedValidators, usize) -> T,
        from_appended: impl Fn(&AppendedValidator) -> T,
    ) -> T {
        let i = idx as usize;
        if i < self.base_count {
            from_base(base, i)
        } else {
            from_appended(&self.appended[i - self.base_count])
        }
    }

    #[inline]
    pub fn effective_balance(&self, base: &FinalizedValidators, idx: u32) -> u64 {
        self.effective_balance_edits.get(idx).copied().unwrap_or_else(|| {
            self.base_field(base, idx, |b, i| b.effective_balance(i), |a| a.effective_balance)
        })
    }

    #[inline]
    pub fn is_slashed(&self, base: &FinalizedValidators, idx: u32) -> bool {
        self.slashed_edits
            .get(idx)
            .copied()
            .unwrap_or_else(|| self.base_field(base, idx, |b, i| b.is_slashed(i), |a| a.slashed))
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.activation_eligibility_epoch_edits.get(idx).copied().unwrap_or_else(|| {
            self.base_field(
                base,
                idx,
                |b, i| b.activation_eligibility_epoch(i),
                |a| a.activation_eligibility_epoch,
            )
        })
    }

    #[inline]
    pub fn activation_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.activation_epoch_edits.get(idx).copied().unwrap_or_else(|| {
            self.base_field(base, idx, |b, i| b.activation_epoch(i), |a| a.activation_epoch)
        })
    }

    #[inline]
    pub fn exit_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.exit_epoch_edits
            .get(idx)
            .copied()
            .unwrap_or_else(|| self.base_field(base, idx, |b, i| b.exit_epoch(i), |a| a.exit_epoch))
    }

    #[inline]
    pub fn withdrawable_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.withdrawable_epoch_edits.get(idx).copied().unwrap_or_else(|| {
            self.base_field(base, idx, |b, i| b.withdrawable_epoch(i), |a| a.withdrawable_epoch)
        })
    }

    /// Recompute the Validator-container hash leaf for `idx` from the
    /// current effective state (overlay + base). Used by every mutator
    /// to keep `hash_overlay` consistent with the field edits.
    pub fn recompute_leaf(&self, base: &FinalizedValidators, idx: u32) -> B256 {
        validator_hash(
            self.effective_pubkey(base, idx),
            self.effective_credentials(base, idx),
            self.effective_balance(base, idx),
            self.is_slashed(base, idx),
            self.activation_eligibility_epoch(base, idx),
            self.activation_epoch(base, idx),
            self.exit_epoch(base, idx),
            self.withdrawable_epoch(base, idx),
        )
    }

    /// SSZ `hash_tree_root` of the validators registry
    /// (`List[Validator, VALIDATOR_REGISTRY_LIMIT]`) from the persistent hash
    /// overlay: finalized base tree + this fork's cached delta-node hashes,
    /// zero work for untouched subtrees. The physical tree only spans the
    /// registry capacity's leaves, so extend its root with zero subtrees up to
    /// the registry-limit depth, then mix in the validator count.
    pub fn hash_root(&self, base: &FinalizedValidators) -> B256 {
        const LIST_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.trailing_zeros();
        let len = self.base_count + self.appended.len();
        self.hash_overlay.ssz_list_root(base.hash(), LIST_DEPTH, len)
    }

    /// Recompute and store the hash leaf for `idx` — every field write calls
    /// this to keep `hash_overlay` consistent with the edits.
    fn refresh_leaf(&mut self, base: &FinalizedValidators, idx: u32) {
        let leaf = self.recompute_leaf(base, idx);
        self.hash_overlay.set_leaf(base.hash(), idx as usize, leaf);
    }

    /// Append a fresh validator with spec-default Validator-container
    /// fields. Returns the absolute index of the new validator.
    pub fn append(
        &mut self,
        base: &FinalizedValidators,
        pubkey: BLSPubkey,
        pubkey_decompressed: PublicKey,
        credentials: Withdrawals,
    ) -> u32 {
        let idx = (self.base_count + self.appended.len()) as u32;
        self.appended.push(AppendedValidator::new(pubkey, pubkey_decompressed, credentials));

        self.refresh_leaf(base, idx);
        idx
    }

    pub fn set_credentials(&mut self, base: &FinalizedValidators, idx: u32, v: Withdrawals) {
        self.credentials_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_effective_balance(&mut self, base: &FinalizedValidators, idx: u32, v: u64) {
        self.effective_balance_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_slashed(&mut self, base: &FinalizedValidators, idx: u32, v: bool) {
        self.slashed_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_activation_eligibility_epoch(
        &mut self,
        base: &FinalizedValidators,
        idx: u32,
        v: Epoch,
    ) {
        self.activation_eligibility_epoch_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_activation_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        self.activation_epoch_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_exit_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        self.exit_epoch_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    pub fn set_withdrawable_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        self.withdrawable_epoch_edits.merge_in_place(&[(idx, v)]);
        self.refresh_leaf(base, idx);
    }

    /// Fold this delta into `base`. Appended records advance
    /// `base.validator_count`; per-field edits land at their absolute
    /// indices.
    pub fn promote_into_base(&self, base: &mut FinalizedValidators) {
        debug_assert_eq!(
            base.validator_count(),
            self.base_count,
            "promote_into_base: delta.base_count must match the current base count",
        );

        // 1. Append new identities (with their baked-in defaults).
        for a in &self.appended {
            base.append(a);
        }

        // 2. Apply per-field edits in index order.
        for &(idx, v) in self.credentials_edits.iter() {
            base.set_withdrawal_credentials_at(idx as usize, v);
        }
        for &(idx, v) in self.effective_balance_edits.iter() {
            base.set_effective_balance_at(idx as usize, v);
        }
        for &(idx, v) in self.slashed_edits.iter() {
            base.set_slashed_at(idx as usize, v);
        }
        for &(idx, v) in self.activation_eligibility_epoch_edits.iter() {
            base.set_activation_eligibility_epoch_at(idx as usize, v);
        }
        for &(idx, v) in self.activation_epoch_edits.iter() {
            base.set_activation_epoch_at(idx as usize, v);
        }
        for &(idx, v) in self.exit_epoch_edits.iter() {
            base.set_exit_epoch_at(idx as usize, v);
        }
        for &(idx, v) in self.withdrawable_epoch_edits.iter() {
            base.set_withdrawable_epoch_at(idx as usize, v);
        }

        // 3. Fold the hash overlay into the finalized tree.
        base.hash_mut().promote_delta(&self.hash_overlay);
    }

    /// Mirror of [`BalancesDelta::rebase_and_prune`] for the multi-column
    /// registry: finalize survivor `self` into `out` against promoted `winner`,
    /// pre-promote and read-only so lock-free readers stay unblocked. The
    /// winner-promoted prefix of `appended` is dropped; every column delegates
    /// the rebase/prune to
    /// [`rebase_and_prune_sparse`](crate::sparse::rebase_and_prune_sparse).
    pub(super) fn rebase_and_prune(
        &self,
        out: &mut ValidatorsDelta,
        base: &FinalizedValidators,
        winner: &ValidatorsDelta,
    ) {
        let valid_below = base.validator_count() as u32;
        let new_count = (winner.base_count + winner.appended.len()) as u32;

        let promoted = (new_count as usize - self.base_count).min(self.appended.len());
        out.appended = self.appended[promoted..].to_vec();
        out.base_count = new_count as usize;

        out.credentials_edits = self.credentials_edits.rebase_and_prune(
            &winner.credentials_edits,
            valid_below,
            new_count,
            |i| *base.withdrawal_credentials(i as usize),
            |i| *winner.effective_credentials(base, i),
        );
        out.effective_balance_edits = self.effective_balance_edits.rebase_and_prune(
            &winner.effective_balance_edits,
            valid_below,
            new_count,
            |i| base.effective_balance(i as usize),
            |i| winner.effective_balance(base, i),
        );
        out.slashed_edits = self.slashed_edits.rebase_and_prune(
            &winner.slashed_edits,
            valid_below,
            new_count,
            |i| base.is_slashed(i as usize),
            |i| winner.is_slashed(base, i),
        );
        out.activation_eligibility_epoch_edits =
            self.activation_eligibility_epoch_edits.rebase_and_prune(
                &winner.activation_eligibility_epoch_edits,
                valid_below,
                new_count,
                |i| base.activation_eligibility_epoch(i as usize),
                |i| winner.activation_eligibility_epoch(base, i),
            );
        out.activation_epoch_edits = self.activation_epoch_edits.rebase_and_prune(
            &winner.activation_epoch_edits,
            valid_below,
            new_count,
            |i| base.activation_epoch(i as usize),
            |i| winner.activation_epoch(base, i),
        );
        out.exit_epoch_edits = self.exit_epoch_edits.rebase_and_prune(
            &winner.exit_epoch_edits,
            valid_below,
            new_count,
            |i| base.exit_epoch(i as usize),
            |i| winner.exit_epoch(base, i),
        );
        out.withdrawable_epoch_edits = self.withdrawable_epoch_edits.rebase_and_prune(
            &winner.withdrawable_epoch_edits,
            valid_below,
            new_count,
            |i| base.withdrawable_epoch(i as usize),
            |i| winner.withdrawable_epoch(base, i),
        );

        out.hash_overlay = self.hash_overlay.clone();
        out.hash_overlay.rebase(base.hash(), &winner.hash_overlay);
        base.hash().prune_delta_against(&mut out.hash_overlay, &winner.hash_overlay);
    }

    /// Reconcile with an advanced base: drop edits that the promoted base
    /// already reflects, and re-anchor `base_count`. Caller must invoke this
    /// on every surviving descendant fork (including the promoter itself)
    /// after `promote_into_base`.
    pub fn prune_to_base(&mut self, base: &FinalizedValidators) {
        let new_base_count = base.validator_count();
        debug_assert!(new_base_count >= self.base_count, "base count cannot regress");

        let promoted = (new_base_count - self.base_count).min(self.appended.len());
        self.appended.drain(..promoted);
        self.base_count = new_base_count;

        self.credentials_edits.retain_diverged(new_base_count, |i| *base.withdrawal_credentials(i));
        self.effective_balance_edits.retain_diverged(new_base_count, |i| base.effective_balance(i));
        self.slashed_edits.retain_diverged(new_base_count, |i| base.is_slashed(i));
        self.activation_eligibility_epoch_edits
            .retain_diverged(new_base_count, |i| base.activation_eligibility_epoch(i));
        self.activation_epoch_edits.retain_diverged(new_base_count, |i| base.activation_epoch(i));
        self.exit_epoch_edits.retain_diverged(new_base_count, |i| base.exit_epoch(i));
        self.withdrawable_epoch_edits
            .retain_diverged(new_base_count, |i| base.withdrawable_epoch(i));

        base.hash().prune_delta(&mut self.hash_overlay);
    }

    /// Anchor a freshly-`reset` delta onto `base`: adopt its count and hash
    /// root (edits/appended already empty). Used by `roll_fresh`.
    pub(super) fn anchor_at(&mut self, base: &FinalizedValidators) {
        self.base_count = base.validator_count();
        self.hash_overlay = DeltaHashTree::new_at(base.hash());
    }
}

impl Reset for ValidatorsDelta {
    fn reset(&mut self) {
        self.base_count = 0;
        self.appended.clear();
        self.credentials_edits.clear();
        self.effective_balance_edits.clear();
        self.slashed_edits.clear();
        self.activation_eligibility_epoch_edits.clear();
        self.activation_epoch_edits.clear();
        self.exit_epoch_edits.clear();
        self.withdrawable_epoch_edits.clear();
        self.hash_overlay = DeltaHashTree::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.base_count = other.base_count;
        self.appended.clone_from(&other.appended);
        self.credentials_edits.clone_from(&other.credentials_edits);
        self.effective_balance_edits.clone_from(&other.effective_balance_edits);
        self.slashed_edits.clone_from(&other.slashed_edits);
        self.activation_eligibility_epoch_edits
            .clone_from(&other.activation_eligibility_epoch_edits);
        self.activation_epoch_edits.clone_from(&other.activation_epoch_edits);
        self.exit_epoch_edits.clone_from(&other.exit_epoch_edits);
        self.withdrawable_epoch_edits.clone_from(&other.withdrawable_epoch_edits);
        // O(1) — `DeltaHashTree::Clone` bumps the Arc refcount.
        self.hash_overlay = other.hash_overlay.clone();
    }
}

/// Value-layer read over the validator registry (base + optional per-fork
/// delta). Built only from a published fork id (or a held writer) — the
/// delta is always present; pre-snapshot readers get no view at all.
#[derive(Clone, Copy)]
pub struct ValidatorsView<'a> {
    base: &'a FinalizedValidators,
    delta: &'a ValidatorsDelta,
}

impl<'a> ValidatorsView<'a> {
    #[inline]
    pub(crate) fn new(base: &'a FinalizedValidators, delta: &'a ValidatorsDelta) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.delta.base_count + self.delta.appended.len()
    }

    #[inline]
    pub fn pubkey(&self, ix: usize) -> &'a BLSPubkey {
        self.delta.effective_pubkey(self.base, ix as u32)
    }

    #[inline]
    pub fn pubkey_decompressed(&self, ix: usize) -> &'a PublicKey {
        self.delta.effective_pubkey_decompressed(self.base, ix as u32)
    }

    #[inline]
    pub fn credentials(&self, ix: usize) -> &'a Withdrawals {
        self.delta.effective_credentials(self.base, ix as u32)
    }

    #[inline]
    pub fn effective_balance(&self, ix: usize) -> u64 {
        self.delta.effective_balance(self.base, ix as u32)
    }

    #[inline]
    pub fn is_slashed(&self, ix: usize) -> bool {
        self.delta.is_slashed(self.base, ix as u32)
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, ix: usize) -> Epoch {
        self.delta.activation_eligibility_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn activation_epoch(&self, ix: usize) -> Epoch {
        self.delta.activation_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn exit_epoch(&self, ix: usize) -> Epoch {
        self.delta.exit_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn withdrawable_epoch(&self, ix: usize) -> Epoch {
        self.delta.withdrawable_epoch(self.base, ix as u32)
    }

    /// Resolve a pubkey to its absolute index: finalized index first, then a
    /// linear scan of the fork's appended records.
    #[inline]
    pub fn find_by_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        if let Some(i) = self.base.find_by_pubkey(pk) {
            return Some(i as u32);
        }
        self.delta.find_by_pubkey(pk).map(|i| i as u32)
    }

    /// Finalized-only pubkey lookup (ignores fork appends).
    #[inline]
    pub fn find_by_finalized_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        self.base.find_by_pubkey(pk).map(|i| i as u32)
    }

    /// SSZ `hash_tree_root` of the registry (base tree + fork overlay).
    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.delta.hash_root(self.base)
    }

    /// The finalized base (for callers that must read the pre-fork registry).
    #[inline]
    pub fn finalized(&self) -> &'a FinalizedValidators {
        self.base
    }

    /// Finalized prefix length (edits/appended index `< base_count` hit the
    /// base columns). `base.validator_count()` when there's no active fork.
    #[inline]
    fn base_count(&self) -> usize {
        self.delta.base_count
    }

    // ── Whole-column iterators (base prefix overlaid by the sparse edits,
    // then the fork's appended records). Used by the epoch-transition passes
    // that consume every validator's columns in index order. With no active
    // fork the edit/appended slices are empty and these iterate the base.

    #[inline]
    fn appended(&self) -> &'a [AppendedValidator] {
        &self.delta.appended
    }

    pub fn iter_activation_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_slice = self.base.activation_epoch_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.activation_epoch_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.activation_epoch,
        )
    }

    pub fn iter_exit_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_slice = self.base.exit_epoch_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.exit_epoch_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.exit_epoch,
        )
    }

    pub fn iter_withdrawable_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_slice = self.base.withdrawable_epoch_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.withdrawable_epoch_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.withdrawable_epoch,
        )
    }

    pub fn iter_activation_eligibility_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_slice = self.base.activation_eligibility_epoch_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.activation_eligibility_epoch_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.activation_eligibility_epoch,
        )
    }

    pub fn iter_effective_balances(self) -> impl Iterator<Item = u64> + 'a {
        let base_slice = self.base.effective_balance_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.effective_balance_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.effective_balance,
        )
    }

    pub fn iter_slashed(self) -> impl Iterator<Item = bool> + 'a {
        let bitset = self.base.slashed_bitset();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.slashed_edits.as_slice(),
            move |i| bitset[i / 8] & (1u8 << (i % 8)) != 0,
            self.appended(),
            |a| a.slashed,
        )
    }

    pub fn iter_credentials(self) -> impl Iterator<Item = Withdrawals> + 'a {
        let base_slice = self.base.withdrawal_credentials_slice();
        column_iter(
            self.base_count(),
            self.count(),
            self.delta.credentials_edits.as_slice(),
            move |i| base_slice[i],
            self.appended(),
            |a| a.credentials,
        )
    }
}

/// Whole-column iterator: base prefix overlaid by the sparse `edits`, then the
/// fork's `appended` records. Free fn so it captures only `'a` borrows (no
/// `&self`), letting the write view build it over a transient view.
fn column_iter<'a, T: Copy + 'a>(
    base_count: usize,
    total: usize,
    edits: &'a [(u32, T)],
    base_at: impl Fn(usize) -> T + 'a,
    appended: &'a [AppendedValidator],
    from_appended: impl Fn(&AppendedValidator) -> T + 'a,
) -> impl Iterator<Item = T> + 'a {
    let mut cursor = 0usize;
    (0..total).map(move |i| {
        if cursor < edits.len() && (edits[cursor].0 as usize) == i {
            let v = edits[cursor].1;
            cursor += 1;
            v
        } else if i < base_count {
            base_at(i)
        } else {
            from_appended(&appended[i - base_count])
        }
    })
}

/// Write view over a validator fork: reads merge base + fork, mutators land on
/// the fork delta (recomputing the hash overlay leaf), publish freezes the id.
pub struct ValidatorsWriteView<'a> {
    base: &'a FinalizedValidators,
    fork: RingSlot<'a, ValidatorsGroup, ValidatorsDelta>,
}

impl<'a> ValidatorsWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedValidators,
        fork: RingSlot<'a, ValidatorsGroup, ValidatorsDelta>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> ValidatorsId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> ValidatorsView<'_> {
        ValidatorsView { base: self.base, delta: &self.fork }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.fork.base_count + self.fork.appended.len()
    }

    #[inline]
    pub fn find_by_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        self.reader().find_by_pubkey(pk)
    }

    /// Finalized-only pubkey lookup (ignores fork appends).
    #[inline]
    pub fn find_by_finalized_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        self.reader().find_by_finalized_pubkey(pk)
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.fork.hash_root(self.base)
    }

    // Per-validator reads go straight to the delta's `effective_*` merge
    // methods — no view construction per call.
    #[inline]
    pub fn pubkey(&self, ix: usize) -> &BLSPubkey {
        self.fork.effective_pubkey(self.base, ix as u32)
    }

    #[inline]
    pub fn pubkey_decompressed(&self, ix: usize) -> &PublicKey {
        self.fork.effective_pubkey_decompressed(self.base, ix as u32)
    }

    #[inline]
    pub fn credentials(&self, ix: usize) -> &Withdrawals {
        self.fork.effective_credentials(self.base, ix as u32)
    }

    #[inline]
    pub fn effective_balance(&self, ix: usize) -> u64 {
        self.fork.effective_balance(self.base, ix as u32)
    }

    #[inline]
    pub fn is_slashed(&self, ix: usize) -> bool {
        self.fork.is_slashed(self.base, ix as u32)
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, ix: usize) -> Epoch {
        self.fork.activation_eligibility_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn activation_epoch(&self, ix: usize) -> Epoch {
        self.fork.activation_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn exit_epoch(&self, ix: usize) -> Epoch {
        self.fork.exit_epoch(self.base, ix as u32)
    }

    #[inline]
    pub fn withdrawable_epoch(&self, ix: usize) -> Epoch {
        self.fork.withdrawable_epoch(self.base, ix as u32)
    }

    pub fn iter_activation_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        self.reader().iter_activation_epochs()
    }

    pub fn iter_exit_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        self.reader().iter_exit_epochs()
    }

    pub fn iter_withdrawable_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        self.reader().iter_withdrawable_epochs()
    }

    pub fn iter_activation_eligibility_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        self.reader().iter_activation_eligibility_epochs()
    }

    pub fn iter_effective_balances(&self) -> impl Iterator<Item = u64> + '_ {
        self.reader().iter_effective_balances()
    }

    pub fn iter_slashed(&self) -> impl Iterator<Item = bool> + '_ {
        self.reader().iter_slashed()
    }

    pub fn iter_credentials(&self) -> impl Iterator<Item = Withdrawals> + '_ {
        self.reader().iter_credentials()
    }

    #[inline]
    pub fn append(&mut self, pk: BLSPubkey, pk_decompressed: PublicKey, creds: Withdrawals) -> u32 {
        self.fork.append(self.base, pk, pk_decompressed, creds)
    }

    #[inline]
    pub fn set_credentials(&mut self, ix: u32, v: Withdrawals) {
        self.fork.set_credentials(self.base, ix, v);
    }

    #[inline]
    pub fn set_effective_balance(&mut self, ix: u32, v: u64) {
        self.fork.set_effective_balance(self.base, ix, v);
    }

    #[inline]
    pub fn set_slashed(&mut self, ix: u32, v: bool) {
        self.fork.set_slashed(self.base, ix, v);
    }

    #[inline]
    pub fn set_activation_eligibility_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.set_activation_eligibility_epoch(self.base, ix, v);
    }

    #[inline]
    pub fn set_activation_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.set_activation_epoch(self.base, ix, v);
    }

    #[inline]
    pub fn set_exit_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.set_exit_epoch(self.base, ix, v);
    }

    #[inline]
    pub fn set_withdrawable_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.set_withdrawable_epoch(self.base, ix, v);
    }
}
