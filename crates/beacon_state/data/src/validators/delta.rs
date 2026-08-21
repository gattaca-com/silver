use blst::min_pk::PublicKey;
use flux_profiler::timed;

use super::{FinalizedValidators, ValidatorsGroup, ValidatorsId, validator_hash};
use crate::{
    B256, Withdrawals,
    column::{ColumnReader, ColumnWriteView, ValidatorsHash},
    ring::{Reset, Slot as RingSlot},
    sparse::Edits,
    types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH},
};

/// A validator appended in this fork. Only the immutable identity fields are
/// stored: the mutable Validator-container fields (balance, slashed, the four
/// epochs) are spec-default until a `set_*` writes an edit, so the effective-
/// read and iter paths return those defaults directly rather than storing them.
#[derive(Clone, PartialEq)]
struct AppendedValidator {
    pubkey: BLSPubkey,
    pubkey_decompressed: PublicKey,
    credentials: Withdrawals,
}

/// Per-fork delta over [`FinalizedValidators`] — an opaque data holder: sparse
/// edits per mutable Validator-container field, appended new-validator records,
/// and a hash overlay keyed by leaf index.
///
/// `appended[p]`'s absolute validator index is `base_count + p`. The `_edits`
/// vecs are sparse, sorted by absolute index. Edits may target either a
/// base validator (idx < base_count) or an appended one (idx >= base_count).
#[derive(Default, Clone)]
pub struct ValidatorsDelta {
    base_count: usize,
    appended: Vec<AppendedValidator>,
    credentials_edits: Edits<Withdrawals>,
    effective_balance_edits: Edits<u64>,
    slashed_edits: Edits<bool>,
    activation_eligibility_epoch_edits: Edits<Epoch>,
    activation_epoch_edits: Edits<Epoch>,
    exit_epoch_edits: Edits<Epoch>,
    withdrawable_epoch_edits: Edits<Epoch>,
}

impl ValidatorsDelta {
    /// Fold this delta into `base`. Appended records advance
    /// `base.validator_count`; per-field edits land at their absolute
    /// indices.
    pub(super) fn promote_into_base(&self, base: &mut FinalizedValidators) {
        debug_assert_eq!(
            base.validator_count(),
            self.base_count,
            "promote_into_base: delta.base_count must match the current base count",
        );

        // 1. Append new identities. Tail slots past the count are pristine
        // spec-default, so the edit scatter below only overwrites appended
        // validators whose fields diverged.
        let start = self.base_count;
        debug_assert!(
            self.appended.is_empty() ||
                (base.effective_balance[start] == 0 &&
                    base.exit_epoch[start] == FAR_FUTURE_EPOCH &&
                    !base.is_slashed(start)),
            "appended tail slots must be pristine spec-default",
        );
        {
            let mut index = base.index.write();
            for (p, a) in self.appended.iter().enumerate() {
                let idx = start + p;
                base.val_pubkey[idx] = a.pubkey;
                base.val_pubkey_decompressed[idx] = a.pubkey_decompressed;
                base.val_withdrawal_credentials[idx] = a.credentials;
                index.insert(a.pubkey, idx as u32);
            }
        }
        base.validator_count = start + self.appended.len();

        // 2. Scatter per-field edits into the base columns at their absolute
        // indices. `slashed` is a packed bitset, so it scatters into the bytes.
        self.credentials_edits.scatter(&mut base.val_withdrawal_credentials);
        self.effective_balance_edits.scatter(&mut base.effective_balance);
        self.activation_eligibility_epoch_edits.scatter(&mut base.activation_eligibility_epoch);
        self.activation_epoch_edits.scatter(&mut base.activation_epoch);
        self.exit_epoch_edits.scatter(&mut base.exit_epoch);
        self.withdrawable_epoch_edits.scatter(&mut base.withdrawable_epoch);
        self.slashed_edits.scatter_bits(&mut base.slashed);
    }

    /// Mirror of [`BalancesDelta::rebase_and_prune_from`] for the multi-column
    /// registry: finalize survivor `old` into `self` against promoted `winner`,
    /// pre-promote and read-only so lock-free readers stay unblocked. The
    /// winner-promoted prefix of `appended` is dropped; every column delegates
    /// the rebase/prune to [`Edits::rebase_and_prune_from`].
    pub(super) fn rebase_and_prune_from(
        &mut self,
        old: &ValidatorsDelta,
        base: &FinalizedValidators,
        winner: &ValidatorsDelta,
    ) {
        let new_count = (winner.base_count + winner.appended.len()) as u32;

        let promoted = (new_count as usize - old.base_count).min(old.appended.len());
        self.appended = old.appended[promoted..].to_vec();
        self.base_count = new_count as usize;

        self.credentials_edits.rebase_and_prune_from(
            &old.credentials_edits,
            &winner.credentials_edits,
            new_count,
            |i| winner.unedited(i, |i| base.val_withdrawal_credentials[i], |a| a.credentials),
        );
        self.effective_balance_edits.rebase_and_prune_from(
            &old.effective_balance_edits,
            &winner.effective_balance_edits,
            new_count,
            |i| winner.unedited(i, |i| base.effective_balance[i], |_| 0),
        );
        self.slashed_edits.rebase_and_prune_from(
            &old.slashed_edits,
            &winner.slashed_edits,
            new_count,
            |i| winner.unedited(i, |i| base.is_slashed(i), |_| false),
        );
        self.activation_eligibility_epoch_edits.rebase_and_prune_from(
            &old.activation_eligibility_epoch_edits,
            &winner.activation_eligibility_epoch_edits,
            new_count,
            |i| winner.unedited(i, |i| base.activation_eligibility_epoch[i], |_| FAR_FUTURE_EPOCH),
        );
        self.activation_epoch_edits.rebase_and_prune_from(
            &old.activation_epoch_edits,
            &winner.activation_epoch_edits,
            new_count,
            |i| winner.unedited(i, |i| base.activation_epoch[i], |_| FAR_FUTURE_EPOCH),
        );
        self.exit_epoch_edits.rebase_and_prune_from(
            &old.exit_epoch_edits,
            &winner.exit_epoch_edits,
            new_count,
            |i| winner.unedited(i, |i| base.exit_epoch[i], |_| FAR_FUTURE_EPOCH),
        );
        self.withdrawable_epoch_edits.rebase_and_prune_from(
            &old.withdrawable_epoch_edits,
            &winner.withdrawable_epoch_edits,
            new_count,
            |i| winner.unedited(i, |i| base.withdrawable_epoch[i], |_| FAR_FUTURE_EPOCH),
        );
    }

    #[inline]
    fn unedited<T>(
        &self,
        i: u32,
        from_base: impl Fn(usize) -> T,
        from_appended: impl Fn(&AppendedValidator) -> T,
    ) -> T {
        let i = i as usize;
        if i < self.base_count {
            from_base(i)
        } else {
            from_appended(&self.appended[i - self.base_count])
        }
    }

    /// Anchor a freshly-`reset` delta onto `base`: adopt its count
    /// (edits/appended already empty). Used by `roll_fresh`.
    pub(super) fn anchor_at(&mut self, base: &FinalizedValidators) {
        self.base_count = base.validator_count();
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
    }
}

/// Value-layer read over the validator registry (base + per-fork delta). Holds
/// every read: per-field `effective_*` merges, the pubkey lookup, the whole-
/// column iterators, and the SSZ root. Built only from a published fork id (or
/// a held writer) — the delta is always present; pre-snapshot readers get none.
#[derive(Clone, Copy)]
pub struct ValidatorsView<'a> {
    base: &'a FinalizedValidators,
    delta: &'a ValidatorsDelta,
    hash: ColumnReader<'a, ValidatorsHash>,
}

impl<'a> ValidatorsView<'a> {
    #[inline]
    pub(crate) fn new(
        base: &'a FinalizedValidators,
        delta: &'a ValidatorsDelta,
        hash: ColumnReader<'a, ValidatorsHash>,
    ) -> Self {
        Self { base, delta, hash }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.delta.base_count + self.delta.appended.len()
    }

    #[inline]
    pub fn pubkey(&self, ix: usize) -> &'a BLSPubkey {
        if ix < self.delta.base_count {
            &self.base.val_pubkey[ix]
        } else {
            &self.delta.appended[ix - self.delta.base_count].pubkey
        }
    }

    #[inline]
    pub fn pubkey_decompressed(&self, ix: usize) -> &'a PublicKey {
        if ix < self.delta.base_count {
            &self.base.val_pubkey_decompressed[ix]
        } else {
            &self.delta.appended[ix - self.delta.base_count].pubkey_decompressed
        }
    }

    #[inline]
    pub fn credentials(&self, ix: usize) -> &'a Withdrawals {
        if let Some(v) = self.delta.credentials_edits.get(ix as u32) {
            return v;
        }
        if ix < self.delta.base_count {
            &self.base.val_withdrawal_credentials[ix]
        } else {
            &self.delta.appended[ix - self.delta.base_count].credentials
        }
    }

    /// Effective value of a `Copy` field at `ix` with no edit: the base column
    /// when `ix < base_count`, otherwise `appended_default` — an appended
    /// validator's mutable fields are spec-default until a `set_*` edit lands.
    #[inline]
    fn base_or<T>(
        &self,
        ix: usize,
        from_base: impl Fn(&FinalizedValidators, usize) -> T,
        appended_default: T,
    ) -> T {
        if ix < self.delta.base_count { from_base(self.base, ix) } else { appended_default }
    }

    #[inline]
    pub fn effective_balance(&self, ix: usize) -> u64 {
        self.delta
            .effective_balance_edits
            .get(ix as u32)
            .copied()
            .unwrap_or_else(|| self.base_or(ix, |b, i| b.effective_balance[i], 0))
    }

    #[inline]
    pub fn is_slashed(&self, ix: usize) -> bool {
        self.delta
            .slashed_edits
            .get(ix as u32)
            .copied()
            .unwrap_or_else(|| self.base_or(ix, |b, i| b.is_slashed(i), false))
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, ix: usize) -> Epoch {
        self.delta.activation_eligibility_epoch_edits.get(ix as u32).copied().unwrap_or_else(|| {
            self.base_or(ix, |b, i| b.activation_eligibility_epoch[i], FAR_FUTURE_EPOCH)
        })
    }

    #[inline]
    pub fn activation_epoch(&self, ix: usize) -> Epoch {
        self.delta
            .activation_epoch_edits
            .get(ix as u32)
            .copied()
            .unwrap_or_else(|| self.base_or(ix, |b, i| b.activation_epoch[i], FAR_FUTURE_EPOCH))
    }

    #[inline]
    pub fn exit_epoch(&self, ix: usize) -> Epoch {
        self.delta
            .exit_epoch_edits
            .get(ix as u32)
            .copied()
            .unwrap_or_else(|| self.base_or(ix, |b, i| b.exit_epoch[i], FAR_FUTURE_EPOCH))
    }

    #[inline]
    pub fn withdrawable_epoch(&self, ix: usize) -> Epoch {
        self.delta
            .withdrawable_epoch_edits
            .get(ix as u32)
            .copied()
            .unwrap_or_else(|| self.base_or(ix, |b, i| b.withdrawable_epoch[i], FAR_FUTURE_EPOCH))
    }

    /// Resolve a pubkey to its absolute index: finalized index first, then a
    /// linear scan of the fork's appended records (bounded by deposits-since-
    /// finalization).
    #[inline]
    pub fn find_by_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        if let Some(i) = self.base.find_by_pubkey(pk) {
            return Some(i as u32);
        }
        self.delta
            .appended
            .iter()
            .position(|a| &a.pubkey == pk)
            .map(|p| (self.delta.base_count + p) as u32)
    }

    /// Finalized-only pubkey lookup (ignores fork appends).
    #[inline]
    pub fn find_by_finalized_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        self.base.find_by_pubkey(pk).map(|i| i as u32)
    }

    /// SSZ `hash_tree_root` of the validators registry, in this fork's own
    /// shape (fulu `List[Validator, N]` padding vs the gloas
    /// `ProgressiveList`).
    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.hash.hash_root()
    }

    /// Recompute the Validator-container hash leaf for `idx` from the current
    /// effective state (overlay + base) — the write view calls this after each
    /// edit to keep the overlay consistent with the field edits.
    fn recompute_leaf(&self, idx: u32) -> B256 {
        let ix = idx as usize;
        validator_hash(
            self.pubkey(ix),
            self.credentials(ix),
            self.effective_balance(ix),
            self.is_slashed(ix),
            self.activation_eligibility_epoch(ix),
            self.activation_epoch(ix),
            self.exit_epoch(ix),
            self.withdrawable_epoch(ix),
        )
    }

    /// The finalized base (for callers that must read the pre-fork registry).
    #[inline]
    pub fn finalized(&self) -> &'a FinalizedValidators {
        self.base
    }

    /// Finalized prefix length — `base.validator_count()` when there's no
    /// active fork.
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

    /// Spec `get_total_active_balance` numerator: Σ effective balance over
    /// validators active at `epoch`, unfloored. A dense fold over the base
    /// slices alone (the whole-column iterators pay a per-element cursor
    /// merge), then each edited index swaps its base contribution for the
    /// merged one. Unedited appends are spec-default — never active.
    #[timed]
    pub fn total_active_at(self, epoch: Epoch) -> u64 {
        fn take<V: Copy>(edits: &mut &[(u32, V)], j: usize) -> Option<V> {
            match edits.first() {
                Some(&(k, v)) if k as usize == j => {
                    *edits = &edits[1..];
                    Some(v)
                }
                _ => None,
            }
        }

        let active = |activation: Epoch, exit: Epoch| activation <= epoch && epoch < exit;
        let base_count = self.base_count();
        let activation = &self.base.activation_epoch[..base_count];
        let exit = &self.base.exit_epoch[..base_count];
        let effective = &self.base.effective_balance[..base_count];

        let mut sum = 0u64;
        for j in 0..base_count {
            if active(activation[j], exit[j]) {
                sum += effective[j];
            }
        }

        let mut activation_edits = self.delta.activation_epoch_edits.as_slice();
        let mut exit_edits = self.delta.exit_epoch_edits.as_slice();
        let mut effective_edits = self.delta.effective_balance_edits.as_slice();
        loop {
            let next = [activation_edits.first(), exit_edits.first(), effective_edits.first()]
                .into_iter()
                .flatten()
                .map(|&(k, _)| k as usize)
                .min();
            let Some(j) = next else { break };
            let edit_activation = take(&mut activation_edits, j);
            let edit_exit = take(&mut exit_edits, j);
            let edit_effective = take(&mut effective_edits, j);
            let (base_activation, base_exit, base_effective) = if j < base_count {
                if active(activation[j], exit[j]) {
                    sum -= effective[j];
                }
                (activation[j], exit[j], effective[j])
            } else {
                (FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, 0)
            };
            if active(edit_activation.unwrap_or(base_activation), edit_exit.unwrap_or(base_exit)) {
                sum += edit_effective.unwrap_or(base_effective);
            }
        }
        sum
    }

    #[timed]
    pub fn active_indices_into(self, epoch: Epoch, out: &mut Vec<u32>) {
        out.clear();
        let mut act = self.iter_activation_epochs();
        let mut exit = self.iter_exit_epochs();
        for i in 0..self.count() {
            let a = act.next().unwrap();
            let x = exit.next().unwrap();
            if a <= epoch && epoch < x {
                out.push(i as u32);
            }
        }
    }

    pub fn iter_activation_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_count = self.base_count();
        self.delta.activation_epoch_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.activation_epoch[i],
            move |_| FAR_FUTURE_EPOCH,
        )
    }

    pub fn iter_exit_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_count = self.base_count();
        self.delta.exit_epoch_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.exit_epoch[i],
            move |_| FAR_FUTURE_EPOCH,
        )
    }

    pub fn iter_withdrawable_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_count = self.base_count();
        self.delta.withdrawable_epoch_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.withdrawable_epoch[i],
            move |_| FAR_FUTURE_EPOCH,
        )
    }

    pub fn iter_activation_eligibility_epochs(self) -> impl Iterator<Item = Epoch> + 'a {
        let base_count = self.base_count();
        self.delta.activation_eligibility_epoch_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.activation_eligibility_epoch[i],
            move |_| FAR_FUTURE_EPOCH,
        )
    }

    pub fn iter_effective_balances(self) -> impl Iterator<Item = u64> + 'a {
        let base_count = self.base_count();
        self.delta.effective_balance_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.effective_balance[i],
            move |_| 0,
        )
    }

    pub fn iter_slashed(self) -> impl Iterator<Item = bool> + 'a {
        let base_count = self.base_count();
        self.delta.slashed_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.is_slashed(i),
            move |_| false,
        )
    }

    pub fn iter_credentials(self) -> impl Iterator<Item = Withdrawals> + 'a {
        let (appended, base_count) = (self.appended(), self.base_count());
        self.delta.credentials_edits.sweep(
            base_count,
            self.count(),
            move |i| self.base.val_withdrawal_credentials[i],
            move |i| appended[i - base_count].credentials,
        )
    }
}

/// Write view over a validator fork: reads delegate to [`ValidatorsView`],
/// mutators land on the fork delta and refresh the hash overlay leaf, publish
/// freezes the id.
pub struct ValidatorsWriteView<'a> {
    base: &'a FinalizedValidators,
    fork: RingSlot<'a, ValidatorsGroup>,
    hash: ColumnWriteView<'a, ValidatorsHash>,
}

impl<'a> ValidatorsWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedValidators,
        fork: RingSlot<'a, ValidatorsGroup>,
        hash: ColumnWriteView<'a, ValidatorsHash>,
    ) -> Self {
        Self { base, fork, hash }
    }

    #[inline]
    pub fn commit(mut self) -> ValidatorsId {
        self.hash.rehash_unsorted();
        ValidatorsId { data: self.fork.commit(), hash: self.hash.commit() }
    }

    #[inline]
    pub fn reader(&self) -> ValidatorsView<'_> {
        ValidatorsView { base: self.base, delta: &self.fork, hash: self.hash.reader() }
    }

    /// Reader with pending deferred leaf writes folded in — required before
    /// hashing the in-flight fork; plain [`reader`](Self::reader) suffices for
    /// value reads.
    #[inline]
    pub fn hashed_reader(&mut self) -> ValidatorsView<'_> {
        self.hash.rehash_unsorted();
        self.reader()
    }

    // All reads delegate to the read view (`reader()` is a two-pointer `Copy`,
    // so this is free) — the base+fork merge logic lives once on `ValidatorsView`.
    #[inline]
    pub fn count(&self) -> usize {
        self.reader().count()
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
    pub fn hash_root(&mut self) -> B256 {
        self.hashed_reader().hash_root()
    }

    #[inline]
    pub fn pubkey(&self, ix: usize) -> &BLSPubkey {
        self.reader().pubkey(ix)
    }

    #[inline]
    pub fn pubkey_decompressed(&self, ix: usize) -> &PublicKey {
        self.reader().pubkey_decompressed(ix)
    }

    #[inline]
    pub fn credentials(&self, ix: usize) -> &Withdrawals {
        self.reader().credentials(ix)
    }

    #[inline]
    pub fn effective_balance(&self, ix: usize) -> u64 {
        self.reader().effective_balance(ix)
    }

    #[inline]
    pub fn is_slashed(&self, ix: usize) -> bool {
        self.reader().is_slashed(ix)
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, ix: usize) -> Epoch {
        self.reader().activation_eligibility_epoch(ix)
    }

    #[inline]
    pub fn activation_epoch(&self, ix: usize) -> Epoch {
        self.reader().activation_epoch(ix)
    }

    #[inline]
    pub fn exit_epoch(&self, ix: usize) -> Epoch {
        self.reader().exit_epoch(ix)
    }

    #[inline]
    pub fn withdrawable_epoch(&self, ix: usize) -> Epoch {
        self.reader().withdrawable_epoch(ix)
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

    /// Recompute and store the hash leaf for `idx` — every mutator calls this
    /// so the hash column stays consistent with the field edits.
    fn refresh_leaf(&mut self, idx: u32) {
        let leaf = self.reader().recompute_leaf(idx);
        self.hash.set_deferred(idx, leaf);
    }

    /// The fork block's EIP-7688 hash migration: this fork's registry root
    /// switches to the gloas `ProgressiveList` shape. Pending deferred writes
    /// fold in first — the migration rebuilds from the leaf bytes.
    pub fn adopt_gloas(&mut self) {
        self.hash.rehash_unsorted();
        self.hash.migrate_to_progressive();
    }

    /// Append a fresh validator with spec-default Validator-container fields.
    /// Returns the absolute index of the new validator.
    #[inline]
    pub fn append(&mut self, pk: BLSPubkey, pk_decompressed: PublicKey, creds: Withdrawals) -> u32 {
        let idx = (self.fork.base_count + self.fork.appended.len()) as u32;
        self.fork.appended.push(AppendedValidator {
            pubkey: pk,
            pubkey_decompressed: pk_decompressed,
            credentials: creds,
        });
        let appended = self.hash.append_empty();
        debug_assert_eq!(appended, idx, "hash column count out of step with registry");
        self.refresh_leaf(idx);
        idx
    }

    #[inline]
    pub fn set_credentials(&mut self, ix: u32, v: Withdrawals) {
        self.fork.credentials_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    #[inline]
    pub fn set_effective_balance(&mut self, ix: u32, v: u64) {
        self.fork.effective_balance_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    /// Batch effective-balance update: one merge into the field edits, then
    /// per-leaf deferred hash writes (rehash stays batched at commit/read).
    /// `changes` must be ascending and distinct.
    pub fn set_effective_balance_many(&mut self, changes: &[(u32, u64)]) {
        if changes.is_empty() {
            return;
        }
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_effective_balance_many input must be ascending with distinct indices",
        );
        self.fork.effective_balance_edits.merge_in_place(changes);
        for &(ix, _) in changes {
            let leaf = self.reader().recompute_leaf(ix);
            self.hash.set_deferred(ix, leaf);
        }
    }

    #[inline]
    pub fn set_slashed(&mut self, ix: u32, v: bool) {
        self.fork.slashed_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    #[inline]
    pub fn set_activation_eligibility_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.activation_eligibility_epoch_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    #[inline]
    pub fn set_activation_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.activation_epoch_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    #[inline]
    pub fn set_exit_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.exit_epoch_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }

    #[inline]
    pub fn set_withdrawable_epoch(&mut self, ix: u32, v: Epoch) {
        self.fork.withdrawable_epoch_edits.merge_in_place(&[(ix, v)]);
        self.refresh_leaf(ix);
    }
}
