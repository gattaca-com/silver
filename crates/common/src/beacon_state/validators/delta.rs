use blst::min_pk::PublicKey;

use super::{FinalizedValidators, validator_hash};
use crate::{
    Withdrawals,
    beacon_state::{
        buffer::Reset,
        hash_tree::DeltaHashTree,
        types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH, VALIDATOR_REGISTRY_LIMIT},
    },
    ssz_hash::{ZERO_HASHES, hash_concat, mix_in_length},
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
    pub credentials_edits: Vec<(u32, Withdrawals)>,
    pub effective_balance_edits: Vec<(u32, u64)>,
    pub slashed_edits: Vec<(u32, bool)>,
    pub activation_eligibility_epoch_edits: Vec<(u32, Epoch)>,
    pub activation_epoch_edits: Vec<(u32, Epoch)>,
    pub exit_epoch_edits: Vec<(u32, Epoch)>,
    pub withdrawable_epoch_edits: Vec<(u32, Epoch)>,
    pub hash_overlay: DeltaHashTree,
}

impl ValidatorsDelta {
    /// Empty delta over `base`.
    pub fn new_at(base: &FinalizedValidators) -> Self {
        Self {
            base_count: base.validator_count(),
            appended: Vec::new(),
            credentials_edits: Vec::new(),
            effective_balance_edits: Vec::new(),
            slashed_edits: Vec::new(),
            activation_eligibility_epoch_edits: Vec::new(),
            activation_epoch_edits: Vec::new(),
            exit_epoch_edits: Vec::new(),
            withdrawable_epoch_edits: Vec::new(),
            hash_overlay: DeltaHashTree::new_at(base.hash()),
        }
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
        if let Some(v) = lookup(&self.credentials_edits, idx) {
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
        lookup_copy(&self.effective_balance_edits, idx)
            .unwrap_or_else(|| self.base_effective_balance(base, idx))
    }

    #[inline]
    pub fn is_slashed(&self, base: &FinalizedValidators, idx: u32) -> bool {
        lookup_copy(&self.slashed_edits, idx).unwrap_or_else(|| self.base_slashed(base, idx))
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        lookup_copy(&self.activation_eligibility_epoch_edits, idx)
            .unwrap_or_else(|| self.base_activation_eligibility_epoch(base, idx))
    }

    #[inline]
    pub fn activation_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        lookup_copy(&self.activation_epoch_edits, idx)
            .unwrap_or_else(|| self.base_activation_epoch(base, idx))
    }

    #[inline]
    pub fn exit_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        lookup_copy(&self.exit_epoch_edits, idx).unwrap_or_else(|| self.base_exit_epoch(base, idx))
    }

    #[inline]
    pub fn withdrawable_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        lookup_copy(&self.withdrawable_epoch_edits, idx)
            .unwrap_or_else(|| self.base_withdrawable_epoch(base, idx))
    }

    // Skipping the edits lookup is intentional — we want the *base* value to
    // know whether the new edit elides back to default.
    #[inline]
    fn base_credentials(&self, base: &FinalizedValidators, idx: u32) -> Withdrawals {
        self.base_field(base, idx, |b, i| *b.withdrawal_credentials(i), |a| a.credentials)
    }

    #[inline]
    fn base_effective_balance(&self, base: &FinalizedValidators, idx: u32) -> u64 {
        self.base_field(base, idx, |b, i| b.effective_balance(i), |a| a.effective_balance)
    }

    #[inline]
    fn base_slashed(&self, base: &FinalizedValidators, idx: u32) -> bool {
        self.base_field(base, idx, |b, i| b.is_slashed(i), |a| a.slashed)
    }

    #[inline]
    fn base_activation_eligibility_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.base_field(
            base,
            idx,
            |b, i| b.activation_eligibility_epoch(i),
            |a| a.activation_eligibility_epoch,
        )
    }

    #[inline]
    fn base_activation_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.base_field(base, idx, |b, i| b.activation_epoch(i), |a| a.activation_epoch)
    }

    #[inline]
    fn base_exit_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.base_field(base, idx, |b, i| b.exit_epoch(i), |a| a.exit_epoch)
    }

    #[inline]
    fn base_withdrawable_epoch(&self, base: &FinalizedValidators, idx: u32) -> Epoch {
        self.base_field(base, idx, |b, i| b.withdrawable_epoch(i), |a| a.withdrawable_epoch)
    }

    /// Recompute the Validator-container hash leaf for `idx` from the
    /// current effective state (overlay + base). Used by every mutator
    /// to keep `hash_overlay` consistent with the field edits.
    pub fn recompute_leaf(&self, base: &FinalizedValidators, idx: u32) -> crate::B256 {
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
    /// zero work for untouched subtrees. The physical tree only spans
    /// `MAX_VALIDATORS` leaves, so extend its root with zero subtrees up to the
    /// registry-limit depth, then mix in the validator count.
    pub fn list_root(&self, base: &FinalizedValidators) -> crate::B256 {
        const LIST_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.trailing_zeros();
        let tree = base.hash();
        let mut root = tree.delta_root(&self.hash_overlay);
        for h in tree.max_elements().trailing_zeros()..LIST_DEPTH {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, self.base_count + self.appended.len())
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

        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
        idx
    }

    pub fn set_credentials(&mut self, base: &FinalizedValidators, idx: u32, v: Withdrawals) {
        let base_val = self.base_credentials(base, idx);
        write_or_elide(&mut self.credentials_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_effective_balance(&mut self, base: &FinalizedValidators, idx: u32, v: u64) {
        let base_val = self.base_effective_balance(base, idx);
        write_or_elide(&mut self.effective_balance_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_slashed(&mut self, base: &FinalizedValidators, idx: u32, v: bool) {
        let base_val = self.base_slashed(base, idx);
        write_or_elide(&mut self.slashed_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_activation_eligibility_epoch(
        &mut self,
        base: &FinalizedValidators,
        idx: u32,
        v: Epoch,
    ) {
        let base_val = self.base_activation_eligibility_epoch(base, idx);
        write_or_elide(&mut self.activation_eligibility_epoch_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_activation_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        let base_val = self.base_activation_epoch(base, idx);
        write_or_elide(&mut self.activation_epoch_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_exit_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        let base_val = self.base_exit_epoch(base, idx);
        write_or_elide(&mut self.exit_epoch_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_withdrawable_epoch(&mut self, base: &FinalizedValidators, idx: u32, v: Epoch) {
        let base_val = self.base_withdrawable_epoch(base, idx);
        write_or_elide(&mut self.withdrawable_epoch_edits, idx, v, base_val);
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
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
            base.append(
                &a.pubkey,
                &a.pubkey_decompressed,
                &a.credentials,
                a.effective_balance,
                a.slashed,
                a.activation_eligibility_epoch,
                a.activation_epoch,
                a.exit_epoch,
                a.withdrawable_epoch,
            );
        }

        // 2. Apply per-field edits in index order.
        for &(idx, v) in &self.credentials_edits {
            base.set_withdrawal_credentials_at(idx as usize, v);
        }
        for &(idx, v) in &self.effective_balance_edits {
            base.set_effective_balance_at(idx as usize, v);
        }
        for &(idx, v) in &self.slashed_edits {
            base.set_slashed_at(idx as usize, v);
        }
        for &(idx, v) in &self.activation_eligibility_epoch_edits {
            base.set_activation_eligibility_epoch_at(idx as usize, v);
        }
        for &(idx, v) in &self.activation_epoch_edits {
            base.set_activation_epoch_at(idx as usize, v);
        }
        for &(idx, v) in &self.exit_epoch_edits {
            base.set_exit_epoch_at(idx as usize, v);
        }
        for &(idx, v) in &self.withdrawable_epoch_edits {
            base.set_withdrawable_epoch_at(idx as usize, v);
        }

        // 3. Fold the hash overlay into the finalized tree.
        base.hash_mut().promote_delta(&self.hash_overlay);
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

        self.credentials_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.withdrawal_credentials(*idx as usize) != v
        });
        self.effective_balance_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.effective_balance(*idx as usize) != *v
        });
        self.slashed_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.is_slashed(*idx as usize) != *v
        });
        self.activation_eligibility_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count ||
                base.activation_eligibility_epoch(*idx as usize) != *v
        });
        self.activation_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.activation_epoch(*idx as usize) != *v
        });
        self.exit_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.exit_epoch(*idx as usize) != *v
        });
        self.withdrawable_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_count || base.withdrawable_epoch(*idx as usize) != *v
        });

        base.hash().prune_delta(&mut self.hash_overlay);
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

#[inline]
fn lookup<T>(edits: &[(u32, T)], idx: u32) -> Option<&T> {
    edits.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| &edits[p].1)
}

#[inline]
fn lookup_copy<T: Copy>(edits: &[(u32, T)], idx: u32) -> Option<T> {
    edits.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| edits[p].1)
}

/// Insert / update / elide-back-to-base in one shot. Maintains the
/// sorted-by-idx invariant. Setting `v == base_val` removes any prior
/// edit at this idx.
#[inline]
fn write_or_elide<T: Copy + PartialEq>(edits: &mut Vec<(u32, T)>, idx: u32, v: T, base_val: T) {
    match edits.binary_search_by_key(&idx, |(k, _)| *k) {
        Ok(p) => {
            if v == base_val {
                edits.remove(p);
            } else {
                edits[p].1 = v;
            }
        }
        Err(p) => {
            if v != base_val {
                edits.insert(p, (idx, v));
            }
        }
    }
}
