use blst::min_pk::PublicKey;

use super::{FinalisedValidators, validator_hash};
use crate::{
    Withdrawals,
    beacon_state::{
        buffer::Reset,
        hash_tree::DeltaHashTree,
        types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH},
    },
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

/// Per-fork delta over [`FinalisedValidators`]. Sparse edits per mutable
/// Validator-container field + appended new-validator records + a hash
/// overlay keyed by leaf index.
///
/// `appended[p]`'s absolute validator index is `base_cnt + p`. The `_edits`
/// vecs are sparse, sorted by absolute index. Edits may target either a
/// base validator (idx < base_cnt) or an appended one (idx >= base_cnt).
#[derive(Default, Clone)]
pub struct ValidatorsDelta {
    pub base_cnt: usize,
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
    /// Empty delta anchored at a base of size `base_cnt`. The hash overlay
    /// starts pointing into the finalised tree (root = `Base(1)`).
    pub fn new_at(base_cnt: usize) -> Self {
        Self {
            base_cnt,
            appended: Vec::new(),
            credentials_edits: Vec::new(),
            effective_balance_edits: Vec::new(),
            slashed_edits: Vec::new(),
            activation_eligibility_epoch_edits: Vec::new(),
            activation_epoch_edits: Vec::new(),
            exit_epoch_edits: Vec::new(),
            withdrawable_epoch_edits: Vec::new(),
            hash_overlay: DeltaHashTree::default(),
        }
    }

    /// Absolute index of an appended validator matching `pubkey`.
    /// Linear scan — `appended` is bounded by deposits-since-finalisation.
    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.appended.iter().position(|a| &a.pubkey == pubkey).map(|p| self.base_cnt + p)
    }

    #[inline]
    pub fn effective_credentials<'a>(
        &'a self,
        base: &'a FinalisedValidators,
        idx: u32,
    ) -> &'a Withdrawals {
        if let Some(v) = lookup(&self.credentials_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.withdrawal_credentials(i)
        } else {
            &self.appended[i - self.base_cnt].credentials
        }
    }

    #[inline]
    pub fn effective_pubkey<'a>(
        &'a self,
        base: &'a FinalisedValidators,
        idx: u32,
    ) -> &'a BLSPubkey {
        let i = idx as usize;
        if i < self.base_cnt { base.pubkey(i) } else { &self.appended[i - self.base_cnt].pubkey }
    }

    #[inline]
    pub fn effective_pubkey_decompressed<'a>(
        &'a self,
        base: &'a FinalisedValidators,
        idx: u32,
    ) -> &'a PublicKey {
        let i = idx as usize;
        if i < self.base_cnt {
            base.pubkey_decompressed(i)
        } else {
            &self.appended[i - self.base_cnt].pubkey_decompressed
        }
    }

    #[inline]
    pub fn effective_balance(&self, base: &FinalisedValidators, idx: u32) -> u64 {
        if let Some(v) = lookup_copy(&self.effective_balance_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.effective_balance(i)
        } else {
            self.appended[i - self.base_cnt].effective_balance
        }
    }

    #[inline]
    pub fn is_slashed(&self, base: &FinalisedValidators, idx: u32) -> bool {
        if let Some(v) = lookup_copy(&self.slashed_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.is_slashed(i)
        } else {
            self.appended[i - self.base_cnt].slashed
        }
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, base: &FinalisedValidators, idx: u32) -> Epoch {
        if let Some(v) = lookup_copy(&self.activation_eligibility_epoch_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.activation_eligibility_epoch(i)
        } else {
            self.appended[i - self.base_cnt].activation_eligibility_epoch
        }
    }

    #[inline]
    pub fn activation_epoch(&self, base: &FinalisedValidators, idx: u32) -> Epoch {
        if let Some(v) = lookup_copy(&self.activation_epoch_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.activation_epoch(i)
        } else {
            self.appended[i - self.base_cnt].activation_epoch
        }
    }

    #[inline]
    pub fn exit_epoch(&self, base: &FinalisedValidators, idx: u32) -> Epoch {
        if let Some(v) = lookup_copy(&self.exit_epoch_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.exit_epoch(i)
        } else {
            self.appended[i - self.base_cnt].exit_epoch
        }
    }

    #[inline]
    pub fn withdrawable_epoch(&self, base: &FinalisedValidators, idx: u32) -> Epoch {
        if let Some(v) = lookup_copy(&self.withdrawable_epoch_edits, idx) {
            return v;
        }
        let i = idx as usize;
        if i < self.base_cnt {
            base.withdrawable_epoch(i)
        } else {
            self.appended[i - self.base_cnt].withdrawable_epoch
        }
    }

    /// Recompute the Validator-container hash leaf for `idx` from the
    /// current effective state (overlay + base). Used by every mutator
    /// to keep `hash_overlay` consistent with the field edits.
    pub fn recompute_leaf(&self, base: &FinalisedValidators, idx: u32) -> crate::B256 {
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

    /// Append a fresh validator with spec-default Validator-container
    /// fields. Returns the absolute index of the new validator.
    pub fn append(
        &mut self,
        base: &FinalisedValidators,
        pubkey: BLSPubkey,
        pubkey_decompressed: PublicKey,
        credentials: Withdrawals,
    ) -> u32 {
        let idx = (self.base_cnt + self.appended.len()) as u32;
        self.appended.push(AppendedValidator::new(pubkey, pubkey_decompressed, credentials));
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
        idx
    }

    pub fn set_credentials(&mut self, base: &FinalisedValidators, idx: u32, v: Withdrawals) {
        write_or_elide(
            &mut self.credentials_edits,
            idx,
            v,
            base_credentials(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_effective_balance(&mut self, base: &FinalisedValidators, idx: u32, v: u64) {
        write_or_elide(
            &mut self.effective_balance_edits,
            idx,
            v,
            base_effective_balance(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_slashed(&mut self, base: &FinalisedValidators, idx: u32, v: bool) {
        write_or_elide(
            &mut self.slashed_edits,
            idx,
            v,
            base_slashed(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_activation_eligibility_epoch(
        &mut self,
        base: &FinalisedValidators,
        idx: u32,
        v: Epoch,
    ) {
        write_or_elide(
            &mut self.activation_eligibility_epoch_edits,
            idx,
            v,
            base_activation_eligibility_epoch(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_activation_epoch(&mut self, base: &FinalisedValidators, idx: u32, v: Epoch) {
        write_or_elide(
            &mut self.activation_epoch_edits,
            idx,
            v,
            base_activation_epoch(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_exit_epoch(&mut self, base: &FinalisedValidators, idx: u32, v: Epoch) {
        write_or_elide(
            &mut self.exit_epoch_edits,
            idx,
            v,
            base_exit_epoch(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    pub fn set_withdrawable_epoch(&mut self, base: &FinalisedValidators, idx: u32, v: Epoch) {
        write_or_elide(
            &mut self.withdrawable_epoch_edits,
            idx,
            v,
            base_withdrawable_epoch(base, &self.appended, self.base_cnt, idx),
        );
        let leaf = self.recompute_leaf(base, idx);
        base.hash().set_delta_leaf(&mut self.hash_overlay, idx as usize, leaf);
    }

    /// Fold this delta into `base`. Appended records advance
    /// `base.validator_cnt`; per-field edits land at their absolute
    /// indices. The hash tree is promoted afterwards via
    /// `base.hash_mut().promote_delta(&self.hash_overlay)`.
    pub fn promote_into_base(&self, base: &mut FinalisedValidators) {
        debug_assert_eq!(
            base.validator_cnt(),
            self.base_cnt,
            "promote_into_base: delta.base_cnt must match the current base count",
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

        // 3. Fold the hash overlay into the finalised tree.
        base.hash_mut().promote_delta(&self.hash_overlay);
    }

    /// Reconcile with an advanced base: drop edits that the promoted base
    /// already reflects, and re-anchor `base_cnt`. Caller must invoke this
    /// on every surviving descendant fork (including the promoter itself)
    /// after `promote_into_base`.
    pub fn prune_to_base(&mut self, base: &FinalisedValidators) {
        let new_base_cnt = base.validator_cnt();
        debug_assert!(new_base_cnt >= self.base_cnt, "base count cannot regress");

        let promoted = (new_base_cnt - self.base_cnt).min(self.appended.len());
        self.appended.drain(..promoted);
        self.base_cnt = new_base_cnt;

        self.credentials_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.withdrawal_credentials(*idx as usize) != v
        });
        self.effective_balance_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.effective_balance(*idx as usize) != *v
        });
        self.slashed_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.is_slashed(*idx as usize) != *v
        });
        self.activation_eligibility_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt ||
                base.activation_eligibility_epoch(*idx as usize) != *v
        });
        self.activation_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.activation_epoch(*idx as usize) != *v
        });
        self.exit_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.exit_epoch(*idx as usize) != *v
        });
        self.withdrawable_epoch_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.withdrawable_epoch(*idx as usize) != *v
        });

        base.hash().prune_delta(&mut self.hash_overlay);
    }
}

impl Reset for ValidatorsDelta {
    fn reset(&mut self) {
        self.base_cnt = 0;
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
        self.base_cnt = other.base_cnt;
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

// Per-field "what is the base value" helpers, used by write_or_elide.
// Skipping the edits lookup is intentional — we want the *base* value to
// know whether the new edit elides back to default.

#[inline]
fn base_credentials<'a>(
    base: &'a FinalisedValidators,
    appended: &'a [AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> Withdrawals {
    let i = idx as usize;
    if i < base_cnt { *base.withdrawal_credentials(i) } else { appended[i - base_cnt].credentials }
}

#[inline]
fn base_effective_balance(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> u64 {
    let i = idx as usize;
    if i < base_cnt { base.effective_balance(i) } else { appended[i - base_cnt].effective_balance }
}

#[inline]
fn base_slashed(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> bool {
    let i = idx as usize;
    if i < base_cnt { base.is_slashed(i) } else { appended[i - base_cnt].slashed }
}

#[inline]
fn base_activation_eligibility_epoch(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> Epoch {
    let i = idx as usize;
    if i < base_cnt {
        base.activation_eligibility_epoch(i)
    } else {
        appended[i - base_cnt].activation_eligibility_epoch
    }
}

#[inline]
fn base_activation_epoch(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> Epoch {
    let i = idx as usize;
    if i < base_cnt { base.activation_epoch(i) } else { appended[i - base_cnt].activation_epoch }
}

#[inline]
fn base_exit_epoch(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> Epoch {
    let i = idx as usize;
    if i < base_cnt { base.exit_epoch(i) } else { appended[i - base_cnt].exit_epoch }
}

#[inline]
fn base_withdrawable_epoch(
    base: &FinalisedValidators,
    appended: &[AppendedValidator],
    base_cnt: usize,
    idx: u32,
) -> Epoch {
    let i = idx as usize;
    if i < base_cnt {
        base.withdrawable_epoch(i)
    } else {
        appended[i - base_cnt].withdrawable_epoch
    }
}
