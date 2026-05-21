use blst::min_pk::PublicKey;

use super::{delta::ValidatorsDelta, finalized::FinalizedValidators, withdrawals::Withdrawals};
use crate::types::BLSPubkey;

/// Per-fork merged view: raw pointer to the tile-owned finalized base
/// + owned `ValidatorsDelta`. Safety: pointee is boxed (stable address) and
///   outlives the state; only `delta` is mutated through this struct.
pub struct ValidatorsState {
    finalized: *const FinalizedValidators,
    delta: ValidatorsDelta,
}

// Safety: pointer is to tile-owned data; the writer tile is
// single-threaded so the state never crosses thread boundaries while
// alive. The marker is needed because raw pointers are `!Send + !Sync`
// by default but `BeaconStateRef` needs to flow through tile methods.
unsafe impl Send for ValidatorsState {}
unsafe impl Sync for ValidatorsState {}

impl Clone for ValidatorsState {
    fn clone(&self) -> Self {
        Self { finalized: self.finalized, delta: self.delta.clone() }
    }
}

#[cfg(test)]
impl Default for ValidatorsState {
    /// Null-pointer sentinel for fork-choice tests that build a
    /// `BeaconStateRef` via `Default` and never read `validators`.
    /// Reading pubkey/credentials/index on a defaulted state derefs null.
    fn default() -> Self {
        Self { finalized: std::ptr::null(), delta: ValidatorsDelta::default() }
    }
}

impl ValidatorsState {
    pub fn new(finalized: &FinalizedValidators, delta: ValidatorsDelta) -> Self {
        Self { finalized: finalized as *const _, delta }
    }

    pub fn with_empty_delta(finalized: &FinalizedValidators) -> Self {
        let base_cnt = finalized.validator_cnt();
        Self::new(finalized, ValidatorsDelta::new_at(base_cnt))
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedValidators {
        // Safety: pointer is set from a live tile-owned reference at
        // construction; tile outlives every BeaconStateRef.
        unsafe { &*self.finalized }
    }

    #[inline]
    pub fn delta(&self) -> &ValidatorsDelta {
        &self.delta
    }

    #[inline]
    pub fn validator_cnt(&self) -> usize {
        self.finalized().validator_cnt() + self.delta.appended.len()
    }

    #[inline]
    pub fn pubkey(&self, i: usize) -> &BLSPubkey {
        let base = self.finalized();
        let n = base.validator_cnt();
        if i < n { base.pubkey(i) } else { &self.delta.appended[i - n].pubkey }
    }

    #[inline]
    pub fn pubkey_decompressed(&self, i: usize) -> &PublicKey {
        let base = self.finalized();
        let n = base.validator_cnt();
        if i < n {
            base.pubkey_decompressed(i)
        } else {
            &self.delta.appended[i - n].pubkey_decompressed
        }
    }

    #[inline]
    pub fn withdrawal_credentials(&self, i: usize) -> &Withdrawals {
        if let Some(creds) = self.delta.get_credentials_edit(i as u32) {
            return creds;
        }
        let base = self.finalized();
        let n = base.validator_cnt();
        if i < n { base.withdrawal_credentials(i) } else { &self.delta.appended[i - n].credentials }
    }

    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        if let Some(idx) = self.delta.find_by_pubkey(pubkey) {
            return Some(idx);
        }
        self.finalized().find_by_pubkey(pubkey)
    }

    pub fn append(&mut self, pubkey: &BLSPubkey, credentials: &Withdrawals) -> u32 {
        self.delta.append(pubkey, credentials)
    }

    pub fn set_withdrawal_credentials(&mut self, i: usize, v: Withdrawals) {
        self.delta.set_credentials_edit(i as u32, v);
    }

    /// Fold this fork's delta into `base`. The caller is expected to
    /// follow up with `prune_to_base` on every fork (including this one)
    /// so deltas get re-anchored to the advanced base.
    pub fn promote_into_base(&self, base: &mut FinalizedValidators) {
        base.apply_delta(&self.delta);
    }

    pub fn prune_to_base(&mut self, base: &FinalizedValidators) {
        self.delta.prune_to_base(base);
    }
}
