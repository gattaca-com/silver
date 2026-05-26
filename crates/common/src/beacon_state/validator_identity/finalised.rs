use blst::min_pk::PublicKey;
use rustc_hash::FxHashMap;

use super::validator_hash;
use crate::{
    Withdrawals,
    beacon_state::{
        hash_tree::FinalisedHashTree,
        types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH, MAX_VALIDATORS, VAL_SLASHED_BYTES},
    },
};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

pub struct FinalisedValidators {
    pub(super) val_pubkey: Box<[BLSPubkey]>,
    pub(super) val_pubkey_decompressed: Box<[PublicKey]>,
    pub(super) val_withdrawal_credentials: Box<[Withdrawals]>,
    pub(super) effective_balance: Box<[u64]>,
    /// Bitset: validator `i` is slashed iff
    /// `slashed[i / 8] & (1 << (i % 8)) != 0`. Length = MAX_VALIDATORS / 8.
    pub(super) slashed: Box<[u8]>,
    pub(super) activation_eligibility_epoch: Box<[Epoch]>,
    pub(super) activation_epoch: Box<[Epoch]>,
    pub(super) exit_epoch: Box<[Epoch]>,
    pub(super) withdrawable_epoch: Box<[Epoch]>,
    pub(super) validator_cnt: usize,
    pub(super) index: PubkeyIndex,
    pub(super) hash: FinalisedHashTree,
}

impl Default for FinalisedValidators {
    fn default() -> Self {
        Self {
            val_pubkey: vec![[0u8; 48]; MAX_VALIDATORS].into_boxed_slice(),
            val_pubkey_decompressed: vec![PublicKey::default(); MAX_VALIDATORS].into_boxed_slice(),
            val_withdrawal_credentials: vec![Withdrawals::default(); MAX_VALIDATORS]
                .into_boxed_slice(),
            effective_balance: vec![0u64; MAX_VALIDATORS].into_boxed_slice(),
            slashed: vec![0u8; VAL_SLASHED_BYTES].into_boxed_slice(),
            activation_eligibility_epoch: vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice(),
            activation_epoch: vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice(),
            exit_epoch: vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice(),
            withdrawable_epoch: vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice(),
            validator_cnt: 0,
            index: PubkeyIndex::default(),
            hash: FinalisedHashTree::new(&[], MAX_VALIDATORS),
        }
    }
}

impl FinalisedValidators {
    #[inline]
    pub fn validator_cnt(&self) -> usize {
        self.validator_cnt
    }

    #[inline]
    pub fn pubkey(&self, i: usize) -> &BLSPubkey {
        &self.val_pubkey[i]
    }

    #[inline]
    pub fn pubkey_decompressed(&self, i: usize) -> &PublicKey {
        &self.val_pubkey_decompressed[i]
    }

    #[inline]
    pub fn withdrawal_credentials(&self, i: usize) -> &Withdrawals {
        &self.val_withdrawal_credentials[i]
    }

    #[inline]
    pub fn effective_balance(&self, i: usize) -> u64 {
        self.effective_balance[i]
    }

    #[inline]
    pub fn is_slashed(&self, i: usize) -> bool {
        self.slashed[i / 8] & (1u8 << (i % 8)) != 0
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self, i: usize) -> Epoch {
        self.activation_eligibility_epoch[i]
    }

    #[inline]
    pub fn activation_epoch(&self, i: usize) -> Epoch {
        self.activation_epoch[i]
    }

    #[inline]
    pub fn exit_epoch(&self, i: usize) -> Epoch {
        self.exit_epoch[i]
    }

    #[inline]
    pub fn withdrawable_epoch(&self, i: usize) -> Epoch {
        self.withdrawable_epoch[i]
    }

    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.index.get(pubkey).map(|&idx| idx as usize)
    }

    /// Number of entries in the pubkey → idx index. Should equal
    /// `validator_cnt` post-`decompose` / `promote_into_base`.
    #[inline]
    pub fn index_len(&self) -> usize {
        self.index.len()
    }

    #[inline]
    pub fn hash(&self) -> &FinalisedHashTree {
        &self.hash
    }

    #[inline]
    pub fn hash_mut(&mut self) -> &mut FinalisedHashTree {
        &mut self.hash
    }

    #[inline]
    pub fn effective_balance_slice(&self) -> &[u64] {
        &self.effective_balance
    }

    #[inline]
    pub fn activation_eligibility_epoch_slice(&self) -> &[Epoch] {
        &self.activation_eligibility_epoch
    }

    #[inline]
    pub fn activation_epoch_slice(&self) -> &[Epoch] {
        &self.activation_epoch
    }

    #[inline]
    pub fn exit_epoch_slice(&self) -> &[Epoch] {
        &self.exit_epoch
    }

    #[inline]
    pub fn withdrawable_epoch_slice(&self) -> &[Epoch] {
        &self.withdrawable_epoch
    }

    #[inline]
    pub fn withdrawal_credentials_slice(&self) -> &[Withdrawals] {
        &self.val_withdrawal_credentials
    }

    #[inline]
    pub fn slashed_bitset(&self) -> &[u8] {
        &self.slashed
    }

    #[inline]
    pub fn pubkey_slice_mut(&mut self) -> &mut [BLSPubkey] {
        &mut self.val_pubkey
    }

    #[inline]
    pub fn pubkey_decompressed_slice_mut(&mut self) -> &mut [PublicKey] {
        &mut self.val_pubkey_decompressed
    }

    #[inline]
    pub fn withdrawal_credentials_slice_mut(&mut self) -> &mut [Withdrawals] {
        &mut self.val_withdrawal_credentials
    }

    #[inline]
    pub fn effective_balance_slice_mut(&mut self) -> &mut [u64] {
        &mut self.effective_balance
    }

    #[inline]
    pub fn activation_eligibility_epoch_slice_mut(&mut self) -> &mut [Epoch] {
        &mut self.activation_eligibility_epoch
    }

    #[inline]
    pub fn activation_epoch_slice_mut(&mut self) -> &mut [Epoch] {
        &mut self.activation_epoch
    }

    #[inline]
    pub fn exit_epoch_slice_mut(&mut self) -> &mut [Epoch] {
        &mut self.exit_epoch
    }

    #[inline]
    pub fn withdrawable_epoch_slice_mut(&mut self) -> &mut [Epoch] {
        &mut self.withdrawable_epoch
    }

    #[inline]
    pub fn slashed_bitset_mut(&mut self) -> &mut [u8] {
        &mut self.slashed
    }

    #[inline]
    pub fn index_mut(&mut self) -> &mut PubkeyIndex {
        &mut self.index
    }

    #[inline]
    pub fn set_validator_cnt(&mut self, n: usize) {
        self.validator_cnt = n;
    }

    /// Rebuild the leaf-hash row from the current populated state. Caller
    /// uses this after a bulk `decompose` populate to align the hash
    /// tree with the columnar data.
    pub fn rebuild_hash_tree(&mut self) {
        let n = self.validator_cnt;
        let mut leaves = vec![[0u8; 32]; n];
        for (i, leaf) in leaves.iter_mut().enumerate().take(n) {
            *leaf = validator_hash(
                &self.val_pubkey[i],
                &self.val_withdrawal_credentials[i],
                self.effective_balance[i],
                self.is_slashed(i),
                self.activation_eligibility_epoch[i],
                self.activation_epoch[i],
                self.exit_epoch[i],
                self.withdrawable_epoch[i],
            );
        }
        self.hash = FinalisedHashTree::new(&leaves, MAX_VALIDATORS);
    }

    /// Append a validator to the finalised base with caller-supplied
    /// Validator-container field values. Updates the pubkey index but NOT
    /// the hash tree — caller is responsible for `rebuild_hash_tree` after
    /// a bulk populate, or use it via `ValidatorsDelta::promote_into_base`
    /// which propagates the hash overlay separately.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        pubkey: &BLSPubkey,
        pubkey_decompressed: &PublicKey,
        credentials: &Withdrawals,
        effective_balance: u64,
        slashed: bool,
        activation_eligibility_epoch: Epoch,
        activation_epoch: Epoch,
        exit_epoch: Epoch,
        withdrawable_epoch: Epoch,
    ) -> u32 {
        let idx = self.validator_cnt;
        debug_assert!(idx < MAX_VALIDATORS);
        self.val_pubkey[idx] = *pubkey;
        self.val_pubkey_decompressed[idx] = *pubkey_decompressed;
        self.val_withdrawal_credentials[idx] = *credentials;
        self.effective_balance[idx] = effective_balance;
        if slashed {
            self.slashed[idx / 8] |= 1u8 << (idx % 8);
        }
        self.activation_eligibility_epoch[idx] = activation_eligibility_epoch;
        self.activation_epoch[idx] = activation_epoch;
        self.exit_epoch[idx] = exit_epoch;
        self.withdrawable_epoch[idx] = withdrawable_epoch;
        self.index.insert(*pubkey, idx as u32);
        self.validator_cnt = idx + 1;
        idx as u32
    }

    pub(super) fn set_withdrawal_credentials_at(&mut self, idx: usize, v: Withdrawals) {
        self.val_withdrawal_credentials[idx] = v;
    }

    pub(super) fn set_effective_balance_at(&mut self, idx: usize, v: u64) {
        self.effective_balance[idx] = v;
    }

    pub(super) fn set_slashed_at(&mut self, idx: usize, v: bool) {
        let mask = 1u8 << (idx % 8);
        if v {
            self.slashed[idx / 8] |= mask;
        } else {
            self.slashed[idx / 8] &= !mask;
        }
    }

    pub(super) fn set_activation_eligibility_epoch_at(&mut self, idx: usize, v: Epoch) {
        self.activation_eligibility_epoch[idx] = v;
    }

    pub(super) fn set_activation_epoch_at(&mut self, idx: usize, v: Epoch) {
        self.activation_epoch[idx] = v;
    }

    pub(super) fn set_exit_epoch_at(&mut self, idx: usize, v: Epoch) {
        self.exit_epoch[idx] = v;
    }

    pub(super) fn set_withdrawable_epoch_at(&mut self, idx: usize, v: Epoch) {
        self.withdrawable_epoch[idx] = v;
    }
}
