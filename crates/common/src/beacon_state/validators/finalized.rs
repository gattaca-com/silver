use blst::min_pk::PublicKey;
use rustc_hash::FxHashMap;
use silver_common_macros::timed;

use super::validator_hash;
use crate::{
    Withdrawals,
    beacon_state::{
        hash_tree::FinalizedHashTree,
        types::{BLSPubkey, Epoch, FAR_FUTURE_EPOCH, MAX_VALIDATORS, VAL_SLASHED_BYTES},
    },
};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

/// Initial values for one validator passed to `Finalized::new`.
pub struct ValSeed {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub effective_balance: u64,
    pub balance: u64,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
}

impl Default for ValSeed {
    fn default() -> Self {
        Self {
            pubkey: [0u8; 48],
            withdrawal_credentials: Withdrawals::default(),
            effective_balance: 0,
            balance: 0,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// SSZ-serialised size of a single `Validator` container (Fulu).
const VALIDATOR_SSZ_SIZE: usize = 121;

#[derive(Debug, thiserror::Error)]
pub enum ValidatorsDecodeError {
    #[error("validators bytes {len} not a multiple of {VALIDATOR_SSZ_SIZE}")]
    LenNotMultiple { len: usize },
    #[error("validator {idx} pubkey failed BLS decompression")]
    InvalidPubkey { idx: usize },
}

#[inline]
fn u64_at(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

pub struct FinalizedValidators {
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
    pub(super) validator_count: usize,
    pub(super) index: PubkeyIndex,
    pub(super) hash: FinalizedHashTree,
}

impl Default for FinalizedValidators {
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
            validator_count: 0,
            index: PubkeyIndex::default(),
            hash: FinalizedHashTree::new(&[], MAX_VALIDATORS),
        }
    }
}

impl FinalizedValidators {
    #[timed]
    pub fn try_new(val_bytes: &[u8]) -> Result<Self, ValidatorsDecodeError> {
        if !val_bytes.len().is_multiple_of(VALIDATOR_SSZ_SIZE) {
            return Err(ValidatorsDecodeError::LenNotMultiple { len: val_bytes.len() });
        }
        let n = val_bytes.len() / VALIDATOR_SSZ_SIZE;
        debug_assert!(n <= MAX_VALIDATORS);

        let mut val_pubkey = vec![[0u8; 48]; MAX_VALIDATORS].into_boxed_slice();
        let mut val_pubkey_decompressed =
            vec![PublicKey::default(); MAX_VALIDATORS].into_boxed_slice();
        let mut val_withdrawal_credentials =
            vec![Withdrawals::default(); MAX_VALIDATORS].into_boxed_slice();
        let mut effective_balances = vec![0u64; MAX_VALIDATORS].into_boxed_slice();
        let mut slashed_bits = vec![0u8; VAL_SLASHED_BYTES].into_boxed_slice();
        let mut activation_eligibility_epochs =
            vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice();
        let mut activation_epochs = vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice();
        let mut exit_epochs = vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice();
        let mut withdrawable_epochs = vec![FAR_FUTURE_EPOCH; MAX_VALIDATORS].into_boxed_slice();
        let mut index = PubkeyIndex::with_capacity_and_hasher(n, Default::default());
        let mut leaf_hashes = vec![[0u8; 32]; n];

        // Validator container layout: pubkey[48] | withdrawal_credentials[32]
        // | effective_balance:u64[8] | slashed:bool[1] | 4 × epoch:u64.
        for i in 0..n {
            let v = &val_bytes[i * VALIDATOR_SSZ_SIZE..];
            let pubkey: BLSPubkey = v[..48].try_into().unwrap();
            let pubkey_decompressed = PublicKey::from_bytes(&pubkey)
                .map_err(|_| ValidatorsDecodeError::InvalidPubkey { idx: i })?;
            let credentials = Withdrawals(v[48..80].try_into().unwrap());
            let effective_balance = u64_at(v, 80);
            let slashed = v[88] != 0;
            let activation_eligibility_epoch = u64_at(v, 89);
            let activation_epoch = u64_at(v, 97);
            let exit_epoch = u64_at(v, 105);
            let withdrawable_epoch = u64_at(v, 113);

            val_pubkey[i] = pubkey;
            val_pubkey_decompressed[i] = pubkey_decompressed;
            val_withdrawal_credentials[i] = credentials;
            effective_balances[i] = effective_balance;
            if slashed {
                slashed_bits[i / 8] |= 1u8 << (i % 8);
            }
            activation_eligibility_epochs[i] = activation_eligibility_epoch;
            activation_epochs[i] = activation_epoch;
            exit_epochs[i] = exit_epoch;
            withdrawable_epochs[i] = withdrawable_epoch;
            index.insert(pubkey, i as u32);
            leaf_hashes[i] = validator_hash(
                &pubkey,
                &credentials,
                effective_balance,
                slashed,
                activation_eligibility_epoch,
                activation_epoch,
                exit_epoch,
                withdrawable_epoch,
            );
        }

        Ok(Self {
            val_pubkey,
            val_pubkey_decompressed,
            val_withdrawal_credentials,
            effective_balance: effective_balances,
            slashed: slashed_bits,
            activation_eligibility_epoch: activation_eligibility_epochs,
            activation_epoch: activation_epochs,
            exit_epoch: exit_epochs,
            withdrawable_epoch: withdrawable_epochs,
            validator_count: n,
            index,
            hash: FinalizedHashTree::new(&leaf_hashes, MAX_VALIDATORS),
        })
    }

    #[inline]
    pub fn validator_count(&self) -> usize {
        self.validator_count
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
    /// `validator_count` post-`decompose` / `promote_into_base`.
    #[inline]
    pub fn index_len(&self) -> usize {
        self.index.len()
    }

    #[inline]
    pub fn hash(&self) -> &FinalizedHashTree {
        &self.hash
    }

    #[inline]
    pub fn hash_mut(&mut self) -> &mut FinalizedHashTree {
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

    pub fn with_validators(seeds: &[ValSeed]) -> Self {
        let mut v = Self::default();
        for s in seeds {
            let decompressed = PublicKey::from_bytes(&s.pubkey).unwrap_or_default();
            v.append(
                &s.pubkey,
                &decompressed,
                &s.withdrawal_credentials,
                s.effective_balance,
                false,
                FAR_FUTURE_EPOCH,
                s.activation_epoch,
                s.exit_epoch,
                FAR_FUTURE_EPOCH,
            );
        }
        v
    }

    /// Append a validator to the finalized base with caller-supplied
    /// Validator-container field values. Updates the pubkey index but NOT
    /// the hash tree.
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
        let idx = self.validator_count;
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
        self.validator_count = idx + 1;
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
