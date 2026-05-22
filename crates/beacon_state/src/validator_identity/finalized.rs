use blst::min_pk::PublicKey;
use rustc_hash::FxHashMap;

use super::{validator_hash, withdrawals::Withdrawals};
use crate::{
    hash_tree::FinalizedHashTree,
    types::{BLSPubkey, MAX_VALIDATORS, ValidatorsData, box_zeroed},
};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

pub struct FinalizedValidators {
    data: Box<ValidatorsData>,
    index: PubkeyIndex,
    hash: FinalizedHashTree,
}

impl ValidatorsData {
    fn append(&mut self, pubkey: &BLSPubkey, credentials: &Withdrawals) -> u32 {
        let idx = self.validator_cnt;
        self.val_pubkey[idx] = *pubkey;
        self.val_pubkey_decompressed[idx] = PublicKey::from_bytes(pubkey).unwrap_or_default();
        self.val_withdrawal_credentials[idx] = *credentials;
        self.validator_cnt = idx + 1;
        idx as u32
    }
}

impl FinalizedValidators {
    pub fn new(pubkeys: &[BLSPubkey], credentials: &[Withdrawals]) -> Self {
        debug_assert_eq!(pubkeys.len(), credentials.len());
        debug_assert!(pubkeys.len() <= MAX_VALIDATORS);

        let mut data: Box<ValidatorsData> = box_zeroed();
        let mut index = PubkeyIndex::with_capacity_and_hasher(MAX_VALIDATORS, Default::default());
        let mut leaf_hashes = vec![[0u8; 32]; MAX_VALIDATORS];

        for (pubkey, creds) in pubkeys.iter().zip(credentials.iter()) {
            let idx = data.append(pubkey, creds);
            index.insert(*pubkey, idx);
            leaf_hashes[idx as usize] = validator_hash(pubkey, creds);
        }

        Self { data, index, hash: FinalizedHashTree::new(leaf_hashes) }
    }

    #[inline]
    pub fn hash(&self) -> &FinalizedHashTree {
        &self.hash
    }

    #[inline]
    pub fn hash_mut(&mut self) -> &mut FinalizedHashTree {
        &mut self.hash
    }

    pub(super) fn append(&mut self, pubkey: &BLSPubkey, credentials: &Withdrawals) -> u32 {
        let idx = self.data.append(pubkey, credentials);
        self.index.insert(*pubkey, idx);
        idx
    }

    #[inline]
    pub(super) fn set_withdrawal_credentials_at(&mut self, idx: usize, credentials: Withdrawals) {
        self.data.val_withdrawal_credentials[idx] = credentials;
    }

    #[inline]
    pub fn validator_cnt(&self) -> usize {
        self.data.validator_cnt
    }

    #[inline]
    pub fn pubkey(&self, i: usize) -> &BLSPubkey {
        &self.data.val_pubkey[i]
    }

    #[inline]
    pub fn pubkey_decompressed(&self, i: usize) -> &PublicKey {
        &self.data.val_pubkey_decompressed[i]
    }

    #[inline]
    pub fn withdrawal_credentials(&self, i: usize) -> &Withdrawals {
        &self.data.val_withdrawal_credentials[i]
    }

    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.index.get(pubkey).map(|&idx| idx as usize)
    }
}
