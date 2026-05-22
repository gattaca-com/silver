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

impl FinalizedValidators {
    pub fn new_empty() -> Self {
        Self {
            data: box_zeroed(),
            index: PubkeyIndex::with_capacity_and_hasher(MAX_VALIDATORS, Default::default()),
            // TODO: change functions so the whole data will be provided in constructor instead of
            // rebuild_hash
            hash: FinalizedHashTree::new(Vec::new()),
        }
    }

    #[inline]
    pub fn hash(&self) -> &FinalizedHashTree {
        &self.hash
    }

    #[inline]
    pub fn hash_mut(&mut self) -> &mut FinalizedHashTree {
        &mut self.hash
    }

    /// Rebuild the hash tree from current `data` used only at bootstrap.
    pub fn rebuild_hash(&mut self) {
        let mut leaves = vec![[0u8; 32]; MAX_VALIDATORS];
        for i in 0..self.data.validator_cnt {
            leaves[i] =
                validator_hash(&self.data.val_pubkey[i], &self.data.val_withdrawal_credentials[i]);
        }
        self.hash = FinalizedHashTree::new(leaves);
    }

    pub fn append(&mut self, pubkey: &BLSPubkey, credentials: &Withdrawals) -> u32 {
        let idx = self.data.validator_cnt;

        self.data.val_pubkey[idx] = *pubkey;
        self.data.val_pubkey_decompressed[idx] = PublicKey::from_bytes(pubkey).unwrap_or_default();
        self.data.val_withdrawal_credentials[idx] = *credentials;

        self.data.validator_cnt = idx + 1;
        self.index.insert(*pubkey, idx as u32);

        idx as u32
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
