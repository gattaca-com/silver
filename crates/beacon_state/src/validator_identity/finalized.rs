use blst::min_pk::PublicKey;
use rustc_hash::FxHashMap;

use super::{delta::ValidatorsDelta, withdrawals::Withdrawals};
use crate::types::{BLSPubkey, MAX_VALIDATORS, ValidatorsData, box_zeroed};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

/// Canonical finalized validator registry: boxed `ValidatorsData` +
/// inline `PubkeyIndex`. Per-fork mutations live in `ValidatorsDelta`
/// overlaid via `ValidatorsState`.
pub struct FinalizedValidators {
    data: Box<ValidatorsData>,
    index: PubkeyIndex,
}

impl FinalizedValidators {
    pub fn new_empty() -> Self {
        Self {
            data: box_zeroed(),
            index: PubkeyIndex::with_capacity_and_hasher(MAX_VALIDATORS, Default::default()),
        }
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

    /// Fold a finalized fork's `delta` into the base. Appended entries
    /// land at `validator_cnt..`; invariant `validator_cnt ==
    /// delta.base_cnt` is upheld by callers (`ForkChoice::finalize_node`).
    pub fn apply_delta(&mut self, delta: &ValidatorsDelta) {
        debug_assert_eq!(
            self.data.validator_cnt, delta.base_cnt,
            "apply_delta: delta.base_cnt must match the current base count",
        );

        for a in &delta.appended {
            self.append(&a.pubkey, &a.credentials);
        }

        for &(idx, v) in &delta.credentials_edits {
            self.data.val_withdrawal_credentials[idx as usize] = v;
        }
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
