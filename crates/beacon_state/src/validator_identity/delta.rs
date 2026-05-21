use blst::min_pk::PublicKey;

use super::{finalized::FinalizedValidators, withdrawals::Withdrawals};
use crate::types::BLSPubkey;

#[derive(Clone, PartialEq)]
pub struct AppendedValidator {
    pub pubkey: BLSPubkey,
    pub pubkey_decompressed: PublicKey,
    pub credentials: Withdrawals,
}

/// Per-fork delta on top of the finalized base. `appended[p]`'s
/// absolute validator index is `base_cnt + p`; `cred_edits` carry an
/// explicit absolute index (may target a base or appended validator).
#[derive(Default, Clone)]
pub struct ValidatorsDelta {
    pub base_cnt: usize,
    pub appended: Vec<AppendedValidator>,
    pub credentials_edits: Vec<(u32, Withdrawals)>,
}

impl ValidatorsDelta {
    pub fn new_at(base_cnt: usize) -> Self {
        Self { base_cnt, appended: Vec::new(), credentials_edits: Vec::new() }
    }

    /// Absolute index of an appended validator matching `pubkey`.
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.appended.iter().position(|a| &a.pubkey == pubkey).map(|p| self.base_cnt + p)
    }

    pub fn get_credentials_edit(&self, idx: u32) -> Option<&Withdrawals> {
        self.credentials_edits.iter().find_map(|(i, v)| (*i == idx).then_some(v))
    }

    /// Append a validator and return its absolute index
    pub(crate) fn append(&mut self, pubkey: &BLSPubkey, credentials: &Withdrawals) -> u32 {
        let idx = (self.base_cnt + self.appended.len()) as u32;
        self.appended.push(AppendedValidator {
            pubkey: *pubkey,
            pubkey_decompressed: PublicKey::from_bytes(pubkey).unwrap_or_default(),
            credentials: *credentials,
        });
        idx
    }

    /// Replace-by-index semantics: spec operations read the latest
    /// credentials within a block, so the newest write must shadow any
    /// earlier one for the same validator.
    pub(crate) fn set_credentials_edit(&mut self, idx: u32, new_credentials: Withdrawals) {
        if let Some((_, old_credentials)) =
            self.credentials_edits.iter_mut().find(|(i, _)| *i == idx)
        {
            *old_credentials = new_credentials;
            return;
        }
        self.credentials_edits.push((idx, new_credentials));
    }

    /// Reconcile with an advanced `base`: drain the promoted prefix of
    /// `appended`, roll `base_cnt` forward, and drop cred_edits that now
    /// match base. Base only grows in finalized progression, so a
    /// shrinking base is a bug.
    pub fn prune_to_base(&mut self, base: &FinalizedValidators) {
        let new_base_cnt = base.validator_cnt();
        debug_assert!(new_base_cnt >= self.base_cnt, "base count cannot regress");

        let promoted = (new_base_cnt - self.base_cnt).min(self.appended.len());
        self.appended.drain(..promoted);
        self.base_cnt = new_base_cnt;

        self.credentials_edits.retain(|(idx, v)| {
            (*idx as usize) >= new_base_cnt || base.withdrawal_credentials(*idx as usize) != v
        });
    }
}
