use blst::min_pk::PublicKey;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, StateReadView, types::Checkpoint};
use silver_common::{column_util, ssz_view::BeaconBlockHeaderView};

use crate::{BlockRoot, availability::ColumnTracker};

pub(super) struct FuluHeader<'a> {
    pub(super) root: BlockRoot,
    pub(super) slot: u64,
    pub(super) parent_root: &'a BlockRoot,
    proposer_index: u64,
    body_root: &'a BlockRoot,
    signature: &'a [u8; 96],
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProposerCheck {
    Matches,
    Mismatch,
    Unresolvable,
}

pub(super) struct HeaderState {
    pub(super) finalized: Checkpoint,
    pub(super) proposer: ProposerCheck,
    pub(super) pubkey: Option<PublicKey>,
    genesis_validators_root: BlockRoot,
}

impl HeaderState {
    pub(super) fn finalized_slot(&self) -> u64 {
        self.finalized.epoch * SLOTS_PER_EPOCH
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SignatureError {
    UnknownProposer,
    InvalidSignature,
}

impl<'a> FuluHeader<'a> {
    #[inline]
    pub(super) fn new(header: &'a [u8; 112], signature: &'a [u8; 96]) -> Self {
        Self {
            root: column_util::block_root_from_header(header),
            slot: BeaconBlockHeaderView::slot(header),
            parent_root: BeaconBlockHeaderView::parent_root(header),
            proposer_index: BeaconBlockHeaderView::proposer_index(header),
            body_root: BeaconBlockHeaderView::body_root(header),
            signature,
        }
    }

    pub(super) fn read_state(&self, view: &StateReadView<'_>) -> HeaderState {
        // Lookahead covers the snapshot's current and next epochs only.
        let expected = self
            .slot
            .checked_sub(view.slot.current_epoch() * SLOTS_PER_EPOCH)
            .and_then(|offset| view.epoch.proposer_at(offset as usize));
        let proposer = match expected {
            Some(index) if index == self.proposer_index => ProposerCheck::Matches,
            Some(_) => ProposerCheck::Mismatch,
            None => ProposerCheck::Unresolvable,
        };
        let pubkey = usize::try_from(self.proposer_index)
            .ok()
            .filter(|&index| index < view.validators.count())
            .map(|index| *view.validators.pubkey_decompressed(index));
        HeaderState {
            finalized: view.epoch.state().finalized_checkpoint,
            proposer,
            pubkey,
            genesis_validators_root: view.imm.genesis_validators_root,
        }
    }

    pub(super) fn verify_signature(
        &self,
        state: &HeaderState,
        fork_version: [u8; 4],
        tracker: &mut ColumnTracker,
    ) -> Result<(), SignatureError> {
        if tracker.signature_verified(&self.root, self.signature, fork_version) {
            return Ok(());
        }
        let pubkey = state.pubkey.as_ref().ok_or(SignatureError::UnknownProposer)?;
        if !column_util::verify_header_signature(
            &self.root,
            self.signature,
            pubkey,
            fork_version,
            &state.genesis_validators_root,
        ) {
            return Err(SignatureError::InvalidSignature);
        }
        tracker.set_signature(self.root, *self.signature, fork_version);
        Ok(())
    }

    pub(super) fn verify_commitments(&self, commitments: &[u8], proof: &[u8; 128]) -> bool {
        // Neither commitments nor their proof are pinned by the header root.
        // A signature cache hit must never bypass this check.
        column_util::verify_commitments_inclusion_proof(commitments, proof, self.body_root)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use blst::min_pk::SecretKey;
    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{merkle::hash_concat, ssz_hash::hash_tree_root_fork_data};

    use super::*;

    #[test]
    fn signature_cache_requires_matching_root_bytes_and_fork() {
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let fork_version = [6, 0, 0, 0];
        let mut state = HeaderState {
            finalized: Checkpoint::default(),
            proposer: ProposerCheck::Matches,
            pubkey: Some(key.sk_to_pk()),
            genesis_validators_root: [7; 32],
        };
        let mut bytes = [0; 112];
        bytes[..8].copy_from_slice(&7u64.to_le_bytes());
        let root = column_util::block_root_from_header(&bytes);
        let fork_root = hash_tree_root_fork_data(fork_version, &state.genesis_validators_root);
        let mut domain = [0; 32];
        domain[4..].copy_from_slice(&fork_root[..28]);
        let signature = key
            .sign(&hash_concat(&root, &domain), b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[])
            .to_bytes();
        let header = FuluHeader::new(&bytes, &signature);
        let mut tracker = ColumnTracker::new(0, Duration::from_secs(60));
        assert_eq!(header.verify_signature(&state, fork_version, &mut tracker), Ok(()));
        assert!(tracker.signature_verified(&root, &signature, fork_version));
        assert!(!tracker.holds(&root, 0), "signature verification does not validate cells");

        // Without a public key, success proves the second check used the memo.
        state.pubkey = None;
        assert_eq!(header.verify_signature(&state, fork_version, &mut tracker), Ok(()));
        assert_eq!(
            header.verify_signature(&state, [5, 0, 0, 0], &mut tracker),
            Err(SignatureError::UnknownProposer)
        );
        let mut altered_signature = signature;
        altered_signature[0] ^= 1;
        let altered = FuluHeader::new(&bytes, &altered_signature);
        assert_eq!(
            altered.verify_signature(&state, fork_version, &mut tracker),
            Err(SignatureError::UnknownProposer)
        );
        let mut altered_bytes = bytes;
        altered_bytes[16] ^= 1;
        let altered = FuluHeader::new(&altered_bytes, &signature);
        assert_eq!(
            altered.verify_signature(&state, fork_version, &mut tracker),
            Err(SignatureError::UnknownProposer)
        );

        state.pubkey = Some(key.sk_to_pk());
        assert_eq!(
            header.verify_signature(&state, [5, 0, 0, 0], &mut tracker),
            Err(SignatureError::InvalidSignature)
        );
        assert!(!tracker.signature_verified(&root, &signature, [5, 0, 0, 0]));
        assert!(tracker.signature_verified(&root, &signature, fork_version));
    }

    #[test]
    fn proposer_checks_respect_snapshot_lookahead_boundaries() {
        let owner = BeaconStateOwner::published_empty_test(SLOTS_PER_EPOCH);
        let reader = owner.reader();
        for (slot, proposer, expected) in [
            (SLOTS_PER_EPOCH - 1, 0u64, ProposerCheck::Unresolvable),
            (SLOTS_PER_EPOCH, 0, ProposerCheck::Matches),
            (3 * SLOTS_PER_EPOCH - 1, 0, ProposerCheck::Matches),
            (3 * SLOTS_PER_EPOCH, 0, ProposerCheck::Unresolvable),
            (SLOTS_PER_EPOCH, 1, ProposerCheck::Mismatch),
        ] {
            let mut bytes = [0; 112];
            bytes[..8].copy_from_slice(&slot.to_le_bytes());
            bytes[8..16].copy_from_slice(&proposer.to_le_bytes());
            let header = FuluHeader::new(&bytes, &[0; 96]);
            let state = reader.read(|view| header.read_state(&view)).unwrap();
            assert_eq!(state.proposer, expected, "slot {slot}, proposer {proposer}");
            assert!(state.pubkey.is_none());
        }
    }
}
