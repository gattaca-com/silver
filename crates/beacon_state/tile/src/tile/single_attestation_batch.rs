use blst::min_pk::{PublicKey, Signature};
use rustc_hash::FxHashSet;
use silver_beacon_state_data::B256;
use silver_common::ssz_view::SINGLE_ATT_SIZE;

use super::gossip_relay::RelayMetadata;
use crate::{counters::BeaconStateCounters, tile::attestation_root_memo::AttestationRootGroup};

mod verifier;

pub(super) const BATCH_CHUNK: usize = 128;

#[derive(Clone)]
pub(super) struct PendingAttestation {
    pub(super) bytes: [u8; SINGLE_ATT_SIZE],
    pub(super) public_key: PublicKey,
    pub(super) signature: Signature,
    pub(super) signing_root: B256,
    pub(super) root_group: Option<AttestationRootGroup>,
    pub(super) data_root: B256,
    pub(super) target_epoch: u64,
    pub(super) attester_index: usize,
    pub(super) committee_position: usize,
    pub(super) committee_len: usize,
    pub(super) block_root: B256,
    pub(super) attestation_slot: u64,
    pub(super) committee_index: usize,
    pub(super) payload_present: bool,
    pub(super) relay: Option<RelayMetadata>,
}

pub(super) struct SingleAttestationBatch {
    pending: Vec<PendingAttestation>,
    keys: FxHashSet<(u64, usize)>,
    verifier: verifier::EntryVerifier,
}

impl Default for SingleAttestationBatch {
    fn default() -> Self {
        Self {
            pending: Vec::with_capacity(BATCH_CHUNK),
            keys: FxHashSet::default(),
            verifier: verifier::EntryVerifier::default(),
        }
    }
}

impl SingleAttestationBatch {
    pub(super) fn enqueue(&mut self, entry: PendingAttestation) -> bool {
        let key = (entry.target_epoch, entry.attester_index);
        if !self.keys.insert(key) {
            BeaconStateCounters::PendingSingleAttestationDuplicate.inc();
            return false;
        }
        debug_assert!(self.pending.len() < BATCH_CHUNK);
        self.pending.push(entry);
        true
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn is_full(&self) -> bool {
        self.pending.len() == BATCH_CHUNK
    }

    pub(super) fn take_pending(&mut self) -> Vec<PendingAttestation> {
        let entries = std::mem::take(&mut self.pending);
        self.keys.clear();
        entries
    }

    pub(super) fn restore_pending_buffer(&mut self, mut entries: Vec<PendingAttestation>) {
        entries.clear();
        self.pending = entries;
    }

    pub(super) fn verify(&mut self, entries: &[PendingAttestation]) -> Vec<bool> {
        self.verifier.verify(entries)
    }

    pub(super) fn recycle_verdicts(&mut self, verdicts: Vec<bool>) {
        self.verifier.recycle_verdicts(verdicts);
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::{PublicKey, SecretKey, Signature};
    use silver_common::ssz_view::SINGLE_ATT_SIZE;

    use super::{
        super::super::bls::DST, BATCH_CHUNK, PendingAttestation, SingleAttestationBatch,
        verifier::EntryVerifier,
    };
    use crate::tile::attestation_root_memo::AttestationRootGroup;

    fn signed(seed: u8, message: [u8; 32]) -> (PublicKey, [u8; 96]) {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        let key = SecretKey::key_gen(&ikm, &[]).unwrap();
        (key.sk_to_pk(), key.sign(&message, DST, &[]).to_bytes())
    }

    fn pending(
        seed: u8,
        target_epoch: u64,
        attester_index: usize,
        message: [u8; 32],
    ) -> PendingAttestation {
        let (public_key, signature) = signed(seed, message);
        let mut bytes = [0u8; SINGLE_ATT_SIZE];
        bytes[144..].copy_from_slice(&signature);
        PendingAttestation {
            bytes,
            public_key,
            signature: Signature::from_bytes(&signature).unwrap(),
            signing_root: message,
            root_group: None,
            data_root: [0u8; 32],
            target_epoch,
            attester_index,
            committee_position: 0,
            committee_len: 1,
            block_root: [0u8; 32],
            attestation_slot: 0,
            committee_index: 0,
            payload_present: false,
            relay: None,
        }
    }

    #[test]
    fn pending_deduplicates_attester_within_target_epoch() {
        let mut batch = SingleAttestationBatch::default();
        assert!(batch.enqueue(pending(6, 3, 42, [1u8; 32])));
        assert!(!batch.enqueue(pending(6, 3, 42, [2u8; 32])));
        assert!(batch.enqueue(pending(6, 4, 42, [2u8; 32])));
    }

    #[test]
    fn pending_chunk_is_bounded_by_batch_size() {
        let template = pending(7, 5, 0, [3u8; 32]);
        let mut batch = SingleAttestationBatch::default();
        for attester_index in 0..BATCH_CHUNK {
            let entry = PendingAttestation { attester_index, ..template.clone() };
            assert!(batch.enqueue(entry));
        }
        assert_eq!(batch.take_pending().len(), BATCH_CHUNK);
    }

    #[test]
    fn pending_chunk_storage_is_reused() {
        let mut batch = SingleAttestationBatch::default();
        batch.enqueue(pending(7, 5, 0, [3u8; 32]));
        let entries = batch.take_pending();
        let capacity = entries.capacity();
        batch.restore_pending_buffer(entries);

        batch.enqueue(pending(8, 5, 1, [3u8; 32]));
        assert_eq!(batch.take_pending().capacity(), capacity);
    }

    #[test]
    fn verification_groups_entries_by_fork_bound_signing_root() {
        let entries = vec![pending(8, 1, 0, [4u8; 32]), pending(9, 1, 1, [5u8; 32])];
        assert_eq!(EntryVerifier::default().verify(&entries), [true, true]);
    }

    #[test]
    fn memo_group_partitions_entries_by_fork_bound_signing_root() {
        let group = Some(AttestationRootGroup::for_test(0));
        let mut entries = vec![
            PendingAttestation { root_group: group, ..pending(12, 1, 0, [7u8; 32]) },
            PendingAttestation { root_group: group, ..pending(13, 1, 1, [7u8; 32]) },
            PendingAttestation { root_group: group, ..pending(14, 1, 2, [8u8; 32]) },
            PendingAttestation { root_group: group, ..pending(15, 1, 3, [8u8; 32]) },
        ];
        entries[3].signature = pending(16, 1, 4, [8u8; 32]).signature;

        assert_eq!(EntryVerifier::default().verify(&entries), [true, true, true, false]);
    }

    #[test]
    fn singleton_verification_checks_the_signature_directly() {
        let valid = pending(10, 1, 0, [6u8; 32]);
        assert_eq!(EntryVerifier::default().verify(&[valid.clone()]), [true]);

        let wrong_signature = pending(11, 1, 1, [6u8; 32]).signature;
        let invalid = PendingAttestation { signature: wrong_signature, ..valid };
        assert_eq!(EntryVerifier::default().verify(&[invalid]), [false]);
    }
}
