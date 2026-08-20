use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use blst::min_pk::{PublicKey, Signature};
use rustc_hash::FxHashSet;
use silver_beacon_state_data::B256;
use silver_common::ssz_view::SINGLE_ATT_SIZE;

use super::gossip::RelayMetadata;
use crate::counters::BeaconStateCounters;

mod verifier;
pub(super) use verifier::verify_entries;

pub(super) const BATCH_CHUNK: usize = 128;
const PENDING_CAP: usize = 4096;
const MAX_WINDOW: Duration = Duration::from_millis(2);

#[derive(Clone)]
pub(super) struct PendingAttestation {
    pub(super) bytes: [u8; SINGLE_ATT_SIZE],
    pub(super) public_key: PublicKey,
    pub(super) signature: Signature,
    pub(super) signing_root: B256,
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
    pending: VecDeque<PendingAttestation>,
    keys: FxHashSet<(u64, usize)>,
    opened_at: Option<Instant>,
}

impl Default for SingleAttestationBatch {
    fn default() -> Self {
        Self {
            pending: VecDeque::with_capacity(BATCH_CHUNK),
            keys: FxHashSet::default(),
            opened_at: None,
        }
    }
}

impl SingleAttestationBatch {
    pub(super) fn enqueue(&mut self, entry: PendingAttestation) -> bool {
        let key = (entry.target_epoch, entry.attester_index);
        if self.pending.len() == PENDING_CAP {
            BeaconStateCounters::PendingSingleAttestationFull.inc();
            return false;
        }
        if !self.keys.insert(key) {
            BeaconStateCounters::PendingSingleAttestationDuplicate.inc();
            return false;
        }
        self.opened_at.get_or_insert_with(Instant::now);
        self.pending.push_back(entry);
        true
    }

    pub(super) fn should_flush(&self) -> bool {
        self.pending.len() >= BATCH_CHUNK ||
            self.opened_at.is_some_and(|opened| opened.elapsed() >= MAX_WINDOW)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn take_chunk(&mut self) -> Vec<PendingAttestation> {
        let count = self.pending.len().min(BATCH_CHUNK);
        let entries: Vec<_> = self.pending.drain(..count).collect();
        for entry in &entries {
            self.keys.remove(&(entry.target_epoch, entry.attester_index));
        }
        self.opened_at = if self.pending.is_empty() { None } else { Some(Instant::now()) };
        entries
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use blst::min_pk::{PublicKey, SecretKey, Signature};
    use silver_common::ssz_view::SINGLE_ATT_SIZE;

    use super::{
        super::super::bls::DST, BATCH_CHUNK, MAX_WINDOW, PENDING_CAP, PendingAttestation,
        SingleAttestationBatch, verifier::verify_entries,
    };

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
    fn pending_cap_and_window_bound_queueing() {
        let template = pending(7, 5, 0, [3u8; 32]);
        let mut batch = SingleAttestationBatch::default();
        for attester_index in 0..PENDING_CAP {
            let entry = PendingAttestation { attester_index, ..template.clone() };
            assert!(batch.enqueue(entry));
        }
        assert!(!batch.enqueue(PendingAttestation { attester_index: PENDING_CAP, ..template }));
        assert_eq!(batch.take_chunk().len(), BATCH_CHUNK);

        batch.opened_at = Some(Instant::now() - MAX_WINDOW);
        assert!(batch.should_flush());
    }

    #[test]
    fn verification_groups_entries_by_fork_bound_signing_root() {
        let entries = vec![pending(8, 1, 0, [4u8; 32]), pending(9, 1, 1, [5u8; 32])];
        assert_eq!(verify_entries(&entries), vec![true, true]);
    }

    #[test]
    fn singleton_verification_checks_the_signature_directly() {
        let valid = pending(10, 1, 0, [6u8; 32]);
        assert_eq!(verify_entries(&[valid.clone()]), vec![true]);

        let wrong_signature = pending(11, 1, 1, [6u8; 32]).signature;
        let invalid = PendingAttestation { signature: wrong_signature, ..valid };
        assert_eq!(verify_entries(&[invalid]), vec![false]);
    }
}
