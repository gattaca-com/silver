#[cfg(test)]
use std::cell::Cell;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use blst::{
    BLST_ERROR, MultiPoint,
    min_pk::{PublicKey, Signature},
};
use ring::rand::{SecureRandom, SystemRandom};
use rustc_hash::{FxHashMap, FxHashSet};
use silver_beacon_state_data::B256;
use silver_common::{
    GossipTopic, MessageId, NewGossipMsg, P2pStreamId, TCacheRead, metrics::timed,
    ssz_view::SINGLE_ATT_SIZE,
};

use crate::{bls::DST, counters::BeaconStateCounters};

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

#[derive(Clone, Copy, Debug)]
pub(super) struct RelayMetadata {
    pub(super) stream_id: P2pStreamId,
    pub(super) topic: GossipTopic,
    pub(super) msg_hash: MessageId,
    pub(super) recv_ts: flux::timing::Nanos,
    pub(super) protobuf: TCacheRead,
}

impl From<&NewGossipMsg> for RelayMetadata {
    fn from(message: &NewGossipMsg) -> Self {
        Self {
            stream_id: message.stream_id,
            topic: message.topic,
            msg_hash: message.msg_hash,
            recv_ts: message.recv_ts,
            protobuf: message.protobuf,
        }
    }
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

    #[timed]
    pub(super) fn verify(entries: &[PendingAttestation]) -> Vec<bool> {
        if let [entry] = entries {
            return vec![
                entry.signature.verify(
                    true,
                    &entry.signing_root,
                    DST,
                    &[],
                    &entry.public_key,
                    false,
                ) == BLST_ERROR::BLST_SUCCESS,
            ];
        }
        let mut groups: FxHashMap<B256, Vec<usize>> = FxHashMap::default();
        for (index, entry) in entries.iter().enumerate() {
            groups.entry(entry.signing_root).or_default().push(index);
        }
        let mut verdicts = vec![false; entries.len()];
        for (signing_root, indices) in groups {
            let mut batch = SameMessageBatch::default();
            for &index in &indices {
                batch.push(entries[index].public_key, entries[index].signature);
            }
            for (index, valid) in indices.into_iter().zip(batch.verify(&signing_root)) {
                verdicts[index] = valid;
            }
        }
        verdicts
    }
}

#[derive(Default)]
pub(super) struct SameMessageBatch {
    public_keys: Vec<PublicKey>,
    signatures: Vec<Signature>,
    #[cfg(test)]
    subgroup_checks: Cell<usize>,
    #[cfg(test)]
    singleton_verifies: Cell<usize>,
}

impl SameMessageBatch {
    pub(super) fn push(&mut self, public_key: PublicKey, signature: Signature) {
        self.public_keys.push(public_key);
        self.signatures.push(signature);
    }

    pub(super) fn verify(&self, message: &[u8; 32]) -> Vec<bool> {
        let subgroup_valid: Vec<_> = self
            .signatures
            .iter()
            .map(|signature| {
                #[cfg(test)]
                self.subgroup_checks.set(self.subgroup_checks.get() + 1);
                signature.validate(true).is_ok()
            })
            .collect();
        let mut verdicts = vec![false; self.public_keys.len()];
        self.verify_range(message, &subgroup_valid, 0, self.public_keys.len(), &mut verdicts);
        verdicts
    }

    fn verify_range(
        &self,
        message: &[u8; 32],
        subgroup_valid: &[bool],
        start: usize,
        end: usize,
        verdicts: &mut [bool],
    ) {
        if start == end {
            return;
        }
        if end - start == 1 {
            if subgroup_valid[start] {
                #[cfg(test)]
                self.singleton_verifies.set(self.singleton_verifies.get() + 1);
                verdicts[start] = self.signatures[start].verify(
                    false,
                    message,
                    DST,
                    &[],
                    &self.public_keys[start],
                    false,
                ) == BLST_ERROR::BLST_SUCCESS;
            }
            return;
        }
        if subgroup_valid[start..end].iter().all(|&valid| valid) &&
            self.verify_weighted(message, start, end)
        {
            verdicts[start..end].fill(true);
            return;
        }
        let middle = start + (end - start) / 2;
        self.verify_range(message, subgroup_valid, start, middle, verdicts);
        self.verify_range(message, subgroup_valid, middle, end, verdicts);
    }

    fn verify_weighted(&self, message: &[u8; 32], start: usize, end: usize) -> bool {
        debug_assert!(end - start >= 2);
        let mut scalars = vec![0u8; (end - start) * 8];
        if SystemRandom::new().fill(&mut scalars).is_err() {
            return false;
        }
        for scalar in scalars.chunks_exact_mut(8) {
            if scalar.iter().all(|&byte| byte == 0) {
                scalar[0] = 1;
            }
        }
        let public_key = self.public_keys[start..end].mult(&scalars, 64).to_public_key();
        let signature = self.signatures[start..end].mult(&scalars, 64).to_signature();
        signature.fast_aggregate_verify_pre_aggregated(false, message, DST, &public_key) ==
            BLST_ERROR::BLST_SUCCESS
    }

    #[cfg(test)]
    fn operation_counts(&self) -> (usize, usize) {
        (self.subgroup_checks.get(), self.singleton_verifies.get())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use blst::min_pk::{SecretKey, Signature};
    use silver_common::ssz_view::SINGLE_ATT_SIZE;

    use super::{
        super::super::bls::DST, BATCH_CHUNK, MAX_WINDOW, PENDING_CAP, PendingAttestation,
        SameMessageBatch, SingleAttestationBatch,
    };

    fn signed(seed: u8, message: [u8; 32]) -> (blst::min_pk::PublicKey, [u8; 96]) {
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
    fn same_message_batch_attributes_one_bad_signature() {
        let message = [7u8; 32];
        let (pk0, sig0) = signed(1, message);
        let (pk1, _) = signed(2, message);
        let (_, wrong_sig) = signed(3, message);
        let mut batch = SameMessageBatch::default();
        batch.push(pk0, Signature::from_bytes(&sig0).unwrap());
        batch.push(pk1, Signature::from_bytes(&wrong_sig).unwrap());

        assert_eq!(batch.verify(&message), vec![true, false]);
    }

    #[test]
    fn weighted_batch_rejects_signatures_that_only_verify_as_an_unweighted_sum() {
        let message = [11u8; 32];
        let (pk0, sig0) = signed(4, message);
        let (pk1, sig1) = signed(5, message);
        let mut batch = SameMessageBatch::default();
        batch.push(pk0, Signature::from_bytes(&sig1).unwrap());
        batch.push(pk1, Signature::from_bytes(&sig0).unwrap());

        assert_eq!(batch.verify(&message), vec![false, false]);
    }

    #[test]
    fn all_invalid_batch_checks_each_subgroup_and_leaf_once() {
        let message = [12u8; 32];
        let pairs: Vec<_> = (0..128u8).map(|index| signed(index + 1, message)).collect();
        let mut batch = SameMessageBatch::default();
        for index in 0..pairs.len() {
            batch.push(pairs[index].0, Signature::from_bytes(&pairs[(index + 1) % 128].1).unwrap());
        }

        assert_eq!(batch.verify(&message), vec![false; 128]);
        assert_eq!(batch.operation_counts(), (128, 128));
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
        assert_eq!(SingleAttestationBatch::verify(&entries), vec![true, true]);
    }

    #[test]
    fn singleton_verification_checks_the_signature_directly() {
        let valid = pending(10, 1, 0, [6u8; 32]);
        assert_eq!(SingleAttestationBatch::verify(&[valid.clone()]), vec![true]);

        let wrong_signature = pending(11, 1, 1, [6u8; 32]).signature;
        let invalid = PendingAttestation { signature: wrong_signature, ..valid };
        assert_eq!(SingleAttestationBatch::verify(&[invalid]), vec![false]);
    }
}
