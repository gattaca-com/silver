use blst::min_pk::{PublicKey, Signature};
use rustc_hash::FxHashSet;
use silver_beacon_state_data::B256;
use silver_common::{NewGossipMsg, ssz_view::SINGLE_ATT_SIZE};

use crate::{
    counters::BeaconStateCounters, stf::AttestationVote,
    tile::attestation_root_memo::AttestationRootGroup,
};

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
    pub(super) vote: AttestationVote,
    pub(super) committee_position: usize,
    pub(super) committee_len: usize,
    pub(super) committee_index: usize,
}

#[derive(Clone)]
pub(super) struct QueuedAttestation {
    pub(super) pending: PendingAttestation,
    pub(super) gossip: NewGossipMsg,
}

pub(super) struct SingleAttestationBatch {
    pending: Vec<QueuedAttestation>,
    keys: FxHashSet<(u64, u32)>,
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
    pub(super) fn enqueue(&mut self, entry: QueuedAttestation) -> bool {
        // Checked before the dedup insert so a refused entry stays admissible
        // on retransmission.
        if self.pending.len() == BATCH_CHUNK {
            BeaconStateCounters::PendingSingleAttestationFull.inc();
            return false;
        }
        let key = (entry.pending.vote.target_epoch, entry.pending.vote.validator);
        if !self.keys.insert(key) {
            BeaconStateCounters::PendingSingleAttestationDuplicate.inc();
            return false;
        }
        self.pending.push(entry);
        true
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn is_full(&self) -> bool {
        self.pending.len() == BATCH_CHUNK
    }

    pub(super) fn take_pending(&mut self) -> Vec<QueuedAttestation> {
        let entries = std::mem::take(&mut self.pending);
        self.keys.clear();
        entries
    }

    pub(super) fn restore_pending_buffer(&mut self, mut entries: Vec<QueuedAttestation>) {
        entries.clear();
        self.pending = entries;
    }

    pub(super) fn verify(&mut self, entries: &[QueuedAttestation]) -> Vec<bool> {
        self.verifier.verify(entries)
    }

    pub(super) fn recycle_verdicts(&mut self, verdicts: Vec<bool>) {
        self.verifier.recycle_verdicts(verdicts);
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::{PublicKey, SecretKey, Signature};
    use flux::timing::Nanos;
    use silver_common::{
        GossipTopic, MessageId, NewGossipMsg, P2pStreamId, StreamProtocol, TCache, TCacheProducer,
        TProducer, ssz_view::SINGLE_ATT_SIZE,
    };

    use super::{
        super::super::bls::DST, BATCH_CHUNK, PendingAttestation, QueuedAttestation,
        SingleAttestationBatch, verifier::EntryVerifier,
    };
    use crate::{stf::AttestationVote, tile::attestation_root_memo::AttestationRootGroup};

    fn signed(seed: u8, message: [u8; 32]) -> (PublicKey, [u8; 96]) {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        let key = SecretKey::key_gen(&ikm, &[]).unwrap();
        (key.sk_to_pk(), key.sign(&message, DST, &[]).to_bytes())
    }

    fn gossip_producer() -> TProducer {
        TCache::producer("single_att_batch_test", 1 << 12)
    }

    fn gossip(producer: &mut TProducer) -> NewGossipMsg {
        let mut reservation = producer.reserve(1, true).unwrap();
        reservation.buffer().unwrap()[0] = 0;
        reservation.increment_offset(1);
        let read = reservation.read();
        producer.publish_head();
        NewGossipMsg {
            stream_id: P2pStreamId::new(1, 0, StreamProtocol::Unset, true),
            topic: GossipTopic::BeaconAttestation(0),
            msg_hash: MessageId { id: [0; 20] },
            recv_ts: Nanos(0),
            ssz: read,
            protobuf: read,
        }
    }

    fn pending(
        seed: u8,
        target_epoch: u64,
        attester_index: u32,
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
            vote: AttestationVote {
                validator: attester_index,
                block_root: [0u8; 32],
                target_epoch,
                attestation_slot: 0,
                payload_present: false,
            },
            committee_position: 0,
            committee_len: 1,
            committee_index: 0,
        }
    }

    fn queued(
        producer: &mut TProducer,
        seed: u8,
        target_epoch: u64,
        attester_index: u32,
        message: [u8; 32],
    ) -> QueuedAttestation {
        QueuedAttestation {
            pending: pending(seed, target_epoch, attester_index, message),
            gossip: gossip(producer),
        }
    }

    #[test]
    fn pending_deduplicates_attester_within_target_epoch() {
        let mut producer = gossip_producer();
        let mut batch = SingleAttestationBatch::default();
        assert!(batch.enqueue(queued(&mut producer, 6, 3, 42, [1u8; 32])));
        assert!(!batch.enqueue(queued(&mut producer, 6, 3, 42, [2u8; 32])));
        assert!(batch.enqueue(queued(&mut producer, 6, 4, 42, [2u8; 32])));
    }

    #[test]
    fn pending_chunk_is_bounded_by_batch_size() {
        let mut producer = gossip_producer();
        let mut batch = SingleAttestationBatch::default();
        for attester_index in 0..BATCH_CHUNK {
            assert!(batch.enqueue(queued(&mut producer, 7, 5, attester_index as u32, [3u8; 32])));
        }
        assert!(batch.is_full());
        assert!(!batch.enqueue(queued(&mut producer, 7, 5, BATCH_CHUNK as u32, [3u8; 32])));
        assert_eq!(batch.take_pending().len(), BATCH_CHUNK);
    }

    #[test]
    fn pending_chunk_storage_is_reused() {
        let mut producer = gossip_producer();
        let mut batch = SingleAttestationBatch::default();
        batch.enqueue(queued(&mut producer, 7, 5, 0, [3u8; 32]));
        let entries = batch.take_pending();
        let capacity = entries.capacity();
        batch.restore_pending_buffer(entries);

        batch.enqueue(queued(&mut producer, 8, 5, 1, [3u8; 32]));
        assert_eq!(batch.take_pending().capacity(), capacity);
    }

    #[test]
    fn fallback_entries_group_by_fork_bound_signing_root() {
        let mut producer = gossip_producer();
        let entries = vec![
            queued(&mut producer, 8, 1, 0, [4u8; 32]),
            queued(&mut producer, 9, 1, 1, [5u8; 32]),
        ];
        assert_eq!(EntryVerifier::default().verify(&entries), [true, true]);
    }

    #[test]
    fn memo_group_partitions_entries_by_fork_bound_signing_root() {
        let mut producer = gossip_producer();
        let group = Some(AttestationRootGroup::for_test(0));
        let mut entries = vec![
            queued(&mut producer, 12, 1, 0, [7u8; 32]),
            queued(&mut producer, 13, 1, 1, [7u8; 32]),
            queued(&mut producer, 14, 1, 2, [8u8; 32]),
            queued(&mut producer, 15, 1, 3, [8u8; 32]),
        ];
        for entry in &mut entries {
            entry.pending.root_group = group;
        }
        entries[3].pending.signature = pending(16, 1, 4, [8u8; 32]).signature;

        assert_eq!(EntryVerifier::default().verify(&entries), [true, true, true, false]);
    }

    #[test]
    fn singleton_verification_checks_the_signature_directly() {
        let mut producer = gossip_producer();
        let valid = queued(&mut producer, 10, 1, 0, [6u8; 32]);
        assert_eq!(EntryVerifier::default().verify(std::slice::from_ref(&valid)), [true]);

        let mut invalid = valid;
        invalid.pending.signature = pending(11, 1, 1, [6u8; 32]).signature;
        assert_eq!(EntryVerifier::default().verify(&[invalid]), [false]);
    }
}
