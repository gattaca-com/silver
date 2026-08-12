use blst::min_pk::{AggregateSignature, Signature};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    metrics::timed,
    ssz_view::{
        ATTESTATION_DATA_SIZE, ATTESTATION_FIXED, MAX_COMMITTEES_PER_SLOT, SINGLE_ATT_SIZE,
        SingleAttestationView,
    },
};

use crate::bls::VerifiedSingleAttestation;

/// Retention is two slots (current + previous) at ≤ MAX_COMMITTEES_PER_SLOT
/// committees each; the ×4 is headroom for competing data_root variants,
/// which honest traffic keeps at ~1 per committee and which cost an
/// attacker a real committee member's one attestation per epoch.
const MAX_ENTRIES: usize = 4 * 2 * MAX_COMMITTEES_PER_SLOT;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AggregateKey {
    slot: Slot,
    committee_index: u64,
    data_root: B256,
}

struct AggregateEntry {
    data: [u8; ATTESTATION_DATA_SIZE],
    committee_len: usize,
    /// Logical participant bits only; the SSZ terminator is appended at
    /// serialization so it can never read as an attester.
    participant_bits: Vec<u8>,
    signature: AggregateSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InsertOutcome {
    Inserted,
    Duplicate,
    /// Slot below the retention floor — valid vote, just not aggregable.
    Stale,
    Full,
    /// Position ≥ committee length, or length differs from the entry's.
    Inconsistent,
}

pub(super) struct AttestationPool {
    entries: FxHashMap<AggregateKey, AggregateEntry>,
    floor: Slot,
}

impl AttestationPool {
    pub(super) fn new() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
        }
    }

    #[timed]
    pub(super) fn insert_verified(
        &mut self,
        att: &[u8; SINGLE_ATT_SIZE],
        committee_position: usize,
        committee_len: usize,
        verified: &VerifiedSingleAttestation,
    ) -> InsertOutcome {
        if committee_position >= committee_len {
            return InsertOutcome::Inconsistent;
        }
        let slot = SingleAttestationView::slot(att);
        if slot < self.floor {
            return InsertOutcome::Stale;
        }
        let committee_index = SingleAttestationView::committee_index(att);
        debug_assert!(committee_index < MAX_COMMITTEES_PER_SLOT as u64);

        let key = AggregateKey { slot, committee_index, data_root: verified.data_root };
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.committee_len != committee_len {
                return InsertOutcome::Inconsistent;
            }
            return entry.add(committee_position, &verified.signature);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return InsertOutcome::Full;
        }
        self.entries.insert(
            key,
            AggregateEntry::new(
                SingleAttestationView::data(att).as_bytes(),
                committee_len,
                committee_position,
                &verified.signature,
            ),
        );
        InsertOutcome::Inserted
    }

    #[allow(dead_code)] // retrieval interface for the aggregate_attestation API milestone
    #[timed]
    pub(super) fn aggregate_ssz(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<Vec<u8>> {
        let entry = self.entries.get(&AggregateKey { slot, committee_index, data_root })?;
        let bitlist_len = entry.committee_len / 8 + 1;
        let mut out = Vec::with_capacity(ATTESTATION_FIXED + bitlist_len);
        out.extend_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        out.extend_from_slice(&entry.data);
        out.extend_from_slice(&entry.signature.to_signature().to_bytes());
        out.extend_from_slice(&(1u64 << committee_index).to_le_bytes());
        out.extend_from_slice(&entry.participant_bits);
        out.resize(ATTESTATION_FIXED + bitlist_len, 0);
        out[ATTESTATION_FIXED + entry.committee_len / 8] |= 1 << (entry.committee_len % 8);
        Some(out)
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|key, _| key.slot >= floor);
    }
}

impl AggregateEntry {
    fn new(
        data: &[u8; ATTESTATION_DATA_SIZE],
        committee_len: usize,
        position: usize,
        signature: &Signature,
    ) -> Self {
        let mut participant_bits = vec![0u8; committee_len.div_ceil(8)];
        participant_bits[position / 8] |= 1 << (position % 8);
        Self {
            data: *data,
            committee_len,
            participant_bits,
            signature: AggregateSignature::from_signature(signature),
        }
    }

    fn add(&mut self, position: usize, signature: &Signature) -> InsertOutcome {
        let (byte, bit) = (position / 8, 1u8 << (position % 8));
        if self.participant_bits[byte] & bit != 0 {
            return InsertOutcome::Duplicate;
        }
        // No group check: `VerifiedSingleAttestation` guarantees a
        // subgroup-checked signature. BLS addition is not idempotent, so the
        // bit test above must gate it.
        self.signature.add_signature(signature, false).expect("infallible without groupcheck");
        self.participant_bits[byte] |= bit;
        InsertOutcome::Inserted
    }
}

#[cfg(test)]
mod tests {
    use blst::BLST_ERROR;
    use silver_beacon_state_data::Immutable;
    use silver_common::ssz_view::AttestationView;

    use super::*;
    use crate::{bls, merkle, ssz_hash, test_signing};

    const SLOT: u64 = 3;

    fn verified_single(sk_idx: usize) -> ([u8; SINGLE_ATT_SIZE], VerifiedSingleAttestation) {
        single_with(sk_idx, |_| {})
    }

    fn single_with(
        sk_idx: usize,
        mutate: impl FnOnce(&mut [u8; SINGLE_ATT_SIZE]),
    ) -> ([u8; SINGLE_ATT_SIZE], VerifiedSingleAttestation) {
        let imm = Immutable::default();
        let mut buf = test_signing::sign_single_attestation(
            sk_idx,
            sk_idx as u64,
            0,
            SLOT,
            [0xAB; 32],
            0,
            [0xAB; 32],
            &imm,
        );
        mutate(&mut buf);
        test_signing::resign_single_attestation(sk_idx, &mut buf, &imm);
        let verified = VerifiedSingleAttestation {
            data_root: ssz_hash::hash_attestation_data(
                SingleAttestationView::data(&buf).as_bytes(),
            ),
            signature: Signature::from_bytes(SingleAttestationView::signature(&buf)).unwrap(),
        };
        (buf, verified)
    }

    /// The message the attesters signed: same domain derivation the seeded
    /// tile resolves (zero fork version, zero gvr).
    fn signing_root(buf: &[u8; SINGLE_ATT_SIZE]) -> B256 {
        let data_root =
            ssz_hash::hash_attestation_data(SingleAttestationView::data(buf).as_bytes());
        let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, [0; 4], &[0u8; 32]);
        bls::compute_signing_root(&data_root, &domain)
    }

    #[test]
    fn two_singles_aggregate_to_two_bits_and_verifying_signature() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = verified_single(1);
        assert_eq!(pool.insert_verified(&a, 1, 4, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 3, 4, &vb), InsertOutcome::Inserted);

        let out = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();

        assert_eq!(&out[0..4], &236u32.to_le_bytes());
        assert_eq!(
            AttestationView::data(&out).as_bytes(),
            SingleAttestationView::data(&a).as_bytes()
        );
        assert_eq!(AttestationView::committee_bits(&out), &1u64.to_le_bytes());
        // positions 1 and 3 set, terminator at bit 4.
        assert_eq!(AttestationView::aggregation_bits(&out), &[0b0001_1010]);

        let sig = Signature::from_bytes(AttestationView::signature(&out)).unwrap();
        let msg = signing_root(&a);
        let pks = [&test_signing::pubkey_pk(0), &test_signing::pubkey_pk(1)];
        assert_eq!(sig.fast_aggregate_verify(true, &msg, bls::DST, &pks), BLST_ERROR::BLST_SUCCESS);
        // No longer either single signer's signature.
        assert_ne!(
            sig.fast_aggregate_verify(true, &msg, bls::DST, &pks[..1]),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    #[test]
    fn insertion_order_does_not_change_serialized_aggregate() {
        let (a, va) = verified_single(0);
        let (b, vb) = verified_single(1);

        let mut fwd = AttestationPool::new();
        assert_eq!(fwd.insert_verified(&a, 0, 5, &va), InsertOutcome::Inserted);
        assert_eq!(fwd.insert_verified(&b, 4, 5, &vb), InsertOutcome::Inserted);

        let mut rev = AttestationPool::new();
        assert_eq!(rev.insert_verified(&b, 4, 5, &vb), InsertOutcome::Inserted);
        assert_eq!(rev.insert_verified(&a, 0, 5, &va), InsertOutcome::Inserted);

        assert_eq!(
            fwd.aggregate_ssz(SLOT, 0, va.data_root).unwrap(),
            rev.aggregate_ssz(SLOT, 0, va.data_root).unwrap()
        );
    }

    #[test]
    fn same_member_twice_is_duplicate_and_leaves_signature_unchanged() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = verified_single(1);
        assert_eq!(pool.insert_verified(&a, 1, 4, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 2, 4, &vb), InsertOutcome::Inserted);
        let before = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();

        assert_eq!(pool.insert_verified(&a, 1, 4, &va), InsertOutcome::Duplicate);
        assert_eq!(pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap(), before);
    }

    #[test]
    fn equal_data_different_committee_index_stays_separate() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        // committee_index lives outside AttestationData → same data_root.
        let (b, vb) = single_with(1, |buf| buf[0..8].copy_from_slice(&1u64.to_le_bytes()));
        assert_eq!(va.data_root, vb.data_root);

        assert_eq!(pool.insert_verified(&a, 0, 4, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 0, 4, &vb), InsertOutcome::Inserted);

        let out_a = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();
        let out_b = pool.aggregate_ssz(SLOT, 1, vb.data_root).unwrap();
        assert_eq!(AttestationView::aggregation_bits(&out_a), &[0b0001_0001]);
        assert_eq!(AttestationView::aggregation_bits(&out_b), &[0b0001_0001]);
        assert_eq!(AttestationView::committee_bits(&out_b), &2u64.to_le_bytes());
    }

    #[test]
    fn different_attestation_data_stays_separate() {
        let mutators: [fn(&mut [u8; SINGLE_ATT_SIZE]); 4] = [
            |buf| buf[32] ^= 1,  // beacon_block_root
            |buf| buf[64] = 1,   // source.epoch
            |buf| buf[112] ^= 1, // target.root
            |buf| buf[24] = 1,   // Gloas payload-status index
        ];
        for mutate in mutators {
            let mut pool = AttestationPool::new();
            let (a, va) = verified_single(0);
            let (b, vb) = single_with(1, mutate);
            assert_ne!(va.data_root, vb.data_root);

            assert_eq!(pool.insert_verified(&a, 0, 4, &va), InsertOutcome::Inserted);
            assert_eq!(pool.insert_verified(&b, 1, 4, &vb), InsertOutcome::Inserted);

            let out_a = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();
            let out_b = pool.aggregate_ssz(SLOT, 0, vb.data_root).unwrap();
            assert_eq!(AttestationView::aggregation_bits(&out_a), &[0b0001_0001]);
            assert_eq!(AttestationView::aggregation_bits(&out_b), &[0b0001_0010]);
        }
    }

    #[test]
    fn out_of_range_position_and_len_mismatch_error_without_mutation() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = verified_single(1);
        assert_eq!(pool.insert_verified(&a, 0, 4, &va), InsertOutcome::Inserted);
        let before = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();

        assert_eq!(pool.insert_verified(&b, 4, 4, &vb), InsertOutcome::Inconsistent);
        assert_eq!(pool.insert_verified(&b, 1, 5, &vb), InsertOutcome::Inconsistent);
        assert_eq!(pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap(), before);

        let mut fresh = AttestationPool::new();
        assert_eq!(fresh.insert_verified(&b, 9, 4, &vb), InsertOutcome::Inconsistent);
        assert_eq!(fresh.aggregate_ssz(SLOT, 0, vb.data_root), None);
    }

    #[test]
    fn bitlist_terminator_crosses_byte_boundaries() {
        let cases: [(usize, usize, &[u8]); 6] = [
            (7, 6, &[0b1100_0000]), // ceil(8/8)=1 byte; term bit 7
            (7, 0, &[0b1000_0001]),
            (8, 7, &[0b1000_0000, 0b0000_0001]), // term overflows to byte1 bit0
            (8, 0, &[0b0000_0001, 0b0000_0001]),
            (9, 8, &[0b0000_0000, 0b0000_0011]), // participant+term share byte1
            (9, 0, &[0b0000_0001, 0b0000_0010]),
        ];
        for (len, pos, expect) in cases {
            let mut pool = AttestationPool::new();
            let (a, va) = verified_single(0);
            assert_eq!(pool.insert_verified(&a, pos, len, &va), InsertOutcome::Inserted);

            let out = pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap();
            let bits = AttestationView::aggregation_bits(&out);
            assert_eq!(bits, expect);
            assert_eq!(out.len(), ATTESTATION_FIXED + expect.len());
            // Closes the loop with the production bitlist reader — the
            // terminator can never read as an attester.
            assert_eq!(merkle::bitlist_len(bits), len);
        }
    }

    #[test]
    fn prune_before_removes_expired_slots() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = single_with(1, |buf| buf[16..24].copy_from_slice(&4u64.to_le_bytes()));
        assert_eq!(pool.insert_verified(&a, 0, 4, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 1, 4, &vb), InsertOutcome::Inserted);

        pool.prune_before(4);

        assert_eq!(pool.aggregate_ssz(SLOT, 0, va.data_root), None);
        assert!(pool.aggregate_ssz(4, 0, vb.data_root).is_some());
        // The floor also gates inserts between prunes.
        assert_eq!(pool.insert_verified(&a, 0, 4, &va), InsertOutcome::Stale);
    }
}
