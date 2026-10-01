use std::cmp::Reverse;

use blst::min_pk::{AggregateSignature, Signature};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    metrics::timed,
    ssz_view::{
        ATTESTATION_DATA_SIZE, ATTESTATION_FIXED, AttestationDataView, MAX_ATTESTATIONS_ELECTRA,
        MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, SINGLE_ATT_SIZE,
        SingleAttestationView,
    },
};

use crate::{bls::VerifiedSingleAttestation, merkle};

/// Retention is the inclusion window, the previous and current epoch, at
/// ≤ MAX_COMMITTEES_PER_SLOT committees per slot; the ×4 is headroom for
/// competing data_root variants, which honest traffic keeps at ~1 per
/// committee and which cost an attacker a real committee member's one
/// attestation per epoch.
const MAX_ENTRIES: usize = 4 * 2 * SLOTS_PER_EPOCH as usize * MAX_COMMITTEES_PER_SLOT;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AggregateKey {
    slot: Slot,
    committee_index: u64,
    data_root: B256,
}

pub(super) struct AggregateEntry {
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
    /// Participation metadata is invalid or conflicts with the entry's.
    Inconsistent,
}

pub(super) struct AttestationPool {
    entries: FxHashMap<AggregateKey, AggregateEntry>,
    floor: Slot,
    candidates: Vec<Candidate>,
}

#[derive(Clone, Copy)]
struct Candidate {
    key: AggregateKey,
    participants: u32,
}

/// The candidates `start..end` share one slot and data.
#[derive(Clone, Copy, Default)]
struct PackedData {
    slot: Slot,
    participants: u32,
    start: usize,
    end: usize,
}

impl AttestationPool {
    pub(super) fn new() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
            candidates: Vec::with_capacity(MAX_ENTRIES),
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
        let mut participant_bits = vec![0u8; committee_len.div_ceil(8)];
        participant_bits[committee_position / 8] |= 1 << (committee_position % 8);
        self.entries.insert(key, AggregateEntry {
            data: *SingleAttestationView::data(att).as_bytes(),
            committee_len,
            participant_bits,
            signature: AggregateSignature::from_signature(&verified.signature),
        });
        InsertOutcome::Inserted
    }

    /// Unions disjoint aggregates; of overlapping ones, keeps the one with
    /// more participants.
    #[timed]
    pub(super) fn insert_verified_aggregate(
        &mut self,
        data: AttestationDataView,
        committee_index: u64,
        data_root: B256,
        committee_len: usize,
        aggregation_bits: &[u8],
        signature: &Signature,
    ) -> InsertOutcome {
        debug_assert!(signature.subgroup_check());
        if committee_len > MAX_VALIDATORS_PER_COMMITTEE ||
            aggregation_bits.len() != committee_len / 8 + 1 ||
            merkle::bitlist_len(aggregation_bits) != committee_len
        {
            return InsertOutcome::Inconsistent;
        }
        let slot = data.slot();
        if slot < self.floor {
            return InsertOutcome::Stale;
        }
        debug_assert!(committee_index < MAX_COMMITTEES_PER_SLOT as u64);

        let mut incoming = [0u8; MAX_VALIDATORS_PER_COMMITTEE / 8];
        let incoming = &mut incoming[..committee_len.div_ceil(8)];
        incoming.copy_from_slice(&aggregation_bits[..incoming.len()]);
        if !committee_len.is_multiple_of(8) {
            incoming[committee_len / 8] &= !(1 << (committee_len % 8));
        }

        let key = AggregateKey { slot, committee_index, data_root };
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.committee_len != committee_len {
                return InsertOutcome::Inconsistent;
            }
            return entry.merge(incoming, signature);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return InsertOutcome::Full;
        }
        self.entries.insert(key, AggregateEntry {
            data: *data.as_bytes(),
            committee_len,
            participant_bits: incoming.to_vec(),
            signature: AggregateSignature::from_signature(signature),
        });
        InsertOutcome::Inserted
    }

    // TODO: Score candidates by the reward they add to the parent state.
    // Map their bits to validators through the parent's shuffling. Count only
    // flags not yet set: head 14, source 14 and target 26. Then pick greedily
    // by score, not newest first. Earlier blocks already include most votes,
    // so newest first wastes most of the 8 picks. Scoring needs the parent
    // state, so a scoring closure joins `admits`.
    #[timed]
    pub(super) fn pack(&mut self, admits: impl Fn(AttestationDataView) -> bool, out: &mut Vec<u8>) {
        out.clear();
        self.candidates.clear();
        self.candidates.extend(
            self.entries
                .iter()
                .filter(|(_, entry)| admits(AttestationDataView::new(&entry.data)))
                .map(|(&key, entry)| Candidate { key, participants: entry.participants() }),
        );
        self.candidates.sort_unstable_by_key(|c| {
            (Reverse(c.key.slot), c.key.data_root, c.key.committee_index)
        });

        let mut packed = [PackedData::default(); MAX_ATTESTATIONS_ELECTRA];
        let mut packed_len = 0;
        let mut start = 0;
        let same_data = |a: &Candidate, b: &Candidate| {
            a.key.slot == b.key.slot && a.key.data_root == b.key.data_root
        };
        for group in self.candidates.chunk_by(same_data) {
            let data = PackedData {
                slot: group[0].key.slot,
                participants: group.iter().map(|c| c.participants).sum(),
                start,
                end: start + group.len(),
            };
            start = data.end;
            match packed[..packed_len].last_mut() {
                Some(last) if last.slot == data.slot => {
                    if data.participants > last.participants {
                        *last = data;
                    }
                }
                _ if packed_len == MAX_ATTESTATIONS_ELECTRA => break,
                _ => {
                    packed[packed_len] = data;
                    packed_len += 1;
                }
            }
        }

        let offset_len = size_of::<u32>();
        out.resize(packed_len * offset_len, 0);
        for (i, data) in packed[..packed_len].iter().enumerate() {
            let at = out.len();
            out[i * offset_len..(i + 1) * offset_len].copy_from_slice(&(at as u32).to_le_bytes());
            let committees = self.candidates[data.start..data.end]
                .iter()
                .map(|c| (c.key.committee_index, &self.entries[&c.key]));
            let len = AggregateEntry::attestation_len(committees.clone());
            out.resize(at + len, 0);
            AggregateEntry::write_attestation(committees, &mut out[at..]);
        }
    }

    #[timed]
    pub(super) fn aggregate(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<&AggregateEntry> {
        self.entries.get(&AggregateKey { slot, committee_index, data_root })
    }

    #[cfg(test)]
    pub(super) fn aggregate_ssz(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<Vec<u8>> {
        let entry = self.aggregate(slot, committee_index, data_root)?;
        let mut out = vec![0u8; entry.ssz_len()];
        entry.write_ssz(committee_index, &mut out);
        Some(out)
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|key, _| key.slot >= floor);
    }
}

impl AggregateEntry {
    pub(super) fn ssz_len(&self) -> usize {
        ATTESTATION_FIXED + self.committee_len / 8 + 1
    }

    /// `out` is exactly [`Self::ssz_len`] bytes and need not be zeroed.
    #[timed]
    pub(super) fn write_ssz(&self, committee_index: u64, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.ssz_len());
        Self::write_attestation([(committee_index, self)].into_iter(), out);
    }

    fn attestation_len<'a>(committees: impl Iterator<Item = (u64, &'a Self)>) -> usize {
        let members: usize = committees.map(|(_, entry)| entry.committee_len).sum();
        ATTESTATION_FIXED + members / 8 + 1
    }

    fn write_attestation<'a>(
        mut committees: impl Iterator<Item = (u64, &'a Self)>,
        out: &mut [u8],
    ) {
        let (fixed, bits) = out.split_at_mut(ATTESTATION_FIXED);
        bits.fill(0);
        let (first_index, first) = committees.next().expect("at least one committee");
        let mut signature = first.signature;
        let mut committee_bits = 1u64 << first_index;
        first.write_bits_at(bits, 0);
        let mut members = first.committee_len;
        for (committee_index, entry) in committees {
            debug_assert!(entry.data == first.data);
            debug_assert!(committee_bits >> committee_index == 0, "ascending committees");
            signature.add_aggregate(&entry.signature);
            committee_bits |= 1 << committee_index;
            entry.write_bits_at(bits, members);
            members += entry.committee_len;
        }
        bits[members / 8] |= 1 << (members % 8);

        fixed[0..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        fixed[4..132].copy_from_slice(&first.data);
        fixed[132..228].copy_from_slice(&signature.to_signature().to_bytes());
        fixed[228..].copy_from_slice(&committee_bits.to_le_bytes());
    }

    /// ORs the participant bits into `bits` from bit `at`.
    fn write_bits_at(&self, bits: &mut [u8], at: usize) {
        let (byte, shift) = (at / 8, at % 8);
        for (i, &participants) in self.participant_bits.iter().enumerate() {
            let shifted = (participants as u16) << shift;
            bits[byte + i] |= shifted as u8;
            if let Some(next) = bits.get_mut(byte + i + 1) {
                *next |= (shifted >> 8) as u8;
            }
        }
    }

    fn participants(&self) -> u32 {
        self.participant_bits.iter().map(|byte| byte.count_ones()).sum()
    }

    #[timed]
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

    fn merge(&mut self, incoming: &[u8], signature: &Signature) -> InsertOutcome {
        let overlaps =
            self.participant_bits.iter().zip(incoming).any(|(held, new)| held & new != 0);
        if !overlaps {
            self.signature.add_signature(signature, false).expect("infallible without groupcheck");
            for (held, new) in self.participant_bits.iter_mut().zip(incoming) {
                *held |= new;
            }
            return InsertOutcome::Inserted;
        }
        let incoming_count: u32 = incoming.iter().map(|byte| byte.count_ones()).sum();
        if incoming_count <= self.participants() {
            return InsertOutcome::Duplicate;
        }
        self.participant_bits.copy_from_slice(incoming);
        self.signature = AggregateSignature::from_signature(signature);
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

    fn bitlist(positions: &[usize], committee_len: usize) -> Vec<u8> {
        let mut bits = vec![0u8; committee_len / 8 + 1];
        for &position in positions.iter().chain([&committee_len]) {
            bits[position / 8] |= 1 << (position % 8);
        }
        bits
    }

    /// The aggregate of `signers`' singles, at the positions given.
    fn insert_aggregate(
        pool: &mut AttestationPool,
        signers: &[(usize, usize)],
        committee_len: usize,
    ) -> InsertOutcome {
        let singles: Vec<_> = signers.iter().map(|&(sk_idx, _)| verified_single(sk_idx)).collect();
        let signatures: Vec<_> = singles.iter().map(|(_, verified)| &verified.signature).collect();
        let signature = AggregateSignature::aggregate(&signatures, false).unwrap().to_signature();
        let positions: Vec<_> = signers.iter().map(|&(_, position)| position).collect();
        let (single, verified) = &singles[0];
        pool.insert_verified_aggregate(
            SingleAttestationView::data(single),
            0,
            verified.data_root,
            committee_len,
            &bitlist(&positions, committee_len),
            &signature,
        )
    }

    fn assert_signed_by(attestation: &[u8], sk_indices: &[usize]) {
        let (single, _) = verified_single(0);
        let sig = Signature::from_bytes(AttestationView::signature(attestation)).unwrap();
        let pks: Vec<_> = sk_indices.iter().map(|&i| test_signing::pubkey_pk(i)).collect();
        let pks: Vec<_> = pks.iter().collect();
        assert_eq!(
            sig.fast_aggregate_verify(true, &signing_root(&single), bls::DST, &pks),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    #[test]
    fn disjoint_aggregates_union_and_overlapping_keep_the_larger() {
        let mut pool = AttestationPool::new();
        let data_root = verified_single(0).1.data_root;
        assert_eq!(insert_aggregate(&mut pool, &[(0, 1)], 4), InsertOutcome::Inserted);
        assert_eq!(insert_aggregate(&mut pool, &[(1, 2)], 4), InsertOutcome::Inserted);
        let union = pool.aggregate_ssz(SLOT, 0, data_root).unwrap();
        assert_eq!(AttestationView::aggregation_bits(&union), &[0b0001_0110]);
        assert_signed_by(&union, &[0, 1]);

        assert_eq!(insert_aggregate(&mut pool, &[(0, 1), (2, 3)], 4), InsertOutcome::Duplicate);
        assert_eq!(pool.aggregate_ssz(SLOT, 0, data_root).unwrap(), union);

        let larger = [(0, 1), (1, 2), (2, 3)];
        assert_eq!(insert_aggregate(&mut pool, &larger, 4), InsertOutcome::Inserted);
        let replaced = pool.aggregate_ssz(SLOT, 0, data_root).unwrap();
        assert_eq!(AttestationView::aggregation_bits(&replaced), &[0b0001_1110]);
        assert_signed_by(&replaced, &[0, 1, 2]);
    }

    #[test]
    fn aggregate_bits_not_sized_to_the_committee_are_inconsistent() {
        let mut pool = AttestationPool::new();
        let (single, verified) = verified_single(0);
        let mut insert = |bits: &[u8], committee_len| {
            pool.insert_verified_aggregate(
                SingleAttestationView::data(&single),
                0,
                verified.data_root,
                committee_len,
                bits,
                &verified.signature,
            )
        };
        assert_eq!(insert(&bitlist(&[0], 5), 4), InsertOutcome::Inconsistent);
        assert_eq!(insert(&[0b0001_0001, 0], 4), InsertOutcome::Inconsistent);
        assert_eq!(insert(&bitlist(&[0], 4), 4), InsertOutcome::Inserted);
        assert_eq!(insert(&bitlist(&[1], 5), 5), InsertOutcome::Inconsistent);
    }

    /// The attestations `pack` writes, split out of their SSZ list.
    fn packed(
        pool: &mut AttestationPool,
        admits: impl Fn(AttestationDataView) -> bool,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        pool.pack(admits, &mut out);
        if out.is_empty() {
            return Vec::new();
        }
        let first = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
        let mut offsets: Vec<_> = out[..first]
            .as_chunks()
            .0
            .iter()
            .map(|offset| u32::from_le_bytes(*offset) as usize)
            .collect();
        offsets.push(out.len());
        offsets.windows(2).map(|w| out[w[0]..w[1]].to_vec()).collect()
    }

    #[test]
    fn pack_joins_the_committees_of_one_data() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = single_with(1, |buf| buf[0..8].copy_from_slice(&1u64.to_le_bytes()));
        assert_eq!(pool.insert_verified(&a, 4, 5, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 0, 4, &vb), InsertOutcome::Inserted);

        let [attestation] = &packed(&mut pool, |_| true)[..] else { panic!("one attestation") };

        assert_eq!(
            AttestationView::data(attestation).as_bytes(),
            SingleAttestationView::data(&a).as_bytes()
        );
        assert_eq!(AttestationView::committee_bits(attestation), &0b11u64.to_le_bytes());
        // Committee 0's bit 4, committee 1's bit 0 at 5, terminator at 9.
        assert_eq!(AttestationView::aggregation_bits(attestation), &[0b0011_0000, 0b0000_0010]);
        assert_signed_by(attestation, &[0, 1]);
    }

    #[test]
    fn pack_takes_the_best_admitted_data_of_the_newest_slots() {
        let mut pool = AttestationPool::new();
        let at_slot = |slot: Slot, sk_idx| {
            single_with(sk_idx, |buf| buf[16..24].copy_from_slice(&slot.to_le_bytes()))
        };
        let slots = SLOT..SLOT + MAX_ATTESTATIONS_ELECTRA as u64 + 2;
        for slot in slots.clone() {
            let (att, verified) = at_slot(slot, 0);
            assert_eq!(pool.insert_verified(&att, 0, 4, &verified), InsertOutcome::Inserted);
        }
        let newest_admitted = slots.end - 2;
        let other_vote = |sk_idx| {
            single_with(sk_idx, |buf| {
                buf[16..24].copy_from_slice(&newest_admitted.to_le_bytes());
                buf[32] ^= 1;
            })
        };
        for (position, sk_idx) in [(1, 1), (2, 2)] {
            let (att, verified) = other_vote(sk_idx);
            assert_eq!(pool.insert_verified(&att, position, 4, &verified), InsertOutcome::Inserted);
        }

        let attestations = packed(&mut pool, |data| data.slot() <= newest_admitted);

        let slots: Vec<_> = attestations.iter().map(|a| AttestationView::data(a).slot()).collect();
        let expected: Vec<_> =
            (0..MAX_ATTESTATIONS_ELECTRA as u64).map(|i| newest_admitted - i).collect();
        assert_eq!(slots, expected);
        assert_eq!(
            AttestationView::data(&attestations[0]).as_bytes(),
            SingleAttestationView::data(&other_vote(1).0).as_bytes()
        );
        assert_eq!(AttestationView::aggregation_bits(&attestations[0]), &[0b0001_0110]);
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
