use std::{cmp::Reverse, collections::hash_map::Entry};

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
const MAX_COMMITTEE_VOTES: usize = 4 * 2 * SLOTS_PER_EPOCH as usize * MAX_COMMITTEES_PER_SLOT;
/// Honest committees of a slot agree on one vote.
const EXPECTED_VOTES: usize = MAX_COMMITTEE_VOTES / MAX_COMMITTEES_PER_SLOT;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VoteKey {
    slot: Slot,
    data_root: B256,
}

struct Vote {
    data: [u8; ATTESTATION_DATA_SIZE],
    /// Ascending by index.
    committees: Vec<CommitteeVote>,
}

struct CommitteeVote {
    index: u64,
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
    votes: FxHashMap<VoteKey, Vote>,
    committee_votes: usize,
    floor: Slot,
}

impl AttestationPool {
    pub(super) fn new() -> Self {
        Self {
            votes: FxHashMap::with_capacity_and_hasher(EXPECTED_VOTES, Default::default()),
            committee_votes: 0,
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
        if committee_position >= committee_len || committee_len > MAX_VALIDATORS_PER_COMMITTEE {
            return InsertOutcome::Inconsistent;
        }
        let mut participants = [0u8; MAX_VALIDATORS_PER_COMMITTEE / 8];
        let participants = &mut participants[..committee_len.div_ceil(8)];
        participants[committee_position / 8] |= 1 << (committee_position % 8);
        self.insert(
            SingleAttestationView::data(att),
            SingleAttestationView::committee_index(att),
            verified.data_root,
            committee_len,
            participants,
            &verified.signature,
        )
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
        if committee_len > MAX_VALIDATORS_PER_COMMITTEE ||
            aggregation_bits.len() != committee_len / 8 + 1 ||
            merkle::bitlist_len(aggregation_bits) != committee_len
        {
            return InsertOutcome::Inconsistent;
        }
        let mut participants = [0u8; MAX_VALIDATORS_PER_COMMITTEE / 8];
        let participants = &mut participants[..committee_len.div_ceil(8)];
        participants.copy_from_slice(&aggregation_bits[..participants.len()]);
        if !committee_len.is_multiple_of(8) {
            participants[committee_len / 8] &= !(1 << (committee_len % 8));
        }
        self.insert(data, committee_index, data_root, committee_len, participants, signature)
    }

    fn insert(
        &mut self,
        data: AttestationDataView,
        committee_index: u64,
        data_root: B256,
        committee_len: usize,
        participants: &[u8],
        signature: &Signature,
    ) -> InsertOutcome {
        debug_assert!(signature.subgroup_check());
        debug_assert!(committee_index < MAX_COMMITTEES_PER_SLOT as u64);
        let slot = data.slot();
        if slot < self.floor {
            return InsertOutcome::Stale;
        }

        let full = self.committee_votes >= MAX_COMMITTEE_VOTES;
        let vote = match self.votes.entry(VoteKey { slot, data_root }) {
            Entry::Occupied(vote) => vote.into_mut(),
            Entry::Vacant(_) if full => return InsertOutcome::Full,
            Entry::Vacant(vote) => {
                vote.insert(Vote { data: *data.as_bytes(), committees: Vec::new() })
            }
        };
        match vote.committees.binary_search_by_key(&committee_index, |c| c.index) {
            Ok(at) if vote.committees[at].committee_len != committee_len => {
                InsertOutcome::Inconsistent
            }
            Ok(at) => vote.committees[at].merge(participants, signature),
            Err(_) if full => InsertOutcome::Full,
            Err(at) => {
                vote.committees.insert(at, CommitteeVote {
                    index: committee_index,
                    committee_len,
                    participant_bits: participants.to_vec(),
                    signature: AggregateSignature::from_signature(signature),
                });
                self.committee_votes += 1;
                InsertOutcome::Inserted
            }
        }
    }

    // TODO: Score candidates by the reward they add to the parent state.
    // Map their bits to validators through the parent's shuffling. Count only
    // flags not yet set: head 14, source 14 and target 26. Then pick greedily
    // by score, not newest first. Earlier blocks already include most votes,
    // so newest first wastes most of the 8 picks. Scoring needs the parent
    // state, so a scoring closure joins `admits`.
    #[timed]
    pub(super) fn pack(&self, admits: impl Fn(AttestationDataView) -> bool, out: &mut Vec<u8>) {
        out.clear();
        let mut newest = NewestVotes::default();
        for (key, vote) in &self.votes {
            if admits(AttestationDataView::new(&vote.data)) {
                newest.offer(*key, vote);
            }
        }

        let offset_len = size_of::<u32>();
        out.resize(newest.len() * offset_len, 0);
        for (i, vote) in newest.newest_first().enumerate() {
            let at = out.len();
            out[i * offset_len..(i + 1) * offset_len].copy_from_slice(&(at as u32).to_le_bytes());
            let aggregate = vote.aggregate();
            out.resize(at + aggregate.ssz_len(), 0);
            aggregate.write_ssz(&mut out[at..]);
        }
    }

    #[timed]
    pub(super) fn aggregate(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<PooledAggregate<'_>> {
        let vote = self.votes.get(&VoteKey { slot, data_root })?;
        let at = vote.committees.binary_search_by_key(&committee_index, |c| c.index).ok()?;
        Some(PooledAggregate { data: &vote.data, committees: &vote.committees[at..=at] })
    }

    #[cfg(test)]
    pub(super) fn aggregate_ssz(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<Vec<u8>> {
        let aggregate = self.aggregate(slot, committee_index, data_root)?;
        let mut out = vec![0u8; aggregate.ssz_len()];
        aggregate.write_ssz(&mut out);
        Some(out)
    }

    #[timed]
    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.votes.retain(|key, vote| {
            let kept = key.slot >= floor;
            if !kept {
                self.committee_votes -= vote.committees.len();
            }
            kept
        });
    }
}

/// The best vote of each of the newest slots offered. Ties go to the
/// lower data root, so the pick does not depend on map order.
#[derive(Default)]
struct NewestVotes<'a>([Option<PackedVote<'a>>; MAX_ATTESTATIONS_ELECTRA]);

#[derive(Clone, Copy)]
struct PackedVote<'a> {
    slot: Slot,
    rank: (u32, Reverse<B256>),
    vote: &'a Vote,
}

impl<'a> NewestVotes<'a> {
    fn offer(&mut self, key: VoteKey, vote: &'a Vote) {
        let offered = PackedVote {
            slot: key.slot,
            rank: (vote.participants(), Reverse(key.data_root)),
            vote,
        };
        if let Some(same_slot) = self.0.iter_mut().flatten().find(|p| p.slot == key.slot) {
            if offered.rank > same_slot.rank {
                *same_slot = offered;
            }
            return;
        }
        let oldest = self.0.iter_mut().min_by_key(|p| p.map(|p| p.slot)).expect("non-empty");
        if oldest.is_none_or(|oldest| oldest.slot < key.slot) {
            *oldest = Some(offered);
        }
    }

    fn len(&self) -> usize {
        self.0.iter().flatten().count()
    }

    fn newest_first(mut self) -> impl Iterator<Item = &'a Vote> {
        self.0.sort_unstable_by_key(|p| Reverse(p.map(|p| p.slot)));
        self.0.into_iter().flatten().map(|p| p.vote)
    }
}

impl Vote {
    fn participants(&self) -> u32 {
        self.committees.iter().map(CommitteeVote::participants).sum()
    }

    fn aggregate(&self) -> PooledAggregate<'_> {
        PooledAggregate { data: &self.data, committees: &self.committees }
    }
}

/// One on-chain `Attestation` over a vote's committees.
#[derive(Clone, Copy)]
pub(super) struct PooledAggregate<'a> {
    data: &'a [u8; ATTESTATION_DATA_SIZE],
    committees: &'a [CommitteeVote],
}

impl PooledAggregate<'_> {
    pub(super) fn ssz_len(&self) -> usize {
        let members: usize = self.committees.iter().map(|c| c.committee_len).sum();
        ATTESTATION_FIXED + members / 8 + 1
    }

    /// `out` is exactly [`Self::ssz_len`] bytes and need not be zeroed.
    #[timed]
    pub(super) fn write_ssz(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.ssz_len());
        let (fixed, bits) = out.split_at_mut(ATTESTATION_FIXED);
        bits.fill(0);
        let (first, rest) = self.committees.split_first().expect("at least one committee");
        let mut signature = first.signature;
        for committee in rest {
            signature.add_aggregate(&committee.signature);
        }
        let mut committee_bits = 0u64;
        let mut members = 0;
        for committee in self.committees {
            committee_bits |= 1 << committee.index;
            committee.write_bits_at(bits, members);
            members += committee.committee_len;
        }
        bits[members / 8] |= 1 << (members % 8);

        fixed[0..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        fixed[4..132].copy_from_slice(self.data);
        fixed[132..228].copy_from_slice(&signature.to_signature().to_bytes());
        fixed[228..].copy_from_slice(&committee_bits.to_le_bytes());
    }
}

impl CommitteeVote {
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
    fn full_pool_admits_committees_again_once_pruned() {
        let mut pool = AttestationPool::new();
        let (mut att, verified) = verified_single(0);
        let mut insert = |pool: &mut AttestationPool, slot: Slot, committee_index: u64| {
            att[16..24].copy_from_slice(&slot.to_le_bytes());
            att[0..8].copy_from_slice(&committee_index.to_le_bytes());
            pool.insert_verified(&att, 0, 4, &verified)
        };
        let committees = MAX_COMMITTEES_PER_SLOT as u64;
        let slots = MAX_COMMITTEE_VOTES as u64 / committees;
        for slot in SLOT..SLOT + slots {
            for committee_index in 0..committees {
                assert_eq!(insert(&mut pool, slot, committee_index), InsertOutcome::Inserted);
            }
        }
        assert_eq!(insert(&mut pool, SLOT + slots, 0), InsertOutcome::Full);

        pool.prune_before(SLOT + 1);

        assert_eq!(insert(&mut pool, SLOT + slots, 0), InsertOutcome::Inserted);
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
