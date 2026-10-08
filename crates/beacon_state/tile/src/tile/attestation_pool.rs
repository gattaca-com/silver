use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    metrics::timed,
    ssz_view::{
        ATTESTATION_FIXED, AttestationDataView, MAX_ATTESTATIONS_ELECTRA, MAX_COMMITTEES_PER_SLOT,
        MAX_VALIDATORS_PER_COMMITTEE, SINGLE_ATT_SIZE, SingleAttestationView,
    },
};

use crate::{
    bls::{Signature, SignatureSum, VerifiedSingleAttestation},
    merkle,
};

mod committee_attestations;
mod committee_bits;
mod committee_store;
mod selection;
mod vote_candidates;

use committee_bits::{CommitteeBits, MAX_COMMITTEE_MEMBERS};
use committee_store::{CommitteeId, CommitteeStore};
use selection::{CommitteeAttestation, Selection};
use vote_candidates::{MAX_CANDIDATES, VoteCandidate, VoteCandidates};

const MAX_COMMITTEE_CANDIDATES: usize = MAX_CANDIDATES * MAX_COMMITTEES_PER_SLOT;
/// The longest SSZ list `pack` writes: every attestation over every
/// committee of a slot at full size, with its offset.
const MAX_PACKED_LEN: usize = MAX_ATTESTATIONS_ELECTRA *
    (size_of::<u32>() +
        ATTESTATION_FIXED +
        MAX_COMMITTEES_PER_SLOT * MAX_COMMITTEE_MEMBERS / 8 +
        1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InsertOutcome {
    Inserted,
    Duplicate,
    Stale,
    Full,
    Invalid,
}

pub(super) struct AttestationPool {
    candidates: VoteCandidates,
    store: CommitteeStore,
    selection: Selection,
}

impl AttestationPool {
    pub(super) fn new() -> Self {
        Self {
            candidates: VoteCandidates::new(),
            store: CommitteeStore::new(MAX_COMMITTEE_CANDIDATES),
            selection: Selection::new(
                MAX_CANDIDATES,
                MAX_COMMITTEE_CANDIDATES,
                MAX_ATTESTATIONS_ELECTRA,
            ),
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
            return InsertOutcome::Invalid;
        }
        if committee_len > MAX_COMMITTEE_MEMBERS {
            return InsertOutcome::Full;
        }
        let mut participants = CommitteeBits::EMPTY;
        participants.insert(committee_position);
        self.insert(
            SingleAttestationView::data(att),
            SingleAttestationView::committee_index(att),
            verified.data_root,
            committee_len,
            participants,
            &verified.signature,
        )
    }

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
            return InsertOutcome::Invalid;
        }
        if committee_len > MAX_COMMITTEE_MEMBERS {
            return InsertOutcome::Full;
        }
        let participants = CommitteeBits::from_participants(aggregation_bits, committee_len);
        self.insert(data, committee_index, data_root, committee_len, participants, signature)
    }

    fn insert(
        &mut self,
        data: AttestationDataView,
        committee_index: u64,
        data_root: B256,
        committee_len: usize,
        participants: CommitteeBits,
        signature: &Signature,
    ) -> InsertOutcome {
        debug_assert!(signature.subgroup_check());
        debug_assert!(committee_index < MAX_COMMITTEES_PER_SLOT as u64);
        let candidate = match self.candidates.find_or_add(data, data_root) {
            Ok(candidate) => candidate,
            Err(outcome) => return outcome,
        };

        let index = committee_index as usize;
        let committee = CommitteeId::new(candidate, index);
        if self.candidates[candidate].open(index) {
            self.store.open(committee, committee_len);
        } else if self.store.committee_len(committee) != committee_len {
            return InsertOutcome::Invalid;
        }
        self.store.insert(committee, participants, signature)
    }

    /// Fills `out` with the SSZ list of up to `MAX_ATTESTATIONS_ELECTRA`
    /// attestations that pay the proposer most; `out` grows once, to
    /// [`MAX_PACKED_LEN`], and is reused after. `weigh` fills each committee
    /// member's reward for the flags its vote candidate still earns, zero
    /// where the block may not include it.
    #[timed]
    pub(super) fn pack(
        &mut self,
        mut weigh: impl FnMut(AttestationDataView, u64, &mut [u64]),
        out: &mut Vec<u8>,
    ) {
        let Self { candidates, store, selection } = self;
        selection.clear();
        let mut weights = [0u64; MAX_COMMITTEE_MEMBERS];
        // Newest first, as the selection breaks ties by push order.
        for id in candidates.retained_ids() {
            let candidate = &candidates[id];
            selection.push_candidate(id as u32);
            for index in candidate.committees() {
                let weights = &mut weights[..store.committee_len(CommitteeId::new(id, index))];
                weigh(candidate.data(), index as u64, weights);
                selection.push_committee(store, index as u32, weights);
            }
        }
        selection.select(MAX_ATTESTATIONS_ELECTRA, store, |id, index, weights| {
            weigh(candidates[id as usize].data(), index as u64, weights)
        });

        let attestations = selection.attestations().map(|(id, committees)| PooledAggregate {
            id: id as usize,
            candidate: &candidates[id as usize],
            store,
            committees,
        });
        write_ssz_list(attestations, out);
    }

    #[timed]
    pub(super) fn aggregate(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<PooledAggregate<'_, [CommitteeAttestation; 1]>> {
        let id = self.candidates.find(slot, data_root)?;
        let index = committee_index as usize;
        if index >= MAX_COMMITTEES_PER_SLOT || !self.candidates[id].is_open(index) {
            return None;
        }

        let committee =
            CommitteeAttestation::best_aggregate(&self.store, CommitteeId::new(id, index))?;
        Some(PooledAggregate {
            id,
            candidate: &self.candidates[id],
            store: &self.store,
            committees: [committee],
        })
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
        self.candidates.prune_before(floor, |committee| self.store.close(committee));
    }
}

/// One on-chain `Attestation` over committees of one vote candidate.
pub(super) struct PooledAggregate<'a, P> {
    id: usize,
    candidate: &'a VoteCandidate,
    store: &'a CommitteeStore,
    /// Ascending by committee index.
    committees: P,
}

impl<P: AsRef<[CommitteeAttestation]>> PooledAggregate<'_, P> {
    fn committee_id(&self, committee: &CommitteeAttestation) -> CommitteeId {
        CommitteeId::new(self.id, committee.committee as usize)
    }

    pub(super) fn ssz_len(&self) -> usize {
        let committee_members: usize = self
            .committees
            .as_ref()
            .iter()
            .map(|committee| self.store.committee_len(self.committee_id(committee)))
            .sum();
        ATTESTATION_FIXED + committee_members / 8 + 1
    }

    /// `out` is exactly [`Self::ssz_len`] bytes and need not be zeroed.
    #[timed]
    pub(super) fn write_ssz(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.ssz_len());
        let (fixed, bits) = out.split_at_mut(ATTESTATION_FIXED);
        bits.fill(0);
        let mut signature = SignatureSum::new();
        let mut committee_bits = 0u64;
        let mut committee_members = 0;
        for committee in self.committees.as_ref() {
            let id = self.committee_id(committee);
            debug_assert!(committee_bits >> committee.committee == 0, "ascending committees");
            self.store.write_attestation(id, *committee, bits, committee_members, &mut signature);
            committee_bits |= 1 << committee.committee;
            committee_members += self.store.committee_len(id);
        }
        bits[committee_members / 8] |= 1 << (committee_members % 8);

        fixed[0..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        fixed[4..132].copy_from_slice(self.candidate.data().as_bytes());
        fixed[132..228].copy_from_slice(&signature.finish().to_signature().to_bytes());
        fixed[228..].copy_from_slice(&committee_bits.to_le_bytes());
    }
}

/// Writes `attestations` as an SSZ list: their offsets, then each in turn.
fn write_ssz_list<'a, P: AsRef<[CommitteeAttestation]>>(
    attestations: impl ExactSizeIterator<Item = PooledAggregate<'a, P>>,
    out: &mut Vec<u8>,
) {
    let offset_len = size_of::<u32>();
    out.clear();
    out.reserve(MAX_PACKED_LEN);
    out.resize(attestations.len() * offset_len, 0);
    for (i, attestation) in attestations.enumerate() {
        let start = out.len();
        out[i * offset_len..(i + 1) * offset_len].copy_from_slice(&(start as u32).to_le_bytes());
        out.resize(start + attestation.ssz_len(), 0);
        attestation.write_ssz(&mut out[start..]);
    }
}

#[cfg(test)]
mod tests {
    use blst::{BLST_ERROR, min_pk::AggregateSignature};
    use silver_beacon_state_data::Immutable;
    use silver_common::ssz_view::AttestationView;

    use super::{
        vote_candidates::{MAX_SLOT_CANDIDATES, RETAINED_SLOTS},
        *,
    };
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
        // committee members 1 and 3 set, terminator at bit 4.
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

        assert_eq!(pool.insert_verified(&b, 4, 4, &vb), InsertOutcome::Invalid);
        assert_eq!(pool.insert_verified(&b, 1, 5, &vb), InsertOutcome::Invalid);
        assert_eq!(pool.aggregate_ssz(SLOT, 0, va.data_root).unwrap(), before);

        let mut fresh = AttestationPool::new();
        assert_eq!(fresh.insert_verified(&b, 9, 4, &vb), InsertOutcome::Invalid);
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

    fn bitlist(members: &[usize], committee_len: usize) -> Vec<u8> {
        let mut bits = vec![0u8; committee_len / 8 + 1];
        for &member in members.iter().chain([&committee_len]) {
            bits[member / 8] |= 1 << (member % 8);
        }
        bits
    }

    /// The aggregate of `signers`' singles, at the committee members given.
    fn insert_aggregate(
        pool: &mut AttestationPool,
        signers: &[(usize, usize)],
        committee_len: usize,
    ) -> InsertOutcome {
        let singles: Vec<_> = signers.iter().map(|&(sk_idx, _)| verified_single(sk_idx)).collect();
        let signatures: Vec<_> = singles.iter().map(|(_, verified)| &verified.signature).collect();
        let signature = AggregateSignature::aggregate(&signatures, false).unwrap().to_signature();
        let members: Vec<_> = signers.iter().map(|&(_, member)| member).collect();
        let (single, verified) = &singles[0];
        pool.insert_verified_aggregate(
            SingleAttestationView::data(single),
            0,
            verified.data_root,
            committee_len,
            &bitlist(&members, committee_len),
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

    /// The signers of a one-committee attestation, by committee member,
    /// where each test signer's key index is its committee member index.
    fn signers(attestation: &[u8], committee_len: usize) -> Vec<usize> {
        let bits = AttestationView::aggregation_bits(attestation);
        (0..committee_len).filter(|&member| bits[member / 8] & (1 << (member % 8)) != 0).collect()
    }

    #[test]
    fn aggregates_overlapping_the_singles_pack_in_later_attestations() {
        let mut pool = AttestationPool::new();
        assert_eq!(insert_aggregate(&mut pool, &[(1, 1)], 5), InsertOutcome::Inserted);
        for aggregate in [[(0, 0), (1, 1)], [(1, 1), (2, 2)], [(1, 1), (3, 3)]] {
            assert_eq!(insert_aggregate(&mut pool, &aggregate, 5), InsertOutcome::Inserted);
        }

        let attestations = packed(&mut pool, weigh_all_alike);

        assert_eq!(attestations.len(), 3);
        let mut covered: Vec<_> = attestations.iter().flat_map(|a| signers(a, 5)).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(covered, [0, 1, 2, 3]);
        for attestation in &attestations {
            assert_signed_by(attestation, &signers(attestation, 5));
        }
    }

    #[test]
    fn singles_and_a_disjoint_aggregate_share_one_attestation() {
        let mut pool = AttestationPool::new();
        let data_root = verified_single(0).1.data_root;
        for sk_idx in 0..6 {
            assert_eq!(
                insert_aggregate(&mut pool, &[(sk_idx, sk_idx)], 8),
                InsertOutcome::Inserted
            );
        }
        assert_eq!(insert_aggregate(&mut pool, &[(6, 6), (7, 7)], 8), InsertOutcome::Inserted);

        let combined = pool.aggregate_ssz(SLOT, 0, data_root).unwrap();

        assert_eq!(AttestationView::aggregation_bits(&combined), &[0b1111_1111, 0b0000_0001]);
        assert_signed_by(&combined, &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn covered_aggregates_are_duplicates_and_a_covering_one_replaces_them() {
        let mut pool = AttestationPool::new();
        let data_root = verified_single(0).1.data_root;
        assert_eq!(insert_aggregate(&mut pool, &[(0, 0)], 4), InsertOutcome::Inserted);
        assert_eq!(insert_aggregate(&mut pool, &[(0, 0), (1, 1)], 4), InsertOutcome::Inserted);
        assert_eq!(insert_aggregate(&mut pool, &[(0, 0), (1, 1)], 4), InsertOutcome::Duplicate);
        assert_eq!(insert_aggregate(&mut pool, &[(1, 1)], 4), InsertOutcome::Inserted);
        assert_eq!(insert_aggregate(&mut pool, &[(0, 0), (1, 1)], 4), InsertOutcome::Duplicate);

        let covering = [(1, 1), (2, 2), (3, 3)];
        assert_eq!(insert_aggregate(&mut pool, &covering, 4), InsertOutcome::Inserted);
        let committee = CommitteeId::new(pool.candidates.find(SLOT, data_root).unwrap(), 0);
        assert_eq!(pool.store.aggregate_count(committee), 1);

        let best = pool.aggregate_ssz(SLOT, 0, data_root).unwrap();
        assert_eq!(AttestationView::aggregation_bits(&best), &[0b0001_1111]);
        assert_signed_by(&best, &[0, 1, 2, 3]);
    }

    /// Singles `singles` beside the aggregate of committee members 0 to 3,
    /// in a committee of 8.
    fn singles_beside_an_aggregate(singles: &[usize]) -> Vec<u8> {
        let mut pool = AttestationPool::new();
        let data_root = verified_single(0).1.data_root;
        for &member in singles {
            assert_eq!(
                insert_aggregate(&mut pool, &[(member, member)], 8),
                InsertOutcome::Inserted
            );
        }
        let aggregate = [(0, 0), (1, 1), (2, 2), (3, 3)];
        assert_eq!(insert_aggregate(&mut pool, &aggregate, 8), InsertOutcome::Inserted);
        pool.aggregate_ssz(SLOT, 0, data_root).unwrap()
    }

    #[test]
    fn singles_the_aggregate_misses_are_added_one_by_one() {
        let attestation = singles_beside_an_aggregate(&[0, 5]);

        assert_eq!(AttestationView::aggregation_bits(&attestation), &[0b0010_1111, 0b0000_0001]);
        assert_signed_by(&attestation, &[0, 1, 2, 3, 5]);
    }

    #[test]
    fn singles_the_aggregate_holds_are_subtracted_from_their_sum() {
        let attestation = singles_beside_an_aggregate(&[0, 4, 5, 6, 7]);

        assert_eq!(AttestationView::aggregation_bits(&attestation), &[0b1111_1111, 0b0000_0001]);
        assert_signed_by(&attestation, &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn aggregate_bits_not_sized_to_the_committee_are_invalid() {
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
        assert_eq!(insert(&bitlist(&[0], 5), 4), InsertOutcome::Invalid);
        assert_eq!(insert(&[0b0001_0001, 0], 4), InsertOutcome::Invalid);
        assert_eq!(insert(&bitlist(&[0], 4), 4), InsertOutcome::Inserted);
        assert_eq!(insert(&bitlist(&[1], 5), 5), InsertOutcome::Invalid);
    }

    /// The attestations `pack` writes, split out of their SSZ list.
    fn packed(
        pool: &mut AttestationPool,
        weigh: impl FnMut(AttestationDataView, u64, &mut [u64]),
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        pool.pack(weigh, &mut out);
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

    fn weigh_all_alike(_: AttestationDataView, _: u64, weights: &mut [u64]) {
        weights.fill(1);
    }

    fn at_slot(slot: Slot, sk_idx: usize) -> ([u8; SINGLE_ATT_SIZE], VerifiedSingleAttestation) {
        single_with(sk_idx, |buf| buf[16..24].copy_from_slice(&slot.to_le_bytes()))
    }

    #[test]
    fn pack_joins_the_committees_of_one_data() {
        let mut pool = AttestationPool::new();
        let (a, va) = verified_single(0);
        let (b, vb) = single_with(1, |buf| buf[0..8].copy_from_slice(&1u64.to_le_bytes()));
        assert_eq!(pool.insert_verified(&a, 4, 5, &va), InsertOutcome::Inserted);
        assert_eq!(pool.insert_verified(&b, 0, 4, &vb), InsertOutcome::Inserted);

        let [attestation] = &packed(&mut pool, weigh_all_alike)[..] else {
            panic!("one attestation")
        };

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
    fn pack_chooses_by_reward_then_newest_and_skips_what_pays_nothing() {
        let mut pool = AttestationPool::new();
        let slots = SLOT..SLOT + MAX_ATTESTATIONS_ELECTRA as u64 + 3;
        for slot in slots.clone() {
            let (att, verified) = at_slot(slot, 0);
            assert_eq!(pool.insert_verified(&att, 0, 4, &verified), InsertOutcome::Inserted);
        }
        let (inadmissible, unpaid, valuable) = (slots.end - 1, slots.end - 2, SLOT);

        let attestations = packed(&mut pool, |data, _, weights| {
            weights.fill(match data.slot() {
                slot if slot == valuable => 9,
                slot if slot == unpaid || slot == inadmissible => 0,
                _ => 1,
            });
        });

        let slots: Vec<_> = attestations.iter().map(|a| AttestationView::data(a).slot()).collect();
        let mut expected = vec![valuable];
        expected.extend((0..MAX_ATTESTATIONS_ELECTRA as u64 - 1).map(|i| unpaid - 1 - i));
        assert_eq!(slots, expected);
    }

    #[test]
    fn conflicting_aggregates_pack_as_separate_attestations_of_one_data() {
        let mut pool = AttestationPool::new();
        assert_eq!(insert_aggregate(&mut pool, &[(0, 0), (1, 1)], 4), InsertOutcome::Inserted);
        assert_eq!(
            insert_aggregate(&mut pool, &[(1, 1), (2, 2), (3, 3)], 4),
            InsertOutcome::Inserted
        );

        let [larger, rest] = &packed(&mut pool, weigh_all_alike)[..] else {
            panic!("two attestations")
        };

        assert_eq!(AttestationView::aggregation_bits(larger), &[0b0001_1110]);
        assert_signed_by(larger, &[1, 2, 3]);
        assert_eq!(AttestationView::aggregation_bits(rest), &[0b0001_0011]);
        assert_signed_by(rest, &[0, 1]);
    }

    #[test]
    fn full_slot_admits_votes_again_once_pruned() {
        let mut pool = AttestationPool::new();
        let vote = |slot: Slot, head: u8| {
            single_with(0, |buf| {
                buf[16..24].copy_from_slice(&slot.to_le_bytes());
                buf[48] = head;
            })
        };
        for head in 0..MAX_SLOT_CANDIDATES as u8 {
            let (att, verified) = vote(SLOT, head);
            assert_eq!(pool.insert_verified(&att, 0, 4, &verified), InsertOutcome::Inserted);
        }
        let (extra, verified) = vote(SLOT, MAX_SLOT_CANDIDATES as u8);
        assert_eq!(pool.insert_verified(&extra, 0, 4, &verified), InsertOutcome::Full);
        let beyond = SLOT + RETAINED_SLOTS as Slot;
        let (late, late_verified) = vote(beyond, 0);
        assert_eq!(pool.insert_verified(&late, 0, 4, &late_verified), InsertOutcome::Full);

        pool.prune_before(SLOT + 1);

        assert_eq!(pool.insert_verified(&late, 0, 4, &late_verified), InsertOutcome::Inserted);
        assert!(pool.aggregate_ssz(beyond, 0, late_verified.data_root).is_some());
        let (stale, verified) = vote(SLOT, 0);
        assert_eq!(pool.aggregate_ssz(SLOT, 0, verified.data_root), None);
        assert_eq!(pool.insert_verified(&stale, 0, 4, &verified), InsertOutcome::Stale);
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
