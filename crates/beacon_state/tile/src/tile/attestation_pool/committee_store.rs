use silver_common::ssz_view::MAX_COMMITTEES_PER_SLOT;
use slab::Slab;

use super::{
    InsertOutcome,
    committee_attestations::{Aggregate, CommitteeAttestations, Single},
    committee_bits::CommitteeBits,
    selection::{CommitteeAttestation, MAX_AGGREGATES},
};
use crate::bls::{AggregateSignature, Signature, SignatureSum};

/// A vote candidate's committee `i` has id
/// `candidate * MAX_COMMITTEES_PER_SLOT + i`.
#[derive(Clone, Copy)]
pub(super) struct CommitteeId(u16);

impl CommitteeId {
    pub(super) fn new(candidate: usize, index: usize) -> Self {
        debug_assert!(index < MAX_COMMITTEES_PER_SLOT);
        Self((candidate * MAX_COMMITTEES_PER_SLOT + index) as u16)
    }

    pub(super) fn index(self) -> usize {
        self.0 as usize % MAX_COMMITTEES_PER_SLOT
    }

    pub(super) fn candidate(self) -> usize {
        self.0 as usize / MAX_COMMITTEES_PER_SLOT
    }
}

/// Every committee's verified attestations, in slabs sized once.
pub(super) struct CommitteeStore {
    attestations: Box<[CommitteeAttestations]>,
    aggregates: Slab<Aggregate>,
    singles: Slab<Single>,
}

impl CommitteeStore {
    pub(super) fn new(max_committees: usize, max_aggregates: usize, max_singles: usize) -> Self {
        debug_assert!(max_committees <= u16::MAX as usize);
        Self {
            attestations: vec![CommitteeAttestations::EMPTY; max_committees].into_boxed_slice(),
            aggregates: Slab::with_capacity(max_aggregates),
            singles: Slab::with_capacity(max_singles),
        }
    }

    fn committee(&self, id: CommitteeId) -> &CommitteeAttestations {
        &self.attestations[id.0 as usize]
    }

    /// Starts the committee empty; it must be closed.
    pub(super) fn open(&mut self, id: CommitteeId, committee_len: usize, collapsed: bool) {
        debug_assert_eq!(self.committee(id).committee_len, 0, "open committee");
        self.attestations[id.0 as usize] = CommitteeAttestations::new(committee_len, collapsed);
    }

    /// Frees the committee's singles from the slab; a block then takes them
    /// all or none.
    pub(super) fn collapse(&mut self, id: CommitteeId) {
        self.attestations[id.0 as usize].collapse(&mut self.singles);
    }

    pub(super) fn collapsed(&self, id: CommitteeId) -> bool {
        self.committee(id).collapsed
    }

    pub(super) fn close(&mut self, id: CommitteeId) {
        let committee = &mut self.attestations[id.0 as usize];
        committee.remove_all(&mut self.aggregates, &mut self.singles);
        *committee = CommitteeAttestations::EMPTY;
    }

    pub(super) fn insert(
        &mut self,
        id: CommitteeId,
        bits: CommitteeBits,
        signature: &Signature,
    ) -> InsertOutcome {
        let committee = &mut self.attestations[id.0 as usize];
        match bits.count() {
            1 => {
                let member = bits.members().next().expect("one member");
                committee.add_single(member, signature, &mut self.singles)
            }
            _ => committee.add_aggregate(bits, signature, &mut self.aggregates),
        }
    }

    pub(super) fn committee_len(&self, id: CommitteeId) -> usize {
        self.committee(id).committee_len
    }

    pub(super) fn attesters(&self, id: CommitteeId) -> &CommitteeBits {
        &self.committee(id).attesters
    }

    pub(super) fn singles(&self, id: CommitteeId) -> &CommitteeBits {
        &self.committee(id).singles
    }

    pub(super) fn singles_sum(&self, id: CommitteeId) -> &AggregateSignature {
        &self.committee(id).singles_signature
    }

    pub(super) fn add_singles_sum(
        &mut self,
        id: CommitteeId,
        singles: &CommitteeBits,
        sum: &AggregateSignature,
    ) -> InsertOutcome {
        self.attestations[id.0 as usize].add_singles_sum(singles, sum)
    }

    pub(super) fn aggregate_entries(
        &self,
        id: CommitteeId,
    ) -> impl Iterator<Item = (&CommitteeBits, &Signature)> + '_ {
        self.committee(id).aggregates().map(|(_, i)| {
            let aggregate = &self.aggregates[i as usize];
            (&aggregate.bits, &aggregate.signature)
        })
    }

    /// Its aggregates' positions, ascending, with their bits.
    pub(super) fn aggregates(
        &self,
        id: CommitteeId,
    ) -> impl Iterator<Item = (usize, &CommitteeBits)> + Clone {
        self.committee(id)
            .aggregates()
            .map(|(position, i)| (position, &self.aggregates[i as usize].bits))
    }

    pub(super) fn aggregate_bits(&self, id: CommitteeId, position: usize) -> &CommitteeBits {
        &self.aggregates[self.committee(id).aggregate(position) as usize].bits
    }

    #[cfg(test)]
    pub(super) fn pooled_singles(&self) -> usize {
        self.singles.len()
    }

    #[cfg(test)]
    pub(super) fn aggregate_count(&self, id: CommitteeId) -> usize {
        self.committee(id).aggregates().count()
    }

    /// Bit `b` of entry `a` is set iff the aggregates at positions `a` and `b`
    /// share a committee member.
    pub(super) fn overlaps(&self, id: CommitteeId) -> [u32; MAX_AGGREGATES] {
        let mut overlaps = [0; MAX_AGGREGATES];
        for (a, bits) in self.aggregates(id) {
            for (b, other) in self.aggregates(id) {
                if a < b && bits.intersects(other) {
                    overlaps[a] |= 1 << b;
                    overlaps[b] |= 1 << a;
                }
            }
        }
        overlaps
    }

    /// ORs the attestation's committee members into `bits` from bit `offset`
    /// and adds their signatures: its aggregates, which never overlap,
    /// then the singles they miss.
    pub(super) fn write_attestation<'s>(
        &'s self,
        id: CommitteeId,
        attestation: CommitteeAttestation,
        bits: &mut [u8],
        offset: usize,
        signature: &mut SignatureSum<'s>,
    ) {
        let committee = self.committee(id);
        let mut members = CommitteeBits::EMPTY;
        for k in attestation.aggregates() {
            let aggregate = &self.aggregates[committee.aggregate(k) as usize];
            members.union_with(&aggregate.bits);
            signature.add(&aggregate.signature);
        }
        if attestation.with_singles {
            if committee.collapsed {
                debug_assert!(!members.intersects(&committee.singles), "disjoint from the singles");
                signature.add_sum(&committee.singles_signature);
            } else {
                self.add_missing_singles(committee, &members, signature);
            }
            members.union_with(&committee.singles);
        }
        members.write_bits_at(bits, offset);
    }

    /// Adds the missing singles, or adds the singles' sum and subtracts those
    /// `members` already holds, whichever sums fewer signatures.
    fn add_missing_singles<'s>(
        &'s self,
        committee: &'s CommitteeAttestations,
        members: &CommitteeBits,
        signature: &mut SignatureSum<'s>,
    ) {
        let missing = committee.singles.difference(members);
        let held = committee.singles.count() - missing.count();
        if missing.count() <= 1 + held {
            for single in committee.singles(&self.singles) {
                if missing.contains(single.member as usize) {
                    signature.add(&single.signature);
                }
            }
        } else {
            signature.add_sum(&committee.singles_signature);
            for single in committee.singles(&self.singles) {
                if members.contains(single.member as usize) {
                    signature.subtract(&single.signature);
                }
            }
        }
    }
}
