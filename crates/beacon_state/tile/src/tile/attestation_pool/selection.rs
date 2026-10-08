use std::{cmp::Reverse, ops::Range};

use silver_common::ssz_view::MAX_COMMITTEES_PER_SLOT;

use super::{
    committee_bits::{CommitteeBits, MAX_COMMITTEE_MEMBERS, bit_positions},
    committee_store::{CommitteeId, CommitteeStore},
};

mod disjoint_aggregates;

use disjoint_aggregates::{CommitteeAggregates, DisjointAggregates};

pub(super) const MAX_AGGREGATES: usize = u32::BITS as usize;

pub(super) struct Selection {
    candidates: Vec<Candidate>,
    committees: Vec<CommitteeSelection>,
    attestations: Vec<BlockAttestation>,
    committee_attestations: Vec<CommitteeAttestation>,
}

struct Candidate {
    id: u32,
    committees: Range<usize>,
}

impl Candidate {
    /// What choosing this candidate now adds: its committees' ready
    /// attestations.
    fn gain(&self, committees: &[CommitteeSelection]) -> u64 {
        committees[self.committees.clone()].iter().map(CommitteeSelection::gain).sum()
    }
}

struct BlockAttestation {
    candidate: u32,
    committees: Range<usize>,
}

/// One committee's share of a block attestation: aggregates that do not
/// overlap, so their signatures simply add, and in the committee's first
/// attestation the singles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::tile) struct CommitteeAttestation {
    pub(super) committee: u32,
    aggregates: u32,
    pub(super) with_singles: bool,
}

impl CommitteeAttestation {
    /// The non-overlapping aggregates plus singles covering the most
    /// committee members, each counting the same. `None` when they cover
    /// nobody.
    pub(super) fn best_aggregate(store: &CommitteeStore, id: CommitteeId) -> Option<Self> {
        let equal_weights = [1; MAX_COMMITTEE_MEMBERS];
        let weights = &equal_weights[..store.committee_len(id)];
        let mut committee = CommitteeSelection::new(store, id, weights);
        (committee.gain() > 0).then(|| committee.take(store, weights))
    }

    /// Positions of the chosen aggregates, ascending.
    pub(super) fn aggregates(&self) -> impl Iterator<Item = usize> + Clone {
        bit_positions(self.aggregates.into())
    }
}

impl Selection {
    /// Allocates every buffer once; `clear` keeps them for the next block.
    pub(super) fn new(
        max_candidates: usize,
        max_committees: usize,
        max_attestations: usize,
    ) -> Self {
        Self {
            candidates: Vec::with_capacity(max_candidates),
            committees: Vec::with_capacity(max_committees),
            attestations: Vec::with_capacity(max_attestations),
            committee_attestations: Vec::with_capacity(max_attestations * MAX_COMMITTEES_PER_SLOT),
        }
    }

    /// Forgets all candidates and attestations, keeping the buffers.
    pub(super) fn clear(&mut self) {
        self.candidates.clear();
        self.committees.clear();
        self.attestations.clear();
        self.committee_attestations.clear();
    }

    /// Starts a candidate; the committees pushed next belong to it.
    pub(super) fn push_candidate(&mut self, id: u32) {
        debug_assert!(self.candidates.len() < self.candidates.capacity());
        let i = self.committees.len();
        self.candidates.push(Candidate { id, committees: i..i });
    }

    /// Adds committee `index` of the last candidate, unless `weights` pays
    /// none of its attesters.
    pub(super) fn push_committee(&mut self, store: &CommitteeStore, index: u32, weights: &[u64]) {
        let candidate = self.candidates.last_mut().expect("pushed candidate");
        let committee = CommitteeId::new(candidate.id as usize, index as usize);
        if !store.attesters(committee).intersects(&CommitteeBits::nonzero(weights)) {
            return;
        }
        debug_assert!(self.committees.len() < self.committees.capacity());
        candidate.committees.end += 1;
        self.committees.push(CommitteeSelection::new(store, committee, weights));
    }

    /// Chooses up to `max_attestations` block attestations, highest reward
    /// first; ties go to the earlier candidate.
    ///
    /// Greedy by gain is exact across candidates: honest attesters of
    /// different vote candidates are disjoint, so choosing one changes no other
    /// candidate's gain. A candidate chosen again packs what its earlier
    /// attestations could not combine. `weigh` must give a committee the
    /// weights it was pushed with.
    pub(super) fn select(
        &mut self,
        max_attestations: usize,
        store: &CommitteeStore,
        mut weigh: impl FnMut(u32, u32, &mut [u64]),
    ) {
        debug_assert!(max_attestations <= self.attestations.capacity());
        let Self { candidates, committees, attestations, committee_attestations } = self;
        attestations.clear();
        committee_attestations.clear();
        let mut weights = [0u64; MAX_COMMITTEE_MEMBERS];

        while attestations.len() < max_attestations {
            let gains = candidates.iter().map(|candidate| candidate.gain(committees));
            let best = gains.enumerate().max_by_key(|&(i, gain)| (gain, Reverse(i)));
            let Some((best, gain)) = best else {
                break;
            };
            if gain == 0 {
                break;
            }

            let candidate = &candidates[best];
            let start = committee_attestations.len();
            for committee in &mut committees[candidate.committees.clone()] {
                if committee.gain() == 0 {
                    continue;
                }
                let weights = &mut weights[..store.committee_len(committee.id)];
                weigh(candidate.id, committee.id.index() as u32, weights);
                committee_attestations.push(committee.take(store, weights));
            }
            let committees = start..committee_attestations.len();
            attestations.push(BlockAttestation { candidate: candidate.id, committees });
        }
    }

    /// Each block attestation's candidate id and committees, in block order.
    pub(super) fn attestations(
        &self,
    ) -> impl ExactSizeIterator<Item = (u32, &[CommitteeAttestation])> {
        self.attestations.iter().map(|attestation| {
            (attestation.candidate, &self.committee_attestations[attestation.committees.clone()])
        })
    }
}

/// One committee across a block's attestations: what earlier ones covered,
/// and the most valuable attestation it can add next.
struct CommitteeSelection {
    id: CommitteeId,
    overlaps: [u32; MAX_AGGREGATES],
    covered: CommitteeBits,
    ready: DisjointAggregates,
    ready_singles_value: u64,
}

impl CommitteeSelection {
    fn new(store: &CommitteeStore, id: CommitteeId, weights: &[u64]) -> Self {
        let mut committee = Self {
            id,
            overlaps: store.overlaps(id),
            covered: CommitteeBits::EMPTY,
            ready: DisjointAggregates::NONE,
            ready_singles_value: 0,
        };
        committee.ready_next(store, weights);
        committee
    }

    /// What its next attestation adds; 0 once no uncovered committee member
    /// pays.
    fn gain(&self) -> u64 {
        self.ready.value + self.ready_singles_value
    }

    /// Its next attestation; the one after is readied, priced by `weights`.
    fn take(&mut self, store: &CommitteeStore, weights: &[u64]) -> CommitteeAttestation {
        let attestation = CommitteeAttestation {
            committee: self.id.index() as u32,
            aggregates: self.ready.aggregates,
            with_singles: self.ready_singles_value > 0,
        };
        for k in attestation.aggregates() {
            self.covered.union_with(store.aggregate_bits(self.id, k));
        }
        if attestation.with_singles {
            self.covered.union_with(store.singles(self.id));
        }
        self.ready_next(store, weights);
        attestation
    }

    /// Readies the next attestation: every uncovered single, plus the
    /// disjoint aggregates whose uncovered committee members outside the
    /// singles weigh most.
    fn ready_next(&mut self, store: &CommitteeStore, weights: &[u64]) {
        let singles = store.singles(self.id);
        self.ready_singles_value = singles.weight_outside(&self.covered, weights);
        let mut counted = self.covered;
        counted.union_with(singles);

        let mut values = [0u64; MAX_AGGREGATES];
        for (position, bits) in store.aggregates(self.id) {
            values[position] = bits.weight_outside(&counted, weights);
        }
        let committee = CommitteeAggregates { values: &values, overlaps: &self.overlaps };
        self.ready = committee.most_valuable_disjoint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::Signature;

    const BLANK_SIGNATURE: Signature = unsafe { std::mem::zeroed() };

    fn bits(members: &[usize]) -> CommitteeBits {
        let mut bits = CommitteeBits::EMPTY;
        for &member in members {
            bits.insert(member);
        }
        bits
    }

    struct Committee {
        candidate: u32,
        index: u32,
        weight: u64,
    }

    /// Committees in push order, each paying one weight for every committee
    /// member.
    struct Pool {
        store: CommitteeStore,
        committees: Vec<Committee>,
    }

    impl Pool {
        fn new() -> Self {
            Self {
                store: CommitteeStore::new(16 * MAX_COMMITTEES_PER_SLOT),
                committees: Vec::new(),
            }
        }

        fn add(
            &mut self,
            (candidate, index): (u32, u32),
            attestations: &[&[usize]],
            committee_len: usize,
            weight: u64,
        ) {
            let id = CommitteeId::new(candidate as usize, index as usize);
            self.store.open(id, committee_len);
            for members in attestations {
                self.store.insert(id, bits(members), &BLANK_SIGNATURE);
            }
            self.committees.push(Committee { candidate, index, weight });
        }

        fn weight(&self, candidate: u32, index: u32) -> u64 {
            let committee =
                self.committees.iter().find(|c| (c.candidate, c.index) == (candidate, index));
            committee.unwrap().weight
        }

        fn select(&self, max_attestations: usize) -> Selection {
            let mut selection = Selection::new(16, 16, max_attestations);
            let mut weights = [0u64; MAX_COMMITTEE_MEMBERS];
            let mut candidate = None;
            for committee in &self.committees {
                if candidate != Some(committee.candidate) {
                    selection.push_candidate(committee.candidate);
                    candidate = Some(committee.candidate);
                }
                let id = CommitteeId::new(committee.candidate as usize, committee.index as usize);
                let weights = &mut weights[..self.store.committee_len(id)];
                weights.fill(committee.weight);
                selection.push_committee(&self.store, committee.index, weights);
            }
            selection.select(max_attestations, &self.store, |candidate, index, weights| {
                weights.fill(self.weight(candidate, index))
            });
            selection
        }
    }

    fn chosen(selection: &Selection) -> Vec<(u32, Vec<CommitteeAttestation>)> {
        let attestations = selection.attestations();
        attestations.map(|(candidate, committees)| (candidate, committees.to_vec())).collect()
    }

    fn attestation(committee: u32, aggregates: u32, with_singles: bool) -> CommitteeAttestation {
        CommitteeAttestation { committee, aggregates, with_singles }
    }

    #[test]
    fn overlapping_aggregates_take_one_attestation_each() {
        let mut pool = Pool::new();
        pool.add((0, 0), &[&[0, 1], &[1, 2, 3]], 4, 1);

        let selection = pool.select(8);

        let first = (0, vec![attestation(0, 0b10, false)]);
        assert_eq!(chosen(&selection), [first, (0, vec![attestation(0, 0b01, false)])]);
    }

    #[test]
    fn singles_join_the_disjoint_aggregates() {
        let mut pool = Pool::new();
        pool.add((0, 0), &[&[0], &[1, 2], &[3]], 4, 1);

        let selection = pool.select(8);

        assert_eq!(chosen(&selection), [(0, vec![attestation(0, 0b1, true)])]);
    }

    #[test]
    fn two_disjoint_aggregates_beat_the_larger_one_overlapping_both() {
        let mut pool = Pool::new();
        pool.add((0, 0), &[&[0, 1, 2], &[0, 3], &[2, 4]], 5, 1);

        let selection = pool.select(1);

        assert_eq!(chosen(&selection), [(0, vec![attestation(0, 0b110, false)])]);
    }

    #[test]
    fn aggregates_are_valued_by_what_the_singles_miss() {
        let mut pool = Pool::new();
        pool.add((0, 0), &[&[0], &[1], &[2], &[0, 1, 2, 3, 5], &[3, 4, 6]], 7, 1);

        let selection = pool.select(1);

        assert_eq!(chosen(&selection), [(0, vec![attestation(0, 0b10, true)])]);
    }

    #[test]
    fn higher_reward_first_ties_to_the_earlier_and_unpaid_never() {
        let mut pool = Pool::new();
        for (candidate, weight) in [(10, 1), (11, 0), (12, 3), (13, 1)] {
            pool.add((candidate, 0), &[&[0]], 2, weight);
        }

        let selection = pool.select(8);

        let order: Vec<_> = selection.attestations().map(|(candidate, _)| candidate).collect();
        assert_eq!(order, [12, 10, 13]);
    }

    #[test]
    fn committees_paid_only_outside_their_attesters_are_never_built() {
        let mut pool = Pool::new();
        pool.add((0, 0), &[&[0]], 2, 0);
        let mut selection = Selection::new(1, 1, 1);
        selection.push_candidate(0);
        selection.push_committee(&pool.store, 0, &[0, 5]);

        assert!(selection.committees.is_empty());
    }

    #[test]
    fn unpaid_committees_are_left_out_of_the_attestation() {
        let mut pool = Pool::new();
        pool.add((0, 3), &[&[0]], 2, 0);
        pool.add((0, 5), &[&[0]], 2, 1);

        let selection = pool.select(8);

        assert_eq!(chosen(&selection), [(0, vec![attestation(5, 0, true)])]);
    }
}
