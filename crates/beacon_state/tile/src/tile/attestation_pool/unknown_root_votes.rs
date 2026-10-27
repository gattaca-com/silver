use silver_beacon_state_data::{B256, ShufflingId, Slot};
use silver_common::ssz_view::{AttestationDataView, MAX_COMMITTEES_PER_SLOT};

use super::{
    AttestationPool, InsertOutcome,
    committee_bits::{CommitteeBits, Participants},
    committee_store::{CommitteeId, CommitteeStore},
    vote_candidates::{MAX_SLOT_CANDIDATES, VoteCandidates},
};
use crate::{bls::Signature, counters::BeaconStateCounters};

const BUFFERED_SLOTS: usize = 3;
const MAX_BUFFERED_CANDIDATES: usize = BUFFERED_SLOTS * MAX_SLOT_CANDIDATES;
/// Sixteen aggregators for each of a candidate's 64 committees, twice over.
const MAX_BUFFERED_AGGREGATES: usize = 2 * 16 * MAX_COMMITTEES_PER_SLOT;

/// Signature-verified votes waiting for their block or its payload, buffered
/// collapsed: a committee keeps its singles only as their sum. The checks that
/// need the block run when it arrives, before the votes reach the pool.
pub(crate) struct UnknownRootVotes {
    candidates: VoteCandidates<BUFFERED_SLOTS>,
    store: CommitteeStore,
    /// The shuffling the committee positions were read from; one block may
    /// sit under another shuffling than the head did.
    shufflings: [ShufflingId; MAX_BUFFERED_CANDIDATES],
}

impl UnknownRootVotes {
    pub(crate) fn new() -> Self {
        Self {
            candidates: VoteCandidates::new(),
            store: CommitteeStore::new(
                MAX_BUFFERED_CANDIDATES * MAX_COMMITTEES_PER_SLOT,
                MAX_BUFFERED_AGGREGATES,
                0,
            ),
            shufflings: [ShufflingId::default(); MAX_BUFFERED_CANDIDATES],
        }
    }

    /// Returns whether no candidate held the vote's data before.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert(
        &mut self,
        data: AttestationDataView,
        committee_index: u64,
        data_root: B256,
        committee_len: usize,
        participants: Participants,
        shuffling: ShufflingId,
        signature: &Signature,
    ) -> bool {
        let existing = self.candidates.find(data.slot(), data_root);
        let outcome = match existing {
            Some(id) if self.shufflings[id] != shuffling => InsertOutcome::Invalid,
            _ => self.try_insert(
                data,
                committee_index,
                data_root,
                committee_len,
                participants,
                shuffling,
                signature,
            ),
        };
        if !matches!(outcome, InsertOutcome::Inserted | InsertOutcome::Duplicate) {
            BeaconStateCounters::UnknownRootVotesDropped.add(participants.count());
        }
        existing.is_none()
    }

    #[allow(clippy::too_many_arguments)]
    fn try_insert(
        &mut self,
        data: AttestationDataView,
        committee_index: u64,
        data_root: B256,
        committee_len: usize,
        participants: Participants,
        shuffling: ShufflingId,
        signature: &Signature,
    ) -> InsertOutcome {
        let bits = match CommitteeBits::new(participants, committee_len) {
            Ok(bits) => bits,
            Err(outcome) => return outcome,
        };
        match self.candidates.committee(
            &mut self.store,
            data,
            data_root,
            committee_index as usize,
            committee_len,
            true,
        ) {
            Ok(committee) => {
                self.shufflings[committee.candidate()] = shuffling;
                self.store.insert(committee, bits, signature)
            }
            Err(outcome) => outcome,
        }
    }

    /// The first candidate from id `from` that holds votes for a block
    /// `is_known` accepts.
    pub(crate) fn next_with_known_block(
        &self,
        from: usize,
        is_known: impl Fn(&B256) -> bool,
    ) -> Option<usize> {
        (from..MAX_BUFFERED_CANDIDATES).find(|&id| {
            let candidate = &self.candidates[id];
            candidate.committees().next().is_some() &&
                is_known(candidate.data().beacon_block_root())
        })
    }

    pub(crate) fn data(&self, id: usize) -> AttestationDataView<'_> {
        self.candidates[id].data()
    }

    pub(crate) fn shuffling(&self, id: usize) -> ShufflingId {
        self.shufflings[id]
    }

    /// Candidate `id`'s committee indices with the positions that voted.
    pub(crate) fn committees(
        &self,
        id: usize,
    ) -> impl Iterator<Item = (usize, impl Iterator<Item = usize> + '_)> + '_ {
        self.candidates[id]
            .committees()
            .map(move |index| (index, self.store.attesters(CommitteeId::new(id, index)).members()))
    }

    pub(crate) fn vote_count(&self, id: usize) -> u64 {
        self.candidates[id]
            .committees()
            .map(|index| u64::from(self.store.attesters(CommitteeId::new(id, index)).count()))
            .sum()
    }

    /// Hands candidate `id`'s committees to `pool`: the singles as their sum,
    /// each aggregate as itself.
    pub(crate) fn promote_into(&self, id: usize, pool: &mut AttestationPool) -> bool {
        let candidate = &self.candidates[id];
        let mut full = false;
        for index in candidate.committees() {
            let committee = CommitteeId::new(id, index);
            let committee_len = self.store.committee_len(committee);
            let singles = self.store.singles(committee);
            if !singles.is_empty() {
                let outcome = pool.insert_singles_sum(
                    candidate.data(),
                    index,
                    *candidate.data_root(),
                    committee_len,
                    singles,
                    self.store.singles_sum(committee),
                );
                full |= outcome == InsertOutcome::Full;
            }
            for (bits, signature) in self.store.aggregate_entries(committee) {
                let outcome = pool.insert(
                    candidate.data(),
                    index as u64,
                    *candidate.data_root(),
                    committee_len,
                    *bits,
                    signature,
                );
                full |= outcome == InsertOutcome::Full;
            }
        }
        !full
    }

    pub(crate) fn close(&mut self, id: usize) {
        let store = &mut self.store;
        self.candidates.close(id, |committee| store.close(committee));
    }

    pub(crate) fn on_slot(&mut self, slot: Slot) {
        let store = &mut self.store;
        let mut expired = 0;
        self.candidates.prune_before(slot.saturating_sub(1), |committee| {
            expired += u64::from(store.attesters(committee).count());
            store.close(committee);
        });
        BeaconStateCounters::UnknownRootVotesDropped.add(expired);
    }
}
