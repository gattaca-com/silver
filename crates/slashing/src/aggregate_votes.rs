use silver_beacon_state_data::{Slot, Version};
use silver_ssz::ssz_view::{
    AttestationView, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE,
};

use crate::{
    Offence,
    signed_vote::{AttesterProof, IndexedVote, SignedVote},
};

// Honest committees attest one or two distinct data per slot.
const AGGREGATES_PER_COMMITTEE: usize = 4;
const WORDS: usize = MAX_VALIDATORS_PER_COMMITTEE / 64;

/// Bit `i` stands for committee member `i`.
#[derive(Clone, Copy, Default)]
struct Participants([u64; WORDS]);

impl Participants {
    /// Bits past the committee, the bitlist terminator among them, are not
    /// participants.
    fn of(aggregation_bits: &[u8], committee_len: usize) -> Self {
        let mut words = [0; WORDS];
        for (at, &byte) in aggregation_bits.iter().take(committee_len.div_ceil(8)).enumerate() {
            words[at / 8] |= u64::from(byte) << (at % 8 * 8);
        }
        if !committee_len.is_multiple_of(64) {
            words[committee_len / 64] &= (1 << (committee_len % 64)) - 1;
        }
        Self(words)
    }

    fn combine(&self, other: &Self, op: impl Fn(u64, u64) -> u64) -> Self {
        Self(std::array::from_fn(|at| op(self.0[at], other.0[at])))
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|&word| word == 0)
    }

    fn count(&self) -> u32 {
        self.0.iter().map(|word| word.count_ones()).sum()
    }

    fn positions(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_VALIDATORS_PER_COMMITTEE).filter(|&at| self.0[at / 64] & (1 << (at % 64)) != 0)
    }
}

struct Aggregate {
    vote: SignedVote,
    participants: Participants,
}

/// Aggregates verified against `members`, kept one per distinct data.
#[derive(Default)]
struct CommitteeVotes {
    members: Vec<u32>,
    aggregates: Vec<Aggregate>,
    proven: Participants,
}

impl CommitteeVotes {
    fn reset(&mut self, members: &[u32]) {
        self.members.clear();
        self.members.extend_from_slice(members);
        self.aggregates.clear();
        self.proven = Participants::default();
    }

    fn double_vote(&mut self, new: &Aggregate) -> Option<AttesterProof> {
        let (stored, offenders) = self.aggregates.iter().find_map(|stored| {
            if !stored.vote.versioned_data().is_double_vote_with(&new.vote.data()) {
                return None;
            }
            let common = stored.participants.combine(&new.participants, |s, n| s & n);
            let unproven = common.combine(&self.proven, |c, proven| c & !proven);
            (!unproven.is_empty()).then_some((stored, common))
        })?;
        self.proven = self.proven.combine(&offenders, |proven, o| proven | o);
        Some(AttesterProof::new(Offence::DoubleVote, self.indexed(stored), self.indexed(new)))
    }

    fn indexed(&self, aggregate: &Aggregate) -> IndexedVote {
        let mut signers: Vec<_> =
            aggregate.participants.positions().map(|at| self.members[at]).collect();
        signers.sort_unstable();
        IndexedVote { vote: aggregate.vote, signers }
    }

    /// Of two aggregates with the same data, the one with more participants
    /// stays.
    fn keep(&mut self, new: Aggregate) {
        let data = new.vote.data();
        let same_data = |stored: &Aggregate| stored.vote.data().as_bytes() == data.as_bytes();
        match self.aggregates.iter().position(same_data) {
            Some(at) => {
                if self.aggregates[at].participants.count() < new.participants.count() {
                    self.aggregates[at] = new;
                }
            }
            None if self.aggregates.len() < AGGREGATES_PER_COMMITTEE => self.aggregates.push(new),
            None => {}
        }
    }
}

struct SlotVotes {
    slot: Slot,
    committees: Vec<CommitteeVotes>,
}

impl SlotVotes {
    fn new() -> Self {
        let committees = (0..MAX_COMMITTEES_PER_SLOT).map(|_| CommitteeVotes::default());
        Self { slot: 0, committees: committees.collect() }
    }
}

/// Double votes between verified aggregates of one committee, in the latest
/// two attestation slots.
pub(crate) struct AggregateVotes {
    slots: [SlotVotes; 2],
}

impl Default for AggregateVotes {
    fn default() -> Self {
        Self { slots: [SlotVotes::new(), SlotVotes::new()] }
    }
}

impl AggregateVotes {
    /// Takes an `Attestation` of one committee whose signature verified
    /// against `committee` under `fork_version`. Proves at most one double
    /// vote, only when `room`; its offenders are not proven again.
    pub(crate) fn record(
        &mut self,
        attestation: &[u8],
        committee: &[u32],
        fork_version: Version,
        room: bool,
    ) -> Option<AttesterProof> {
        if committee.len() > MAX_VALIDATORS_PER_COMMITTEE {
            return None;
        }
        let data = AttestationView::data(attestation);
        let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(attestation));
        debug_assert_eq!(committee_bits.count_ones(), 1);
        let slot = data.slot();
        let slot_votes = &mut self.slots[(slot % 2) as usize];
        if slot_votes.slot != slot {
            if slot_votes.slot > slot {
                return None;
            }
            slot_votes.slot = slot;
            slot_votes.committees.iter_mut().for_each(|votes| votes.reset(&[]));
        }
        let votes = slot_votes.committees.get_mut(committee_bits.trailing_zeros() as usize)?;
        if votes.members != committee {
            votes.reset(committee);
        }

        let signature = AttestationView::signature(attestation);
        let aggregation_bits = AttestationView::aggregation_bits(attestation);
        let new = Aggregate {
            vote: SignedVote::new(data, signature, fork_version),
            participants: Participants::of(aggregation_bits, committee.len()),
        };
        let proof = if room { votes.double_vote(&new) } else { None };
        votes.keep(new);
        proof
    }
}
