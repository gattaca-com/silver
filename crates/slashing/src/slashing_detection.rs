use silver_beacon_state_data::{Epoch, Slot, Version};
use silver_ssz::ssz_view::SINGLE_ATT_SIZE;

use crate::{
    DoubleProposals, aggregate_votes::AggregateVotes, public_votes::PublicVotes,
    signed_vote::AttesterProof, surround_votes::SurroundVotes,
};

// Each publication costs two signature checks when gossip validation sees it.
const PUBLICATIONS_PER_SLOT: u8 = 16;
const PROOFS_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    DoubleProposal,
    DoubleVote,
    SurroundVote,
}

#[derive(Default)]
struct SlotBudget<const PER_SLOT: u8> {
    slot: Slot,
    spent: u8,
}

impl<const PER_SLOT: u8> SlotBudget<PER_SLOT> {
    fn available(&mut self, wall_slot: Slot) -> bool {
        if self.slot != wall_slot {
            *self = Self { slot: wall_slot, spent: 0 };
        }
        self.spent < PER_SLOT
    }
}

pub struct SlashingDetection {
    pub proposals: DoubleProposals,
    votes: PublicVotes,
    surround: Option<SurroundVotes>,
    aggregates: AggregateVotes,
    proofs: Vec<AttesterProof>,
    publications: SlotBudget<PUBLICATIONS_PER_SLOT>,
}

impl SlashingDetection {
    /// Zero `surround_epochs` disables surround detection. Otherwise it
    /// reserves one lane per epoch, plus one for the current epoch.
    pub fn new(surround_epochs: u8, validators: usize) -> Self {
        Self {
            proposals: DoubleProposals::default(),
            votes: PublicVotes::default(),
            surround: (surround_epochs > 0)
                .then(|| SurroundVotes::new(surround_epochs, validators)),
            aggregates: AggregateVotes::default(),
            proofs: Vec::with_capacity(PROOFS_CAPACITY),
            publications: SlotBudget::default(),
        }
    }

    pub fn reserved_bytes(&self) -> usize {
        self.surround.as_ref().map_or(0, SurroundVotes::reserved_bytes)
    }

    /// Takes a verified vote received from the network or accepted for relay.
    pub fn record_vote(&mut self, accepted: &[u8; SINGLE_ATT_SIZE], fork_version: Version) {
        self.votes.record(accepted, fork_version);
        if let Some(proof) =
            self.surround.as_mut().and_then(|history| history.record(accepted, fork_version))
        {
            self.queue(proof);
        }
    }

    /// Takes a verified `Attestation` received from the network or accepted
    /// for relay, signed by `committee` under `fork_version`.
    pub fn record_aggregate(
        &mut self,
        attestation: &[u8],
        committee: &[u32],
        fork_version: Version,
    ) {
        let room = self.proofs.len() < PROOFS_CAPACITY;
        if let Some(proof) = self.aggregates.record(attestation, committee, fork_version, room) {
            self.proofs.push(proof);
        }
    }

    /// Compares data and recorded fork versions; does not verify signatures.
    pub fn conflicts_with_public(
        &self,
        single: &[u8; SINGLE_ATT_SIZE],
        signing_version: impl Fn(Epoch) -> Version,
    ) -> Option<Offence> {
        if self.votes.conflicts(single, &signing_version) {
            return Some(Offence::DoubleVote);
        }
        let surrounds = self
            .surround
            .as_ref()
            .is_some_and(|history| history.conflicts(single, &signing_version));
        surrounds.then_some(Offence::SurroundVote)
    }

    pub fn has_proofs(&self) -> bool {
        self.proposals.has_proofs() || !self.proofs.is_empty()
    }

    /// The newest queued proof that verifies under the head's fork versions
    /// and slashes someone, left queued; proofs ahead of it are dropped. None
    /// once this slot's publications are spent.
    pub fn next_attester_proof(
        &mut self,
        wall_slot: Slot,
        slashable: impl Fn(u64) -> bool,
        signing_version: impl Fn(Epoch) -> Version,
    ) -> Option<&AttesterProof> {
        if !self.publications.available(wall_slot) {
            return None;
        }
        while let Some(proof) = self.proofs.last() {
            if proof.verifies_under(&signing_version) && proof.offenders().any(&slashable) {
                break;
            }
            self.proofs.pop();
        }
        self.proofs.last()
    }

    /// Spends one of this slot's publications.
    pub fn pop_attester_proof(&mut self) {
        self.proofs.pop();
        self.publications.spent += 1;
    }

    fn queue(&mut self, proof: AttesterProof) {
        if self.proofs.len() < PROOFS_CAPACITY {
            self.proofs.push(proof);
        }
    }
}
