use silver_beacon_state_data::{Epoch, Slot};
use silver_ssz::ssz_view::SINGLE_ATT_SIZE;

use crate::{
    DoubleProposals, PROOFS_CAPACITY, aggregate_votes::AggregateVotes,
    attester_proof::AttesterProof, public_votes::PublicVotes, surround_votes::SurroundVotes,
};

// Each publication costs two signature checks when gossip validation sees it.
const PUBLICATIONS_PER_SLOT: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    DoubleProposal,
    DoubleVote,
    SurroundVote,
}

#[derive(Default)]
struct SlotBudget {
    slot: Slot,
    spent: u8,
}

impl SlotBudget {
    fn available(&self, wall_slot: Slot) -> bool {
        self.slot != wall_slot || self.spent < PUBLICATIONS_PER_SLOT
    }

    fn spend(&mut self, wall_slot: Slot) {
        if self.slot != wall_slot {
            *self = Self { slot: wall_slot, spent: 0 };
        }
        self.spent += 1;
    }
}

pub struct SlashingDetection {
    pub proposals: DoubleProposals,
    votes: PublicVotes,
    surround: Option<SurroundVotes>,
    aggregates: AggregateVotes,
    proofs: Vec<AttesterProof>,
    publications: SlotBudget,
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

    /// Takes a public vote whose signature verified.
    pub fn record_vote(&mut self, accepted: &[u8; SINGLE_ATT_SIZE]) {
        self.votes.record(accepted);
        let room = self.has_room();
        if let Some(proof) =
            self.surround.as_mut().and_then(|history| history.record(accepted, room))
        {
            self.proofs.push(proof);
        }
    }

    /// Takes a public `Attestation` of one committee whose signature verified
    /// against `committee`.
    pub fn record_aggregate(&mut self, attestation: &[u8], committee: &[u32]) {
        let room = self.has_room();
        if let Some(proof) = self.aggregates.record(attestation, committee, room) {
            self.proofs.push(proof);
        }
    }

    /// Signatures are not checked here.
    pub fn conflicts_with_public(&self, single: &[u8; SINGLE_ATT_SIZE]) -> Option<Offence> {
        if self.votes.conflicts(single) {
            return Some(Offence::DoubleVote);
        }
        let surrounds = self.surround.as_ref().is_some_and(|history| history.conflicts(single));
        surrounds.then_some(Offence::SurroundVote)
    }

    /// False while only attester proofs wait and this slot's publications
    /// are spent.
    pub fn has_proofs(&self, wall_slot: Slot) -> bool {
        self.proposals.has_proofs() ||
            !self.proofs.is_empty() && self.publications.available(wall_slot)
    }

    /// The newest queued proof that peers can verify and that slashes
    /// someone, left queued; proofs ahead of it are dropped. None once this
    /// slot's publications are spent.
    pub fn next_attester_proof(
        &mut self,
        wall_slot: Slot,
        slashable: impl Fn(u64) -> bool,
        verifiable: impl Fn(Epoch) -> bool,
    ) -> Option<&AttesterProof> {
        if !self.publications.available(wall_slot) {
            return None;
        }
        while let Some(proof) = self.proofs.last() {
            if proof.verifies_under(&verifiable) && proof.offenders().any(&slashable) {
                break;
            }
            self.proofs.pop();
        }
        self.proofs.last()
    }

    /// Spends one of this slot's publications.
    pub fn pop_attester_proof(&mut self, wall_slot: Slot) {
        self.proofs.pop();
        self.publications.spend(wall_slot);
    }

    fn has_room(&self) -> bool {
        self.proofs.len() < PROOFS_CAPACITY
    }
}
