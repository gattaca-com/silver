use silver_beacon_state_data::{Epoch, Slot};
use silver_ssz::ssz_view::{SINGLE_ATT_SIZE, SingleAttestationView};

use crate::{
    DoubleProposals, aggregate_votes::AggregateVotes, double_proposals::PROOFS_CAPACITY,
    public_votes::PublicVotes, signed_vote::AttesterProof,
};

// Each publication costs two signature checks when gossip validation sees it.
const PUBLICATIONS_PER_SLOT: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    DoubleProposal,
    DoubleVote,
}

#[derive(Default)]
struct SlotBudget {
    slot: Slot,
    spent: u8,
}

impl SlotBudget {
    fn available(&mut self, wall_slot: Slot) -> bool {
        if self.slot != wall_slot {
            *self = Self { slot: wall_slot, spent: 0 };
        }
        self.spent < PUBLICATIONS_PER_SLOT
    }

    fn spend(&mut self) {
        self.spent += 1;
    }
}

pub struct SlashingDetection {
    pub proposals: DoubleProposals,
    votes: PublicVotes,
    aggregates: AggregateVotes,
    proofs: Vec<AttesterProof>,
    publications: SlotBudget,
}

impl Default for SlashingDetection {
    fn default() -> Self {
        Self {
            proposals: DoubleProposals::default(),
            votes: PublicVotes::default(),
            aggregates: AggregateVotes::default(),
            proofs: Vec::with_capacity(PROOFS_CAPACITY),
            publications: SlotBudget::default(),
        }
    }
}

impl SlashingDetection {
    /// Takes a public vote whose signature verified.
    pub fn record_vote(&mut self, accepted: &[u8; SINGLE_ATT_SIZE]) {
        self.votes.record(accepted);
    }

    /// Takes a public `Attestation` of one committee whose signature verified
    /// against `committee`.
    pub fn record_aggregate(&mut self, attestation: &[u8], committee: &[u32]) {
        let room = self.has_room();
        if let Some(proof) = self.aggregates.record(attestation, committee, room) {
            self.proofs.push(proof);
        }
    }

    /// `verifiable` tells whether peers verify votes targeting an epoch under
    /// the fork version recorded votes were verified under. Signatures are
    /// not checked here.
    pub fn conflicts_with_public(
        &self,
        single: &[u8; SINGLE_ATT_SIZE],
        verifiable: impl Fn(Epoch) -> bool,
    ) -> Option<Offence> {
        if !verifiable(SingleAttestationView::target_epoch(single)) {
            return None;
        }
        self.votes.conflicts(single).then_some(Offence::DoubleVote)
    }

    /// False while only attester proofs wait and this slot's publications
    /// are spent.
    pub fn has_proofs(&mut self, wall_slot: Slot) -> bool {
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
    pub fn pop_attester_proof(&mut self) {
        self.proofs.pop();
        self.publications.spend();
    }

    fn has_room(&self) -> bool {
        self.proofs.len() < PROOFS_CAPACITY
    }
}
