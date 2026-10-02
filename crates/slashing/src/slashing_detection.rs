use silver_beacon_state_data::Epoch;
use silver_ssz::ssz_view::{SINGLE_ATT_SIZE, SingleAttestationView};

use crate::{DoubleProposals, public_votes::PublicVotes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    DoubleProposal,
    DoubleVote,
}

#[derive(Default)]
pub struct SlashingDetection {
    pub proposals: DoubleProposals,
    votes: PublicVotes,
}

impl SlashingDetection {
    /// Takes a public vote whose signature verified.
    pub fn record_vote(&mut self, accepted: &[u8; SINGLE_ATT_SIZE]) {
        self.votes.record(accepted);
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

    pub fn has_proofs(&self) -> bool {
        self.proposals.has_proofs()
    }
}
