use silver_beacon_state_data::{Epoch, Version};
use silver_ssz::ssz_view::SINGLE_ATT_SIZE;

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
    pub fn record_vote(&mut self, accepted: &[u8; SINGLE_ATT_SIZE], fork_version: Version) {
        self.votes.record(accepted, fork_version);
    }

    /// Compares data and recorded fork versions; does not verify signatures.
    pub fn conflicts_with_public(
        &self,
        single: &[u8; SINGLE_ATT_SIZE],
        signing_version: impl Fn(Epoch) -> Version,
    ) -> Option<Offence> {
        self.votes.conflicts(single, signing_version).then_some(Offence::DoubleVote)
    }

    pub fn has_proofs(&self) -> bool {
        self.proposals.has_proofs()
    }
}
