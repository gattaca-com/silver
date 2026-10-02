use crate::DoubleProposals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    DoubleProposal,
}

#[derive(Default)]
pub struct SlashingDetection {
    pub proposals: DoubleProposals,
}

impl SlashingDetection {
    pub fn has_proofs(&self) -> bool {
        self.proposals.has_proofs()
    }
}
