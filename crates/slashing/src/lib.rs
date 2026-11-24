mod aggregate_votes;
mod attester_proof;
mod double_proposals;
mod public_votes;
mod slashing_detection;
mod slashing_pool;
mod surround_votes;

pub use attester_proof::AttesterProof;
pub use double_proposals::{DoubleProposals, SignedHeader};
pub use slashing_detection::{Offence, SlashingDetection};
pub use slashing_pool::{Admission, Selection, SlashingPool};

const PROOFS_CAPACITY: usize = 64;
