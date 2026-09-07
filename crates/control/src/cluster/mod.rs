mod admission;
mod command;
#[path = "generated/protobuf.eraftpb.rs"]
#[allow(clippy::all, dead_code)]
#[rustfmt::skip]
mod generated;
mod lock_store;
mod node;
mod wire;

pub use admission::AdmissionError;
pub use command::{AttestationKey, AttestationLockCommand, CommandDecodeError};
pub use lock_store::LockResult;
pub use node::{
    AttestationCluster, AttestationClusterConfig, AttestationDecision, ClusterError, ClusterEvent,
    ProposalId, ProposeError,
};
