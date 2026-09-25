mod admission;
mod command;
#[path = "generated/protobuf.eraftpb.rs"]
#[allow(clippy::all, dead_code)]
#[rustfmt::skip]
mod generated;
mod lock_store;
mod node;
#[cfg(target_os = "linux")]
mod storage;
mod wire;

pub use admission::AdmissionError;
pub(crate) use admission::AttestationAdmission;
pub use command::{AttestationKey, AttestationLockCommand, CommandDecodeError};
pub(crate) use lock_store::AttestationLockStore;
pub use lock_store::LockResult;
pub use node::{
    AttestationCluster, AttestationClusterConfig, AttestationDecision, ClusterError, ClusterEvent,
    ProposalId, ProposeError,
};
#[cfg(target_os = "linux")]
pub use storage::{ClusterStorage, ClusterStorageEvent, RecoveredStorage, StorageIdentity};
pub(crate) use wire::{decode_message, encode_message};
