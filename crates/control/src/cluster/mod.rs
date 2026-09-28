mod admission;
mod command;
#[path = "generated/protobuf.eraftpb.rs"]
#[allow(clippy::all, dead_code)]
#[rustfmt::skip]
mod generated;
mod lock_store;
mod node;
mod persistence;
mod raft_storage;
mod snapshot_transfers;
#[cfg(target_os = "linux")]
mod storage;
mod wire;

pub use admission::AdmissionError;
pub(crate) use admission::SlashingAdmission;
pub use command::{AttestationKey, AttestationLockCommand, BlockKey, CommandDecodeError};
pub use lock_store::LockResult;
pub(crate) use lock_store::SlashingLockStore;
pub use node::{
    AttestationDecision, BlockDecision, ClusterError, ClusterEvent, ProposalId, ProposeError,
    SlashingProtectionCluster, SlashingProtectionConfig,
};
pub use persistence::{ClusterStorageConfig, RecoveredStorage};
#[cfg(target_os = "linux")]
pub use storage::{ClusterStorage, ClusterStorageEvent, StorageIdentity};
pub(crate) use wire::{decode_message, encode_message};
