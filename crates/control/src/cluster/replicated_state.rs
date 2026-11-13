use std::io;

use bytes::BytesMut;
use raft::eraftpb::Snapshot;

use super::{
    lock_store::SlashingLockStore, membership::ClusterMembership, persistence::RecoveredStorage,
    raft_storage::validate_snapshot,
};

/// Everything the log decides, and so everything a snapshot carries.
pub(super) struct ReplicatedState {
    pub locks: SlashingLockStore,
    pub membership: ClusterMembership,
}

impl ReplicatedState {
    pub fn new(initial_voters: &[u64]) -> Self {
        Self {
            locks: SlashingLockStore::default(),
            membership: ClusterMembership::new(initial_voters),
        }
    }

    pub fn recovered(recovered: &RecoveredStorage) -> io::Result<Self> {
        if recovered.snapshot.is_empty() {
            return Ok(Self::new(&recovered.initial_voters));
        }
        Self::decode_snapshot(&recovered.snapshot)
    }

    pub fn snapshot_len(&self) -> usize {
        self.membership.snapshot_len() + self.locks.snapshot_len()
    }

    pub fn encode_snapshot(&self, bytes: &mut BytesMut) -> io::Result<()> {
        self.membership.encode_snapshot(bytes);
        self.locks.encode_snapshot(bytes)
    }

    pub fn decode_snapshot(snapshot: &Snapshot) -> io::Result<Self> {
        validate_snapshot(snapshot)?;
        let roles = snapshot.get_metadata().get_conf_state();
        let (membership, locks) = ClusterMembership::split_from_snapshot(&snapshot.data, roles)?;
        Ok(Self { locks: SlashingLockStore::decode_snapshot(locks)?, membership })
    }
}
