use std::io;

use bytes::{Bytes, BytesMut};
use raft::{
    GetEntriesContext, RaftState, Ready, Storage, StorageError,
    eraftpb::{ConfState, Entry, HardState, Snapshot},
    storage::MemStorage,
};

use super::{
    lock_store::MAX_SNAPSHOT_BYTES, membership::member_ids, persistence::RecoveredStorage,
    voters::MAX_VOTERS,
};

/// Storage still holds snapshot N while N+1 is written, so the two take turns.
/// Once storage drops N, writing N+2 reclaims its allocation.
#[derive(Default)]
pub(super) struct SnapshotBuffers {
    buffers: [BytesMut; 2],
    next: usize,
}

impl SnapshotBuffers {
    pub fn write(
        &mut self,
        len: usize,
        encode: impl FnOnce(&mut BytesMut) -> io::Result<()>,
    ) -> io::Result<Bytes> {
        let buffer = &mut self.buffers[self.next];
        self.next ^= 1;
        buffer.clear();
        buffer.reserve(len);
        encode(buffer)?;
        Ok(buffer.split().freeze())
    }
}

pub(super) struct RaftStorage {
    pub memory: MemStorage,
    snapshot: Snapshot,
}

impl RaftStorage {
    pub fn new(voters: &[u64]) -> Self {
        Self {
            memory: MemStorage::new_with_conf_state((voters.to_vec(), Vec::<u64>::new())),
            snapshot: Snapshot::default(),
        }
    }

    pub fn recovered(recovered: &RecoveredStorage) -> raft::Result<Self> {
        let mut storage = Self::new(&recovered.initial_voters);
        if !recovered.snapshot.is_empty() {
            storage.install_snapshot(recovered.snapshot.clone())?;
        }
        storage.memory.wl().append(&recovered.entries)?;
        storage.memory.wl().set_hardstate(recovered.hard_state.clone());
        Ok(storage)
    }

    pub fn append_ready(&mut self, ready: &Ready) -> raft::Result<()> {
        if !ready.snapshot().is_empty() {
            self.install_snapshot(ready.snapshot().clone())?;
        }
        let mut memory = self.memory.wl();
        memory.append(ready.entries())?;
        if let Some(hard_state) = ready.hs() {
            memory.set_hardstate(hard_state.clone());
        }
        Ok(())
    }

    pub fn snapshot_index(&self) -> u64 {
        self.snapshot.get_metadata().index
    }

    pub fn install_snapshot(&mut self, snapshot: Snapshot) -> raft::Result<()> {
        self.memory.wl().apply_snapshot(snapshot.clone())?;
        self.snapshot = snapshot;
        Ok(())
    }

    pub fn suffix(&self, index: u64) -> raft::Result<Vec<Entry>> {
        let last = self.last_index()?;
        if index >= last {
            return Ok(Vec::new());
        }
        self.entries(index + 1, last + 1, None, GetEntriesContext::empty(false))
    }

    pub fn compact(&mut self, snapshot: Snapshot) -> raft::Result<()> {
        if snapshot.get_metadata().index == self.snapshot_index() {
            self.snapshot = snapshot;
            return Ok(());
        }
        let entries = self.suffix(snapshot.get_metadata().index)?;
        let hard_state = self.memory.rl().hard_state().clone();
        self.install_snapshot(snapshot)?;
        let mut memory = self.memory.wl();
        memory.append(&entries)?;
        memory.set_hardstate(hard_state);
        Ok(())
    }

    pub fn checkpoint(&self, index: u64, data: Bytes) -> raft::Result<(Snapshot, HardState)> {
        let mut snapshot = Snapshot { data, ..Snapshot::default() };
        let metadata = snapshot.mut_metadata();
        metadata.index = index;
        metadata.term = self.term(index)?;
        metadata.set_conf_state(self.initial_state()?.conf_state);
        Ok((snapshot, self.memory.rl().hard_state().clone()))
    }
}

// MemStorage synthesizes empty snapshots at its commit index, which can exceed
// the applied index during asynchronous persistence. Serve only our captured
// state.
impl Storage for RaftStorage {
    fn initial_state(&self) -> raft::Result<RaftState> {
        self.memory.initial_state()
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        context: GetEntriesContext,
    ) -> raft::Result<Vec<Entry>> {
        if low == high && low >= self.first_index()? && low <= self.last_index()?.saturating_add(1)
        {
            return Ok(Vec::new());
        }
        self.memory.entries(low, high, max_size, context)
    }

    fn term(&self, index: u64) -> raft::Result<u64> {
        self.memory.term(index)
    }
    fn first_index(&self) -> raft::Result<u64> {
        self.memory.first_index()
    }
    fn last_index(&self) -> raft::Result<u64> {
        self.memory.last_index()
    }

    /// raft-rs refuses to restore a snapshot whose membership lacks it, so a
    /// learner waits for one cut after it was added.
    fn snapshot(&self, request_index: u64, to: u64) -> raft::Result<Snapshot> {
        let members = self.snapshot.get_metadata().get_conf_state();
        if self.snapshot.is_empty() ||
            request_index > self.snapshot_index() ||
            !member_ids(members).any(|id| id == to)
        {
            return Err(StorageError::SnapshotTemporarilyUnavailable.into());
        }
        Ok(self.snapshot.clone())
    }
}

pub(super) fn validate_snapshot(snapshot: &Snapshot) -> io::Result<()> {
    let metadata = snapshot.get_metadata();
    if snapshot.data.len() > MAX_SNAPSHOT_BYTES ||
        metadata.index == 0 ||
        metadata.index == u64::MAX ||
        metadata.term == 0 ||
        !is_consistent(metadata.get_conf_state())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Raft snapshot size, metadata or membership",
        ));
    }
    Ok(())
}

/// Refuses shapes raft-rs never produces: no voters, zero or repeated ids, a
/// learner that votes, or `auto_leave` outside a joint config.
fn is_consistent(membership: &ConfState) -> bool {
    let joint = !membership.voters_outgoing.is_empty();
    !membership.voters.is_empty() &&
        are_distinct_ids(&membership.voters) &&
        are_distinct_ids(&membership.voters_outgoing) &&
        are_distinct_ids(&membership.learners) &&
        are_distinct_ids(&membership.learners_next) &&
        membership.learners.iter().all(|id| {
            !membership.voters.contains(id) && !membership.voters_outgoing.contains(id)
        }) &&
        membership
            .learners_next
            .iter()
            .all(|id| !membership.voters.contains(id) && membership.voters_outgoing.contains(id)) &&
        (joint || !membership.auto_leave)
}

fn are_distinct_ids(ids: &[u64]) -> bool {
    ids.len() <= MAX_VOTERS &&
        ids.iter().enumerate().all(|(i, id)| *id != 0 && !ids[i + 1..].contains(id))
}
