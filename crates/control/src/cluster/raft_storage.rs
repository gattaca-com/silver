use std::io;

use raft::{
    GetEntriesContext, RaftState, Storage, StorageError,
    eraftpb::{Entry, HardState, Snapshot},
    storage::MemStorage,
};

use super::lock_store::AttestationLockStore;

pub(super) struct RestoredSnapshot {
    pub index: u64,
    pub locks: AttestationLockStore,
}

impl RestoredSnapshot {
    pub fn decode(snapshot: &Snapshot, voters: &[u64]) -> io::Result<Self> {
        validate_snapshot(snapshot, voters)?;
        Ok(Self {
            index: snapshot.get_metadata().index,
            locks: AttestationLockStore::decode_snapshot(&snapshot.data)?,
        })
    }
}

pub(super) struct RaftStorage {
    pub memory: MemStorage,
    snapshot: Snapshot,
}

impl RaftStorage {
    #[cfg(any(target_os = "linux", test))]
    pub fn new(voters: Vec<u64>) -> Self {
        Self {
            memory: MemStorage::new_with_conf_state((voters, Vec::<u64>::new())),
            snapshot: Snapshot::default(),
        }
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

    pub fn checkpoint(&self, index: u64, data: Vec<u8>) -> raft::Result<(Snapshot, HardState)> {
        let mut snapshot = Snapshot { data: data.into(), ..Snapshot::default() };
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

    fn snapshot(&self, request_index: u64, _to: u64) -> raft::Result<Snapshot> {
        if self.snapshot.is_empty() || request_index > self.snapshot_index() {
            return Err(StorageError::SnapshotTemporarilyUnavailable.into());
        }
        Ok(self.snapshot.clone())
    }
}

pub(super) fn validate_snapshot(snapshot: &Snapshot, voters: &[u64]) -> io::Result<()> {
    let metadata = snapshot.get_metadata();
    let conf = metadata.get_conf_state();
    let mut actual = conf.voters.clone();
    actual.sort_unstable();
    let mut expected = voters.to_vec();
    expected.sort_unstable();
    if metadata.index == 0 ||
        metadata.index == u64::MAX ||
        metadata.term == 0 ||
        actual != expected ||
        !conf.learners.is_empty() ||
        !conf.voters_outgoing.is_empty() ||
        !conf.learners_next.is_empty() ||
        conf.auto_leave
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Raft snapshot metadata or membership",
        ));
    }
    Ok(())
}
