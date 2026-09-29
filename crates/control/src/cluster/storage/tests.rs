use std::{
    fs,
    time::{Duration, Instant},
};

use flux_disk::FailedOp;
use raft::{Storage as _, storage::MemStorage};

use super::*;
use crate::cluster::{
    AttestationKey, AttestationLockCommand, AttestationLockStore, LockResult,
    command::ReplicatedCommand,
};

pub(super) fn identity() -> StorageIdentity {
    StorageIdentity::new(1, vec![1, 2, 3]).unwrap()
}

pub(super) fn entry(index: u64, term: u64) -> Entry {
    Entry { index, term, data: vec![index as u8; 32].into(), ..Entry::default() }
}

pub(super) fn state(term: u64, commit: u64) -> HardState {
    HardState { term, vote: 1, commit, ..HardState::default() }
}

pub(super) fn event(storage: &mut ClusterStorage) -> io::Result<ClusterStorageEvent> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(event) = storage.poll()? {
            return Ok(event);
        }
        assert!(Instant::now() < deadline, "Raft storage completion timed out");
        std::thread::yield_now();
    }
}

pub(super) fn recovered(storage: &mut ClusterStorage) -> RecoveredStorage {
    match event(storage).unwrap() {
        ClusterStorageEvent::Recovered(recovered) => recovered,
        event => panic!("unexpected event: {event:?}"),
    }
}

pub(super) fn persisted(storage: &mut ClusterStorage, number: u64) {
    assert!(
        matches!(event(storage).unwrap(), ClusterStorageEvent::Persisted { ready_number } if ready_number == number)
    );
    assert!(storage.is_ready());
}

#[test]
fn durable_batches_recover_entries_hard_state_and_suffix_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    assert!(!storage.is_ready());
    assert!(recovered(&mut storage).entries.is_empty());

    storage.persist(1, &[entry(1, 1), entry(2, 1), entry(3, 1)], Some(&state(1, 1))).unwrap();
    assert!(!storage.is_ready());
    assert_eq!(storage.persist(2, &[], None).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    persisted(&mut storage, 1);
    assert_eq!(storage.persist(1, &[], None).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    storage.persist(2, &[entry(2, 2)], Some(&state(2, 2))).unwrap();
    persisted(&mut storage, 2);
    drop(storage);

    let mut storage = ClusterStorage::open(&path, identity()).unwrap();
    let restored = recovered(&mut storage);
    assert_eq!(restored.entries, vec![entry(1, 1), entry(2, 2)]);
    assert_eq!(restored.hard_state, state(2, 2));
    let memory = MemStorage::new_with_conf_state((vec![1, 2, 3], vec![]));
    memory.wl().append(&restored.entries).unwrap();
    memory.wl().set_hardstate(restored.hard_state);
    assert_eq!(memory.last_index().unwrap(), 2);
    assert_eq!(memory.initial_state().unwrap().hard_state.commit, 2);

    storage.persist(1, &[entry(3, 2)], Some(&state(2, 2))).unwrap();
    persisted(&mut storage, 1);
    storage.persist(2, &[], Some(&state(2, 3))).unwrap();
    persisted(&mut storage, 2);
    drop(storage);
    let restored = recovered(&mut ClusterStorage::open(&path, identity()).unwrap());
    assert_eq!(restored.entries, vec![entry(1, 1), entry(2, 2), entry(3, 2)]);
    assert_eq!(restored.hard_state.commit, 3);
}

#[test]
fn recovery_truncates_incomplete_tail_before_appending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    recovered(&mut storage);
    storage.persist(1, &[entry(1, 1)], Some(&state(1, 1))).unwrap();
    persisted(&mut storage, 1);
    drop(storage);
    let intact = fs::read(&path).unwrap();
    let mut partial = intact.clone();
    Record::new(&[entry(2, 2)], Some(&state(2, 2))).unwrap().write(&mut partial);
    partial.truncate(partial.len() - 3);
    fs::write(&path, partial).unwrap();

    let mut storage = ClusterStorage::open(&path, identity()).unwrap();
    assert_eq!(recovered(&mut storage).entries, vec![entry(1, 1)]);
    assert_eq!(fs::read(&path).unwrap(), intact);
    storage.persist(1, &[entry(2, 3)], Some(&state(3, 2))).unwrap();
    persisted(&mut storage, 1);
    drop(storage);
    assert_eq!(recovered(&mut ClusterStorage::open(&path, identity()).unwrap()).entries, vec![
        entry(1, 1),
        entry(2, 3)
    ]);
}

#[test]
fn replay_reads_large_records_across_multiple_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    recovered(&mut storage);
    let mut large = entry(1, 1);
    large.data = vec![0x71; READ_CHUNK_BYTES * 3].into();
    storage.persist(1, &[large.clone()], Some(&state(1, 1))).unwrap();
    persisted(&mut storage, 1);
    drop(storage);
    assert_eq!(recovered(&mut ClusterStorage::open(&path, identity()).unwrap()).entries, vec![
        large
    ]);
}

#[test]
fn failed_or_mismatched_recovery_never_initializes_an_empty_voter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut missing = ClusterStorage::open(&path, identity()).unwrap();
    assert_eq!(event(&mut missing).unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(missing.persist(1, &[], None).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    drop(missing);

    recovered(&mut ClusterStorage::create(&path, identity()).unwrap());
    let original = fs::read(&path).unwrap();
    let mut exists = ClusterStorage::create(&path, identity()).unwrap();
    assert_eq!(event(&mut exists).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    drop(exists);
    assert_eq!(fs::read(&path).unwrap(), original);

    let wrong_node = StorageIdentity::new(2, vec![1, 2, 3]).unwrap();
    let mut mismatch = ClusterStorage::open(&path, wrong_node).unwrap();
    assert_eq!(event(&mut mismatch).unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop(mismatch);
    assert_eq!(fs::read(&path).unwrap(), original);

    let mut corrupt = original.clone();
    corrupt[0] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    let mut storage = ClusterStorage::open(&path, identity()).unwrap();
    assert_eq!(event(&mut storage).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}

#[test]
fn writes_do_not_acknowledge_and_failed_writes_cannot_be_hidden_by_a_later_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    recovered(&mut storage);
    storage.persist(7, &[entry(1, 1)], Some(&state(1, 1))).unwrap();
    let Phase::SyncingBatch { sync, .. } = storage.state.phase else { panic!("not syncing") };
    let file = storage.state.file;
    assert!(
        storage.state.on_event(DiskEvent::Written { file, offset: 0, len: 32 }).unwrap().is_none()
    );
    assert!(!storage.is_ready());
    assert!(
        storage
            .state
            .on_event(DiskEvent::Failed {
                file,
                op: FailedOp::Write { offset: 0, len: 32 },
                operation_id: None,
                error: io::Error::other("injected write failure"),
            })
            .is_err()
    );
    assert!(
        storage.state.on_event(DiskEvent::Synced { file, operation_id: sync }).unwrap().is_none()
    );
    assert_eq!(storage.persist(8, &[], None).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn new_journal_is_not_ready_before_its_directory_entry_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    let Phase::SyncingLog { sync } = storage.state.phase else { panic!("not syncing") };
    let file = storage.state.file;
    assert!(
        storage.state.on_event(DiskEvent::Synced { file, operation_id: sync }).unwrap().is_none()
    );
    assert!(!storage.is_ready());
    storage.state.advance(&mut storage.disk).unwrap();
    let Phase::SyncingDirectory { sync } = storage.state.phase else {
        panic!("not syncing directory")
    };
    assert!(matches!(
        storage
            .state
            .on_event(DiskEvent::Synced { file: storage.state.directory, operation_id: sync })
            .unwrap(),
        Some(ClusterStorageEvent::Recovered(_))
    ));
    assert!(storage.is_ready());
}

#[test]
fn sync_failure_keeps_storage_failed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    recovered(&mut storage);
    storage.persist(1, &[entry(1, 1)], Some(&state(1, 1))).unwrap();
    let Phase::SyncingBatch { sync, .. } = storage.state.phase else { panic!("not syncing") };
    assert!(
        storage
            .state
            .on_event(DiskEvent::Failed {
                file: storage.state.file,
                op: FailedOp::Sync,
                operation_id: Some(sync),
                error: io::Error::other("injected sync failure"),
            })
            .is_err()
    );
    assert!(!storage.is_ready());
    assert_eq!(storage.persist(2, &[], None).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn committed_epoch_locks_can_be_rebuilt_without_applying_the_uncommitted_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let command = AttestationLockCommand {
        key: AttestationKey { attester_index: 7, slot: 100 },
        subnet: 0,
        ssz: [0; silver_common::ssz_view::SINGLE_ATT_SIZE],
    };
    let mut later = command;
    later.key.attester_index = 8;
    let entries = [
        Entry {
            index: 1,
            term: 1,
            data: ReplicatedCommand::Lock(command).encode().into(),
            ..Entry::default()
        },
        Entry {
            index: 2,
            term: 1,
            data: ReplicatedCommand::Lock(later).encode().into(),
            ..Entry::default()
        },
    ];
    let mut storage = ClusterStorage::create(&path, identity()).unwrap();
    recovered(&mut storage);
    storage.persist(1, &entries, Some(&state(1, 1))).unwrap();
    persisted(&mut storage, 1);
    drop(storage);
    let restored = recovered(&mut ClusterStorage::open(&path, identity()).unwrap());
    let mut locks = AttestationLockStore::default();
    for entry in
        restored.entries.iter().take_while(|entry| entry.index <= restored.hard_state.commit)
    {
        let ReplicatedCommand::Lock(command) = ReplicatedCommand::decode(&entry.data).unwrap()
        else {
            panic!("not a lock")
        };
        assert_eq!(locks.apply(&command), LockResult::Accepted);
    }
    let mut conflict = command;
    conflict.key.slot = 105;
    conflict.ssz[0] = 1;
    assert_eq!(locks.apply(&command), LockResult::AlreadyAcceptedSame);
    assert_eq!(locks.apply(&conflict), LockResult::ConflictingAttestation);
    assert_eq!(locks.apply(&later), LockResult::Accepted);
}
