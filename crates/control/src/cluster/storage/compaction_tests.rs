use std::{
    fs,
    time::{Duration, Instant},
};

use flux_disk::FailedOp;

use super::{
    tests::{entry, event, identity, persisted, recovered, state},
    *,
};

fn snapshot(index: u64) -> Snapshot {
    let mut snapshot = Snapshot { data: vec![7; 32].into(), ..Snapshot::default() };
    let metadata = snapshot.mut_metadata();
    metadata.index = index;
    metadata.term = 2;
    metadata.mut_conf_state().voters = vec![1, 2, 3];
    snapshot
}

fn seeded(path: &Path) -> ClusterStorage {
    let mut storage = ClusterStorage::create(path, identity()).unwrap();
    recovered(&mut storage);
    let entries: Vec<_> = (1..=20).map(|index| entry(index, 2)).collect();
    storage.persist(1, &entries, Some(&state(2, 18))).unwrap();
    persisted(&mut storage, 1);
    storage
}

fn start_checkpoint(storage: &mut ClusterStorage) -> FileToken {
    storage.checkpoint(None, &snapshot(18), &[entry(19, 2), entry(20, 2)], &state(2, 18)).unwrap();
    match &storage.state.phase {
        Phase::Replacing(replacement) => replacement.file,
        _ => panic!("not replacing"),
    }
}

fn poll_disk_until(storage: &mut ClusterStorage, matched: impl Fn(&DiskEvent<'_>) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = false;
    while !found {
        storage.disk.poll_with(|event| {
            found |= matched(&event);
            assert!(
                storage.state.on_event(event).unwrap().is_none(),
                "checkpoint acknowledged before directory sync"
            );
        });
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn compaction_shrinks_the_journal_and_preserves_the_uncommitted_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = seeded(&path);
    let original_len = fs::metadata(&path).unwrap().len();
    start_checkpoint(&mut storage);
    assert!(!storage.is_ready());
    assert!(matches!(event(&mut storage).unwrap(), ClusterStorageEvent::Compacted { index: 18 }));
    assert!(storage.is_ready());
    assert_eq!(storage.appended_bytes(), 0);
    assert!(fs::metadata(&path).unwrap().len() < original_len / 2);
    drop(storage);
    let mut storage = ClusterStorage::open(&path, identity()).unwrap();
    let restored = recovered(&mut storage);
    assert_eq!(restored.snapshot, snapshot(18));
    assert_eq!(restored.entries, [entry(19, 2), entry(20, 2)]);
    assert_eq!(restored.hard_state, state(2, 18));
    storage.persist(1, &[entry(19, 3)], Some(&state(3, 19))).unwrap();
    persisted(&mut storage, 1);
    drop(storage);
    let restored = recovered(&mut ClusterStorage::open(&path, identity()).unwrap());
    assert_eq!(restored.snapshot, snapshot(18));
    assert_eq!(restored.entries, [entry(19, 3)]);
    assert_eq!(restored.hard_state, state(3, 19));
}

#[test]
fn restart_before_rename_uses_the_old_journal_and_ignores_staging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = seeded(&path);
    let old = fs::read(&path).unwrap();
    let file = start_checkpoint(&mut storage);
    poll_disk_until(
        &mut storage,
        |event| matches!(event, DiskEvent::Synced { file: completed, .. } if *completed == file),
    );
    assert_eq!(fs::read(&path).unwrap(), old);
    drop(storage);
    assert!(dir.path().join("raft.wal.next").exists());
    let mut storage = ClusterStorage::open(&path, identity()).unwrap();
    let restored = recovered(&mut storage);
    assert!(restored.snapshot.is_empty());
    assert_eq!(restored.entries.len(), 20);
    start_checkpoint(&mut storage);
    assert!(matches!(event(&mut storage).unwrap(), ClusterStorageEvent::Compacted { index: 18 }));
}

#[test]
fn rename_does_not_acknowledge_and_the_new_image_is_self_contained() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = seeded(&path);
    let file = start_checkpoint(&mut storage);
    poll_disk_until(
        &mut storage,
        |event| matches!(event, DiskEvent::Synced { file: completed, .. } if *completed == file),
    );
    storage.state.advance(&mut storage.disk).unwrap();
    poll_disk_until(
        &mut storage,
        |event| matches!(event, DiskEvent::Renamed { file: completed, .. } if *completed == file),
    );
    assert!(!storage.is_ready());
    drop(storage);
    let restored = recovered(&mut ClusterStorage::open(&path, identity()).unwrap());
    assert_eq!(restored.snapshot, snapshot(18));
    assert_eq!(restored.hard_state, state(2, 18));
    assert_eq!(restored.entries, [entry(19, 2), entry(20, 2)]);
}

#[test]
fn checkpoint_failure_never_releases_a_completion() {
    for op in [FailedOp::Write { offset: 0, len: 1 }, FailedOp::Sync, FailedOp::Rename] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.wal");
        let mut storage = seeded(&path);
        let file = start_checkpoint(&mut storage);
        assert!(
            storage
                .state
                .on_event(DiskEvent::Failed {
                    file,
                    op,
                    operation_id: None,
                    error: io::Error::other("injected checkpoint failure"),
                })
                .is_err()
        );
        assert!(!storage.is_ready());
        assert!(storage.poll().is_err());
    }
}

#[test]
fn directory_sync_failure_after_rename_does_not_acknowledge_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = seeded(&path);
    let file = start_checkpoint(&mut storage);
    poll_disk_until(
        &mut storage,
        |event| matches!(event, DiskEvent::Synced { file: completed, .. } if *completed == file),
    );
    storage.state.advance(&mut storage.disk).unwrap();
    poll_disk_until(
        &mut storage,
        |event| matches!(event, DiskEvent::Renamed { file: completed, .. } if *completed == file),
    );
    storage.state.advance(&mut storage.disk).unwrap();
    assert!(
        storage
            .state
            .on_event(DiskEvent::Failed {
                file: storage.state.directory,
                op: FailedOp::Sync,
                operation_id: None,
                error: io::Error::other("injected directory sync failure"),
            })
            .is_err()
    );
    assert!(storage.poll().is_err());
    assert!(!storage.is_ready());
}

#[test]
fn local_checkpoint_cannot_discard_durable_suffix_or_change_hard_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft.wal");
    let mut storage = seeded(&path);
    let original = fs::read(&path).unwrap();
    assert!(storage.checkpoint(None, &snapshot(18), &[], &state(2, 18)).is_err());
    assert!(storage.checkpoint(None, &snapshot(20), &[], &state(2, 20)).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}
