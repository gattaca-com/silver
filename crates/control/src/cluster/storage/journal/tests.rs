use super::*;

fn identity() -> StorageIdentity {
    StorageIdentity::new(1, vec![3, 1, 2]).unwrap()
}

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        data: vec![index as u8; 80].into(),
        context: vec![term as u8; 16].into(),
        ..Entry::default()
    }
}

fn state(term: u64, vote: u64, commit: u64) -> HardState {
    HardState { term, vote, commit, ..HardState::default() }
}

fn header() -> Vec<u8> {
    let mut bytes = Vec::new();
    identity().write(&mut bytes);
    bytes
}

fn snapshot(index: u64, term: u64) -> Snapshot {
    let mut snapshot = Snapshot { data: vec![7; 100].into(), ..Snapshot::default() };
    let metadata = snapshot.mut_metadata();
    metadata.index = index;
    metadata.term = term;
    metadata.mut_conf_state().voters = vec![1, 2, 3];
    snapshot
}

#[test]
fn checkpoint_replays_a_compacted_base_and_replaces_only_the_uncommitted_suffix() {
    let snapshot = snapshot(10, 2);
    let mut bytes = Vec::new();
    identity().write_checkpoint(&mut bytes);
    Record::checkpoint(&snapshot, &[entry(11, 2), entry(12, 2)], &state(2, 1, 11))
        .unwrap()
        .write(&mut bytes);
    append(&mut bytes, &[entry(12, 3)], Some(&state(3, 1, 12)));
    let recovered = replay(&bytes).unwrap().recovered;
    assert_eq!(recovered.snapshot, snapshot);
    assert_eq!(recovered.entries, vec![entry(11, 2), entry(12, 3)]);
    assert_eq!(recovered.hard_state, state(3, 1, 12));
}

#[test]
fn an_incomplete_checkpoint_is_never_recovered_as_an_empty_voter() {
    let mut bytes = Vec::new();
    identity().write_checkpoint(&mut bytes);
    Record::checkpoint(&snapshot(10, 2), &[], &state(2, 1, 10)).unwrap().write(&mut bytes);
    for length in 0..bytes.len() {
        assert!(replay(&bytes[..length]).is_err(), "accepted truncated checkpoint at {length}");
    }
    assert!(replay(&bytes).is_ok());
    let valid = bytes.len();
    append(&mut bytes, &[entry(11, 2)], Some(&state(2, 1, 10)));
    for length in valid..bytes.len() {
        let recovered = replay(&bytes[..length]).unwrap().recovered;
        assert_eq!(recovered.snapshot.get_metadata().index, 10);
        assert!(recovered.entries.is_empty());
    }
}

#[test]
fn legacy_journal_headers_remain_readable() {
    let mut bytes = header();
    bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + MAGIC.len()].copy_from_slice(LEGACY_MAGIC);
    bytes.pop();
    Frame::finish(&mut bytes, 0);
    append(&mut bytes, &[entry(1, 1)], Some(&state(1, 1, 1)));
    assert_eq!(replay(&bytes).unwrap().recovered.entries, vec![entry(1, 1)]);
}

fn append(bytes: &mut Vec<u8>, entries: &[Entry], hard_state: Option<&HardState>) {
    Record::new(entries, hard_state).unwrap().write(bytes);
}

fn replay(bytes: &[u8]) -> io::Result<JournalReplay> {
    let mut replay = JournalReplay::new(identity());
    replay.feed(bytes)?;
    replay.finish()?;
    Ok(replay)
}

#[test]
fn identity_is_order_independent_and_rejects_invalid_membership() {
    assert_eq!(identity(), StorageIdentity::new(1, vec![1, 2, 3]).unwrap());
    for (node, voters) in
        [(0, vec![0]), (1, vec![]), (1, vec![2]), (1, vec![0, 1]), (1, vec![1, 1])]
    {
        assert_eq!(
            StorageIdentity::new(node, voters).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn identity_and_membership_must_match_on_recovery() {
    for identity in [
        StorageIdentity::new(2, vec![1, 2, 3]).unwrap(),
        StorageIdentity::new(1, vec![1, 2]).unwrap(),
    ] {
        let mut replay = JournalReplay::new(identity);
        assert_eq!(replay.feed(&header()).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn missing_or_incomplete_identity_is_not_a_fresh_store() {
    let bytes = header();
    for len in 0..bytes.len() {
        assert!(replay(&bytes[..len]).is_err(), "accepted incomplete identity at {len}");
    }
}

#[test]
fn records_round_trip_through_fragmented_reads() {
    let mut bytes = header();
    let mut first = entry(1, 1);
    first.sync_log = true;
    first.entry_type = raft::eraftpb::EntryType::EntryConfChange;
    let entries = vec![first, entry(2, 2)];
    append(&mut bytes, &entries, Some(&state(2, 1, 1)));
    append(&mut bytes, &[], Some(&state(2, 1, 2)));

    for chunk_size in [1, 7, 16, 67, bytes.len()] {
        let mut replay = JournalReplay::new(identity());
        for chunk in bytes.chunks(chunk_size) {
            replay.feed(chunk).unwrap();
        }
        assert!(!replay.finish().unwrap());
        assert_eq!(replay.valid_len, bytes.len() as u64);
        assert_eq!(replay.recovered.entries, entries);
        assert_eq!(replay.recovered.hard_state, state(2, 1, 2));
    }
}

#[test]
fn replacing_an_uncommitted_suffix_preserves_the_prefix() {
    let mut bytes = header();
    append(&mut bytes, &[entry(1, 1), entry(2, 1), entry(3, 1)], Some(&state(1, 1, 1)));
    append(&mut bytes, &[entry(2, 2)], Some(&state(2, 2, 2)));
    let recovered = replay(&bytes).unwrap().recovered;
    assert_eq!(recovered.entries, vec![entry(1, 1), entry(2, 2)]);
    assert_eq!(recovered.hard_state, state(2, 2, 2));
}

#[test]
fn every_incomplete_tail_preserves_complete_batches_only() {
    let mut bytes = header();
    append(&mut bytes, &[entry(1, 1)], Some(&state(1, 1, 1)));
    let valid_len = bytes.len();
    append(&mut bytes, &[entry(2, 2)], Some(&state(2, 2, 2)));
    for len in valid_len..bytes.len() {
        let replay = replay(&bytes[..len]).unwrap();
        assert_eq!(replay.valid_len, valid_len as u64);
        assert_eq!(replay.finish().unwrap(), len != valid_len);
        assert_eq!(replay.recovered.hard_state, state(1, 1, 1));
        assert_eq!(replay.recovered.entries, vec![entry(1, 1)]);
    }
}

#[test]
fn complete_corrupt_records_fail_closed_including_length_corruption() {
    let mut bytes = header();
    let start = bytes.len();
    append(&mut bytes, &[entry(1, 1)], Some(&state(1, 1, 1)));
    for index in start..bytes.len() {
        bytes[index] ^= 1;
        assert!(replay(&bytes).is_err(), "accepted corruption at {index}");
        bytes[index] ^= 1;
    }
}

#[test]
fn impossible_log_and_hard_state_transitions_are_rejected() {
    let initial = LogState::default();
    assert!(initial.next(&[entry(0, 1)], Some(&state(1, 1, 0))).is_err());
    assert!(initial.next(&[entry(2, 1)], Some(&state(1, 1, 0))).is_err());
    assert!(initial.next(&[entry(1, 1), entry(3, 1)], Some(&state(1, 1, 0))).is_err());
    assert!(initial.next(&[entry(1, 1)], Some(&state(1, 1, 2))).is_err());
    assert!(initial.next(&[entry(1, 2)], Some(&state(1, 1, 0))).is_err());

    let current = initial.next(&[entry(1, 1), entry(2, 2)], Some(&state(2, 1, 1))).unwrap();
    assert!(current.next(&[entry(1, 2)], None).is_err());
    assert!(current.next(&[], Some(&state(1, 0, 1))).is_err());
    assert!(current.next(&[], Some(&state(2, 2, 1))).is_err());
    assert!(current.next(&[], Some(&state(2, 0, 1))).is_err());
    assert!(current.next(&[], Some(&state(2, 1, 0))).is_err());
    assert!(current.next(&[entry(3, 1)], None).is_err());
    assert!(current.next(&[], Some(&state(3, 0, 1))).is_ok());
}

#[test]
fn checksummed_records_cannot_overwrite_commits_or_introduce_gaps() {
    let mut initial = header();
    append(&mut initial, &[entry(1, 2), entry(2, 2)], Some(&state(2, 1, 1)));
    for entries in [vec![entry(1, 3)], vec![entry(4, 3)], vec![entry(2, 1)]] {
        let mut bytes = initial.clone();
        append(&mut bytes, &entries, Some(&state(3, 1, 1)));
        assert!(replay(&bytes).is_err());
    }
}

#[test]
fn unknown_format_and_malformed_batches_fail_closed() {
    let mut bytes = header();
    bytes[FRAME_HEADER_LEN + MAGIC.len() - 1] = 0xff;
    Frame::finish(&mut bytes, 0);
    assert!(replay(&bytes).is_err());

    for payload in [vec![2], vec![0, 0xff, 0xff, 0xff, 0xff], vec![0, 0, 0, 0, 0, 1]] {
        let mut bytes = header();
        let start = Frame::start(&mut bytes);
        bytes.extend_from_slice(&payload);
        Frame::finish(&mut bytes, start);
        assert!(replay(&bytes).is_err());
    }
}
