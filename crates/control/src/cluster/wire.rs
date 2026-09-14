use buffa::Message as _;
use raft::eraftpb::{
    ConfState, Entry, EntryType, Message, MessageType, Snapshot, SnapshotMetadata,
};
use silver_common::{Error, TCacheProducer, TCacheRead, TProducer};

use super::generated as wire;

/// Encode directly into the outbound TCache. Buffa computes the exact wire
/// size first, so no intermediate serialized `Vec<u8>` is needed.
pub(crate) fn encode_message(
    message: Message,
    producer: &mut TProducer,
) -> Result<TCacheRead, Error> {
    let message = to_wire_message(message);
    let len = message.compute_size() as usize;
    let mut reservation = producer.reserve(len, true).ok_or(Error::BufferTooSmall)?;
    let output = producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut output[..len];
    message.write_to(&mut cursor);
    debug_assert!(cursor.is_empty());
    reservation.increment_offset(len);
    Ok(reservation.read())
}

pub(crate) fn decode_message(bytes: &[u8]) -> Result<Message, DecodeError> {
    from_wire_message(wire::Message::decode_from_slice(bytes)?)
}

#[derive(Debug)]
pub(crate) enum DecodeError {
    Buffa(buffa::DecodeError),
    UnknownMessageType(i32),
    UnknownEntryType(i32),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Buffa(error) => error.fmt(formatter),
            Self::UnknownMessageType(value) => {
                write!(formatter, "unknown Raft message type {value}")
            }
            Self::UnknownEntryType(value) => {
                write!(formatter, "unknown Raft entry type {value}")
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Buffa(error) => Some(error),
            Self::UnknownMessageType(_) | Self::UnknownEntryType(_) => None,
        }
    }
}

impl From<buffa::DecodeError> for DecodeError {
    fn from(error: buffa::DecodeError) -> Self {
        Self::Buffa(error)
    }
}

fn to_wire_message(mut message: Message) -> wire::Message {
    let entries = message.take_entries().into_iter().map(to_wire_entry).collect();
    let snapshot = if message.has_snapshot() {
        buffa::MessageField::some(to_wire_snapshot(message.take_snapshot()))
    } else {
        buffa::MessageField::default()
    };

    wire::Message {
        msg_type: (message.msg_type as i32).into(),
        to: message.to,
        from: message.from,
        term: message.term,
        log_term: message.log_term,
        index: message.index,
        entries,
        commit: message.commit,
        snapshot,
        reject: message.reject,
        reject_hint: message.reject_hint,
        context: message.context,
        request_snapshot: message.request_snapshot,
        deprecated_priority: message.deprecated_priority,
        commit_term: message.commit_term,
        priority: message.priority,
        ..wire::Message::default()
    }
}

fn to_wire_entry(entry: Entry) -> wire::Entry {
    wire::Entry {
        entry_type: (entry.entry_type as i32).into(),
        term: entry.term,
        index: entry.index,
        data: entry.data,
        sync_log: entry.sync_log,
        context: entry.context,
        ..wire::Entry::default()
    }
}

fn to_wire_snapshot(mut snapshot: Snapshot) -> wire::Snapshot {
    let metadata = if snapshot.has_metadata() {
        buffa::MessageField::some(to_wire_snapshot_metadata(snapshot.take_metadata()))
    } else {
        buffa::MessageField::default()
    };
    wire::Snapshot { data: snapshot.data, metadata, ..wire::Snapshot::default() }
}

fn to_wire_snapshot_metadata(mut metadata: SnapshotMetadata) -> wire::SnapshotMetadata {
    let conf_state = if metadata.has_conf_state() {
        buffa::MessageField::some(to_wire_conf_state(metadata.take_conf_state()))
    } else {
        buffa::MessageField::default()
    };
    wire::SnapshotMetadata {
        conf_state,
        index: metadata.index,
        term: metadata.term,
        ..wire::SnapshotMetadata::default()
    }
}

fn to_wire_conf_state(conf_state: ConfState) -> wire::ConfState {
    wire::ConfState {
        voters: conf_state.voters,
        learners: conf_state.learners,
        voters_outgoing: conf_state.voters_outgoing,
        learners_next: conf_state.learners_next,
        auto_leave: conf_state.auto_leave,
        ..wire::ConfState::default()
    }
}

fn from_wire_message(message: wire::Message) -> Result<Message, DecodeError> {
    let entries =
        message.entries.into_iter().map(from_wire_entry).collect::<Result<Vec<_>, _>>()?;
    let snapshot = message.snapshot.into_option().map(from_wire_snapshot).transpose()?;

    let mut decoded = Message::default();
    decoded.set_msg_type(message_type(message.msg_type.to_i32())?);
    decoded.set_to(message.to);
    decoded.set_from(message.from);
    decoded.set_term(message.term);
    decoded.set_log_term(message.log_term);
    decoded.set_index(message.index);
    decoded.set_entries(entries.into());
    decoded.set_commit(message.commit);
    if let Some(snapshot) = snapshot {
        decoded.set_snapshot(snapshot);
    }
    decoded.set_reject(message.reject);
    decoded.set_reject_hint(message.reject_hint);
    decoded.set_context(message.context);
    decoded.set_request_snapshot(message.request_snapshot);
    decoded.set_deprecated_priority(message.deprecated_priority);
    decoded.set_commit_term(message.commit_term);
    decoded.set_priority(message.priority);
    Ok(decoded)
}

fn from_wire_entry(entry: wire::Entry) -> Result<Entry, DecodeError> {
    let mut decoded = Entry::default();
    decoded.set_entry_type(entry_type(entry.entry_type.to_i32())?);
    decoded.set_term(entry.term);
    decoded.set_index(entry.index);
    decoded.set_data(entry.data);
    decoded.set_sync_log(entry.sync_log);
    decoded.set_context(entry.context);
    Ok(decoded)
}

fn from_wire_snapshot(snapshot: wire::Snapshot) -> Result<Snapshot, DecodeError> {
    let metadata = snapshot.metadata.into_option().map(from_wire_snapshot_metadata).transpose()?;
    let mut decoded = Snapshot::default();
    decoded.set_data(snapshot.data);
    if let Some(metadata) = metadata {
        decoded.set_metadata(metadata);
    }
    Ok(decoded)
}

fn from_wire_snapshot_metadata(
    metadata: wire::SnapshotMetadata,
) -> Result<SnapshotMetadata, DecodeError> {
    let conf_state = metadata.conf_state.into_option().map(from_wire_conf_state).transpose()?;
    let mut decoded = SnapshotMetadata::default();
    if let Some(conf_state) = conf_state {
        decoded.set_conf_state(conf_state);
    }
    decoded.set_index(metadata.index);
    decoded.set_term(metadata.term);
    Ok(decoded)
}

fn from_wire_conf_state(conf_state: wire::ConfState) -> Result<ConfState, DecodeError> {
    Ok(ConfState {
        voters: conf_state.voters,
        learners: conf_state.learners,
        voters_outgoing: conf_state.voters_outgoing,
        learners_next: conf_state.learners_next,
        auto_leave: conf_state.auto_leave,
        ..ConfState::default()
    })
}

fn message_type(value: i32) -> Result<MessageType, DecodeError> {
    match value {
        0 => Ok(MessageType::MsgHup),
        1 => Ok(MessageType::MsgBeat),
        2 => Ok(MessageType::MsgPropose),
        3 => Ok(MessageType::MsgAppend),
        4 => Ok(MessageType::MsgAppendResponse),
        5 => Ok(MessageType::MsgRequestVote),
        6 => Ok(MessageType::MsgRequestVoteResponse),
        7 => Ok(MessageType::MsgSnapshot),
        8 => Ok(MessageType::MsgHeartbeat),
        9 => Ok(MessageType::MsgHeartbeatResponse),
        10 => Ok(MessageType::MsgUnreachable),
        11 => Ok(MessageType::MsgSnapStatus),
        12 => Ok(MessageType::MsgCheckQuorum),
        13 => Ok(MessageType::MsgTransferLeader),
        14 => Ok(MessageType::MsgTimeoutNow),
        15 => Ok(MessageType::MsgReadIndex),
        16 => Ok(MessageType::MsgReadIndexResp),
        17 => Ok(MessageType::MsgRequestPreVote),
        18 => Ok(MessageType::MsgRequestPreVoteResponse),
        other => Err(DecodeError::UnknownMessageType(other)),
    }
}

fn entry_type(value: i32) -> Result<EntryType, DecodeError> {
    match value {
        0 => Ok(EntryType::EntryNormal),
        1 => Ok(EntryType::EntryConfChange),
        2 => Ok(EntryType::EntryConfChangeV2),
        other => Err(DecodeError::UnknownEntryType(other)),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use silver_common::{TCache, TCacheProducer};

    use super::*;

    #[test]
    fn raft_message_round_trips_through_buffa_and_tcache() {
        let mut entry = Entry::default();
        entry.set_entry_type(EntryType::EntryConfChangeV2);
        entry.set_term(6);
        entry.set_index(9);
        entry.set_data(Bytes::from_static(b"entry data"));
        entry.set_context(Bytes::from_static(b"entry context"));
        entry.set_sync_log(true);

        let mut conf_state = ConfState::default();
        conf_state.voters = vec![1, 2, 3];
        conf_state.learners = vec![4];
        conf_state.voters_outgoing = vec![5, 6];
        conf_state.learners_next = vec![7];
        conf_state.auto_leave = true;

        let mut metadata = SnapshotMetadata::default();
        metadata.set_conf_state(conf_state);
        metadata.set_index(17);
        metadata.set_term(8);

        let mut snapshot = Snapshot::default();
        snapshot.set_data(Bytes::from_static(b"snapshot"));
        snapshot.set_metadata(metadata);

        let mut message = Message::default();
        message.set_msg_type(MessageType::MsgSnapshot);
        message.set_to(2);
        message.set_from(1);
        message.set_term(8);
        message.set_log_term(7);
        message.set_index(16);
        message.mut_entries().push(entry);
        message.set_commit(15);
        message.set_snapshot(snapshot);
        message.set_reject(true);
        message.set_reject_hint(14);
        message.set_context(Bytes::from_static(b"message context"));
        message.set_request_snapshot(13);
        message.set_deprecated_priority(12);
        message.set_commit_term(11);
        message.set_priority(-10);

        let expected = message.clone();
        let mut producer = TCache::producer("cluster_wire_test", 1 << 14);
        let mut consumer =
            producer.cache_ref().strict_random_access("cluster_wire_test_consumer", true).unwrap();
        let read = encode_message(message, &mut producer).unwrap();
        let acquired = consumer.acquire_strict(read).unwrap();
        let (bytes, _) = acquired.buffer().unwrap();

        assert_eq!(decode_message(bytes).unwrap(), expected);
    }
}
