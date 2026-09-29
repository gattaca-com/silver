use std::io;

use buffa::Message as _;
use raft::eraftpb::{Entry, HardState, Snapshot};

use super::super::{
    generated,
    persistence::RecoveredStorage,
    raft_storage::validate_snapshot,
    wire::{from_wire_entry, from_wire_snapshot, to_wire_entry, to_wire_snapshot},
};

const MAGIC: &[u8; 8] = b"SLVRAFT\x02";
const LEGACY_MAGIC: &[u8; 8] = b"SLVRAFT\x01";
const FRAME_HEADER_LEN: usize = 16;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub(super) const READ_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageIdentity {
    node_id: u64,
    voters: Vec<u64>,
}

impl StorageIdentity {
    pub fn new(node_id: u64, mut voters: Vec<u64>) -> io::Result<Self> {
        voters.sort_unstable();
        if node_id == 0 ||
            !voters.contains(&node_id) ||
            voters.contains(&0) ||
            voters.windows(2).any(|pair| pair[0] == pair[1]) ||
            voters.len() > (MAX_RECORD_BYTES - 20) / 8
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Raft storage identity",
            ));
        }
        Ok(Self { node_id, voters })
    }

    pub(super) fn write(&self, output: &mut Vec<u8>) {
        self.write_header(output, false);
    }

    pub(super) fn write_checkpoint(&self, output: &mut Vec<u8>) {
        self.write_header(output, true);
    }

    fn write_header(&self, output: &mut Vec<u8>, checkpoint: bool) {
        let start = Frame::start(output);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&self.node_id.to_le_bytes());
        output.extend_from_slice(&(self.voters.len() as u32).to_le_bytes());
        for voter in &self.voters {
            output.extend_from_slice(&voter.to_le_bytes());
        }
        output.push(u8::from(checkpoint));
        Frame::finish(output, start);
    }

    pub(super) fn validate_snapshot(&self, snapshot: &Snapshot) -> io::Result<()> {
        validate_snapshot(snapshot, &self.voters)
    }

    fn verify(&self, payload: &[u8]) -> io::Result<bool> {
        let mut cursor = Cursor(payload);
        let magic = cursor.take(MAGIC.len())?;
        if magic != MAGIC && magic != LEGACY_MAGIC {
            return Err(invalid_data("unsupported Raft journal format"));
        }
        if cursor.u64()? != self.node_id || cursor.u32()? as usize != self.voters.len() {
            return Err(invalid_data("Raft journal identity does not match configuration"));
        }
        for voter in &self.voters {
            if cursor.u64()? != *voter {
                return Err(invalid_data("Raft journal voters do not match configuration"));
            }
        }
        let checkpoint = if magic == LEGACY_MAGIC {
            false
        } else {
            match cursor.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(invalid_data("invalid Raft journal header kind")),
            }
        };
        cursor.finish()?;
        Ok(checkpoint)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct LogState {
    pub hard_state: HardState,
    pub last_index: u64,
    last_term: u64,
}

impl LogState {
    pub fn from_snapshot(snapshot: &Snapshot, hard_state: &HardState) -> io::Result<Self> {
        let metadata = snapshot.get_metadata();
        if metadata.index == 0 ||
            metadata.index == u64::MAX ||
            metadata.term == 0 ||
            metadata.term > hard_state.term ||
            metadata.index > hard_state.commit
        {
            return Err(invalid_data("Raft snapshot is inconsistent with hard state"));
        }
        let mut state = hard_state.clone();
        state.commit = metadata.index;
        Ok(Self { hard_state: state, last_index: metadata.index, last_term: metadata.term })
    }

    pub fn next(&self, entries: &[Entry], hard_state: Option<&HardState>) -> io::Result<Self> {
        let hard_state = hard_state.unwrap_or(&self.hard_state);
        if hard_state.term < self.hard_state.term ||
            hard_state.commit < self.hard_state.commit ||
            (hard_state.term == self.hard_state.term &&
                self.hard_state.vote != 0 &&
                hard_state.vote != self.hard_state.vote)
        {
            return Err(invalid_data("Raft hard state regressed"));
        }

        let mut next = Self {
            hard_state: hard_state.clone(),
            last_index: self.last_index,
            last_term: self.last_term,
        };
        if let Some(first) = entries.first() {
            if first.index <= self.hard_state.commit ||
                self.last_index.checked_add(1).is_none_or(|end| first.index > end)
            {
                return Err(invalid_data(
                    "Raft append overwrites committed entries or leaves a gap",
                ));
            }
            let mut index = first.index;
            let mut term = if first.index > self.last_index { self.last_term } else { 0 };
            for entry in entries {
                if entry.index != index ||
                    entry.term == 0 ||
                    entry.term < term ||
                    entry.term > hard_state.term
                {
                    return Err(invalid_data("invalid Raft entry index or term"));
                }
                index = index.checked_add(1).ok_or_else(|| invalid_data("Raft index overflow"))?;
                term = entry.term;
            }
            next.last_index = index - 1;
            next.last_term = term;
        }
        if next.hard_state.commit > next.last_index {
            return Err(invalid_data("Raft commit exceeds the stored log"));
        }
        Ok(next)
    }
}

pub(super) struct Record<'a> {
    entries: &'a [Entry],
    hard_state: Option<&'a HardState>,
    snapshot: Option<&'a Snapshot>,
    payload_len: usize,
}

struct DecodedRecord {
    hard_state: Option<HardState>,
    snapshot: Option<Snapshot>,
}

impl<'a> Record<'a> {
    pub fn new(entries: &'a [Entry], hard_state: Option<&'a HardState>) -> io::Result<Self> {
        let mut payload_len = 1usize + 4 + if hard_state.is_some() { 24 } else { 0 };
        for entry in entries {
            // Reject oversized byte fields before protobuf's u32 size calculation.
            if entry.data.len() > MAX_RECORD_BYTES || entry.context.len() > MAX_RECORD_BYTES {
                return Err(invalid_data("Raft journal record exceeds 64 MiB"));
            }
            payload_len += 4 + to_wire_entry(entry.clone()).compute_size() as usize;
            if payload_len > MAX_RECORD_BYTES {
                return Err(invalid_data("Raft journal record exceeds 64 MiB"));
            }
        }
        Ok(Self { entries, hard_state, snapshot: None, payload_len })
    }

    pub fn checkpoint(
        snapshot: &'a Snapshot,
        entries: &'a [Entry],
        hard_state: &'a HardState,
    ) -> io::Result<Self> {
        let mut record = Self::new(entries, Some(hard_state))?;
        if snapshot.data.len() > MAX_RECORD_BYTES {
            return Err(invalid_data("Raft snapshot exceeds journal limit"));
        }
        record.payload_len += 4 + to_wire_snapshot(snapshot.clone()).compute_size() as usize;
        if record.payload_len > MAX_RECORD_BYTES {
            return Err(invalid_data("Raft checkpoint exceeds journal limit"));
        }
        record.snapshot = Some(snapshot);
        Ok(record)
    }

    pub fn len(&self) -> u64 {
        (FRAME_HEADER_LEN + self.payload_len) as u64
    }

    pub fn write(&self, output: &mut Vec<u8>) {
        output.reserve(FRAME_HEADER_LEN + self.payload_len);
        let start = Frame::start(output);
        output.push(u8::from(self.hard_state.is_some()) | (u8::from(self.snapshot.is_some()) << 1));
        if let Some(state) = self.hard_state {
            output.extend_from_slice(&state.term.to_le_bytes());
            output.extend_from_slice(&state.vote.to_le_bytes());
            output.extend_from_slice(&state.commit.to_le_bytes());
        }
        if let Some(snapshot) = self.snapshot {
            let snapshot = to_wire_snapshot(snapshot.clone());
            output.extend_from_slice(&snapshot.compute_size().to_le_bytes());
            snapshot.write_to(output);
        }
        output.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in self.entries {
            let entry = to_wire_entry(entry.clone());
            output.extend_from_slice(&entry.compute_size().to_le_bytes());
            entry.write_to(output);
        }
        Frame::finish(output, start);
    }

    fn decode(payload: &[u8], entries: &mut Vec<Entry>) -> io::Result<DecodedRecord> {
        let mut cursor = Cursor(payload);
        let flags = cursor.take(1)?[0];
        let hard_state = match flags {
            0 => None,
            1 | 3 => Some(HardState {
                term: cursor.u64()?,
                vote: cursor.u64()?,
                commit: cursor.u64()?,
                ..HardState::default()
            }),
            _ => return Err(invalid_data("invalid Raft hard state tag")),
        };
        let snapshot = if flags & 2 != 0 {
            let len = cursor.u32()? as usize;
            let snapshot = generated::Snapshot::decode_from_slice(cursor.take(len)?)
                .map_err(|_| invalid_data("invalid Raft snapshot protobuf"))?;
            Some(from_wire_snapshot(snapshot).map_err(|_| invalid_data("invalid Raft snapshot"))?)
        } else {
            None
        };
        let count = cursor.u32()? as usize;
        if count > cursor.0.len() / 4 {
            return Err(invalid_data("invalid Raft journal entry count"));
        }
        entries.clear();
        for _ in 0..count {
            let len = cursor.u32()? as usize;
            let entry = generated::Entry::decode_from_slice(cursor.take(len)?)
                .map_err(|_| invalid_data("invalid Raft journal protobuf entry"))?;
            entries
                .push(from_wire_entry(entry).map_err(|_| invalid_data("invalid Raft entry type"))?);
        }
        cursor.finish()?;
        Ok(DecodedRecord { hard_state, snapshot })
    }
}

pub(super) struct JournalReplay {
    identity: StorageIdentity,
    buffer: Vec<u8>,
    header_read: bool,
    checkpoint_required: bool,
    record_entries: Vec<Entry>,
    pub recovered: RecoveredStorage,
    pub log: LogState,
    pub valid_len: u64,
    pub appended_bytes: u64,
}

impl JournalReplay {
    pub fn new(identity: StorageIdentity) -> Self {
        Self {
            identity,
            buffer: Vec::with_capacity(READ_CHUNK_BYTES),
            header_read: false,
            checkpoint_required: false,
            record_entries: Vec::new(),
            recovered: RecoveredStorage::default(),
            log: LogState::default(),
            valid_len: 0,
            appended_bytes: 0,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.buffer.extend_from_slice(bytes);
        let mut consumed = 0;
        while let Some(frame) = Frame::read(&self.buffer[consumed..])? {
            if !self.header_read {
                self.checkpoint_required = self.identity.verify(frame.payload)?;
                self.header_read = true;
            } else {
                let record = Record::decode(frame.payload, &mut self.record_entries)?;
                if record.snapshot.is_none() {
                    self.appended_bytes += (FRAME_HEADER_LEN + frame.payload.len()) as u64;
                }
                if self.checkpoint_required &&
                    self.recovered.snapshot.is_empty() &&
                    record.snapshot.is_none()
                {
                    return Err(invalid_data("Raft journal is missing its checkpoint"));
                }
                if let Some(snapshot) = record.snapshot {
                    if !self.checkpoint_required ||
                        self.log.last_index != 0 ||
                        self.log.hard_state != HardState::default()
                    {
                        return Err(invalid_data("Raft checkpoint must precede journal appends"));
                    }
                    self.identity.validate_snapshot(&snapshot)?;
                    self.log = LogState::from_snapshot(
                        &snapshot,
                        record
                            .hard_state
                            .as_ref()
                            .ok_or_else(|| invalid_data("checkpoint has no hard state"))?,
                    )?;
                    self.recovered.snapshot = snapshot;
                }
                let next = self.log.next(&self.record_entries, record.hard_state.as_ref())?;
                if let Some(first) = self.record_entries.first() {
                    let base = self.recovered.snapshot.get_metadata().index + 1;
                    let retain = usize::try_from(
                        first
                            .index
                            .checked_sub(base)
                            .ok_or_else(|| invalid_data("append precedes Raft snapshot"))?,
                    )
                    .map_err(|_| invalid_data("Raft index exceeds address space"))?;
                    if retain > self.recovered.entries.len() {
                        return Err(invalid_data("Raft append leaves a gap after snapshot"));
                    }
                    let previous_term = if retain == 0 {
                        self.recovered.snapshot.get_metadata().term
                    } else {
                        self.recovered.entries[retain - 1].term
                    };
                    if previous_term > first.term {
                        return Err(invalid_data("Raft entry terms regressed across an append"));
                    }
                    self.recovered.entries.truncate(retain);
                    self.recovered.entries.append(&mut self.record_entries);
                }
                self.recovered.hard_state = next.hard_state.clone();
                self.log = next;
            }
            consumed += FRAME_HEADER_LEN + frame.payload.len();
        }
        self.valid_len += consumed as u64;
        self.buffer.drain(..consumed);
        Ok(())
    }

    pub fn finish(&self) -> io::Result<bool> {
        if !self.header_read {
            return Err(invalid_data("Raft journal has no complete identity header"));
        }
        if self.checkpoint_required && self.recovered.snapshot.is_empty() {
            return Err(invalid_data("Raft journal has no complete checkpoint"));
        }
        Ok(!self.buffer.is_empty())
    }
}

struct Frame<'a> {
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    fn start(output: &mut Vec<u8>) -> usize {
        let start = output.len();
        output.resize(start + FRAME_HEADER_LEN, 0);
        start
    }

    fn finish(output: &mut [u8], start: usize) {
        let payload = &output[start + FRAME_HEADER_LEN..];
        let len = payload.len() as u64;
        let checksum = crc32c::crc32c(payload);
        output[start..start + 8].copy_from_slice(&len.to_le_bytes());
        output[start + 8..start + 12].copy_from_slice(&checksum.to_le_bytes());
        let header_checksum = crc32c::crc32c(&output[start..start + 12]);
        output[start + 12..start + FRAME_HEADER_LEN]
            .copy_from_slice(&header_checksum.to_le_bytes());
    }

    fn read(bytes: &'a [u8]) -> io::Result<Option<Self>> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let mut cursor = Cursor(bytes);
        let len = cursor.u64()?;
        let checksum = cursor.u32()?;
        let header_checksum = cursor.u32()?;
        // Protect the length too: corruption must not masquerade as an incomplete tail.
        if crc32c::crc32c(&bytes[..12]) != header_checksum || len > MAX_RECORD_BYTES as u64 {
            return Err(invalid_data("invalid Raft journal frame header"));
        }
        if cursor.0.len() < len as usize {
            return Ok(None);
        }
        let payload = cursor.take(len as usize)?;
        if crc32c::crc32c(payload) != checksum {
            return Err(invalid_data("Raft journal checksum mismatch"));
        }
        Ok(Some(Self { payload }))
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let (value, remainder) = self
            .0
            .split_at_checked(len)
            .ok_or_else(|| invalid_data("truncated Raft journal record"))?;
        self.0 = remainder;
        Ok(value)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let bytes = self.take(4)?.try_into().map_err(|_| invalid_data("invalid u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let bytes = self.take(8)?.try_into().map_err(|_| invalid_data("invalid u64"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn finish(self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid_data("trailing Raft journal record bytes"))
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
