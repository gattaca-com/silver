use raft::{
    RaftLog,
    eraftpb::{Message, MessageType},
};

use super::{
    command::{DecodedEntry, EntryError},
    raft_storage::{RaftStorage, RestoredSnapshot},
};

/// Why a member's Raft message was refused before reaching raft-rs. raft-rs
/// panics on several malformed shapes, and a bad committed entry fails every
/// node on each replay, so both are stopped here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberMessageError {
    EmptyProposal,
    Entry(EntryError),
    ProposalOrigin { origin: u64, from: u64 },
    ForwardedMinimumSlot,
    FutureProposal { slot: u64, wall_slot: u64 },
    EntryIndexGap { expected: u64, actual: u64 },
    CommitPastLog { commit: u64, last_index: u64 },
    Snapshot,
}

/// The local state a member's message is checked against.
pub(super) struct MemberMessageCheck<'a> {
    pub log: &'a RaftLog<RaftStorage>,
    pub voters: &'a [u64],
    pub wall_slot: u64,
}

impl MemberMessageCheck<'_> {
    pub(super) fn check(&self, message: &Message) -> Result<(), MemberMessageError> {
        match message.get_msg_type() {
            MessageType::MsgPropose => self.check_proposal(message),
            MessageType::MsgAppend => self.check_append(message),
            MessageType::MsgHeartbeat => self.check_heartbeat_commit(message.commit),
            MessageType::MsgSnapshot => {
                RestoredSnapshot::decode(message.get_snapshot(), self.voters)
                    .map(|_| ())
                    .map_err(|_| MemberMessageError::Snapshot)
            }
            _ => Ok(()),
        }
    }

    /// Only followers forward proposals, each carrying its own context. The
    /// leader proposes the minimum slot itself and never forwards it.
    fn check_proposal(&self, message: &Message) -> Result<(), MemberMessageError> {
        if message.entries.is_empty() {
            return Err(MemberMessageError::EmptyProposal);
        }
        for entry in &message.entries {
            if entry.data.is_empty() {
                return Err(MemberMessageError::EmptyProposal);
            }
            let (slot, origin) =
                match DecodedEntry::decode(entry).map_err(MemberMessageError::Entry)? {
                    DecodedEntry::Lock(command, id) => (command.key.slot, id.origin_node_id),
                    DecodedEntry::BlockLock(command, id) => (command.key.slot, id.origin_node_id),
                    DecodedEntry::AdvanceMinimumSlot(_) => {
                        return Err(MemberMessageError::ForwardedMinimumSlot);
                    }
                };
            if origin != message.from {
                return Err(MemberMessageError::ProposalOrigin { origin, from: message.from });
            }
            if slot > self.wall_slot {
                return Err(MemberMessageError::FutureProposal { slot, wall_slot: self.wall_slot });
            }
        }
        Ok(())
    }

    /// Mirrors the decoding `apply_entries` relies on, and the log shapes
    /// raft-rs treats as fatal in `handle_append_entries`.
    fn check_append(&self, message: &Message) -> Result<(), MemberMessageError> {
        for (offset, entry) in (1..).zip(&message.entries) {
            // raft-rs trusts each entry's own index when looking for a
            // conflict, and one at or below the commit index is fatal.
            let expected = message.index.saturating_add(offset);
            if entry.index != expected {
                return Err(MemberMessageError::EntryIndexGap { expected, actual: entry.index });
            }
            if !entry.data.is_empty() {
                DecodedEntry::decode(entry).map_err(MemberMessageError::Entry)?;
            }
        }
        Ok(())
    }

    fn check_heartbeat_commit(&self, commit: u64) -> Result<(), MemberMessageError> {
        let last_index = self.log.last_index();
        if commit > last_index {
            return Err(MemberMessageError::CommitPastLog { commit, last_index });
        }
        Ok(())
    }
}
