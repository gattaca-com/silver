use flux::utils::ArrayVec;
use raft::{
    RaftLog,
    eraftpb::{Message, MessageType},
};

use super::{
    command::{DecodedEntry, EntryError},
    metrics::ClusterCounters,
    node::MAX_VOTERS,
    raft_storage::{RaftStorage, RestoredSnapshot},
};

/// A member can reach the next slot before this node's own Status does.
const CLOCK_SLACK_SLOTS: u64 = 1;

/// Why a member's Raft message was refused before reaching raft-rs. raft-rs
/// panics on several malformed shapes, and a bad committed entry fails every
/// node on each replay, so both are stopped here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberMessageError {
    EmptyProposal,
    Entry(EntryError),
    ProposalOrigin {
        origin: u64,
        from: u64,
    },
    ForwardedMinimumSlot,
    /// A forwarded proposal its member could only make with a clock ahead
    /// of ours.
    ProposalAheadOfClock {
        slot: u64,
        wall_slot: u64,
    },
    /// An appended entry its leader could only make with a clock ahead of
    /// ours.
    LeaderAheadOfClock {
        slot: u64,
        wall_slot: u64,
    },
    EntryIndexGap {
        expected: u64,
        actual: u64,
    },
    CommitPastLog {
        commit: u64,
        last_index: u64,
    },
    Snapshot,
}

/// A member that appended an entry ahead of this node's clock. Until this
/// node's clock reaches that entry, its leadership messages go unanswered. It
/// loses its quorum, and its longer log cannot win it the next election.
#[derive(Default)]
pub(super) struct LeaderBoycott(ArrayVec<BoycottedLeader, MAX_VOTERS>);

#[derive(Debug, Clone, Copy)]
struct BoycottedLeader {
    id: u64,
    slot: u64,
}

impl LeaderBoycott {
    pub(super) fn covers(&self, message: &Message, wall_slot: u64) -> bool {
        is_leadership(message.get_msg_type()) &&
            self.0.iter().any(|leader| {
                leader.id == message.from && is_ahead_of_clock(leader.slot, wall_slot)
            })
    }

    pub(super) fn start(&mut self, message: &Message, slot: u64, wall_slot: u64) {
        let (id, term) = (message.from, message.term);
        match self.0.iter_mut().find(|leader| leader.id == id) {
            Some(leader) => leader.slot = leader.slot.max(slot),
            None => {
                let overflow = self.0.try_push(BoycottedLeader { id, slot });
                debug_assert!(overflow.is_none(), "messages come from at most {MAX_VOTERS} voters");
            }
        }
        ClusterCounters::LeadersBoycotted.inc();
        silver_log::warn!(
            leader = id,
            term,
            slot,
            wall_slot,
            "boycotting leader until this node's clock reaches its entry"
        );
    }

    #[cfg(test)]
    pub(super) fn boycotts(&self, id: u64, wall_slot: u64) -> bool {
        self.0.iter().any(|leader| leader.id == id && is_ahead_of_clock(leader.slot, wall_slot))
    }
}

/// Messages through which a member leads, or seeks to lead.
fn is_leadership(msg_type: MessageType) -> bool {
    matches!(
        msg_type,
        MessageType::MsgAppend |
            MessageType::MsgHeartbeat |
            MessageType::MsgSnapshot |
            MessageType::MsgRequestVote |
            MessageType::MsgRequestPreVote
    )
}

fn is_ahead_of_clock(slot: u64, wall_slot: u64) -> bool {
    slot > wall_slot.saturating_add(CLOCK_SLACK_SLOTS)
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
            let decoded = DecodedEntry::decode(entry).map_err(MemberMessageError::Entry)?;
            let origin = match &decoded {
                DecodedEntry::Lock(_, id) | DecodedEntry::BlockLock(_, id) => id.origin_node_id,
                DecodedEntry::AdvanceMinimumSlot(_) => {
                    return Err(MemberMessageError::ForwardedMinimumSlot);
                }
            };
            if origin != message.from {
                return Err(MemberMessageError::ProposalOrigin { origin, from: message.from });
            }
            let slot = decoded.earliest_wall_slot();
            if is_ahead_of_clock(slot, self.wall_slot) {
                return Err(MemberMessageError::ProposalAheadOfClock {
                    slot,
                    wall_slot: self.wall_slot,
                });
            }
        }
        Ok(())
    }

    /// Mirrors the decoding `apply_entries` relies on, and the log shapes
    /// raft-rs treats as fatal in `handle_append_entries`.
    fn check_append(&self, message: &Message) -> Result<(), MemberMessageError> {
        for (offset, entry) in (1..).zip(&message.entries) {
            // raft-rs finds conflicts by each entry's own index, and a conflict
            // at or below the commit index is fatal. It ignores appends whose
            // `index` is below the commit index, so contiguous entries start
            // above it.
            let expected = message.index.saturating_add(offset);
            if entry.index != expected {
                return Err(MemberMessageError::EntryIndexGap { expected, actual: entry.index });
            }
            if entry.data.is_empty() {
                continue;
            }
            let slot = DecodedEntry::decode(entry)
                .map_err(MemberMessageError::Entry)?
                .earliest_wall_slot();
            if is_ahead_of_clock(slot, self.wall_slot) {
                return Err(MemberMessageError::LeaderAheadOfClock {
                    slot,
                    wall_slot: self.wall_slot,
                });
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
