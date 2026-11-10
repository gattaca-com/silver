use flux::utils::ArrayVec;
use raft::{
    RaftLog,
    eraftpb::{Message, MessageType},
};

use super::{
    command::{DecodedEntry, EntryError},
    metrics::ClusterCounters,
    raft_storage::{RaftStorage, RestoredSnapshot},
    voters::MAX_VOTERS,
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
    ForwardedMembershipChange,
    ProposalOrigin { origin: u64, from: u64 },
    ForwardedMinimumSlot,
    ProposalAheadOfClock { slot: u64, wall_slot: u64 },
    LeaderAheadOfClock { slot: u64, wall_slot: u64 },
    EntryIndexGap { expected: u64, actual: u64 },
    CommitPastLog { commit: u64, last_index: u64 },
    Snapshot,
}

/// A member that appended an entry ahead of this node's clock. Until this
/// node's clock reaches that entry, its leadership messages go unanswered. It
/// loses its quorum, and its longer log cannot win it the next election.
///
/// A joint config replacing one of 7 voters has 8 distinct voters.
#[derive(Default)]
pub(super) struct LeaderBoycott(ArrayVec<BoycottedLeader, { MAX_VOTERS + 1 }>);

#[derive(Debug, Clone, Copy)]
struct BoycottedLeader {
    id: u64,
    slot: u64,
}

impl LeaderBoycott {
    pub(super) fn retain(&mut self, is_member: impl Fn(u64) -> bool) {
        let leaders = self.0.as_mut_slice();
        let mut kept = 0;
        for i in 0..leaders.len() {
            if is_member(leaders[i].id) {
                leaders.swap(kept, i);
                kept += 1;
            }
        }
        self.0.truncate(kept);
    }

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
                debug_assert!(
                    overflow.is_none(),
                    "leaders are among at most {} voters",
                    MAX_VOTERS + 1
                );
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

pub(super) struct MemberMessageCheck<'a> {
    pub log: &'a RaftLog<RaftStorage>,
    pub wall_slot: u64,
}

impl MemberMessageCheck<'_> {
    pub(super) fn check(&self, message: &Message) -> Result<(), MemberMessageError> {
        match message.get_msg_type() {
            MessageType::MsgPropose => self.check_proposal(message),
            MessageType::MsgAppend => self.check_append(message),
            MessageType::MsgHeartbeat => self.check_heartbeat_commit(message.commit),
            MessageType::MsgSnapshot => self.check_snapshot(message),
            _ => Ok(()),
        }
    }

    /// raft-rs ignores a snapshot below its commit index, so only a newer one
    /// is decoded.
    fn check_snapshot(&self, message: &Message) -> Result<(), MemberMessageError> {
        let snapshot = message.get_snapshot();
        if snapshot.get_metadata().index < self.log.committed {
            return Ok(());
        }
        RestoredSnapshot::check(snapshot).map_err(|_| MemberMessageError::Snapshot)
    }

    /// Only followers forward proposals, each carrying its own context. The
    /// leader proposes the minimum slot and membership changes itself, and
    /// never forwards them.
    fn check_proposal(&self, message: &Message) -> Result<(), MemberMessageError> {
        if message.entries.is_empty() {
            return Err(MemberMessageError::EmptyProposal);
        }
        for entry in &message.entries {
            let decoded = DecodedEntry::decode(entry).map_err(MemberMessageError::Entry)?;
            let origin = match &decoded {
                DecodedEntry::Lock(_, id) |
                DecodedEntry::BlockLock(_, id) |
                DecodedEntry::AnnounceAddress { proposal_id: id, .. } => id.origin_node_id,
                DecodedEntry::Empty => return Err(MemberMessageError::EmptyProposal),
                DecodedEntry::AdvanceMinimumSlot(_) => {
                    return Err(MemberMessageError::ForwardedMinimumSlot);
                }
                DecodedEntry::MembershipChange { .. } => {
                    return Err(MemberMessageError::ForwardedMembershipChange);
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
