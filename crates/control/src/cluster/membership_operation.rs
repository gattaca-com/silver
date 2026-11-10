use std::{error::Error, fmt};

use raft::{
    ProgressState, RawNode,
    eraftpb::{ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2},
};

use super::{
    membership::{ClusterMembership, Member, MemberAddress, MemberRecords},
    raft_storage::RaftStorage,
    voters::MAX_VOTERS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperation {
    /// Joins as a learner, which receives the log but does not vote.
    Add {
        node_id: u64,
        address: MemberAddress,
    },
    Promote {
        node_id: u64,
    },
    /// Swaps one voter for a caught-up learner through a joint config, so a
    /// majority of the old voters keeps committing throughout.
    Replace {
        old: u64,
        new: u64,
    },
    Remove {
        node_id: u64,
    },
    TransferLeader {
        node_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipError {
    NotReady,
    Removed,
    NotLeader {
        leader_id: Option<u64>,
    },
    ChangePending,
    /// A new member starts from a snapshot, and the locks no longer fit one.
    SnapshotTooLarge,
    IdReused {
        highest_node_id: u64,
    },
    KeyInUse {
        node_id: u64,
    },
    NotAMember(u64),
    NotALearner(u64),
    NotAVoter(u64),
    NotCaughtUp(u64),
    TooManyVoters,
    LeaderTargeted,
    ProposalDropped,
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => f.write_str("Raft storage recovery is not complete"),
            Self::Removed => f.write_str("this node was removed from the cluster"),
            Self::NotLeader { leader_id: Some(id) } => write!(f, "not the leader; node {id} is"),
            Self::NotLeader { leader_id: None } => f.write_str("not the leader; none is known"),
            Self::ChangePending => f.write_str("another membership change is still in progress"),
            Self::SnapshotTooLarge => {
                f.write_str("the locks are too large for the snapshot a new member starts from")
            }
            Self::IdReused { highest_node_id } => {
                write!(f, "node ids are never reused; use one above {highest_node_id}")
            }
            Self::KeyInUse { node_id } => write!(f, "node {node_id} already uses this key"),
            Self::NotAMember(id) => write!(f, "node {id} is not a member"),
            Self::NotALearner(id) => write!(f, "node {id} is not a learner"),
            Self::NotAVoter(id) => write!(f, "node {id} is not a voter"),
            Self::NotCaughtUp(id) => write!(f, "node {id} has not caught up with the log"),
            Self::TooManyVoters => write!(f, "a cluster has at most {MAX_VOTERS} voters"),
            Self::LeaderTargeted => {
                f.write_str("the leader cannot remove itself; transfer leadership first")
            }
            Self::ProposalDropped => f.write_str("Raft dropped the proposal; retry"),
        }
    }
}

impl Error for MembershipError {}

/// A membership change the leader may propose.
pub(super) enum Proposal {
    Change { change: ConfChangeV2, context: Vec<u8> },
    TransferLeader(u64),
}

/// This node's view of the membership: Raft's roles and progress, and the
/// replicated address book.
pub(super) struct MembershipView<'a> {
    pub node: &'a RawNode<RaftStorage>,
    pub membership: &'a ClusterMembership,
    pub local_id: u64,
}

impl MembershipView<'_> {
    fn is_voter(&self, node_id: u64) -> bool {
        self.node.raft.prs().conf().voters().contains(node_id)
    }

    fn is_learner(&self, node_id: u64) -> bool {
        self.node.raft.prs().conf().learners().contains(&node_id)
    }

    fn voter_count(&self) -> usize {
        self.node.raft.prs().conf().voters().ids().len()
    }

    /// The leader's view only, so this decides liveness, never safety.
    fn is_caught_up(&self, node_id: u64) -> bool {
        self.node.raft.prs().get(node_id).is_some_and(|progress| {
            progress.state == ProgressState::Replicate &&
                progress.recent_active &&
                progress.matched >= self.node.raft.raft_log.committed
        })
    }

    pub(super) fn propose(
        &self,
        operation: MembershipOperation,
    ) -> Result<Proposal, MembershipError> {
        if self.node.raft.has_pending_conf() || self.membership.is_joint() {
            return Err(MembershipError::ChangePending);
        }
        let caught_up_learner = |node_id| {
            if !self.is_learner(node_id) {
                Err(MembershipError::NotALearner(node_id))
            } else if !self.is_caught_up(node_id) {
                Err(MembershipError::NotCaughtUp(node_id))
            } else {
                Ok(())
            }
        };
        let (transition, changes): (_, &[_]) = match operation {
            MembershipOperation::Add { node_id, address } => {
                let highest_node_id = self.membership.highest_node_id();
                if node_id <= highest_node_id {
                    return Err(MembershipError::IdReused { highest_node_id });
                }
                if let Some(member) = self
                    .membership
                    .members()
                    .find(|member| member.address.public_key == address.public_key)
                {
                    return Err(MembershipError::KeyInUse { node_id: member.node_id });
                }
                let change = membership_change(ConfChangeTransition::Auto, &[(
                    ConfChangeType::AddLearnerNode,
                    node_id,
                )]);
                let context = Member { node_id, address }.change_context();
                return Ok(Proposal::Change { change, context });
            }
            MembershipOperation::Promote { node_id } => {
                caught_up_learner(node_id)?;
                if self.voter_count() >= MAX_VOTERS {
                    return Err(MembershipError::TooManyVoters);
                }
                (ConfChangeTransition::Auto, &[(ConfChangeType::AddNode, node_id)])
            }
            MembershipOperation::Replace { old, new } => {
                if !self.is_voter(old) {
                    return Err(MembershipError::NotAVoter(old));
                }
                if old == self.local_id {
                    return Err(MembershipError::LeaderTargeted);
                }
                caught_up_learner(new)?;
                (ConfChangeTransition::Implicit, &[
                    (ConfChangeType::AddNode, new),
                    (ConfChangeType::RemoveNode, old),
                ])
            }
            MembershipOperation::Remove { node_id } => {
                if !self.is_voter(node_id) && !self.is_learner(node_id) {
                    return Err(MembershipError::NotAMember(node_id));
                }
                if node_id == self.local_id {
                    return Err(MembershipError::LeaderTargeted);
                }
                (ConfChangeTransition::Auto, &[(ConfChangeType::RemoveNode, node_id)])
            }
            MembershipOperation::TransferLeader { node_id } => {
                if !self.is_voter(node_id) || node_id == self.local_id {
                    return Err(MembershipError::NotAVoter(node_id));
                }
                return Ok(Proposal::TransferLeader(node_id));
            }
        };
        Ok(Proposal::Change { change: membership_change(transition, changes), context: Vec::new() })
    }

    /// The rules every node re-checks when the change applies, from
    /// replicated state alone, so all of them accept or skip it alike.
    pub(super) fn check_applied(
        &self,
        change: &ConfChangeV2,
        added: MemberRecords,
    ) -> Result<(), &'static str> {
        if change.get_changes().is_empty() {
            return Ok(());
        }
        let mut voters = self.voter_count();
        for single in change.get_changes() {
            let node_id = single.node_id;
            match single.get_change_type() {
                ConfChangeType::AddLearnerNode => {
                    if node_id <= self.membership.highest_node_id() {
                        return Err("a learner reuses a node id");
                    }
                    let Some(address) =
                        added.iter().find(|member| member.node_id == node_id).map(|m| m.address)
                    else {
                        return Err("a learner has no address");
                    };
                    if self.membership.members().any(|m| m.address.public_key == address.public_key)
                    {
                        return Err("a learner reuses a member's key");
                    }
                }
                ConfChangeType::AddNode if !self.is_learner(node_id) => {
                    return Err("a new voter was not a learner");
                }
                ConfChangeType::AddNode => voters += 1,
                ConfChangeType::RemoveNode if self.is_voter(node_id) => voters -= 1,
                ConfChangeType::RemoveNode if !self.is_learner(node_id) => {
                    return Err("a removed node is not a member");
                }
                ConfChangeType::RemoveNode => {}
            }
        }
        if voters > MAX_VOTERS {
            return Err("too many voters");
        }
        Ok(())
    }
}

pub(super) fn membership_change(
    transition: ConfChangeTransition,
    changes: &[(ConfChangeType, u64)],
) -> ConfChangeV2 {
    let mut change = ConfChangeV2::default();
    change.set_transition(transition);
    for &(change_type, node_id) in changes {
        let mut single = ConfChangeSingle::default();
        single.set_change_type(change_type);
        single.set_node_id(node_id);
        change.mut_changes().push(single);
    }
    change
}
