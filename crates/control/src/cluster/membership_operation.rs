use std::{error::Error, fmt};

use raft::eraftpb::{ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2};

use super::{
    membership::{Member, MemberAddress},
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
}

impl MembershipOperation {
    pub(super) fn change(self) -> (ConfChangeV2, Option<Member>) {
        use ConfChangeTransition::{Auto, Implicit};
        use ConfChangeType::{AddLearnerNode, AddNode, RemoveNode};
        match self {
            Self::Add { node_id, address } => (
                membership_change(Auto, &[(AddLearnerNode, node_id)]),
                Some(Member { node_id, address }),
            ),
            Self::Promote { node_id } => (membership_change(Auto, &[(AddNode, node_id)]), None),
            Self::Replace { old, new } => {
                (membership_change(Implicit, &[(AddNode, new), (RemoveNode, old)]), None)
            }
            Self::Remove { node_id } => (membership_change(Auto, &[(RemoveNode, node_id)]), None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipError {
    Failed,
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
    NoAddress(u64),
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
            Self::Failed => f.write_str("Raft processing has stopped after a failure"),
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
            Self::NoAddress(id) => write!(f, "node {id} is added without its address"),
            Self::NotAMember(id) => write!(f, "node {id} is not a member"),
            Self::NotALearner(id) => write!(f, "node {id} is not a learner"),
            Self::NotAVoter(id) => write!(f, "node {id} is not another voter"),
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
