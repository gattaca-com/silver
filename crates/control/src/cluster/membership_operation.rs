use raft::eraftpb::{ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2};
use silver_common::MembershipOperation;

use super::membership::Member;

pub(super) fn conf_change(operation: MembershipOperation) -> (ConfChangeV2, Option<Member>) {
    use ConfChangeTransition::{Auto, Implicit};
    use ConfChangeType::{AddLearnerNode, AddNode, RemoveNode};
    match operation {
        MembershipOperation::Add { node_id, address } => (
            membership_change(Auto, &[(AddLearnerNode, node_id)]),
            Some(Member { node_id, address }),
        ),
        MembershipOperation::Promote { node_id } => {
            (membership_change(Auto, &[(AddNode, node_id)]), None)
        }
        MembershipOperation::Replace { old, new } => {
            (membership_change(Implicit, &[(AddNode, new), (RemoveNode, old)]), None)
        }
        MembershipOperation::Remove { node_id } => {
            (membership_change(Auto, &[(RemoveNode, node_id)]), None)
        }
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
