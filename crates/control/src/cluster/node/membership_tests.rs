use raft::{
    Storage,
    eraftpb::{ConfChangeTransition, ConfChangeType, ConfState, EntryType},
};
use silver_common::{SLOTS_PER_EPOCH, ssz_view::SINGLE_ATT_SIZE};

use super::*;
use crate::cluster::{
    AttestationKey, MembershipError, MembershipOperation,
    membership::{Member, MemberAddress},
    membership_operation::membership_change,
    test_address,
};

const WALL_SLOT: u64 = 10;

fn config(id: u64, storage: ClusterStorageConfig) -> SlashingProtectionConfig {
    let mut config =
        SlashingProtectionConfig::new(id, [1, 2, 3], test_address(id), storage).unwrap();
    config.tick_interval = Duration::from_millis(1);
    config.heartbeat_ticks = 1;
    config.election_ticks = 5;
    config
}

/// A node an operator adds to the running cluster: it starts with no
/// membership and waits for the leader's snapshot.
fn joiner(node_id: u64, now: Instant) -> SlashingProtectionCluster {
    let storage = ClusterStorageConfig::Join("unused-test-journal".into());
    let mut config =
        SlashingProtectionConfig::new(node_id, [1, 2, 3, node_id], test_address(node_id), storage)
            .unwrap();
    config.tick_interval = Duration::from_millis(1);
    config.heartbeat_ticks = 1;
    config.election_ticks = 5;
    let mut node = SlashingProtectionCluster::in_memory_with(config, None, now).unwrap();
    node.set_startup_wall_slot(WALL_SLOT - 1);
    node
}

fn command(attester_index: u64) -> AttestationLockCommand {
    let mut ssz = [0; SINGLE_ATT_SIZE];
    ssz[104..112].copy_from_slice(&(WALL_SLOT / SLOTS_PER_EPOCH).to_le_bytes());
    AttestationLockCommand {
        key: AttestationKey { attester_index, slot: WALL_SLOT },
        subnet: 0,
        ssz,
    }
}

/// raft-rs keeps voters in hash sets, so order is not meaningful.
fn sorted(mut membership: ConfState) -> ConfState {
    membership.voters.sort_unstable();
    membership.voters_outgoing.sort_unstable();
    membership.learners.sort_unstable();
    membership.learners_next.sort_unstable();
    membership
}

/// Checks that storage, which every checkpoint copies, agrees with raft-rs.
/// A stepped snapshot reaches storage only with the next `Ready`.
fn membership(node: &SlashingProtectionCluster) -> ConfState {
    let raw_node = node.node.as_ref().unwrap();
    let membership = sorted(raw_node.raft.prs().conf().to_conf_state());
    if !raw_node.has_ready() && !node.persistence.is_pending() {
        assert_eq!(sorted(raw_node.store().initial_state().unwrap().conf_state), membership);
    }
    membership
}

fn has_voters(node: &SlashingProtectionCluster, voters: &[u64]) -> bool {
    let membership = membership(node);
    membership.voters == voters && membership.voters_outgoing.is_empty()
}

fn knows_addresses(node: &SlashingProtectionCluster, ids: &[u64]) -> bool {
    ids.iter().all(|&id| node.membership.address(id) == Some(&test_address(id)))
}

fn is_joint(node: &SlashingProtectionCluster) -> bool {
    !membership(node).voters_outgoing.is_empty()
}

fn carries_joint_leave(message: &Message) -> bool {
    message.entries.iter().any(|entry| {
        entry.get_entry_type() == EntryType::EntryConfChangeV2 && entry.data.is_empty()
    })
}

struct Cluster {
    nodes: Vec<SlashingProtectionCluster>,
    now: Instant,
    decisions: Vec<AttestationDecision>,
    isolated: Option<u64>,
    drop_joint_leaves: bool,
}

impl Cluster {
    fn in_memory(now: Instant) -> Self {
        let nodes = (1..=3)
            .map(|id| {
                let storage = ClusterStorageConfig::Create("unused-test-journal".into());
                SlashingProtectionCluster::in_memory(config(id, storage), now).unwrap()
            })
            .collect();
        Self::started(nodes, now)
    }

    #[track_caller]
    fn started(nodes: Vec<SlashingProtectionCluster>, now: Instant) -> Self {
        let mut cluster =
            Self { nodes, now, decisions: Vec::new(), isolated: None, drop_joint_leaves: false };
        cluster
            .rounds_until(|cluster| cluster.nodes.iter().all(SlashingProtectionCluster::is_ready));
        for node in &mut cluster.nodes {
            node.set_startup_wall_slot(WALL_SLOT - 1);
        }
        cluster
    }

    /// Retries while the target learner catches up or a change is pending.
    #[track_caller]
    fn operate(&mut self, operation: MembershipOperation) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let leader = self.elect();
            match self.node(leader).propose_membership(operation) {
                Ok(()) => return,
                Err(
                    MembershipError::NotCaughtUp(_) |
                    MembershipError::ChangePending |
                    MembershipError::ProposalDropped,
                ) => self.round(),
                Err(error) => panic!("{operation:?} refused: {error}"),
            }
            assert!(Instant::now() < deadline, "{operation:?} never accepted");
        }
    }

    /// Adds `node_id` as a learner and waits until it holds the cluster's
    /// locks.
    #[track_caller]
    fn add_joiner(&mut self, node_id: u64) {
        self.operate(MembershipOperation::Add { node_id, address: test_address(node_id) });
        self.nodes.push(joiner(node_id, self.now));
        let locks = self.nodes[0].state.len();
        self.rounds_until(|cluster| {
            cluster.nodes.iter().all(|node| membership(node).learners == [node_id]) &&
                cluster.nodes.iter().all(|node| node.state.len() == locks)
        });
    }

    fn node(&mut self, id: u64) -> &mut SlashingProtectionCluster {
        self.nodes.iter_mut().find(|node| node.node_id() == id).unwrap()
    }

    /// Messages to a node that is absent, isolated or still recovering are
    /// lost. The clock waits for disk writes, so real fsync time cannot fire
    /// elections.
    fn round(&mut self) {
        let mut messages = Vec::new();
        for node in &mut self.nodes {
            node.spin(self.now, WALL_SLOT, |event| match event {
                ClusterEvent::SendRaftMessage(message) => messages.push(message),
                ClusterEvent::AttestationCommitted(decision) => self.decisions.push(decision),
                ClusterEvent::BlockCommitted(decision) => panic!("unexpected block {decision:?}"),
                ClusterEvent::ProposalTimedOut(id) => panic!("proposal {id:?} timed out"),
            })
            .unwrap();
        }
        for message in messages {
            if self.isolated.is_some_and(|id| message.from == id || message.to == id) ||
                (self.drop_joint_leaves && carries_joint_leave(&message))
            {
                continue;
            }
            if let Some(node) =
                self.nodes.iter_mut().find(|node| node.node_id() == message.to && node.is_ready())
            {
                node.step(message, self.now, WALL_SLOT).unwrap();
            }
        }
        if self.nodes.iter().all(|node| !node.persistence.is_pending()) {
            self.now += Duration::from_millis(1);
        }
    }

    #[track_caller]
    fn rounds_until(&mut self, done: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(self) {
            assert!(Instant::now() < deadline, "cluster did not converge");
            self.round();
        }
    }

    /// Whichever node wins: on disk, one may time out before any campaign.
    /// Returns once every node knows the leader, since a follower drops
    /// proposals until then.
    #[track_caller]
    fn elect(&mut self) -> u64 {
        if self.nodes.iter().all(|node| node.leader_id().is_none()) {
            self.nodes[0].campaign().unwrap();
        }
        self.rounds_until(|cluster| {
            let leader = cluster.nodes.iter().find(|node| node.is_leader());
            leader.is_some_and(|leader| {
                cluster.nodes.iter().all(|node| node.leader_id() == Some(leader.node_id()))
            })
        });
        self.nodes.iter().find(|node| node.is_leader()).unwrap().node_id()
    }

    #[track_caller]
    fn follower(&mut self) -> u64 {
        self.elect();
        self.nodes.iter().find(|node| !node.is_leader()).unwrap().node_id()
    }

    fn propose_membership_change(&mut self, change: ConfChangeV2) {
        self.propose_membership_change_with(change, Vec::new());
    }

    fn propose_membership_change_with(&mut self, change: ConfChangeV2, context: Vec<u8>) {
        let leader = self.elect();
        self.node(leader).node.as_mut().unwrap().propose_conf_change(context, change).unwrap();
    }

    /// Removes a follower through a joint config, and returns the remaining
    /// voters.
    #[track_caller]
    fn remove_follower(&mut self, transition: ConfChangeTransition) -> Vec<u64> {
        let removed = self.follower();
        self.propose_membership_change(membership_change(transition, &[(
            ConfChangeType::RemoveNode,
            removed,
        )]));
        let mut remaining: Vec<_> = self
            .nodes
            .iter()
            .map(SlashingProtectionCluster::node_id)
            .filter(|&id| id != removed)
            .collect();
        remaining.sort_unstable();
        self.rounds_until(|cluster| {
            cluster
                .nodes
                .iter()
                .filter(|node| remaining.contains(&node.node_id()))
                .all(|node| has_voters(node, &remaining))
        });
        self.nodes.retain(|node| node.node_id() != removed);
        remaining
    }

    #[track_caller]
    fn commit_attestation(&mut self, origin: u64, attester_index: u64) {
        let now = self.now;
        let id =
            self.node(origin).propose_attestation(command(attester_index), WALL_SLOT, now).unwrap();
        self.rounds_until(|cluster| {
            cluster.decisions.iter().any(|decision| decision.proposal_id == id)
        });
    }
}

#[test]
fn learner_is_added_on_every_node_and_peers_follow() {
    let mut cluster = Cluster::in_memory(Instant::now());
    let add = membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::AddLearnerNode, 4)]);
    let added = Member { node_id: 4, address: test_address(4) };
    cluster.propose_membership_change_with(add, added.change_context());
    cluster
        .rounds_until(|cluster| cluster.nodes.iter().all(|node| membership(node).learners == [4]));

    let now = cluster.now;
    for node in &cluster.nodes {
        assert_eq!(membership(node).voters, [1, 2, 3]);
        let mut peers: Vec<_> = node.peer_stats(now).map(|peer| peer.node_id).collect();
        peers.sort_unstable();
        let expected: Vec<_> =
            [1, 2, 3, 4].into_iter().filter(|&id| id != node.node_id()).collect();
        assert_eq!(peers, expected);
    }
}

/// The leave is an empty `EntryConfChangeV2`. A node that skipped empty
/// entries would stay joint, and still count the removed node towards every
/// quorum.
#[test]
fn joint_removal_leaves_the_joint_config_on_every_node() {
    let mut cluster = Cluster::in_memory(Instant::now());
    cluster.remove_follower(ConfChangeTransition::Implicit);

    let follower = cluster.follower();
    cluster.commit_attestation(follower, 1);
    assert!(cluster.nodes.iter().all(|node| node.state.len() == 1));
}

/// raft-rs leaves an explicit joint config only on request, so this one is
/// left by the leader's own proposal.
#[test]
fn leader_leaves_an_explicit_joint_config() {
    let mut cluster = Cluster::in_memory(Instant::now());
    cluster.remove_follower(ConfChangeTransition::Explicit);

    let follower = cluster.follower();
    cluster.commit_attestation(follower, 1);
}

/// The old leader's leave entry never reaches the others. Adding a learner
/// leaves both halves `[1, 2, 3]`, so two nodes can elect a new leader.
/// raft-rs leaves on the new leader by itself here; this pins the outcome.
#[test]
fn leader_elected_inside_a_joint_config_leaves_it() {
    let mut cluster = Cluster::in_memory(Instant::now());
    let old_leader = cluster.elect();
    cluster.drop_joint_leaves = true;
    let add =
        membership_change(ConfChangeTransition::Implicit, &[(ConfChangeType::AddLearnerNode, 4)]);
    let added = Member { node_id: 4, address: test_address(4) };
    cluster.propose_membership_change_with(add, added.change_context());
    cluster.rounds_until(|cluster| cluster.nodes.iter().all(is_joint));

    cluster.isolated = Some(old_leader);
    cluster.drop_joint_leaves = false;
    let successor =
        cluster.nodes.iter().find(|node| node.node_id() != old_leader).unwrap().node_id();
    cluster.node(successor).campaign().unwrap();
    cluster.rounds_until(|cluster| {
        cluster
            .nodes
            .iter()
            .filter(|node| node.node_id() != old_leader)
            .all(|node| !is_joint(node) && membership(node).learners == [4])
    });
}

#[test]
fn every_member_announces_its_address() {
    let mut cluster = Cluster::in_memory(Instant::now());
    cluster.elect();
    cluster
        .rounds_until(|cluster| cluster.nodes.iter().all(|node| knows_addresses(node, &[1, 2, 3])));
}

#[test]
fn added_learner_address_replicates_and_leaves_with_it() {
    let mut cluster = Cluster::in_memory(Instant::now());
    let add = membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::AddLearnerNode, 4)]);
    let added = Member { node_id: 4, address: test_address(4) };
    cluster.propose_membership_change_with(add, added.change_context());
    cluster.rounds_until(|cluster| cluster.nodes.iter().all(|node| knows_addresses(node, &[4])));
    assert!(cluster.nodes.iter().all(|node| node.membership.highest_node_id() == 4));

    cluster.propose_membership_change(membership_change(ConfChangeTransition::Auto, &[(
        ConfChangeType::RemoveNode,
        4,
    )]));
    cluster.rounds_until(|cluster| {
        cluster.nodes.iter().all(|node| node.membership.address(4).is_none())
    });
    assert!(cluster.nodes.iter().all(|node| node.membership.highest_node_id() == 4));
}

/// A restart with an edited config looks the same to the others.
#[test]
fn moved_member_announces_its_new_address() {
    let mut cluster = Cluster::in_memory(Instant::now());
    cluster.elect();
    cluster
        .rounds_until(|cluster| cluster.nodes.iter().all(|node| knows_addresses(node, &[1, 2, 3])));

    let follower = cluster.follower();
    let moved = MemberAddress { addr: test_address(9).addr, ..test_address(follower) };
    cluster.node(follower).config.advertised = moved;
    cluster.rounds_until(|cluster| {
        cluster.nodes.iter().all(|node| node.membership.address(follower) == Some(&moved))
    });
}

#[test]
fn announcement_under_another_key_is_refused() {
    let mut cluster = Cluster::in_memory(Instant::now());
    cluster.elect();
    cluster
        .rounds_until(|cluster| cluster.nodes.iter().all(|node| knows_addresses(node, &[1, 2, 3])));

    let follower = cluster.follower();
    cluster.node(follower).config.advertised =
        MemberAddress { public_key: [3; 33], ..test_address(follower) };
    let until = cluster.now + 2 * DEFAULT_PROPOSAL_TIMEOUT;
    cluster.rounds_until(|cluster| cluster.now >= until);

    assert!(cluster.nodes.iter().all(|node| knows_addresses(node, &[1, 2, 3])));
    assert!(cluster.nodes.iter().all(|node| !node.is_failed()));
}

#[test]
fn refused_membership_change_is_skipped_and_the_node_keeps_serving() {
    let now = Instant::now();
    let storage = ClusterStorageConfig::Create("unused-test-journal".into());
    let mut config = config(1, storage);
    config.voters = Voters::new(1, [1]).unwrap();
    let node = SlashingProtectionCluster::in_memory(config, now).unwrap();
    let mut cluster = Cluster::started(vec![node], now);
    cluster.propose_membership_change(membership_change(ConfChangeTransition::Auto, &[(
        ConfChangeType::RemoveNode,
        1,
    )]));
    cluster.commit_attestation(1, 1);

    assert!(!cluster.nodes[0].is_failed());
    assert!(has_voters(&cluster.nodes[0], &[1]));
}

/// The restarted nodes keep the config's voter list `[1, 2, 3]`. Their
/// membership comes from the journal: from replayed membership changes without
/// a snapshot, and from the snapshot's membership with one.
#[cfg(target_os = "linux")]
#[test]
fn membership_survives_a_restart_from_the_log_or_a_snapshot() {
    for snapshot_interval in [4096, 4] {
        let directory = tempfile::tempdir().unwrap();
        let journal = |id: u64| directory.path().join(format!("{id}.wal"));
        let start = |ids: &[u64], storage: &dyn Fn(u64) -> ClusterStorageConfig, now| {
            let nodes = ids
                .iter()
                .map(|&id| {
                    let mut config = config(id, storage(id));
                    config.snapshot_interval = snapshot_interval;
                    SlashingProtectionCluster::new(config, now).unwrap()
                })
                .collect();
            Cluster::started(nodes, now)
        };

        let create = |id| ClusterStorageConfig::Create(journal(id));
        let mut cluster = start(&[1, 2, 3], &create, Instant::now());
        let remaining = cluster.remove_follower(ConfChangeTransition::Implicit);
        for attester_index in 0..6 {
            let follower = cluster.follower();
            cluster.commit_attestation(follower, attester_index);
        }
        cluster.rounds_until(|cluster| {
            cluster.nodes.iter().all(|node| knows_addresses(node, &remaining))
        });
        let now = cluster.now;
        drop(cluster);

        let mut cluster = start(&remaining, &|id| ClusterStorageConfig::Open(journal(id)), now);
        for node in &cluster.nodes {
            assert!(has_voters(node, &remaining), "snapshot interval {snapshot_interval}");
            assert!(knows_addresses(node, &remaining), "before any announcement");
            assert_eq!(node.state.len(), 6);
            let snapshot_index = node.node.as_ref().unwrap().store().snapshot_index();
            assert_eq!(snapshot_index > 0, snapshot_interval == 4, "{snapshot_index}");
        }
        let follower = cluster.follower();
        cluster.commit_attestation(follower, 6);
    }
}

#[test]
fn added_node_catches_up_by_snapshot_and_is_promoted() {
    let now = Instant::now();
    let mut cluster = Cluster::in_memory(now);
    let leader = cluster.elect();
    for attester_index in 0..3 {
        cluster.commit_attestation(leader, attester_index);
    }
    let mut early = joiner(4, now);
    assert!(matches!(
        early.propose_attestation(command(9), WALL_SLOT, now),
        Err(ProposeError::NotMember)
    ));
    assert!(!early.is_removed());

    cluster.add_joiner(4);
    cluster.operate(MembershipOperation::Promote { node_id: 4 });
    cluster
        .rounds_until(|cluster| cluster.nodes.iter().all(|node| has_voters(node, &[1, 2, 3, 4])));
    cluster.commit_attestation(4, 10);
    assert!(cluster.nodes.iter().all(|node| node.state.len() == 4));
}

/// The dead voter never answers again; nodes 1 and 2 form a quorum in both
/// halves of the joint config.
#[test]
fn dead_voter_is_replaced_by_a_caught_up_learner() {
    let mut cluster = Cluster::in_memory(Instant::now());
    let dead = cluster.follower();
    cluster.nodes.retain(|node| node.node_id() != dead);
    let leader = cluster.elect();
    cluster.commit_attestation(leader, 1);

    cluster.add_joiner(4);
    cluster.operate(MembershipOperation::Replace { old: dead, new: 4 });
    let mut voters: Vec<u64> =
        cluster.nodes.iter().map(SlashingProtectionCluster::node_id).collect();
    voters.sort_unstable();
    cluster.rounds_until(|cluster| cluster.nodes.iter().all(|node| has_voters(node, &voters)));
    cluster.commit_attestation(4, 2);
}

#[test]
fn removed_node_refuses_every_duty() {
    let now = Instant::now();
    let mut cluster = Cluster::in_memory(now);
    let removed = cluster.follower();
    cluster.operate(MembershipOperation::Remove { node_id: removed });
    cluster.rounds_until(|cluster| {
        cluster.nodes.iter().any(|node| node.node_id() == removed && node.is_removed())
    });

    let node = cluster.node(removed);
    assert!(!node.is_ready());
    assert!(matches!(
        node.propose_attestation(command(1), WALL_SLOT, now),
        Err(ProposeError::Removed)
    ));
    let operation = MembershipOperation::Promote { node_id: removed };
    assert_eq!(node.propose_membership(operation), Err(MembershipError::Removed));
}

#[test]
fn membership_operations_are_refused_with_a_reason() {
    let mut cluster = Cluster::in_memory(Instant::now());
    let leader = cluster.elect();
    let follower = cluster.follower();
    let refused = [
        (follower, MembershipOperation::Remove { node_id: 3 }, MembershipError::NotLeader {
            leader_id: Some(leader),
        }),
        (
            leader,
            MembershipOperation::Add { node_id: 2, address: test_address(9) },
            MembershipError::IdReused { highest_node_id: 3 },
        ),
        (
            leader,
            MembershipOperation::Promote { node_id: follower },
            MembershipError::NotALearner(follower),
        ),
        (leader, MembershipOperation::Remove { node_id: leader }, MembershipError::LeaderTargeted),
        (
            leader,
            MembershipOperation::Replace { old: leader, new: 9 },
            MembershipError::LeaderTargeted,
        ),
        (leader, MembershipOperation::Remove { node_id: 9 }, MembershipError::NotAMember(9)),
        (leader, MembershipOperation::TransferLeader { node_id: 9 }, MembershipError::NotAVoter(9)),
    ];
    for (node_id, operation, expected) in refused {
        assert_eq!(
            cluster.node(node_id).propose_membership(operation),
            Err(expected),
            "{operation:?}"
        );
    }

    cluster.add_joiner(4);
    let reused_key = MembershipOperation::Add { node_id: 5, address: test_address(4) };
    assert_eq!(
        cluster.node(leader).propose_membership(reused_key),
        Err(MembershipError::KeyInUse { node_id: 4 })
    );
    cluster.node(leader).propose_membership(MembershipOperation::Remove { node_id: 4 }).unwrap();
    assert_eq!(
        cluster.node(leader).propose_membership(MembershipOperation::Remove { node_id: follower }),
        Err(MembershipError::ChangePending)
    );
}

/// Proposed past the leader's checks, so only the checks every node makes
/// on apply stop them.
#[test]
fn invalid_changes_are_skipped_on_every_node() {
    let mut cluster = Cluster::in_memory(Instant::now());
    for change in [
        membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::AddNode, 9)]),
        membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::AddLearnerNode, 2)]),
        membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::AddLearnerNode, 9)]),
        membership_change(ConfChangeTransition::Auto, &[(ConfChangeType::RemoveNode, 9)]),
    ] {
        cluster.propose_membership_change(change);
        let leader = cluster.elect();
        cluster.commit_attestation(leader, 0);
    }
    for node in &cluster.nodes {
        assert!(has_voters(node, &[1, 2, 3]) && membership(node).learners.is_empty());
        assert!(!node.is_failed());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn removed_node_stays_removed_after_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let journal = |id: u64| directory.path().join(format!("{id}.wal"));
    let nodes = (1..=3)
        .map(|id| {
            let config = config(id, ClusterStorageConfig::Create(journal(id)));
            SlashingProtectionCluster::new(config, Instant::now()).unwrap()
        })
        .collect();
    let mut cluster = Cluster::started(nodes, Instant::now());
    let removed = cluster.follower();
    cluster.operate(MembershipOperation::Remove { node_id: removed });
    cluster.rounds_until(|cluster| {
        cluster.nodes.iter().any(|node| node.node_id() == removed && node.is_removed())
    });
    let now = cluster.now;
    drop(cluster);

    let config = config(removed, ClusterStorageConfig::Open(journal(removed)));
    let mut node = SlashingProtectionCluster::new(config, now).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while node.node.is_none() {
        assert!(Instant::now() < deadline, "recovery did not finish");
        node.spin(now, WALL_SLOT, |_| {}).unwrap();
    }
    assert!(node.is_removed());
    assert!(matches!(
        node.propose_attestation(command(1), WALL_SLOT, now),
        Err(ProposeError::Removed)
    ));
}

/// Entries from the start of the log would leave the joiner without the
/// initial voters, so it waits for a snapshot instead.
#[test]
fn joiner_takes_no_entries_before_its_snapshot() {
    let now = Instant::now();
    let mut node = joiner(4, now);
    let append = Message {
        msg_type: MessageType::MsgAppend,
        from: 1,
        to: 4,
        term: 1,
        entries: vec![Entry { term: 1, index: 1, ..Entry::default() }].into(),
        ..Message::default()
    };
    node.step(append, now, WALL_SLOT).unwrap();
    node.spin(now, WALL_SLOT, |_| {}).unwrap();
    assert_eq!(raft::Storage::last_index(node.node.as_ref().unwrap().store()).unwrap(), 0);
}
