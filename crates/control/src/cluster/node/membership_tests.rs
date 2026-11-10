use raft::{
    Storage,
    eraftpb::{ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfState},
};
use silver_common::{SLOTS_PER_EPOCH, ssz_view::SINGLE_ATT_SIZE};

use super::*;
use crate::cluster::AttestationKey;

const WALL_SLOT: u64 = 10;

fn config(id: u64, storage: ClusterStorageConfig) -> SlashingProtectionConfig {
    let mut config = SlashingProtectionConfig::new(id, [1, 2, 3], storage).unwrap();
    config.tick_interval = Duration::from_millis(1);
    config.heartbeat_ticks = 1;
    config.election_ticks = 5;
    config
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

fn membership_change(
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

/// raft-rs keeps voters in hash sets, so order is not meaningful.
fn sorted(mut membership: ConfState) -> ConfState {
    membership.voters.sort_unstable();
    membership.voters_outgoing.sort_unstable();
    membership.learners.sort_unstable();
    membership.learners_next.sort_unstable();
    membership
}

/// Checks that storage, which every checkpoint copies, agrees with raft-rs.
fn membership(node: &SlashingProtectionCluster) -> ConfState {
    let raw_node = node.node.as_ref().unwrap();
    let membership = sorted(raw_node.raft.prs().conf().to_conf_state());
    assert_eq!(sorted(raw_node.store().initial_state().unwrap().conf_state), membership);
    membership
}

fn has_voters(node: &SlashingProtectionCluster, voters: &[u64]) -> bool {
    let membership = membership(node);
    membership.voters == voters && membership.voters_outgoing.is_empty()
}

struct Cluster {
    nodes: Vec<SlashingProtectionCluster>,
    now: Instant,
    decisions: Vec<AttestationDecision>,
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
        let mut cluster = Self { nodes, now, decisions: Vec::new() };
        cluster
            .rounds_until(|cluster| cluster.nodes.iter().all(SlashingProtectionCluster::is_ready));
        for node in &mut cluster.nodes {
            node.set_startup_wall_slot(WALL_SLOT - 1);
        }
        cluster
    }

    fn node(&mut self, id: u64) -> &mut SlashingProtectionCluster {
        self.nodes.iter_mut().find(|node| node.node_id() == id).unwrap()
    }

    /// Messages to a node that is absent or still recovering are lost. The
    /// clock waits for disk writes, so real fsync time cannot fire elections.
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
        let leader = self.elect();
        self.node(leader).node.as_mut().unwrap().propose_conf_change(Vec::new(), change).unwrap();
    }

    /// Removes a follower through a joint config, and returns the remaining
    /// voters.
    #[track_caller]
    fn remove_follower(&mut self) -> Vec<u64> {
        let removed = self.follower();
        self.propose_membership_change(membership_change(ConfChangeTransition::Implicit, &[(
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
    cluster.propose_membership_change(membership_change(ConfChangeTransition::Auto, &[(
        ConfChangeType::AddLearnerNode,
        4,
    )]));
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
    cluster.remove_follower();

    let follower = cluster.follower();
    cluster.commit_attestation(follower, 1);
    assert!(cluster.nodes.iter().all(|node| node.state.len() == 1));
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
        let remaining = cluster.remove_follower();
        for attester_index in 0..6 {
            let follower = cluster.follower();
            cluster.commit_attestation(follower, attester_index);
        }
        let now = cluster.now;
        drop(cluster);

        let mut cluster = start(&remaining, &|id| ClusterStorageConfig::Open(journal(id)), now);
        for node in &cluster.nodes {
            assert!(has_voters(node, &remaining), "snapshot interval {snapshot_interval}");
            assert_eq!(node.state.len(), 6);
            let snapshot_index = node.node.as_ref().unwrap().store().snapshot_index();
            assert_eq!(snapshot_index > 0, snapshot_interval == 4, "{snapshot_index}");
        }
        let follower = cluster.follower();
        cluster.commit_attestation(follower, 6);
    }
}
