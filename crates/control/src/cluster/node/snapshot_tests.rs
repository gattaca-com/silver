use raft::{
    Storage,
    eraftpb::{HardState, MessageType, Snapshot},
};
use silver_common::ssz_view::SINGLE_ATT_SIZE;

use super::*;
use crate::cluster::AttestationKey;

fn config(id: u64) -> AttestationClusterConfig {
    let mut config = AttestationClusterConfig::new(
        id,
        vec![1, 2, 3],
        ClusterStorageConfig::Create("unused-test-journal".into()),
    );
    config.snapshot_interval = 4;
    config
}

fn command(validator: u64, root: u8) -> AttestationLockCommand {
    AttestationLockCommand {
        key: AttestationKey { attester_index: validator, slot: 100 },
        subnet: 0,
        ssz: [root; SINGLE_ATT_SIZE],
    }
}

fn snapshot(index: u64) -> Snapshot {
    let mut state = AttestationLockStore::default();
    state.advance_minimum_slot(68);
    state.apply(&command(7, 1));
    let mut snapshot =
        Snapshot { data: state.encode_snapshot().unwrap().into(), ..Snapshot::default() };
    let metadata = snapshot.mut_metadata();
    metadata.index = index;
    metadata.term = 2;
    metadata.mut_conf_state().voters = vec![1, 2, 3];
    snapshot
}

fn snapshot_message(snapshot: Snapshot) -> Message {
    let mut message = Message {
        from: 2,
        to: 1,
        term: 2,
        msg_type: MessageType::MsgSnapshot,
        ..Message::default()
    };
    message.set_snapshot(snapshot);
    message
}

fn quiet(node: &AttestationCluster) -> bool {
    node.is_ready() && !node.persistence.is_pending() && !node.node.as_ref().unwrap().has_ready()
}

#[test]
fn snapshot_installation_and_acknowledgement_wait_for_durability() {
    let now = Instant::now();
    let mut node = AttestationCluster::in_memory(config(1), now).unwrap();
    node.set_startup_wall_slot(99);
    node.persistence.paused = true;
    node.step(snapshot_message(snapshot(10))).unwrap();
    node.spin(now, 100, |_| panic!("snapshot acknowledged before sync")).unwrap();
    assert_eq!(node.state.len(), 0);
    assert_eq!(node.node.as_ref().unwrap().raft.raft_log.applied, 0);
    node.persistence.paused = false;
    let mut messages = Vec::new();
    node.spin(now, 100, |event| messages.push(event)).unwrap();
    assert!(messages.iter().any(|event| matches!(event, ClusterEvent::SendRaftMessage(message)
        if message.msg_type == MessageType::MsgAppendResponse && message.index == 10)));
    assert_eq!(node.node.as_ref().unwrap().raft.raft_log.applied, 10);
    assert_eq!(node.state.minimum_slot(), 68);
    assert_eq!(node.state.apply(&command(7, 2)), LockResult::ConflictingAttestation);
    assert!(
        node.admission.validate(99, 100).is_err(),
        "snapshot must not replace startup admission"
    );
}

#[test]
fn invalid_snapshot_payload_or_membership_stops_participation() {
    for bad_membership in [false, true] {
        let now = Instant::now();
        let mut node = AttestationCluster::in_memory(config(1), now).unwrap();
        let mut snapshot = snapshot(10);
        if bad_membership {
            snapshot.mut_metadata().mut_conf_state().voters = vec![1, 4];
        } else {
            snapshot.data = vec![0; 20].into();
        }
        node.step(snapshot_message(snapshot)).unwrap();
        assert!(matches!(
            node.spin(now, 100, |_| panic!("released invalid snapshot")),
            Err(ClusterError::Snapshot(_))
        ));
        assert!(node.is_failed());
    }
}

#[test]
fn storage_serves_captured_state_not_a_snapshot_at_an_unapplied_commit() {
    let mut storage = RaftStorage::new(vec![1, 2, 3]);
    storage.install_snapshot(snapshot(10)).unwrap();
    storage.memory.wl().append(&[Entry { index: 11, term: 2, ..Entry::default() }]).unwrap();
    storage.memory.wl().set_hardstate(HardState { term: 2, commit: 11, ..HardState::default() });
    assert_eq!(storage.snapshot(0, 3).unwrap(), snapshot(10));
    assert!(storage.snapshot(11, 3).is_err());
    assert_eq!(storage.term(10).unwrap(), 2);
    assert_eq!(storage.first_index().unwrap(), 11);
    assert_eq!(storage.last_index().unwrap(), 11);
}

struct Network {
    nodes: Vec<AttestationCluster>,
    now: Instant,
    isolated: Option<u64>,
    drop_snapshot: bool,
    drop_snapshot_ack: bool,
    snapshots: usize,
    decisions: Vec<AttestationDecision>,
}

impl Network {
    fn new(nodes: Vec<AttestationCluster>, now: Instant) -> Self {
        Self {
            nodes,
            now,
            isolated: None,
            drop_snapshot: false,
            drop_snapshot_ack: false,
            snapshots: 0,
            decisions: Vec::new(),
        }
    }

    fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut messages = Vec::new();
            for node in &mut self.nodes {
                node.spin(self.now, 100, |event| match event {
                    ClusterEvent::SendRaftMessage(message) => messages.push(message),
                    ClusterEvent::AttestationCommitted(decision) => self.decisions.push(decision),
                    ClusterEvent::AttestationProposalTimedOut(_) => panic!("proposal timed out"),
                })
                .unwrap();
            }
            for message in messages {
                if self.isolated.is_some_and(|id| message.from == id || message.to == id) {
                    continue;
                }
                if message.msg_type == MessageType::MsgSnapshot {
                    self.snapshots += 1;
                    if self.drop_snapshot {
                        self.drop_snapshot = false;
                        continue;
                    }
                }
                if self.drop_snapshot_ack &&
                    self.snapshots != 0 &&
                    message.from == 3 &&
                    message.msg_type == MessageType::MsgAppendResponse
                {
                    self.drop_snapshot_ack = false;
                    continue;
                }
                self.nodes
                    .iter_mut()
                    .find(|node| node.node_id() == message.to)
                    .unwrap()
                    .step(message)
                    .unwrap();
            }
            if self.nodes.iter().all(quiet) {
                return;
            }
            assert!(Instant::now() < deadline, "Raft cluster did not become idle");
            std::thread::yield_now();
        }
    }

    fn populate_with_one_follower_offline(&mut self) {
        self.settle();
        for node in &mut self.nodes {
            node.set_startup_wall_slot(99);
        }
        self.isolated = Some(3);
        self.nodes[0].campaign().unwrap();
        self.settle();
        assert!(self.nodes[0].is_leader());
        for validator in 0..24 {
            self.nodes[0].propose_attestation(command(validator, 1), 100, self.now).unwrap();
            self.settle();
        }
        assert_eq!(self.decisions.len(), 24);
        assert!(self.decisions.iter().all(AttestationDecision::may_validate));
        assert!(self.nodes[0].node.as_ref().unwrap().store().first_index().unwrap() > 1);
        assert_eq!(self.nodes[2].state.len(), 0);
    }

    fn reconnect(&mut self) {
        self.isolated = None;
        for _ in 0..70 {
            self.now += Duration::from_millis(100);
            self.settle();
            if self.nodes[2].state.len() == 24 {
                return;
            }
        }
        panic!("lagging follower did not install snapshot");
    }
}

#[test]
fn a_lost_snapshot_is_retried_and_a_lagging_follower_catches_up() {
    let now = Instant::now();
    let nodes = (1..=3).map(|id| AttestationCluster::in_memory(config(id), now).unwrap()).collect();
    let mut network = Network::new(nodes, now);
    network.populate_with_one_follower_offline();
    network.drop_snapshot = true;
    network.reconnect();
    assert!(network.snapshots >= 2);
    for node in &mut network.nodes {
        assert_eq!(node.state.apply(&command(7, 2)), LockResult::ConflictingAttestation);
    }
    let request = network.nodes[2].propose_attestation(command(50, 1), 100, network.now).unwrap();
    network.settle();
    assert!(
        network
            .decisions
            .iter()
            .any(|decision| decision.proposal_id == request && decision.may_validate())
    );
}

#[test]
fn a_lost_snapshot_ack_does_not_stall_replication() {
    let now = Instant::now();
    let nodes = (1..=3).map(|id| AttestationCluster::in_memory(config(id), now).unwrap()).collect();
    let mut network = Network::new(nodes, now);
    network.populate_with_one_follower_offline();
    network.drop_snapshot_ack = true;
    network.reconnect();
    assert!(!network.drop_snapshot_ack);
    for _ in 0..60 {
        network.now += Duration::from_millis(100);
        network.settle();
    }
    assert!(network.snapshots >= 2);
    network.nodes[0].propose_attestation(command(50, 1), 100, network.now).unwrap();
    network.settle();
    assert_eq!(network.nodes[2].state.len(), 25);
}

#[test]
fn compacting_again_at_the_same_applied_index_preserves_the_suffix() {
    let mut storage = RaftStorage::new(vec![1, 2, 3]);
    storage.install_snapshot(snapshot(10)).unwrap();
    let entry = Entry { index: 11, term: 2, ..Entry::default() };
    storage.memory.wl().append(&[entry.clone()]).unwrap();
    storage.compact(snapshot(10)).unwrap();
    assert_eq!(storage.suffix(10).unwrap(), [entry]);
    assert_eq!(storage.snapshot(0, 3).unwrap(), snapshot(10));
}

#[cfg(target_os = "linux")]
#[test]
fn durable_snapshot_catch_up_survives_a_full_cluster_restart() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let nodes = (1..=3)
        .map(|id| {
            let mut config = config(id);
            config.storage =
                ClusterStorageConfig::Create(directory.path().join(format!("{id}.wal")));
            AttestationCluster::new(config, now).unwrap()
        })
        .collect();
    let mut network = Network::new(nodes, now);
    network.populate_with_one_follower_offline();
    network.reconnect();
    assert!(network.snapshots > 0);
    drop(network);
    let nodes = (1..=3)
        .map(|id| {
            let mut config = config(id);
            config.storage = ClusterStorageConfig::Open(directory.path().join(format!("{id}.wal")));
            AttestationCluster::new(config, now).unwrap()
        })
        .collect();
    let mut network = Network::new(nodes, now);
    network.settle();
    assert!(network.decisions.is_empty());
    for node in &mut network.nodes {
        assert_eq!(node.state.len(), 24);
        assert_eq!(node.state.minimum_slot(), 68);
        assert_eq!(node.state.apply(&command(7, 2)), LockResult::ConflictingAttestation);
        assert!(node.node.as_ref().unwrap().store().snapshot_index() > 0);
    }
}
