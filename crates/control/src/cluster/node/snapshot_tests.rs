use bytes::BytesMut;
use raft::{
    Storage,
    eraftpb::{ConfState, HardState, MessageType, Snapshot},
};
use silver_common::{SLOTS_PER_EPOCH, ssz_view::SINGLE_ATT_SIZE};

use super::*;
use crate::cluster::{AttestationKey, raft_storage::validate_snapshot, test_address};

fn config(id: u64) -> SlashingProtectionConfig {
    let mut config = SlashingProtectionConfig::new(
        id,
        [1, 2, 3],
        test_address(id),
        ClusterStorageConfig::Create("unused-test-journal".into()),
    )
    .unwrap();
    config.snapshot_interval = 4;
    config
}

fn command(validator: u64, root: u8) -> AttestationLockCommand {
    let slot = 100;
    let mut ssz = [root; SINGLE_ATT_SIZE];
    ssz[64..72].fill(0);
    ssz[104..112].copy_from_slice(&(slot / SLOTS_PER_EPOCH).to_le_bytes());
    AttestationLockCommand {
        key: AttestationKey { attester_index: validator, slot },
        subnet: 0,
        ssz,
    }
}

fn snapshot(index: u64) -> Snapshot {
    let mut state = SlashingLockStore::default();
    state.advance_minimum_slot(68);
    state.apply(&command(7, 1));
    let members = ConfState { voters: vec![1, 2, 3], ..ConfState::default() };
    let mut data = BytesMut::new();
    ClusterMembership::new(member_ids(&members)).encode_snapshot(&mut data);
    state.encode_snapshot(&mut data).unwrap();
    let mut snapshot = Snapshot { data: data.freeze(), ..Snapshot::default() };
    let metadata = snapshot.mut_metadata();
    metadata.index = index;
    metadata.term = 2;
    metadata.set_conf_state(members);
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

fn quiet(node: &SlashingProtectionCluster) -> bool {
    node.is_ready() && !node.persistence.is_pending() && !node.node.as_ref().unwrap().has_ready()
}

#[test]
fn snapshot_installation_and_acknowledgement_wait_for_durability() {
    let now = Instant::now();
    let mut node = SlashingProtectionCluster::in_memory(config(1), now).unwrap();
    node.set_startup_wall_slot(99);
    node.persistence.paused = true;
    node.step(snapshot_message(snapshot(10)), now, 100).unwrap();
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
    assert_eq!(node.state.apply(&command(7, 2)), LockResult::Conflicting);
    assert!(
        node.admission.validate(99, 100).is_err(),
        "snapshot must not replace startup admission"
    );
}

#[test]
fn snapshot_below_the_commit_index_is_not_decoded() {
    let now = Instant::now();
    let mut node = SlashingProtectionCluster::in_memory(config(1), now).unwrap();
    node.set_startup_wall_slot(99);
    node.step(snapshot_message(snapshot(10)), now, 100).unwrap();
    node.spin(now, 100, |_| {}).unwrap();

    let mut stale = snapshot(9);
    stale.data = vec![0; 20].into();
    node.step(snapshot_message(stale), now, 100).unwrap();
    node.spin(now, 100, |_| {}).unwrap();
    assert!(!node.is_failed());
    assert_eq!(node.state.len(), 1);
}

/// raft-rs panics on a follower when an append claims a committed index with
/// another term, or a heartbeat commits past its log.
#[test]
fn forged_append_and_heartbeat_are_refused_on_a_follower() {
    let now = Instant::now();
    let mut node = SlashingProtectionCluster::in_memory(config(1), now).unwrap();
    node.set_startup_wall_slot(99);
    node.step(snapshot_message(snapshot(10)), now, 100).unwrap();
    node.spin(now, 100, |_| {}).unwrap();
    assert_eq!(node.node.as_ref().unwrap().raft.raft_log.committed, 10);

    let leader = |msg_type| Message { msg_type, from: 2, to: 1, term: 2, ..Message::default() };
    let append = Message {
        index: 10,
        log_term: 2,
        entries: vec![Entry { index: 5, term: 9, ..Entry::default() }].into(),
        ..leader(MessageType::MsgAppend)
    };
    assert!(matches!(
        node.step(append, now, 100),
        Err(ClusterError::MemberMessage(MemberMessageError::EntryIndexGap {
            expected: 11,
            actual: 5
        }))
    ));
    let heartbeat = Message { commit: 1_000, ..leader(MessageType::MsgHeartbeat) };
    assert!(matches!(
        node.step(heartbeat, now, 100),
        Err(ClusterError::MemberMessage(MemberMessageError::CommitPastLog {
            commit: 1_000,
            last_index: 10
        }))
    ));
    node.spin(now, 100, |_| {}).unwrap();
    assert!(!node.is_failed());
}

/// A member's bad snapshot is refused before raft-rs restores it, so the node
/// keeps participating instead of failing on apply.
#[test]
fn invalid_snapshot_payload_or_membership_is_refused() {
    for bad_membership in [false, true] {
        let now = Instant::now();
        let mut node = SlashingProtectionCluster::in_memory(config(1), now).unwrap();
        let mut snapshot = snapshot(10);
        if bad_membership {
            snapshot.mut_metadata().mut_conf_state().learners = vec![1];
        } else {
            snapshot.data = vec![0; 20].into();
        }
        assert!(matches!(
            node.step(snapshot_message(snapshot), now, 100),
            Err(ClusterError::MemberMessage(MemberMessageError::Snapshot))
        ));
        node.spin(now, 100, |_| panic!("released invalid snapshot")).unwrap();
        assert!(!node.is_failed());
    }
}

#[test]
fn snapshot_membership_is_checked_for_shape_alone() {
    let with_membership = |edit: fn(&mut ConfState)| {
        let mut snapshot = snapshot(10);
        edit(snapshot.mut_metadata().mut_conf_state());
        validate_snapshot(&snapshot).is_ok()
    };
    assert!(with_membership(|membership| membership.voters = vec![4, 5, 6]));
    assert!(with_membership(|membership| membership.learners = vec![4]));
    assert!(with_membership(|membership| {
        membership.voters_outgoing = vec![1, 2, 4];
        membership.learners_next = vec![4];
        membership.auto_leave = true;
    }));

    assert!(!with_membership(|membership| membership.voters.clear()));
    assert!(!with_membership(|membership| membership.voters = vec![1, 1, 2]));
    assert!(!with_membership(|membership| membership.voters = vec![0, 1, 2]));
    assert!(!with_membership(|membership| membership.voters = (1..=8).collect()));
    assert!(!with_membership(|membership| membership.learners = vec![2]));
    assert!(!with_membership(|membership| membership.learners_next = vec![4]));
    assert!(!with_membership(|membership| membership.auto_leave = true));
}

#[test]
fn snapshot_buffers_reclaim_an_allocation_once_its_snapshot_is_dropped() {
    let mut buffers = SnapshotBuffers::default();
    let mut write = |byte| {
        buffers
            .write(1024, |data| {
                data.extend_from_slice(&[byte; 1024]);
                Ok(())
            })
            .unwrap()
    };
    let first = write(1);
    let first_allocation = first.as_ptr();
    let second = write(2);
    drop(first);

    let third = write(3);
    assert_eq!(third.as_ptr(), first_allocation);
    let fourth = write(4);
    assert_ne!(fourth.as_ptr(), second.as_ptr(), "a held snapshot is never overwritten");
    assert_eq!(
        (&second[..], &third[..], &fourth[..]),
        (&[2; 1024][..], &[3; 1024][..], &[4; 1024][..])
    );
}

#[test]
fn storage_serves_captured_state_not_a_snapshot_at_an_unapplied_commit() {
    let mut storage = RaftStorage::new(&[1, 2, 3]);
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
    nodes: Vec<SlashingProtectionCluster>,
    now: Instant,
    isolated: Option<u64>,
    drop_snapshot: bool,
    drop_snapshot_ack: bool,
    snapshots: usize,
    decisions: Vec<AttestationDecision>,
}

impl Network {
    fn new(nodes: Vec<SlashingProtectionCluster>, now: Instant) -> Self {
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
                    ClusterEvent::BlockCommitted(decision) => {
                        panic!("unexpected block decision {decision:?}")
                    }
                    ClusterEvent::ProposalTimedOut(_) => panic!("proposal timed out"),
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
                    .step(message, self.now, 100)
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
    let nodes =
        (1..=3).map(|id| SlashingProtectionCluster::in_memory(config(id), now).unwrap()).collect();
    let mut network = Network::new(nodes, now);
    network.populate_with_one_follower_offline();
    network.drop_snapshot = true;
    network.reconnect();
    assert!(network.snapshots >= 2);
    for node in &mut network.nodes {
        assert_eq!(node.state.apply(&command(7, 2)), LockResult::Conflicting);
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

/// A send failure to the peer fails its snapshot transfer at once, so the
/// retry does not wait out the transfer timeout.
#[test]
fn _unreachable_peer_fails_its_snapshot_transfer_at_once() {
    let now = Instant::now();
    let nodes =
        (1..=3).map(|id| SlashingProtectionCluster::in_memory(config(id), now).unwrap()).collect();
    let mut network = Network::new(nodes, now);
    network.populate_with_one_follower_offline();
    network.drop_snapshot = true;
    network.isolated = None;
    while network.snapshots == 0 {
        network.now += Duration::from_millis(100);
        network.settle();
    }
    assert!(network.nodes[0].snapshot_transfers.is_pending(3));

    network.nodes[0].report_unreachable(3);
    assert!(!network.nodes[0].snapshot_transfers.is_pending(3));
    let started = network.now;
    while network.nodes[2].state.len() < 24 {
        network.now += Duration::from_millis(100);
        network.settle();
        assert!(network.now - started < Duration::from_secs(2), "waited for the timeout");
    }
}

#[test]
fn a_lost_snapshot_ack_does_not_stall_replication() {
    let now = Instant::now();
    let nodes =
        (1..=3).map(|id| SlashingProtectionCluster::in_memory(config(id), now).unwrap()).collect();
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
    let mut storage = RaftStorage::new(&[1, 2, 3]);
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
            SlashingProtectionCluster::new(config, now).unwrap()
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
            SlashingProtectionCluster::new(config, now).unwrap()
        })
        .collect();
    let mut network = Network::new(nodes, now);
    network.settle();
    assert!(network.decisions.is_empty());
    for node in &mut network.nodes {
        assert_eq!(node.state.len(), 24);
        assert_eq!(node.state.minimum_slot(), 68);
        assert_eq!(node.state.apply(&command(7, 2)), LockResult::Conflicting);
        assert!(node.node.as_ref().unwrap().store().snapshot_index() > 0);
    }
}
