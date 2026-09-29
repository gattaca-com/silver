use raft::eraftpb::MessageType;
use silver_common::ssz_view::SINGLE_ATT_SIZE;

use super::*;
use crate::cluster::AttestationKey;

fn config(node_id: u64, voters: Vec<u64>) -> AttestationClusterConfig {
    AttestationClusterConfig::new(
        node_id,
        voters,
        ClusterStorageConfig::Create("unused-test-journal".into()),
    )
}

fn command(slot: u64, root: u8) -> AttestationLockCommand {
    let mut ssz = [0; SINGLE_ATT_SIZE];
    ssz[0] = root;
    AttestationLockCommand { key: AttestationKey { attester_index: 7, slot }, subnet: 0, ssz }
}

fn memory(now: Instant, voters: Vec<u64>) -> AttestationCluster {
    let mut cluster = AttestationCluster::in_memory(config(1, voters), now).unwrap();
    cluster.set_startup_wall_slot(9);
    cluster
}

fn leader(now: Instant) -> AttestationCluster {
    let mut cluster = memory(now, vec![1]);
    cluster.campaign().unwrap();
    cluster.spin(now, 10, |_| {}).unwrap();
    assert!(cluster.is_leader());
    cluster
}

fn events(cluster: &mut AttestationCluster, now: Instant) -> Vec<ClusterEvent> {
    let mut events = Vec::new();
    cluster.spin(now, 10, |event| events.push(event)).unwrap();
    events
}

#[test]
fn vote_responses_wait_for_persistence_and_steps_remain_legal_while_waiting() {
    let now = Instant::now();
    let mut cluster = memory(now, vec![1, 2, 3]);
    cluster.persistence.paused = true;
    cluster
        .step(Message {
            msg_type: MessageType::MsgRequestVote,
            from: 2,
            to: 1,
            term: 1,
            ..Message::default()
        })
        .unwrap();
    assert!(events(&mut cluster, now).is_empty());
    assert!(cluster.persistence.is_pending());

    cluster
        .step(Message {
            msg_type: MessageType::MsgHeartbeat,
            from: 3,
            to: 1,
            term: 2,
            ..Message::default()
        })
        .unwrap();
    assert!(events(&mut cluster, now).is_empty());
    assert_eq!(cluster.node.as_ref().unwrap().raft.term, 2);

    cluster.persistence.paused = false;
    let messages = events(&mut cluster, now);
    assert!(messages.iter().any(|event| matches!(event,
        ClusterEvent::SendRaftMessage(message) if message.msg_type == MessageType::MsgRequestVoteResponse && message.to == 2
    )));
    assert!(messages.iter().any(|event| matches!(event,
        ClusterEvent::SendRaftMessage(message) if message.msg_type == MessageType::MsgHeartbeatResponse && message.to == 3
    )));
}

#[test]
fn pending_disk_io_does_not_stop_proposal_timeouts_or_accept_late_decisions() {
    let now = Instant::now();
    let mut cluster = leader(now);
    cluster.persistence.paused = true;
    let first = cluster.propose_attestation(command(10, 1), 10, now).unwrap();
    assert!(events(&mut cluster, now).is_empty());
    assert_eq!(cluster.state.len(), 0);
    let mut other = command(10, 2);
    other.key.attester_index = 8;
    let second = cluster.propose_attestation(other, 10, now).unwrap();
    let later = now + Duration::from_millis(100);
    let expired = events(&mut cluster, later);
    assert!(matches!(&expired[..], [
        ClusterEvent::AttestationProposalTimedOut(a), ClusterEvent::AttestationProposalTimedOut(b)
    ] if *a == first && *b == second));
    assert_eq!(cluster.state.len(), 0);

    cluster.persistence.paused = false;
    assert!(events(&mut cluster, later).is_empty());
    assert_eq!(cluster.state.len(), 2);
    assert_eq!(cluster.state.apply(&command(10, 3)), LockResult::ConflictingAttestation);
}

#[test]
fn persistence_failure_stops_votes_proposals_and_committed_decisions() {
    let now = Instant::now();
    let mut cluster = leader(now);
    cluster.persistence.paused = true;
    cluster.propose_attestation(command(10, 1), 10, now).unwrap();
    assert!(events(&mut cluster, now).is_empty());
    cluster.fail_persistence();
    assert!(matches!(
        cluster.spin(now, 10, |_| panic!("released failed write")),
        Err(ClusterError::Storage(_))
    ));
    assert!(cluster.is_failed());
    assert!(!cluster.is_ready());
    assert!(!cluster.is_leader());
    assert_eq!(cluster.pending_proposals(), 0);
    assert!(matches!(cluster.campaign(), Err(ClusterError::Failed)));
    assert!(matches!(cluster.step(Message::default()), Err(ClusterError::Failed)));
    assert!(matches!(
        cluster.propose_attestation(command(10, 2), 10, now),
        Err(ProposeError::Failed)
    ));
    assert!(events(&mut cluster, now).is_empty());
    assert_eq!(cluster.state.len(), 0);
}

#[test]
fn previous_incarnation_cannot_complete_a_new_request_with_the_same_sequence() {
    let now = Instant::now();
    let mut old = leader(now);
    let previous = old.propose_attestation(command(10, 1), 10, now).unwrap();
    let mut cluster = leader(now);
    let current = cluster.propose_attestation(command(10, 2), 10, now).unwrap();
    assert_eq!(previous.sequence, current.sequence);
    assert_ne!(previous.incarnation, current.incarnation);
    cluster
        .apply_entries(
            [Entry {
                data: ReplicatedCommand::Lock(command(10, 1)).encode().into(),
                context: previous.encode().into(),
                ..Entry::default()
            }],
            now,
            10,
            &mut |_| panic!("previous incarnation completed new request"),
        )
        .unwrap();
    assert_eq!(cluster.pending_proposals(), 1);
    assert!(events(&mut cluster, now).iter().any(|event| matches!(event,
        ClusterEvent::AttestationCommitted(decision) if decision.proposal_id == current && decision.result == LockResult::ConflictingAttestation
    )));
    assert_eq!(cluster.pending_proposals(), 0);
}

#[test]
fn proposal_contexts_round_trip_and_legacy_contexts_cannot_match_new_requests() {
    let now = Instant::now();
    let mut cluster = leader(now);
    let proposal = cluster.propose_attestation(command(10, 1), 10, now).unwrap();
    let encoded = proposal.encode();
    assert_eq!(ProposalId::decode(&encoded).unwrap(), proposal);
    let legacy = ProposalId::decode(&encoded[..16]).unwrap();
    assert_eq!(legacy.incarnation, [0; 16]);
    assert_ne!(legacy, proposal);
    for len in [0, 15, 17, 31] {
        assert!(ProposalId::decode(&encoded[..len]).is_err());
    }
}

#[cfg(target_os = "linux")]
mod disk {
    use std::{path::Path, thread};

    use super::*;

    fn stored_config(
        path: &Path,
        create: bool,
        node: u64,
        voters: Vec<u64>,
    ) -> AttestationClusterConfig {
        let mut config = config(node, voters);
        config.storage = if create {
            ClusterStorageConfig::Create(path.into())
        } else {
            ClusterStorageConfig::Open(path.into())
        };
        config
    }

    fn quiet(cluster: &AttestationCluster) -> bool {
        cluster.is_ready() &&
            !cluster.persistence.is_pending() &&
            !cluster.node.as_ref().unwrap().has_ready()
    }

    fn drain(cluster: &mut AttestationCluster, now: Instant, slot: u64) -> Vec<ClusterEvent> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut events = Vec::new();
        loop {
            cluster.spin(now, slot, |event| events.push(event)).unwrap();
            if quiet(cluster) {
                return events;
            }
            assert!(Instant::now() < deadline, "journal did not become idle");
            thread::yield_now();
        }
    }

    #[test]
    fn recovery_gates_participation_and_restores_epoch_locks_and_retention_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.wal");
        let now = Instant::now();
        let mut cluster =
            AttestationCluster::new(stored_config(&path, true, 1, vec![1]), now).unwrap();
        cluster.set_startup_wall_slot(99);
        assert!(matches!(cluster.campaign(), Err(ClusterError::NotReady)));
        assert!(matches!(cluster.step(Message::default()), Err(ClusterError::NotReady)));
        assert!(matches!(
            cluster.propose_attestation(command(100, 1), 100, now),
            Err(ProposeError::NotReady)
        ));
        assert!(drain(&mut cluster, now, 100).is_empty());
        cluster.campaign().unwrap();
        drain(&mut cluster, now, 100);
        let old_id = cluster.propose_attestation(command(100, 1), 100, now).unwrap();
        assert!(drain(&mut cluster, now, 100).iter().any(|event| matches!(event,
            ClusterEvent::AttestationCommitted(decision) if decision.result == LockResult::Accepted
        )));
        let node = cluster.node.as_ref().unwrap();
        let hard_state = node.store().memory.rl().hard_state().clone();
        assert_eq!(hard_state.commit, node.raft.raft_log.applied);
        drop(cluster);

        let mut cluster =
            AttestationCluster::new(stored_config(&path, false, 1, vec![1]), now).unwrap();
        cluster.set_startup_wall_slot(104);
        assert!(drain(&mut cluster, now, 105).is_empty());
        assert_eq!(cluster.state.len(), 1);
        assert_eq!(cluster.state.minimum_slot(), 68);
        assert_eq!(cluster.node.as_ref().unwrap().raft.hard_state(), hard_state);
        assert_eq!(cluster.node.as_ref().unwrap().raft.raft_log.applied, hard_state.commit);
        cluster.campaign().unwrap();
        drain(&mut cluster, now, 105);
        let new_id = cluster.propose_attestation(command(105, 2), 105, now).unwrap();
        assert_ne!(old_id, new_id);
        assert!(drain(&mut cluster, now, 105).iter().any(|event| matches!(event,
            ClusterEvent::AttestationCommitted(decision) if decision.proposal_id == new_id && decision.result == LockResult::ConflictingAttestation
        )));
    }

    #[test]
    fn recovered_uncommitted_suffix_is_not_applied_and_can_be_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("raft.wal");
        let now = Instant::now();
        let mut cluster =
            AttestationCluster::new(stored_config(&path, true, 1, vec![1, 2, 3]), now).unwrap();
        drain(&mut cluster, now, 10);
        let context = ProposalId { origin_node_id: 2, sequence: 1, incarnation: [1; 16] }.encode();
        cluster
            .step(Message {
                msg_type: MessageType::MsgAppend,
                from: 2,
                to: 1,
                term: 1,
                entries: vec![Entry {
                    index: 1,
                    term: 1,
                    context: context.clone().into(),
                    data: ReplicatedCommand::Lock(command(10, 1)).encode().into(),
                    ..Entry::default()
                }]
                .into(),
                ..Message::default()
            })
            .unwrap();
        drain(&mut cluster, now, 10);
        assert_eq!(cluster.state.len(), 0);
        drop(cluster);

        let mut cluster =
            AttestationCluster::new(stored_config(&path, false, 1, vec![1, 2, 3]), now).unwrap();
        assert!(drain(&mut cluster, now, 10).is_empty());
        assert_eq!(cluster.state.len(), 0);
        assert_eq!(cluster.node.as_ref().unwrap().raft.raft_log.last_index(), 1);
        cluster
            .step(Message {
                msg_type: MessageType::MsgAppend,
                from: 2,
                to: 1,
                term: 2,
                commit: 1,
                entries: vec![Entry {
                    index: 1,
                    term: 2,
                    context: context.into(),
                    data: ReplicatedCommand::Lock(command(10, 2)).encode().into(),
                    ..Entry::default()
                }]
                .into(),
                ..Message::default()
            })
            .unwrap();
        drain(&mut cluster, now, 10);
        assert_eq!(cluster.state.len(), 1);
        assert_eq!(cluster.state.apply(&command(10, 2)), LockResult::AlreadyAcceptedSame);
        assert_eq!(cluster.state.apply(&command(10, 1)), LockResult::ConflictingAttestation);
        drop(cluster);

        let mut cluster =
            AttestationCluster::new(stored_config(&path, false, 1, vec![1, 2, 3]), now).unwrap();
        assert!(drain(&mut cluster, now, 10).is_empty());
        assert_eq!(cluster.state.len(), 1);
        assert_eq!(cluster.state.apply(&command(10, 2)), LockResult::AlreadyAcceptedSame);
    }

    #[test]
    fn missing_journal_disables_cluster_without_bootstrapping_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.wal");
        let now = Instant::now();
        let mut cluster =
            AttestationCluster::new(stored_config(&path, false, 1, vec![1]), now).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cluster.is_failed() {
            let _ = cluster.spin(now, 10, |_| panic!("unrecovered node emitted work"));
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(!path.exists());
        assert!(matches!(cluster.campaign(), Err(ClusterError::Failed)));
    }

    #[test]
    fn three_durable_nodes_commit_a_follower_proposal_and_recover_the_same_lock() {
        let dir = tempfile::tempdir().unwrap();
        let now = Instant::now();
        let voters = vec![1, 2, 3];
        let paths: Vec<_> = voters.iter().map(|id| dir.path().join(format!("{id}.wal"))).collect();
        let mut nodes: Vec<_> = voters
            .iter()
            .zip(&paths)
            .map(|(id, path)| {
                let mut node =
                    AttestationCluster::new(stored_config(path, true, *id, voters.clone()), now)
                        .unwrap();
                node.set_startup_wall_slot(9);
                drain(&mut node, now, 10);
                node
            })
            .collect();
        let mut messages = Vec::new();
        let mut decisions = Vec::new();
        let mut pump = |nodes: &mut [AttestationCluster]| {
            for node in nodes.iter_mut() {
                node.spin(now, 10, |event| match event {
                    ClusterEvent::SendRaftMessage(message) => messages.push(message),
                    ClusterEvent::AttestationCommitted(decision) => decisions.push(decision),
                    ClusterEvent::AttestationProposalTimedOut(_) => panic!("unexpected timeout"),
                })
                .unwrap();
            }
            for message in messages.drain(..) {
                nodes
                    .iter_mut()
                    .find(|node| node.node_id() == message.to)
                    .unwrap()
                    .step(message)
                    .unwrap();
            }
        };
        nodes[0].campaign().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !nodes[0].is_leader() || !nodes.iter().all(quiet) {
            pump(&mut nodes);
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let proposal = nodes[1].propose_attestation(command(10, 4), 10, now).unwrap();
        while !nodes.iter().all(|node| quiet(node) && node.state.len() == 1) {
            pump(&mut nodes);
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].proposal_id, proposal);
        assert!(decisions[0].may_validate());
        drop(nodes);
        for (id, path) in voters.iter().zip(&paths) {
            let mut node =
                AttestationCluster::new(stored_config(path, false, *id, voters.clone()), now)
                    .unwrap();
            assert!(drain(&mut node, now, 10).is_empty());
            assert_eq!(node.state.len(), 1);
            assert_eq!(node.state.apply(&command(10, 5)), LockResult::ConflictingAttestation);
        }
    }
}
