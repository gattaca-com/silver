use std::time::{Duration, Instant};

use silver_common::{
    GossipTopic, P2pSend, PeerControl, PeerEvent, PeerStatus, TCache, TCacheId, TCacheProducer,
};
use silver_config::ScoreParams;

use super::fixture::*;

const OLD: [u8; 4] = [0; 4];
const NEW: [u8; 4] = [1; 4];
const TOPIC: GossipTopic = GossipTopic::DataColumnSidecar(3);

#[test]
fn overlap_preserves_meshes_and_retires_without_score_or_backoff_penalties() {
    let now = Instant::now();
    let (mut manager, mut captured) = fixture(vec![TOPIC], ScoreParams::default());
    connect(&mut manager, &mut captured, 1, 1, now);
    manager.on_subscribe(1, TOPIC, OLD, now, &mut |_| {});
    manager.set_active_domains(OLD, Some(NEW), &mut |event| captured.0.push(event));
    manager.on_subscribe(1, TOPIC, NEW, now + Duration::from_secs(1), &mut |_| {});
    let score = &manager.peers[&1].topic_stats[&TOPIC];
    assert_eq!(score.meshed_since, Some(now));
    manager.set_active_domains(NEW, Some(OLD), &mut |_| {});
    assert_eq!(manager.mesh[&TOPIC].get(NEW).unwrap().peers, [1]);
    assert_eq!(manager.mesh[&TOPIC].get(OLD).unwrap().peers, [1]);
    captured.0.clear();
    manager.set_active_domains(NEW, None, &mut |event| captured.0.push(event));
    assert!(manager.mesh[&TOPIC].get(OLD).is_none());
    assert_eq!(manager.mesh[&TOPIC].get(NEW).unwrap().peers, [1]);
    assert!(matches!(captured.0.as_slice(), [
        PeerControl::P2pGossipPrune { digest: OLD, backoff_seconds: None, .. },
        PeerControl::P2pGossipUnsubscribe { digest: OLD, .. },
    ]));
    let peer = &manager.peers[&1];
    assert!(!peer.subscriptions.contains_key(&(OLD, TOPIC)));
    assert!(peer.subscriptions.contains_key(&(NEW, TOPIC)));
    assert!(peer.backoffs.is_empty());
    assert_eq!(peer.topic_stats[&TOPIC].mesh_failure_penalty, 0.0);
    assert_eq!(peer.topic_stats[&TOPIC].meshed_since, Some(now));
    captured.0.clear();
    manager.set_active_domains(NEW, None, &mut |event| captured.0.push(event));
    assert!(captured.0.is_empty());
}

#[test]
fn skipped_overlap_creates_current_mesh_and_clears_old_score_residency() {
    let now = Instant::now();
    let (mut manager, mut captured) = fixture(vec![TOPIC], ScoreParams::default());
    connect(&mut manager, &mut captured, 1, 1, now);
    manager.on_subscribe(1, TOPIC, OLD, now, &mut |_| {});
    manager.set_active_domains(NEW, None, &mut |_| {});
    assert!(manager.mesh[&TOPIC].get(OLD).is_none());
    assert!(manager.mesh[&TOPIC].get(NEW).unwrap().peers.is_empty());
    assert_eq!(manager.peers[&1].topic_stats[&TOPIC].meshed_since, None);
    manager.on_subscribe(1, TOPIC, NEW, now, &mut |_| {});
    assert_eq!(manager.mesh[&TOPIC].get(NEW).unwrap().peers, [1]);
}

#[test]
fn connections_and_deferred_topics_subscribe_to_both_domains() {
    let now = Instant::now();
    let (mut manager, mut captured) = fixture(vec![TOPIC], ScoreParams::default());
    manager.set_active_domains(OLD, Some(NEW), &mut |_| {});
    connect(&mut manager, &mut captured, 1, 1, now);
    let digests: Vec<_> = captured
        .0
        .iter()
        .filter_map(|event| match event {
            PeerControl::P2pGossipSubscribe { digest, .. } => Some(*digest),
            _ => None,
        })
        .collect();
    assert_eq!(digests, [OLD, NEW]);
    captured.0.clear();
    manager.activate_topics(&[GossipTopic::BeaconBlock], &mut |event| captured.0.push(event));
    assert_eq!(captured.0.len(), 2);
    assert!(manager.mesh[&GossipTopic::BeaconBlock].get(OLD).is_some());
    assert!(manager.mesh[&GossipTopic::BeaconBlock].get(NEW).is_some());
    captured.0.clear();
    manager.fan_out_subscriptions(&mut |event| captured.0.push(event));
    assert_eq!(captured.0.len(), 4);
}

#[test]
fn mesh_refill_and_ihave_use_exact_domain_subscriptions() {
    let now = Instant::now();
    let mut params = ScoreParams::default();
    params.d_low = 0;
    params.d = 1;
    let (mut manager, mut captured) = fixture(vec![TOPIC], params);
    manager.set_active_domains(OLD, Some(NEW), &mut |_| {});
    for (conn, digest) in [(1, OLD), (2, NEW)] {
        connect(&mut manager, &mut captured, conn, conn as u8, now);
        manager.on_subscribe(conn, TOPIC, digest, now, &mut |_| {});
    }
    manager.manage_mesh(now, &mut |_| {});
    assert_eq!(manager.mesh[&TOPIC].get(OLD).unwrap().peers, [1]);
    assert_eq!(manager.mesh[&TOPIC].get(NEW).unwrap().peers, [2]);
    // Peer 1 is meshed only on OLD, so it remains eligible for NEW's IHAVE.
    manager.on_subscribe(1, TOPIC, NEW, now, &mut |_| {});
    let mut cache = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
    let mut reservation = cache.reserve(1, false).unwrap();
    let protobuf = reservation.read();
    reservation.increment_offset(1);
    captured.0.clear();
    manager.on_outbound_ihave(TOPIC, NEW, protobuf, false, &mut |event| captured.0.push(event));
    assert!(
        matches!(captured.0.as_slice(), [PeerControl::P2pSend(P2pSend::Gossip(message))] if message.peer_id == 1)
    );
    manager.on_unsubscribe(1, TOPIC, NEW, now, &mut |_| {});
    captured.0.clear();
    manager.on_outbound_ihave(TOPIC, NEW, protobuf, false, &mut |event| captured.0.push(event));
    assert!(captured.0.is_empty());
}

#[test]
fn inactive_digest_cannot_create_a_subscription_or_capabilities() {
    let now = Instant::now();
    let (mut manager, mut captured) = fixture(vec![TOPIC], ScoreParams::default());
    connect(&mut manager, &mut captured, 1, 1, now);
    manager.on_subscribe(1, TOPIC, NEW, now, &mut |_| {});
    manager.handle_event(
        PeerEvent::P2pGossipPartialCaps {
            p2p_peer: 1,
            digest: NEW,
            subnet: 3,
            requests: true,
            supports_sending: true,
        },
        now,
        &mut |_| {},
    );
    assert!(manager.peers[&1].subscriptions.is_empty());
    assert!(manager.mesh[&TOPIC].get(NEW).is_none());
}

#[test]
fn neighbouring_status_is_accepted_during_overlap() {
    let now = Instant::now();
    let (mut manager, mut captured) = fixture(vec![], ScoreParams::default());
    manager.set_active_domains(NEW, Some(OLD), &mut |_| {});
    connect(&mut manager, &mut captured, 1, 1, now);
    manager.on_p2p_peer_status(1, PeerStatus::V2(status_v2_ssz(OLD, [0; 32], 0, [0; 32], 0)));
    assert!(manager.database.peer_status_bytes(1).is_some());
    assert_eq!(manager.peers[&1].application_score, 0.0);
}
