use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};

use discovery::{DiscV5, Discovery, DiscoveryConfig, DiscoveryEvent, DiscoveryNetworking};
use k256::ecdsa::SigningKey;
use silver_common::{Enr, NodeId};

struct TestNode {
    disco: DiscV5,
    addr: SocketAddr,
    pubkey: [u8; 33],
    enr_seq: u64,
}

impl TestNode {
    fn new(port: u16) -> Self {
        Self::build(port, default_config(), true)
    }

    /// No IP in ENR (so Pong-reported IP is always "new") and ping fires on
    /// every poll call.
    fn no_ip_fast_ping(port: u16) -> Self {
        Self::build(port, zero_ping_config(), false)
    }

    fn build(port: u16, config: DiscoveryConfig, with_ip: bool) -> Self {
        let key = SigningKey::random(&mut rand::thread_rng());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let enr = if with_ip {
            Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(port).build(&key).unwrap()
        } else {
            Enr::builder().build(&key).unwrap()
        };
        let enr_seq = enr.seq();
        let pubkey: [u8; 33] =
            key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
        Self { disco: DiscV5::new(config, key, enr, [0u8; 4]), addr, pubkey, enr_seq }
    }

    fn node_id(&self) -> NodeId {
        self.disco.local_id()
    }

    fn poll(&mut self) -> Vec<DiscoveryEvent> {
        let mut ev = Vec::new();
        self.disco.poll(|e| ev.push(e));
        ev
    }

    fn deliver(&mut self, from: SocketAddr, data: &[u8], now: Instant) {
        self.disco.handle(from, data, now);
    }
}

fn default_config() -> DiscoveryConfig {
    DiscoveryConfig {
        find_nodes_peer_count: 3,
        ping_frequency_s: 3600,
        query_parallelism: 3,
        query_peer_timeout_ms: 5_000,
    }
}

fn zero_ping_config() -> DiscoveryConfig {
    DiscoveryConfig {
        find_nodes_peer_count: 3,
        ping_frequency_s: 0,
        query_parallelism: 3,
        query_peer_timeout_ms: 5_000,
    }
}

/// All SendMessage packets destined for `to`, in event order.
fn sends_to(events: &[DiscoveryEvent], to: SocketAddr) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            DiscoveryEvent::SendMessage { to: addr, data } if *addr == to => Some(data.to_vec()),
            _ => None,
        })
        .collect()
}

fn has_session_established(events: &[DiscoveryEvent], node_id: NodeId) -> bool {
    events.iter().any(|e| {
        matches!(e,
            DiscoveryEvent::SessionEstablished { node_id: id, .. } if *id == node_id
        )
    })
}

/// Full WhoAreYou→Handshake exchange. Both sides emit SessionEstablished.
#[test]
fn handshake_establishes_session() {
    let now = Instant::now();
    let mut a = TestNode::new(9001);
    let mut b = TestNode::new(9002);

    a.disco.add_node(b.node_id(), b.addr, b.enr_seq, b.pubkey, now);
    a.disco.find_node(NodeId::random());

    // A → probe → B
    let a_ev = a.poll();
    let probes = sends_to(&a_ev, b.addr);
    assert!(!probes.is_empty(), "expected probe packet from A");

    // B issues WhoAreYou
    b.deliver(a.addr, &probes[0], now);
    let b_ev = b.poll();
    let to_a = sends_to(&b_ev, a.addr);
    assert!(!to_a.is_empty(), "expected WhoAreYou from B");

    // A handles WhoAreYou, queues Handshake + FindNode
    a.deliver(b.addr, &to_a[0], now);
    let a_ev = a.poll();

    assert!(has_session_established(&a_ev, b.node_id()), "A: expected SessionEstablished(B)");

    // Route A's packets to B in order: Handshake must arrive before FindNode.
    for pkt in sends_to(&a_ev, b.addr) {
        b.deliver(a.addr, &pkt, now);
    }
    let b_ev = b.poll();

    assert!(has_session_established(&b_ev, a.node_id()), "B: expected SessionEstablished(A)");
}

/// A message packet from an unknown source triggers a WhoAreYou reply.
#[test]
fn probe_from_unknown_source_triggers_whoareyou() {
    let now = Instant::now();
    let mut a = TestNode::new(9011);
    let mut b = TestNode::new(9012);

    // A initiates but B has no prior knowledge of A.
    a.disco.add_node(b.node_id(), b.addr, b.enr_seq, b.pubkey, now);
    a.disco.find_node(NodeId::random());

    let a_ev = a.poll();
    let probes = sends_to(&a_ev, b.addr);
    assert!(!probes.is_empty());

    b.deliver(a.addr, &probes[0], now);
    let b_ev = b.poll();

    // B must have queued a response to A's address (the WhoAreYou).
    let b_to_a = sends_to(&b_ev, a.addr);
    assert!(!b_to_a.is_empty(), "B should respond to unknown sender with WhoAreYou");
}

/// Drive the probe → WhoAreYou → Handshake exchange so both sides have a
/// session.
fn do_handshake(a: &mut TestNode, b: &mut TestNode, now: Instant) {
    a.disco.add_node(b.node_id(), b.addr, b.enr_seq, b.pubkey, now);
    a.disco.find_node(NodeId::random());

    let a_ev = a.poll();
    let probes = sends_to(&a_ev, b.addr);
    b.deliver(a.addr, &probes[0], now);

    let b_ev = b.poll();
    let to_a = sends_to(&b_ev, a.addr);
    a.deliver(b.addr, &to_a[0], now);

    let a_ev = a.poll();
    for pkt in sends_to(&a_ev, b.addr) {
        b.deliver(a.addr, &pkt, now);
    }
    b.poll();
}

/// ExternalAddrChanged fires when IP_VOTE_THRESHOLD (3) **distinct** peers each
/// report the same external address via Pong.
#[test]
fn pong_ip_vote_triggers_external_addr_changed() {
    let now = Instant::now();
    // A has no IP in ENR so the Pong-observed address is always new.
    // zero_ping_config means pings fire on every poll.
    let mut a = TestNode::no_ip_fast_ping(9021);
    let mut b = TestNode::new(9022);
    let mut c = TestNode::new(9023);
    let mut d = TestNode::new(9024);

    do_handshake(&mut a, &mut b, now);
    do_handshake(&mut a, &mut c, now);
    do_handshake(&mut a, &mut d, now);

    // One ping round from A → B, C, D; each responds with one Pong.
    let a_ev = a.poll();
    for pkt in sends_to(&a_ev, b.addr) {
        b.deliver(a.addr, &pkt, now);
    }
    for pkt in sends_to(&a_ev, c.addr) {
        c.deliver(a.addr, &pkt, now);
    }
    for pkt in sends_to(&a_ev, d.addr) {
        d.deliver(a.addr, &pkt, now);
    }

    let b_ev = b.poll();
    let c_ev = c.poll();
    let d_ev = d.poll();
    for pkt in sends_to(&b_ev, a.addr) {
        a.deliver(b.addr, &pkt, now);
    }
    for pkt in sends_to(&c_ev, a.addr) {
        a.deliver(c.addr, &pkt, now);
    }
    for pkt in sends_to(&d_ev, a.addr) {
        a.deliver(d.addr, &pkt, now);
    }

    let final_ev = a.poll();
    assert!(
        final_ev.iter().any(|e| matches!(e, DiscoveryEvent::ExternalAddrChanged(_))),
        "expected ExternalAddrChanged after 3 Pong votes from distinct peers"
    );
}
