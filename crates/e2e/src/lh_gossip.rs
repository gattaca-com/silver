//! rust-libp2p gossipsub peer for end-to-end gossip latency benchmarks.
//!
//! Listener-only role for variant A: the silver publisher dials this peer,
//! opens an outbound `/meshsub/1.1.0` stream, and pushes synthetic
//! `RPC { publish[Message{topic, data: snappy(ssz)}] }` frames. This client
//! subscribes to the same topic, runs gossipsub's `handle_received_message`
//! path, and surfaces `Event::Message` carrying the snappy-decompressed
//! payload (via `SnappyTransform::inbound_transform`).
//!
//! Eth2 conventions:
//!   - `MessageAuthenticity::Anonymous` and `ValidationMode::Anonymous`:
//!     publishes carry only `topic` and `data` (no signed `from` / `seqno` /
//!     `signature` / `key`). silver's `inject::build_publish_frame` emits
//!     exactly this shape.
//!   - `IdentityHash` topics: the topic hash equals its wire string, so
//!     `TopicHash::as_str()` is the eth2 wire topic.
//!   - Message-id: `silver_common::msg_id_valid_snappy(topic, decompressed)`.
//!     Both sides must compute the same id; libp2p's default `sha256(data)`
//!     would diverge from silver's eth2-domain id and break dedup, so we plug a
//!     custom `message_id_fn` into the config.

use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::timing::Nanos;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    gossipsub::{
        self, IdentTopic, Message, MessageAuthenticity, MessageId, RawMessage, TopicHash,
        ValidationMode, Version,
    },
    identity::Keypair,
    multiaddr::Protocol,
    swarm::SwarmEvent,
};
use silver_common::{GossipTopic, msg_id_valid_snappy};
use tokio::runtime::Runtime;

use crate::Stats;

/// Snappy block-format transform. Inbound: decompress so the application
/// (and the message-id fn) sees the SSZ payload. Outbound: compress before
/// the bytes hit the gossipsub publish path. Eth2 does NOT use the
/// gossipsub on-wire signature scheme, but it DOES wrap message data in
/// snappy block format — exactly what `DataTransform` is for.
#[derive(Default, Clone)]
pub struct SnappyTransform;

impl gossipsub::DataTransform for SnappyTransform {
    fn inbound_transform(&self, raw: RawMessage) -> Result<Message, io::Error> {
        let data = snap::raw::Decoder::new()
            .decompress_vec(&raw.data)
            .map_err(|e| io::Error::other(format!("snappy decompress: {e}")))?;
        Ok(Message {
            source: raw.source,
            data,
            sequence_number: raw.sequence_number,
            topic: raw.topic,
        })
    }

    fn outbound_transform(&self, _topic: &TopicHash, data: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        snap::raw::Encoder::new()
            .compress_vec(&data)
            .map_err(|e| io::Error::other(format!("snappy compress: {e}")))
    }
}

pub struct LhGossipClient {
    runtime: Runtime,
    swarm: Swarm<gossipsub::Behaviour<SnappyTransform>>,
    listen_addr: Option<SocketAddr>,
    connected: Option<PeerId>,
    pub stats: Stats,
}

impl LhGossipClient {
    /// Build a listener bound to an ephemeral 127.0.0.1 QUIC port. Caller
    /// reads back the bound address via `listen_addr()` once it resolves.
    pub fn new() -> Self {
        let keypair = Keypair::generate_secp256k1();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let mut swarm = runtime.block_on(async {
            libp2p::SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_quic()
                .with_behaviour(|_| {
                    // Silver only speaks `/meshsub/1.1.0`. libp2p's default
                    // protocol set advertises 1.2.0 first via multistream-
                    // select; silver rejects unknown protocols and tears the
                    // stream down without iterating fallbacks, so we pin a
                    // single protocol id here.
                    // `flood_publish(true)`: variant B publishes to silver
                    // without expecting silver to GRAFT into our mesh —
                    // silver isn't a real gossipsub peer. flood_publish
                    // still requires the peer to have signalled topic
                    // subscription via SUBSCRIBE; that's the bridge
                    // `inject::build_subscribe_frame` provides on the
                    // silver side.
                    let config = gossipsub::ConfigBuilder::default()
                        .protocol_id("/meshsub/1.1.0", Version::V1_1)
                        .validation_mode(ValidationMode::Anonymous)
                        .message_id_fn(eth2_message_id)
                        .flood_publish(true)
                        .build()
                        .expect("gossipsub config");
                    gossipsub::Behaviour::<SnappyTransform>::new_with_transform(
                        MessageAuthenticity::Anonymous,
                        config,
                        SnappyTransform,
                    )
                    .expect("gossipsub behaviour")
                })
                .expect("behaviour")
                .build()
        });

        runtime.block_on(async {
            swarm
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr"))
                .expect("listen_on");
        });

        let mut client =
            Self { runtime, swarm, listen_addr: None, connected: None, stats: Stats::default() };

        // Pump until NewListenAddr resolves so the caller can immediately
        // read the bound port.
        for _ in 0..50 {
            if client.listen_addr.is_some() {
                break;
            }
            client.tick(Duration::from_millis(20));
        }

        client
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }

    pub fn connected_peer(&self) -> Option<PeerId> {
        self.connected
    }

    pub fn dial(&mut self, addr: SocketAddr) -> Result<(), libp2p::swarm::DialError> {
        let multiaddr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", addr.ip(), addr.port())
            .parse()
            .expect("valid multiaddr");
        let swarm = &mut self.swarm;
        self.runtime.block_on(async move { swarm.dial(multiaddr) })
    }

    /// Subscribe to an eth2 gossip topic. Mesh entry is created on subscribe;
    /// inbound publishes for this topic will be surfaced via `Event::Message`.
    pub fn subscribe(
        &mut self,
        topic: GossipTopic,
        fork_digest_hex: &str,
    ) -> Result<bool, gossipsub::SubscriptionError> {
        let wire = topic.to_wire(fork_digest_hex);
        let topic = IdentTopic::new(wire);
        self.swarm.behaviour_mut().subscribe(&topic)
    }

    /// Publish a payload on the eth2 gossip topic. `data` is the raw
    /// (uncompressed) payload — `SnappyTransform::outbound_transform` does
    /// the snappy block compression before the bytes hit the wire.
    pub fn publish(
        &mut self,
        topic: GossipTopic,
        fork_digest_hex: &str,
        data: Vec<u8>,
    ) -> Result<MessageId, gossipsub::PublishError> {
        let wire = topic.to_wire(fork_digest_hex);
        self.swarm.behaviour_mut().publish(IdentTopic::new(wire), data)
    }

    /// Number of peers libp2p has observed as subscribed to `topic`. Used
    /// by variant B to gate the start of the publish loop on silver's
    /// SUBSCRIBE having been processed.
    pub fn subscribed_peer_count(&self, topic: GossipTopic, fork_digest_hex: &str) -> usize {
        let wire = topic.to_wire(fork_digest_hex);
        let hash = IdentTopic::new(wire).hash();
        self.swarm.behaviour().all_peers().filter(|(_, topics)| topics.contains(&&hash)).count()
    }

    pub fn connected_count(&self) -> usize {
        self.swarm.behaviour().all_peers().count()
    }

    /// Drive one swarm event with a bounded wait. `Duration::ZERO` polls
    /// without sleeping — the example loop interleaves this tightly with
    /// silver's tile `loop_body` calls.
    pub fn tick(&mut self, timeout: Duration) {
        let connected = &mut self.connected;
        let listen_addr = &mut self.listen_addr;
        let stats = &mut self.stats;
        let swarm = &mut self.swarm;
        self.runtime.block_on(async {
            if let Ok(event) = tokio::time::timeout(timeout, swarm.select_next_some()).await {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        *connected = Some(peer_id);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(addr) = multiaddr_to_socket(&address) {
                            *listen_addr = Some(addr);
                        }
                    }
                    SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                        record_message(stats, &message);
                    }
                    _ => {}
                }
            }
        });
    }
}

impl Default for LhGossipClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Eth2 valid-snappy message-id over the post-transform (decompressed) data.
/// `IdentityHash` topics make `topic.as_str()` the wire string we hash with.
fn eth2_message_id(message: &Message) -> MessageId {
    let id = msg_id_valid_snappy(message.topic.as_str(), &message.data);
    MessageId::from(id.id.to_vec())
}

fn record_message(stats: &mut Stats, message: &Message) {
    let now_wall = Instant::now();
    stats.gossip_received += 1;
    stats.first_seen_at.get_or_insert(now_wall);
    stats.last_seen_at = Some(now_wall);
    stats.gossip_decompressed_bytes += message.data.len() as u64;
    if message.data.len() >= 8 {
        let sent_ns = u64::from_le_bytes(message.data[..8].try_into().expect("8 bytes"));
        let _ = stats.latency_ns.record(Nanos(sent_ns).elapsed_saturating().0);
    }
}

fn multiaddr_to_socket(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();
    let ip = match iter.next()? {
        Protocol::Ip4(v4) => std::net::IpAddr::V4(v4),
        Protocol::Ip6(v6) => std::net::IpAddr::V6(v6),
        _ => return None,
    };
    let port = match iter.next()? {
        Protocol::Udp(p) => p,
        Protocol::Tcp(p) => p,
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}
