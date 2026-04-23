//! Per-stack wiring: spine, TCaches, tiles, and their per-tile adapters.
//!
//! Each stack is a self-contained silver node (network + optionally gossip
//! compression) bound to its own `path_suffix` on the shared flux base_dir so
//! two stacks coexist in one process.

use std::{net::SocketAddr, sync::atomic::AtomicUsize};

use flux::{spine::SpineAdapter, tile::Tile};
use quinn_proto::Endpoint;
use silver_common::{
    Enr, Keypair, PeerId, SilverSpine, TCache, TConsumer, TProducer, TRandomAccess,
};
use silver_compression::GossipCompressionTile;
use silver_discovery::{DiscV5, DiscoveryConfig};
use silver_network::{NetworkTile, P2p, TCacheStreamData, create_endpoint, create_server_config};

use crate::Stats;

/// How much space each dedicated TCache gets. Kept small — tests are
/// bounded in message count. Must be a power of two.
const TCACHE_SIZE: usize = 1 << 25; // 4 MB per cache

/// Dummy tile marker types — only exist so flux can derive unique tile names
/// (via `short_typename`) when building auxiliary `SpineAdapter`s.
pub struct Injector;
pub struct StatsSink;

impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {}
}
impl Tile<SilverSpine> for StatsSink {
    fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {}
}

/// Minimal stack holding only the network tile — used for the publisher side
/// in the one-way test. The publisher crafts synthetic outbound traffic and
/// does not consume inbound gossip messages.
pub struct PublisherStack {
    pub addr: SocketAddr,
    pub peer_id: PeerId,
    pub spine: SilverSpine,
    pub network: NetworkTile,
    pub network_adapter: SpineAdapter<SilverSpine>,
    pub injector_adapter: SpineAdapter<SilverSpine>,
    /// Producer into the publisher's dedicated "mcache" TCache — harness
    /// writes snappy-ready protobuf RPC frames here to get a `TCacheRead`
    /// which is then referenced by an outbound `GossipMsgOut`.
    pub mcache_producer: TProducer,
    // Hold on to producers/consumers that would otherwise be dropped; they
    // keep their TCaches alive for the lifetime of the stack.
    _keep_alive: StackKeepAlive,
}

/// Full stack: network + compression + stats sink. Used for the echo side.
pub struct EchoStack {
    pub addr: SocketAddr,
    pub peer_id: PeerId,
    pub spine: SilverSpine,
    pub network: NetworkTile,
    pub ssz_consumer: TRandomAccess,
    pub compression: GossipCompressionTile,
    pub network_adapter: SpineAdapter<SilverSpine>,
    pub compression_adapter: SpineAdapter<SilverSpine>,
    /// Adapter whose consumers cover `new_gossip` (Gossip) and `peer_events`
    /// (PeerEvent); ticked by the harness after each compression cycle to
    /// drain into `stats`.
    pub stats_adapter: SpineAdapter<SilverSpine>,
    pub received: AtomicUsize,
    pub stats: Stats,
    _keep_alive: StackKeepAlive,
}

/// Holds TCache producers/consumers that the tiles reference but would
/// otherwise have no owning slot. Dropping this closes the caches.
#[allow(dead_code)]
struct StackKeepAlive {
    // SSZ-decompressed output cache (compression writes, nobody reads in this
    // harness). Kept so the producer inside GossipCompressionTile stays live.
    ssz_consumer: Option<TConsumer>,
    // Inbound gossip-bytes cache consumer (kept alive; compression owns the
    // consumer in the echo stack).
    gossip_in_consumer: Option<TConsumer>,
    // Publisher-side dummy RPC caches.
    rpc_in_consumer: Option<TConsumer>,
    rpc_out_producer: Option<TProducer>,
    // Gossip-out random-access consumer — alive on publisher side.
    gossip_out_ra: Option<TRandomAccess>,
}

/// Build a keypair deterministically from a single-byte salt — makes test
/// peer ids predictable.
pub fn keypair_from_seed(seed: u8) -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    // Ensure non-zero scalar by bumping low bits; secp256k1 rejects zero.
    bytes[31] = 1;
    Keypair::from_secret(&bytes).expect("valid secret")
}

/// Construct a silver endpoint (QUIC) with the given role.
fn quic_endpoint(keypair: &Keypair, is_server: bool) -> Endpoint {
    let server_config =
        is_server.then(|| std::sync::Arc::new(create_server_config(keypair).unwrap()));
    // `silver_network::create_endpoint` wraps quinn's Endpoint::new with the
    // right configuration for silver.
    create_endpoint(server_config).expect("create_endpoint")
}

impl PublisherStack {
    pub fn new(
        base_dir: &std::path::Path,
        path_suffix: &str,
        addr: SocketAddr,
        disc_addr: SocketAddr,
        keypair: Keypair,
    ) -> std::io::Result<Self> {
        let peer_id = keypair.peer_id();

        // TCaches needed by the network tile on the publisher side.
        // gossip_in: network writes raw inbound gossip here; nobody reads.
        let gossip_in_producer = TCache::producer(TCACHE_SIZE);
        let gossip_in_consumer = gossip_in_producer.cache_ref().consumer().ok();

        // gossip_out: network reads outbound bytes from here via random-access.
        // The publisher's mcache TCache IS the gossip_out source — same cache.
        let mcache_producer = TCache::producer(TCACHE_SIZE);
        let gossip_out_ra = mcache_producer.cache_ref().random_access().expect("random_access");

        // rpc_in / rpc_out: not exercised; give dummy caches.
        let rpc_in_producer = TCache::producer(TCACHE_SIZE);
        let rpc_in_consumer = rpc_in_producer.cache_ref().consumer().ok();
        let rpc_out_producer_keepalive = TCache::producer(TCACHE_SIZE);
        let rpc_out_ra =
            rpc_out_producer_keepalive.cache_ref().random_access().expect("random_access");

        // gossip_out handle given to network.
        let gossip_out_ra_for_network =
            mcache_producer.cache_ref().random_access().expect("random_access");

        let stream_data = TCacheStreamData::new(
            gossip_in_producer,
            gossip_out_ra_for_network,
            rpc_in_producer,
            rpc_out_ra,
        );

        let discovery = DiscV5::new(
            DiscoveryConfig::default(),
            *keypair.secret_key(),
            Enr::empty(keypair.secret_key()).unwrap(),
            [0, 0, 0, 0],
        );

        let endpoint = quic_endpoint(&keypair, /* is_server= */ true);
        let p2p = P2p::new(keypair, endpoint);
        let network = NetworkTile::new(disc_addr, discovery, addr, p2p, stream_data)
            .map_err(std::io::Error::other)?;

        // Spine + per-tile adapters.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, Some(path_suffix));
        let network_adapter = SpineAdapter::connect_tile(&network, &mut spine);
        let injector_tile = Injector;
        let injector_adapter = SpineAdapter::connect_tile(&injector_tile, &mut spine);

        Ok(Self {
            addr,
            peer_id,
            spine,
            network,
            network_adapter,
            injector_adapter,
            mcache_producer,
            _keep_alive: StackKeepAlive {
                ssz_consumer: None,
                gossip_in_consumer,
                rpc_in_consumer,
                rpc_out_producer: Some(rpc_out_producer_keepalive),
                gossip_out_ra: Some(gossip_out_ra),
            },
        })
    }
}

impl EchoStack {
    pub fn new(
        base_dir: &std::path::Path,
        path_suffix: &str,
        addr: SocketAddr,
        disc_addr: SocketAddr,
        keypair: Keypair,
        fork_digest_hex: String,
    ) -> std::io::Result<Self> {
        let peer_id = keypair.peer_id();

        // Inbound gossip raw bytes: network writes, compression consumes.
        let gossip_in_producer = TCache::producer(TCACHE_SIZE);
        let gossip_in_consumer = gossip_in_producer.cache_ref().consumer().expect("consumer");

        // SSZ output: compression writes, stats-sink reads.
        let ssz_producer = TCache::producer(TCACHE_SIZE);
        let ssz_consumer = ssz_producer.cache_ref().random_access().expect("consumer");

        // Protobuf mcache: compression writes; network reads via random_access
        // when re-forwarding. Not exercised in one-way test but wiring must
        // exist.
        let protobuf_producer = TCache::producer(TCACHE_SIZE);
        let protobuf_ra_for_network =
            protobuf_producer.cache_ref().random_access().expect("random_access");

        // RPC caches: dummy.
        let rpc_in_producer = TCache::producer(TCACHE_SIZE);
        let rpc_in_consumer = rpc_in_producer.cache_ref().consumer().ok();
        let rpc_out_producer = TCache::producer(TCACHE_SIZE);
        let rpc_out_ra = rpc_out_producer.cache_ref().random_access().expect("random_access");

        let stream_data = TCacheStreamData::new(
            gossip_in_producer,
            protobuf_ra_for_network,
            rpc_in_producer,
            rpc_out_ra,
        );

        let discovery = DiscV5::new(
            DiscoveryConfig::default(),
            *keypair.secret_key(),
            Enr::empty(keypair.secret_key()).unwrap(),
            [0, 0, 0, 0],
        );

        let endpoint = quic_endpoint(&keypair, /* is_server= */ true);
        let p2p = P2p::new(keypair, endpoint);
        let network = NetworkTile::new(disc_addr, discovery, addr, p2p, stream_data)
            .map_err(std::io::Error::other)?;

        let compression = GossipCompressionTile::new(
            gossip_in_consumer,
            ssz_producer,
            protobuf_producer,
            fork_digest_hex,
        )
        .map_err(std::io::Error::other)?;

        let mut spine = SilverSpine::new_with_base_dir(base_dir, Some(path_suffix));
        let network_adapter = SpineAdapter::connect_tile(&network, &mut spine);
        let compression_adapter = SpineAdapter::connect_tile(&compression, &mut spine);
        let stats_tile = StatsSink;
        let stats_adapter = SpineAdapter::connect_tile(&stats_tile, &mut spine);

        Ok(Self {
            addr,
            peer_id,
            spine,
            network,
            compression,
            ssz_consumer,
            network_adapter,
            compression_adapter,
            stats_adapter,
            stats: Stats::default(),
            received: AtomicUsize::default(),
            _keep_alive: StackKeepAlive {
                ssz_consumer: None,
                gossip_in_consumer: None,
                rpc_in_consumer,
                rpc_out_producer: Some(rpc_out_producer),
                gossip_out_ra: None,
            },
        })
    }
}
