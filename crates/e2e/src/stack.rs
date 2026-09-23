//! Per-stack wiring: spine, TCaches, tiles, and their per-tile adapters.
//!
//! Each stack is a self-contained silver node (network + optionally gossip
//! compression) bound to its own `path_suffix` on the shared flux base_dir so
//! two stacks coexist in one process.

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
};

use flux::{spine::SpineAdapter, tile::Tile};
use quinn_proto::Endpoint;
use silver_beacon_state_data::SpecConfig;
use silver_common::{
    Enr, Identify, Keypair, PeerId, ProtoIdentify, SilverSpine, TCache, TCacheId, TCacheProducer,
    TCacheReader, TCacheTable, TConsumer, TProducer, TReadMode, ssz_view::METADATA_SIZE,
};
use silver_config::{DiscoveryConfig, ScoreParams, SyncingConfig};
use silver_control::{Controller, sync_engine::SyncEngine};
use silver_discovery::DiscV5;
use silver_gossip::GossipHandler;
use silver_network::{Context, NetworkTile, P2p, create_endpoint, create_server_config};
use silver_peer::PeerManager;

use crate::Stats;

/// How much space each dedicated TCache gets.
const TCACHE_SIZE: usize = 1 << 25;

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
    pub controller: Controller,
    pub network_adapter: SpineAdapter<SilverSpine>,
    pub controller_adapter: SpineAdapter<SilverSpine>,
    pub injector_adapter: SpineAdapter<SilverSpine>,
    /// Producer into the publisher's dedicated "mcache" TCache — harness
    /// writes snappy-ready protobuf RPC frames here to get a `TCacheRead`
    /// which is then referenced by an outbound `GossipMsgOut`.
    pub mcache_producer: TProducer,
    /// Producer for inbound RPC payload bytes (the network tile reserves
    /// here as it decompresses chunks; the resulting `TCacheRead` rides
    /// inside `RpcResponse::BeaconBlock`/`DataColumnSidecar`). Exposed for
    /// the multipart-RPC tests that need a `TCacheReader` peer of this
    /// cache; production-time the field is owned by `Context.rpc_producer`.
    pub rpc_in_ra: TCacheReader,
    /// Producer for outbound RPC payload bytes — multipart-RPC tests
    /// reserve here, write SSZ, and reference the resulting `TCacheRead`
    /// in `RpcOutbound::Response(BeaconBlock { ssz })`. The network tile
    /// reads via the cache's `Context.rpc_consumer` random-access handle.
    pub rpc_out_producer: TProducer,
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
    pub ssz_consumer: TCacheReader,
    pub controller: Controller,
    pub network_adapter: SpineAdapter<SilverSpine>,
    pub controller_adapter: SpineAdapter<SilverSpine>,
    /// Auxiliary adapter for the harness to inject `PeerControl` events
    /// (e.g. `P2pGossipSubscribe`) onto the spine. Required by lh_gossip
    /// variant B, where the libp2p peer only publishes to silver after
    /// observing silver's SUBSCRIBE for the topic.
    pub injector_adapter: SpineAdapter<SilverSpine>,
    /// Adapter whose consumers cover `new_gossip` (Gossip) and `peer_events`
    /// (PeerEvent); ticked by the harness after each compression cycle to
    /// drain into `stats`.
    pub stats_adapter: SpineAdapter<SilverSpine>,
    pub received: AtomicUsize,
    pub stats: Stats,
    _keep_alive: StackKeepAlive,
}

/// Network-side half of a split `EchoStack`: network tile + controller +
/// the injector adapter. Designed to run on its own thread; communicates
/// with `EchoCompressionHalf` exclusively via the spine (lock-free
/// queues) and TCaches (shmem-backed).
pub struct EchoNetworkHalf {
    pub addr: SocketAddr,
    pub peer_id: PeerId,
    pub network: NetworkTile,
    pub controller: Controller,
    pub network_adapter: SpineAdapter<SilverSpine>,
    pub controller_adapter: SpineAdapter<SilverSpine>,
    pub injector_adapter: SpineAdapter<SilverSpine>,
    /// Held to keep the spine and ancillary TCache handles alive for the
    /// lifetime of both threads.
    _spine: SilverSpine,
    _keep_alive: StackKeepAlive,
}

/// Compression-side half of a split `EchoStack`: gossip handler + ssz
/// consumer + stats. The network half writes raw bytes to the gossip-in
/// TCache; this half reads them, decodes/decompresses, emits
/// `NewGossipMsg` onto the spine.
pub struct EchoCompressionHalf {
    pub stats_adapter: SpineAdapter<SilverSpine>,
    pub ssz_consumer: TCacheReader,
    pub stats: Stats,
}

impl EchoStack {
    /// Move the network/controller and the compression tile onto separate
    /// ownerships so callers can spawn each on its own thread. Spine
    /// queues are lock-free MPMC, so cross-thread is safe.
    pub fn split(self) -> (EchoNetworkHalf, EchoCompressionHalf) {
        (
            EchoNetworkHalf {
                addr: self.addr,
                peer_id: self.peer_id,
                network: self.network,
                controller: self.controller,
                network_adapter: self.network_adapter,
                controller_adapter: self.controller_adapter,
                injector_adapter: self.injector_adapter,
                _spine: self.spine,
                _keep_alive: self._keep_alive,
            },
            EchoCompressionHalf {
                stats_adapter: self.stats_adapter,
                ssz_consumer: self.ssz_consumer,
                stats: self.stats,
            },
        )
    }
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
    gossip_in_consumer: Option<TCacheReader>,
    // Publisher-side dummy RPC caches.
    rpc_in_consumer: Option<TConsumer>,
    rpc_out_producer: Option<TProducer>,
    // Gossip-out reader — alive on publisher side.
    gossip_out_ra: Option<TCacheReader>,
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
        let gossip_in_producer = TCache::producer(TCacheId::NetworkIngress, TCACHE_SIZE);
        let gossip_in_consumer =
            TCacheReader::single(gossip_in_producer.cache_ref(), "e2e", TReadMode::Sliding).ok();

        // gossip_out: network reads outbound bytes from here via its reader.
        // The publisher's mcache TCache IS the gossip_out source — same cache.
        let mcache_producer = TCache::producer(TCacheId::ControlGossip, TCACHE_SIZE);
        let gossip_out_ra =
            TCacheReader::single(mcache_producer.cache_ref(), "e2e", TReadMode::Sliding)
                .expect("random_access");

        // rpc_in: network writes inbound RPC payload bytes here; tests
        // (multipart-RPC) read via `rpc_in_ra`. Regular consumer also
        // attached for keep-alive.
        let rpc_in_producer = TCache::producer(TCacheId::NetworkProcessing, TCACHE_SIZE);
        let rpc_in_consumer = rpc_in_producer.cache_ref().consumer("e2e").ok();
        let rpc_in_ra =
            TCacheReader::single(rpc_in_producer.cache_ref(), "e2e", TReadMode::Sliding)
                .expect("rpc_in random_access");
        // rpc_out: tests reserve here to inject outbound BeaconBlock
        // chunks; the network tile reads via its reader.
        let rpc_out_producer = TCache::producer(TCacheId::StorageDelivery, TCACHE_SIZE);
        let control_rpc_producer = TCache::producer(TCacheId::ControlRpc, 32);

        let cluster_in_producer = TCache::producer(TCacheId::ClusterInbound, 1 << 12);
        let cluster_out_producer = TCache::producer(TCacheId::ClusterOutbound, 1 << 12);

        // Dummies the controller and gossip handler read from or write to.
        let ssz_producer = TCache::producer(TCacheId::ControlProcessing, 32);
        let protobuf_producer = TCache::producer(TCacheId::ControlGossip, 32);
        let el_producer = TCache::producer(TCacheId::ColumnsProcessing, 32);

        let network_tcaches = TCacheTable::from_iter(
            [&mcache_producer, &rpc_out_producer, &control_rpc_producer, &cluster_out_producer]
                .map(|p| p.cache_ref()),
        );
        let gossip_tcaches =
            TCacheTable::from_iter([gossip_in_producer.cache_ref(), protobuf_producer.cache_ref()]);
        let controller_tcaches = TCacheTable::from_iter(
            [&rpc_in_producer, &el_producer, &cluster_in_producer].map(|p| p.cache_ref()),
        );

        let context = Context {
            gossip_producer: gossip_in_producer,
            rpc_producer: rpc_in_producer,
            // Build a fully-populated `ProtoIdentify` via the `Identify`
            // -> protobuf conversion: a default-constructed protobuf has
            // every field as `None`, including `protocolVersion`, which
            // the receiver rejects with `IdentifyInvalidProtocol`.
            identify: Some(ProtoIdentify::from((&Identify::default(), &keypair))),
            cluster_nodes: None,
            cluster_inbound_producer: cluster_in_producer,
            partial_columns: false,
            reader: TCacheReader::new(network_tcaches),
        };

        let discovery = DiscV5::new(
            DiscoveryConfig::default(),
            *keypair.secret_key(),
            Enr::empty(keypair.secret_key()).unwrap(),
            [0, 0, 0, 0],
        );

        let endpoint = quic_endpoint(&keypair, /* is_server= */ true);
        let p2p = P2p::new(keypair, endpoint, 1024, Default::default());
        let mut network = NetworkTile::new(disc_addr, discovery, addr, p2p, context)
            .map_err(std::io::Error::other)?;
        network.open_tcaches().map_err(std::io::Error::other)?;

        // Tests don't subscribe to gossip topics, so PeerManager runs with
        // an empty subscription set — meshes stay empty, score deltas
        // exercise only the connection / RPC paths.
        let mut controller = Controller::new(
            PeerManager::new(
                PeerId::default(),
                Vec::new(),
                Vec::new(),
                ScoreParams::default(),
                SyncingConfig::default(),
                [0u8; 4],
                [0u8; METADATA_SIZE],
                0,
            ),
            GossipHandler::new(gossip_tcaches, ssz_producer, protobuf_producer, None).unwrap(),
            control_rpc_producer,
            controller_tcaches,
            cluster_out_producer,
            None,
            SyncEngine::new(SyncingConfig::default(), false, 0, Arc::new(SpecConfig::mainnet())),
            Arc::new(SpecConfig::mainnet()),
        )
        .map_err(std::io::Error::other)?;
        controller.open_tcaches().map_err(std::io::Error::other)?;

        // Spine + per-tile adapters.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, Some(path_suffix));
        let network_adapter = SpineAdapter::connect_tile(&network, &mut spine);
        let controller_adapter = SpineAdapter::connect_tile(&controller, &mut spine);
        let injector_tile = Injector;
        let injector_adapter = SpineAdapter::connect_tile(&injector_tile, &mut spine);

        Ok(Self {
            addr,
            peer_id,
            spine,
            network,
            controller,
            network_adapter,
            controller_adapter,
            injector_adapter,
            mcache_producer,
            rpc_in_ra,
            rpc_out_producer,
            _keep_alive: StackKeepAlive {
                ssz_consumer: None,
                gossip_in_consumer,
                rpc_in_consumer,
                rpc_out_producer: None,
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
        let boot_domain = (!fork_digest_hex.is_empty()).then(|| {
            let mut digest = [0u8; 4];
            hex::decode_to_slice(&fork_digest_hex, &mut digest).expect("valid fork digest hex");
            silver_common::GossipDomain::new(digest, silver_common::ForkName::Fulu)
        });

        // Inbound gossip raw bytes: network writes, compression consumes.
        let gossip_in_producer = TCache::producer(TCacheId::NetworkIngress, TCACHE_SIZE);

        // SSZ output: compression writes, stats-sink reads.
        let ssz_producer = TCache::producer(TCacheId::ControlProcessing, TCACHE_SIZE);
        let ssz_consumer =
            TCacheReader::single(ssz_producer.cache_ref(), "e2e", TReadMode::Sliding)
                .expect("consumer");

        // Protobuf mcache: compression writes; network reads via its reader
        // when re-forwarding. Not exercised in one-way test but wiring must
        // exist.
        let protobuf_producer = TCache::producer(TCacheId::ControlGossip, TCACHE_SIZE);

        // RPC caches: dummy.
        let rpc_in_producer = TCache::producer(TCacheId::NetworkProcessing, TCACHE_SIZE);
        let rpc_in_consumer = rpc_in_producer.cache_ref().consumer("e2e").ok();
        let rpc_out_producer = TCache::producer(TCacheId::StorageDelivery, TCACHE_SIZE);
        let control_rpc_producer = TCache::producer(TCacheId::ControlRpc, 32);

        let cluster_in_producer = TCache::producer(TCacheId::ClusterInbound, 1 << 12);
        let cluster_out_producer = TCache::producer(TCacheId::ClusterOutbound, 1 << 12);

        // Dummies the controller reads from.
        let ctl_rpc_producer = TCache::producer(TCacheId::NetworkProcessing, 32);
        let el_producer = TCache::producer(TCacheId::ColumnsProcessing, 32);

        let network_tcaches = TCacheTable::from_iter(
            [&protobuf_producer, &rpc_out_producer, &control_rpc_producer, &cluster_out_producer]
                .map(|p| p.cache_ref()),
        );
        let gossip_tcaches =
            TCacheTable::from_iter([gossip_in_producer.cache_ref(), protobuf_producer.cache_ref()]);
        let controller_tcaches = TCacheTable::from_iter(
            [&ctl_rpc_producer, &el_producer, &cluster_in_producer].map(|p| p.cache_ref()),
        );

        let context = Context {
            gossip_producer: gossip_in_producer,
            rpc_producer: rpc_in_producer,
            // Build a fully-populated `ProtoIdentify` via the `Identify`
            // -> protobuf conversion: a default-constructed protobuf has
            // every field as `None`, including `protocolVersion`, which
            // the receiver rejects with `IdentifyInvalidProtocol`.
            identify: Some(ProtoIdentify::from((&Identify::default(), &keypair))),
            cluster_nodes: None,
            cluster_inbound_producer: cluster_in_producer,
            partial_columns: false,
            reader: TCacheReader::new(network_tcaches),
        };

        let discovery = DiscV5::new(
            DiscoveryConfig::default(),
            *keypair.secret_key(),
            Enr::empty(keypair.secret_key()).unwrap(),
            [0, 0, 0, 0],
        );

        let endpoint = quic_endpoint(&keypair, /* is_server= */ true);
        let p2p = P2p::new(keypair, endpoint, 1024, Default::default());
        let mut network = NetworkTile::new(disc_addr, discovery, addr, p2p, context)
            .map_err(std::io::Error::other)?;
        network.open_tcaches().map_err(std::io::Error::other)?;

        let compression =
            GossipHandler::new(gossip_tcaches, ssz_producer, protobuf_producer, boot_domain)
                .map_err(std::io::Error::other)?;

        let mut controller = Controller::new(
            PeerManager::new(
                PeerId::default(),
                Vec::new(),
                Vec::new(),
                ScoreParams::default(),
                SyncingConfig::default(),
                [0u8; 4],
                [0u8; METADATA_SIZE],
                0,
            ),
            compression,
            control_rpc_producer,
            controller_tcaches,
            cluster_out_producer,
            None,
            SyncEngine::new(SyncingConfig::default(), false, 0, Arc::new(SpecConfig::mainnet())),
            Arc::new(SpecConfig::mainnet()),
        )
        .map_err(std::io::Error::other)?;
        controller.open_tcaches().map_err(std::io::Error::other)?;

        let mut spine = SilverSpine::new_with_base_dir(base_dir, Some(path_suffix));
        let network_adapter = SpineAdapter::connect_tile(&network, &mut spine);
        let controller_adapter = SpineAdapter::connect_tile(&controller, &mut spine);
        let injector_tile = Injector;
        let injector_adapter = SpineAdapter::connect_tile(&injector_tile, &mut spine);
        let stats_tile = StatsSink;
        let stats_adapter = SpineAdapter::connect_tile(&stats_tile, &mut spine);

        Ok(Self {
            addr,
            peer_id,
            spine,
            network,
            controller,
            ssz_consumer,
            network_adapter,
            controller_adapter,
            injector_adapter,
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
