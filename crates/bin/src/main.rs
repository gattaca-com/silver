use std::{error::Error, sync::Arc};

use flux::{
    tile::{TileConfig, attach_tile},
    utils::ThreadPriority,
};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::RngCore;
use silver_common::{Config, ProtoIdentify, SilverSpine, TCache, TCacheProducer};
use silver_control::Controller;
use silver_discovery::DiscV5;
use silver_gossip::GossipHandler;
use silver_network::{Context, NetworkTile, P2p};
use silver_peer::PeerManager;
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::debug!("start");

    // TODO: generate random key pair
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    // TODO: fork digest
    let fork_digest = [0u8; 4];

    // Config
    let config = Config::new(secret, fork_digest).with_discovery_port(31133).with_quic_port(31123);

    // TCaches
    let incoming_gossip_producer = TCache::producer(config.incoming_gossip_tcache_size());
    let incoming_gossip_consumer = incoming_gossip_producer.cache_ref().consumer()?;
    let ssz_gossip_producer = TCache::producer(config.incoming_gossip_ssz_tcache_size());
    let _ssz_gossip_consumer = ssz_gossip_producer.cache_ref().random_access()?;
    let outgoing_gossip_producer = TCache::producer(config.outgoing_gossip_tcache_size());
    let incoming_rpc_producer = TCache::producer(config.incoming_rpc_tcache_size());
    let outgoing_rpc_producer = TCache::multi_producer(config.outgoing_rpc_tcache_size());

    // Tiles.
    let keypair = config.keypair()?;

    let discv5_addr = config.discovery_bind_addr().expect("no discovery port");
    let p2p_addr = config.p2p_bind_addr().expect("no p2p port");
    let discv5 = DiscV5::new(
        config.discovery_config(),
        *keypair.secret_key(),
        config.enr()?,
        config.fork_digest(),
    );
    let server_config = silver_network::create_server_config(&keypair)?;
    let p2p_endpoint = P2p::new(
        keypair,
        Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server_config)),
            false,
            None,
        ),
    );
    let p2p_context = Context {
        gossip_producer: incoming_gossip_producer,
        gossip_consumer: outgoing_gossip_producer.cache_ref().random_access()?,
        rpc_producer: incoming_rpc_producer,
        rpc_consumer: outgoing_rpc_producer.cache_ref().random_access()?,
        identify: Some(ProtoIdentify::from((&config.identify()?, &keypair))),
    };

    let network_tile = NetworkTile::new(discv5_addr, discv5, p2p_addr, p2p_endpoint, p2p_context)?;
    let gossip_tile = GossipHandler::new(
        incoming_gossip_consumer,
        ssz_gossip_producer,
        outgoing_gossip_producer,
        hex::encode(fork_digest),
    )?;
    let control_tile =
        Controller::new(PeerManager::new(config.gossip_topics()?, config.peer_score_params()));

    // Spine
    let spine = SilverSpine::new(None);
    // TODO panic handler
    spine.start(None, None, |scoped_spine| {
        // TODO core config
        attach_tile(control_tile, scoped_spine, TileConfig::new(1, ThreadPriority::OSDefault));
        attach_tile(gossip_tile, scoped_spine, TileConfig::new(2, ThreadPriority::OSDefault));
        attach_tile(network_tile, scoped_spine, TileConfig::new(3, ThreadPriority::OSDefault));
    });

    Ok(())
}
