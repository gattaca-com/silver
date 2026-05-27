use std::{error::Error, path::Path, str::FromStr, sync::Arc, time::Instant};

use flux::{
    tile::{TileConfig, attach_tile},
    utils::ThreadPriority,
};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::RngCore;
use silver_beacon_state::{BeaconStateTile, SlotTicker};
use silver_common::{Config, Enr, ProtoIdentify, SilverSpine, TCache, TCacheProducer};
use silver_control::Controller;
use silver_discovery::{DiscV5, Discovery};
use silver_gossip::GossipHandler;
use silver_network::{Context, NetworkTile, P2p};
use silver_peer::PeerManager;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "alloc-profile")]
    let _alloc_profile_guard = silver_common::allocator::init_allocator_trace();

    tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::debug!("start");

    // TODO: generate random key pair
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    // TODO: fork digest
    let fork_digest = [0x8c, 0x9f, 0x62, 0xfe];
    let next_fork_version = [6, 0, 0, 0];
    let next_fork_epoch = u64::MAX;

    // Config
    let mut config = Config::new(secret, fork_digest, next_fork_version, next_fork_epoch)
        .with_discovery_port(31133)
        .with_quic_port(31123);
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() > 1 {
        config = config.with_checkpoint(args[1].clone());
    }

    // TCaches
    let incoming_gossip_producer =
        TCache::producer("incoming_gossip", config.incoming_gossip_tcache_size());
    let incoming_gossip_consumer =
        incoming_gossip_producer.cache_ref().consumer("incoming_gossip")?;
    let ssz_gossip_producer =
        TCache::producer("ssz_gossip", config.incoming_gossip_ssz_tcache_size());
    let ssz_gossip_consumer =
        ssz_gossip_producer.cache_ref().random_access("bs_ssz_gossip", true)?;
    let outgoing_gossip_producer =
        TCache::producer("outgoing_gossip", config.outgoing_gossip_tcache_size());
    let incoming_rpc_producer = TCache::producer("incoming_rpc", config.incoming_rpc_tcache_size());
    let incoming_rpc_consumer =
        incoming_rpc_producer.cache_ref().random_access("bs_incoming_rpc", true)?;

    // rpc producer
    let outgoing_rpc_producer = TCache::producer("outgoing_rpc", config.outgoing_rpc_tcache_size());

    // Tiles.
    let keypair = config.keypair()?;
    let local_enr = config.enr()?;

    let discv5_addr = config.discovery_bind_addr().expect("no discovery port");
    let p2p_addr = config.p2p_bind_addr().expect("no p2p port");
    let mut discv5 = DiscV5::new(
        config.discovery_config(),
        *keypair.secret_key(),
        local_enr,
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
        gossip_consumer: outgoing_gossip_producer
            .cache_ref()
            .random_access("p2p_outgoing_gossip", true)?,
        rpc_producer: incoming_rpc_producer,
        rpc_consumer: outgoing_rpc_producer.cache_ref().random_access("p2p_outgoing_rpc", true)?,
        identify: Some(ProtoIdentify::from((&config.identify()?, &keypair))),
    };

    let now = Instant::now();
    let enr1 = Enr::from_str(
        "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    )?;
    let enr2 = Enr::from_str(
        "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    )?;
    let enr3 = Enr::from_str(
        "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    )?;
    discv5.add_enr(&enr1, now);
    discv5.add_enr(&enr2, now);
    discv5.add_enr(&enr3, now);

    let network_tile = NetworkTile::new(discv5_addr, discv5, p2p_addr, p2p_endpoint, p2p_context)?;
    let gossip_tile = GossipHandler::new(
        incoming_gossip_consumer,
        ssz_gossip_producer,
        outgoing_gossip_producer,
        hex::encode(fork_digest),
    )?;
    let control_tile = Controller::new(
        PeerManager::new(
            config.gossip_topics()?,
            config.peer_score_params(),
            config.syncing(),
            config.fork_digest(),
            local_enr.into(),
        ),
        outgoing_rpc_producer,
    );

    let chain_config = config.chain_config();
    let ticker = SlotTicker::new(
        chain_config.genesis_unix_secs,
        chain_config.slot_duration(),
        chain_config.playload_lookahead(),
    );

    let checkpoint = match chain_config.checkpoint_file {
        Some(file) => load_checkpoint(file)?,
        None => vec![],
    };
    let beacon_state_tile = BeaconStateTile::new(
        ticker,
        chain_config.spec.clone(),
        ssz_gossip_consumer,
        incoming_rpc_consumer,
        &checkpoint,
    );

    // Spine
    let spine = SilverSpine::new(None);
    // TODO panic handler
    spine.start(None, None, |scoped_spine| {
        // TODO core config
        attach_tile(control_tile, scoped_spine, TileConfig::new(1, ThreadPriority::OSDefault));
        attach_tile(gossip_tile, scoped_spine, TileConfig::new(2, ThreadPriority::OSDefault));
        attach_tile(network_tile, scoped_spine, TileConfig::new(3, ThreadPriority::OSDefault));
        attach_tile(beacon_state_tile, scoped_spine, TileConfig::new(4, ThreadPriority::OSDefault));
    });

    Ok(())
}

fn load_checkpoint<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(file_path)
}
