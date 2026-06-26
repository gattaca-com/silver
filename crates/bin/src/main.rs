use std::{error::Error, str::FromStr, sync::Arc, time::Instant};

use flux::{
    tile::{TileConfig, attach_tile},
    utils::ThreadPriority,
};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::RngCore;
use silver_beacon_state::{BeaconStateTile, SlotTicker};
use silver_beacon_state_data::BeaconState;
use silver_common::{
    Enr, ProtoIdentify, SilverSpine, TCache, TCacheProducer, tracing::initialise_tracing_log,
};
use silver_config::Config;
use silver_control::Controller;
use silver_discovery::{DiscV5, Discovery};
use silver_engine::EngineTile;
use silver_gossip::GossipHandler;
use silver_network::{Context, NetworkTile, P2p};
use silver_peer::PeerManager;
use silver_storage::{latest_local_checkpoint, tile::StorageTile};

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "alloc-profile")]
    let _alloc_profile_guard = silver_common::allocator::init_allocator_trace();

    let _tracing = initialise_tracing_log("silver", 10, None, false);
    tracing::debug!("start");

    // `#[timed]` is inert until a process opts in.
    silver_common::flamegraph_timer::enable_surfer();

    let config = load_config()?;

    tracing::info!("loaded config with fork digest: {}", hex::encode(config.fork_digest()));

    // TCaches
    let incoming_gossip_producer =
        TCache::producer("incoming_gossip", config.incoming_gossip_tcache_size());
    let incoming_gossip_consumer =
        incoming_gossip_producer.cache_ref().consumer("incoming_gossip")?;
    let ssz_gossip_producer =
        TCache::producer("ssz_gossip", config.incoming_gossip_ssz_tcache_size());
    let ssz_gossip_consumer =
        ssz_gossip_producer.cache_ref().random_access("bs_ssz_gossip", true)?;
    let ssz_gossip_consumer_ds =
        ssz_gossip_producer.cache_ref().random_access("ds_ssz_gossip", true)?;
    let ssz_persist_gossip_consumer_ds =
        ssz_gossip_producer.cache_ref().random_access("ds_persist_ssz_gossip", true)?;
    let ssz_gossip_consumer_eng =
        ssz_gossip_producer.cache_ref().random_access("eng_ssz_gossip", true)?;
    let outgoing_gossip_producer =
        TCache::producer("outgoing_gossip", config.outgoing_gossip_tcache_size());
    let incoming_rpc_producer = TCache::producer("incoming_rpc", config.incoming_rpc_tcache_size());
    let incoming_rpc_consumer =
        incoming_rpc_producer.cache_ref().random_access("bs_incoming_rpc", true)?;
    let incoming_rpc_consumer_ds =
        incoming_rpc_producer.cache_ref().random_access("ds_incoming_rpc", true)?;
    let persist_rpc_consumer_ds =
        incoming_rpc_producer.cache_ref().random_access("ds_persist_incoming_rpc", true)?;
    let incoming_rpc_consumer_eng =
        incoming_rpc_producer.cache_ref().random_access("eng_incoming_rpc", true)?;
    let incoming_engine_resp_producer = TCache::producer(
        "incoming_engine_resp",
        config.engine_config().incoming_engine_resp_tcache_size,
    );
    let incoming_engine_resp_consumer =
        incoming_engine_resp_producer.cache_ref().random_access("engine_incoming_resp", true)?;
    let incoming_engine_resp_consumer_ds =
        incoming_engine_resp_producer.cache_ref().random_access("ds_engine_incoming_resp", true)?;

    // rpc producer
    let outgoing_rpc_producer =
        TCache::multi_producer("outgoing_rpc", config.outgoing_rpc_tcache_size());
    let replay_blocks_producer = TCache::producer("replay_blocks", 1 << 25);
    let replay_blocks_consumer =
        replay_blocks_producer.cache_ref().random_access("bs_replay", true)?;

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

    let bootnodes = if !config.chain_config().bootstrap_enrs.is_empty() {
        config.chain_config().bootstrap_enrs.clone()
    } else {
        vec![
            Enr::from_str(
                "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
            )?,
            Enr::from_str(
                "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
            )?,
            Enr::from_str(
                "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
            )?,
        ]
    };

    for enr in &bootnodes {
        discv5.add_enr(enr, now);
    }

    // cgc is floored at SAMPLES_PER_SLOT when the ENR is built (see Config::enr).
    let das_custody_groups = local_enr
        .node_id()
        .custody_groups(local_enr.cgc().unwrap_or(silver_common::SAMPLES_PER_SLOT as u64) as u8);
    let mut gossip_topics = config.gossip_topics()?;
    for i in 0..128 {
        if das_custody_groups & (1 << i) != 0 {
            gossip_topics.push(silver_common::GossipTopic::DataColumnSidecar(i));
        }
    }

    let network_tile = NetworkTile::new(discv5_addr, discv5, p2p_addr, p2p_endpoint, p2p_context)?;
    let gossip_tile = GossipHandler::new(
        incoming_gossip_consumer,
        ssz_gossip_producer,
        outgoing_gossip_producer,
        hex::encode(config.fork_digest()),
    )?;

    let chain_config = config.chain_config();
    let ticker = SlotTicker::new(
        chain_config.genesis_unix_secs,
        chain_config.slot_duration(),
        chain_config.playload_lookahead(),
    );

    let (checkpoint, checkpoint_pubkeys) = load_checkpoint(&config)?;
    let booting_from_local_checkpoint = !checkpoint.is_empty();

    tracing::info!("booting from local checkpoint: {booting_from_local_checkpoint}");

    let control_tile = Controller::new(
        PeerManager::new(
            gossip_topics,
            config.peer_score_params(),
            config.syncing_config(),
            config.fork_digest(),
            local_enr.into(),
            das_custody_groups,
            booting_from_local_checkpoint,
        ),
        outgoing_rpc_producer.clone(),
    );

    // A finalized checkpoint state is mandatory (no genesis or runtime sync):
    // an empty/absent blob falls through to `decompose`, which errors here and
    // crashes the boot rather than running an inert node.
    let state = BeaconState::from_checkpoint(&checkpoint, &chain_config.spec, &checkpoint_pubkeys)
        .unwrap_or_else(|e| panic!("bootstrap: decompose checkpoint failed: {e}"));
    let beacon_state_tile = BeaconStateTile::new(
        ticker,
        chain_config.spec.clone(),
        &config.syncing_config(),
        ssz_gossip_consumer,
        incoming_rpc_consumer,
        incoming_engine_resp_consumer,
        replay_blocks_consumer,
        !config.disable_weak_subjectivity_check(),
        state,
    );
    let state_reader = beacon_state_tile.reader();

    let storage_tile = StorageTile::new(
        ssz_gossip_consumer_ds,
        ssz_persist_gossip_consumer_ds,
        incoming_rpc_consumer_ds,
        persist_rpc_consumer_ds,
        outgoing_rpc_producer,
        replay_blocks_producer,
        state_reader,
        das_custody_groups,
        config.fork_digest(),
        config.data_storage_dir().into(),
        booting_from_local_checkpoint,
        incoming_engine_resp_consumer_ds,
    );

    let engine_tile = EngineTile::new(
        config.engine_config(),
        ssz_gossip_consumer_eng,
        incoming_rpc_consumer_eng,
        incoming_engine_resp_producer,
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
        attach_tile(storage_tile, scoped_spine, TileConfig::new(5, ThreadPriority::OSDefault));
        attach_tile(engine_tile, scoped_spine, TileConfig::new(6, ThreadPriority::OSDefault));
    });

    Ok(())
}

fn load_config() -> Result<Config, silver_common::Error> {
    let args = std::env::args().collect::<Vec<_>>();
    let config_path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1));
    let mut config = match config_path {
        // Devnet / custom: every network-specific value (fork_digest,
        // genesis, bootstrap ENRs, external IP, ports, secret key) comes
        // from the file — no source edits needed.
        Some(path) => Config::from_file(path)?,
        // Default: mainnet, random identity, hardcoded bootnodes below.
        None => {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            let fork_digest = [0x8c, 0x9f, 0x62, 0xfe];
            let next_fork_version = [6, 0, 0, 0];
            let next_fork_epoch = u64::MAX;
            let mut config = Config::new(secret, fork_digest, next_fork_version, next_fork_epoch)
                .with_discovery_port(31133)
                .with_quic_port(31123);

            if let Some(ckpt) = args.get(1).filter(|a| !a.starts_with("--")) {
                config = config.with_checkpoint(ckpt.to_string());
                if let Some(pk) = args.get(2).filter(|a| !a.starts_with("--")) {
                    config = config.with_checkpoint_pubkeys(pk.to_string());
                }
            }

            config
        }
    };

    if args.iter().any(|a| a == "--disable-weak-subjectivity") {
        config = config.with_disable_weak_subjectivity_check(true);
    }
    if args.iter().any(|a| a == "--unsafe-no-el") {
        config = config.with_unsafe_no_el(true);
    }

    Ok(config)
}

fn load_checkpoint(config: &Config) -> Result<(Vec<u8>, Vec<u8>), std::io::Error> {
    let chain_config = config.chain_config();
    match &chain_config.checkpoint_file {
        Some(file) => {
            tracing::info!("using the config checkpoint at {}", file);
            let checkpoint = std::fs::read(file)?;
            let pubkeys = match &chain_config.checkpoint_pubkeys_file {
                Some(file) if !checkpoint.is_empty() => std::fs::read(file)?,
                _ => vec![],
            };
            Ok((checkpoint, pubkeys))
        }
        None => match latest_local_checkpoint(config.data_storage_dir()) {
            Some((slot, ssz_path, pubkeys_path)) => {
                tracing::info!(
                    slot,
                    "checkpoint not set in the config, booting from the latest persisted one."
                );
                let pubkeys = pubkeys_path.map(std::fs::read).transpose()?.unwrap_or_default();
                Ok((std::fs::read(ssz_path)?, pubkeys))
            }
            None => {
                panic!(
                    "no checkpoint to bootstrap from: `chain_config.checkpoint_file` is unset \
                     and no persisted checkpoint was found under the data directory ({}). \
                     Set `checkpoint_file` to a finalized BeaconState SSZ (e.g. fetched from a \
                     trusted node's /eth/v2/debug/beacon/states/finalized), or run against a \
                     data directory that already holds a persisted checkpoint.",
                    config.data_storage_dir()
                );
            }
        },
    }
}
