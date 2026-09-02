use std::{error::Error, str::FromStr, sync::Arc, time::Instant};

use flux::{
    tile::{TileConfig, attach_tile},
    utils::ThreadNiceness,
};
use mimalloc::MiMalloc;
use quinn_proto::{Endpoint, EndpointConfig};
use rand::RngCore;
use silver_application_boundary::ApplicationBoundaryTile;
use silver_beacon_state::{BeaconStateTile, SlotTicker};
use silver_beacon_state_data::{BeaconState, SLOTS_PER_EPOCH};
use silver_columns::tile::{ColumnConsumers, DataColumnsTile};
#[cfg(feature = "alloc-profile")]
use silver_common::metrics::CountingAllocator;
use silver_common::{
    APP_NAME, Enr, ProtoIdentify, SilverSpine, TCache, TCacheProducer, profiler::enable_profiler,
    tracing::initialise_tracing_log,
};
use silver_config::Config;
use silver_control::{Controller, sync_engine::SyncEngine};
use silver_discovery::{DiscV5, Discovery};
use silver_gossip::GossipHandler;
use silver_httpcore::Bind;
use silver_network::{Context, NetworkTile, P2p};
use silver_peer::PeerManager;
use silver_storage::{latest_local_checkpoint, tile::StorageTile};

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(feature = "alloc-profile")]
#[global_allocator]
static GLOBAL: CountingAllocator<MiMalloc> = CountingAllocator(MiMalloc);

fn main() -> Result<(), Box<dyn Error>> {
    let _tracing = initialise_tracing_log("silver", 10, None, false);
    tracing::debug!("start");

    // `#[timed]` is inert until a process opts in.
    enable_profiler(APP_NAME);

    let config = load_config()?;

    tracing::info!("loaded config with fork digest: {}", hex::encode(config.fork_digest()));

    // TCaches
    let incoming_gossip_producer =
        TCache::producer("incoming_gossip", config.incoming_gossip_tcache_size());
    let incoming_gossip_consumer =
        incoming_gossip_producer.cache_ref().random_access("incoming_gossip", true)?; //.consumer("incoming_gossip")?;
    let ssz_gossip_producer =
        TCache::producer("ssz_gossip", config.incoming_gossip_ssz_tcache_size());
    let ssz_gossip_consumer =
        ssz_gossip_producer.cache_ref().random_access("bs_ssz_gossip", true)?;
    let ssz_gossip_consumer_dc =
        ssz_gossip_producer.cache_ref().random_access("dc_ssz_gossip", true)?;
    let ssz_persist_gossip_consumer_ds =
        ssz_gossip_producer.cache_ref().random_access("ds_persist_ssz_gossip", true)?;
    let ssz_persist_gossip_consumer_dc =
        ssz_gossip_producer.cache_ref().random_access("dc_persist_ssz_gossip", true)?;
    let ssz_gossip_consumer_eng =
        ssz_gossip_producer.cache_ref().random_access("eng_ssz_gossip", true)?;
    let outgoing_gossip_producer =
        TCache::producer("outgoing_gossip", config.outgoing_gossip_tcache_size());
    let incoming_rpc_producer = TCache::producer("incoming_rpc", config.incoming_rpc_tcache_size());
    let incoming_rpc_consumer =
        incoming_rpc_producer.cache_ref().random_access("bs_incoming_rpc", true)?;
    let incoming_rpc_consumer_ds =
        incoming_rpc_producer.cache_ref().random_access("ds_incoming_rpc", true)?;
    let incoming_rpc_consumer_dc =
        incoming_rpc_producer.cache_ref().random_access("dc_incoming_rpc", true)?;
    let persist_rpc_consumer_ds =
        incoming_rpc_producer.cache_ref().random_access("ds_persist_incoming_rpc", true)?;
    let persist_rpc_consumer_dc =
        incoming_rpc_producer.cache_ref().random_access("dc_persist_incoming_rpc", true)?;
    let incoming_rpc_consumer_eng =
        incoming_rpc_producer.cache_ref().random_access("eng_incoming_rpc", true)?;
    let incoming_rpc_consumer_ctl =
        incoming_rpc_producer.cache_ref().random_access("ctl_incoming_rpc", true)?;
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

    // engine producer
    let el_producer = TCache::producer("el_data_columns", 1 << 25);
    let el_columns_consumer = el_producer.cache_ref().random_access("el_data_columns", true)?;

    // Tiles.
    let keypair = config.keypair()?;
    let mut local_enr = config.enr()?;

    let chain_config = config.chain_config();
    let ticker = SlotTicker::new(
        chain_config.genesis_unix_secs,
        chain_config.slot_duration(),
        chain_config.playload_lookahead(),
    );

    // Long-lived attnets: advertised from boot (peer retention exempts us
    // from excess-peer pruning); the gossip subscriptions themselves
    // activate once Following — see `Controller::pending_subnet_topics`.
    let boot_epoch = ticker.current_slot() / SLOTS_PER_EPOCH;
    let attnet_count = config.attestation_subnet_count();
    let subnets = local_enr.node_id().attestation_subnets(boot_epoch, attnet_count);
    local_enr.set_attnets(subnets, keypair.secret_key())?;

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
        config.max_connections(),
    );
    let identify = config.identify()?;
    let p2p_context = Context {
        gossip_producer: incoming_gossip_producer,
        gossip_consumer: outgoing_gossip_producer
            .cache_ref()
            .strict_random_access("p2p_outgoing_gossip", true)?,
        rpc_producer: incoming_rpc_producer,
        rpc_consumer: outgoing_rpc_producer.cache_ref().random_access("p2p_outgoing_rpc", true)?,
        identify: Some(ProtoIdentify::from((&identify, &keypair))),
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

    let (checkpoint, checkpoint_pubkeys) = load_checkpoint(&config)?;
    let booting_from_local_checkpoint = !checkpoint.is_empty();

    tracing::info!("booting from local checkpoint: {booting_from_local_checkpoint}");

    let spec = Arc::new(chain_config.spec.clone());

    let gossip_handler = GossipHandler::new(
        incoming_gossip_consumer,
        ssz_gossip_producer,
        outgoing_gossip_producer,
        hex::encode(config.fork_digest()),
    )?;

    let mut control_tile = Controller::new(
        PeerManager::new(
            keypair.peer_id(),
            gossip_topics,
            config.peer_score_params(),
            config.syncing_config(),
            config.fork_digest(),
            local_enr.into(),
            das_custody_groups,
        ),
        gossip_handler,
        outgoing_rpc_producer.clone(),
        incoming_rpc_consumer_ctl,
        SyncEngine::new(
            config.syncing_config(),
            booting_from_local_checkpoint,
            das_custody_groups,
            spec.clone(),
        ),
    );
    control_tile.set_pending_subnet_topics(
        silver_common::attnet_subnets(subnets)
            .map(silver_common::GossipTopic::BeaconAttestation)
            .collect(),
    );

    // A finalized checkpoint state is mandatory (no genesis or runtime sync):
    // an empty/absent blob falls through to `decompose`, which errors here and
    // crashes the boot rather than running an inert node.
    let state = BeaconState::from_checkpoint(&checkpoint, &chain_config.spec, &checkpoint_pubkeys)
        .unwrap_or_else(|e| panic!("bootstrap: decompose checkpoint failed: {e}"));
    let beacon_state_tile = BeaconStateTile::new(
        ticker,
        spec.clone(),
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
        ssz_persist_gossip_consumer_ds,
        incoming_rpc_consumer_ds,
        persist_rpc_consumer_ds,
        el_columns_consumer,
        outgoing_rpc_producer,
        replay_blocks_producer,
        state_reader,
        das_custody_groups,
        spec.clone(),
        config.data_storage_dir().into(),
        booting_from_local_checkpoint,
    );

    let state_reader = beacon_state_tile.reader();
    let data_columns_tile = DataColumnsTile::new(
        ColumnConsumers {
            gossip: ssz_gossip_consumer_dc,
            persist_gossip: ssz_persist_gossip_consumer_dc,
            rpc: incoming_rpc_consumer_dc,
            persist_rpc: persist_rpc_consumer_dc,
        },
        state_reader,
        das_custody_groups,
        spec.clone(),
        incoming_engine_resp_consumer_ds,
        el_producer,
    );

    let beacon_api_binds =
        config.beacon_api_bind().iter().map(String::as_str).map(Bind::parse).collect::<Vec<_>>();
    let application_boundary_tile = ApplicationBoundaryTile::new(
        &beacon_api_binds,
        config.beacon_api_max_connections(),
        config.beacon_api_idle_timeout(),
        &keypair,
        local_enr,
        &identify,
        &spec,
        beacon_state_tile.reader(),
        config.engine_config(),
        ssz_gossip_consumer_eng,
        incoming_rpc_consumer_eng,
        incoming_engine_resp_producer,
    );

    // Spine
    let spine = SilverSpine::new(None);
    spine.start(None, None, |scoped_spine| {
        // TODO core config
        attach_tile(control_tile, scoped_spine, TileConfig::new(1, Some(ThreadNiceness::Highest)));
        attach_tile(network_tile, scoped_spine, TileConfig::new(2, Some(ThreadNiceness::Highest)));
        attach_tile(
            beacon_state_tile,
            scoped_spine,
            TileConfig::new(3, Some(ThreadNiceness::Highest)),
        );
        attach_tile(storage_tile, scoped_spine, TileConfig::new(4, Some(ThreadNiceness::Highest)));
        attach_tile(
            application_boundary_tile,
            scoped_spine,
            TileConfig::new(5, Some(ThreadNiceness::Highest)),
        );
        attach_tile(
            data_columns_tile,
            scoped_spine,
            TileConfig::new(6, Some(ThreadNiceness::Highest)),
        );
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
    if let Some(binds) =
        args.iter().position(|a| a == "--beacon-api-bind").and_then(|i| args.get(i + 1))
    {
        config = config.with_beacon_api_bind(comma_separated(binds));
    }

    tracing::info!("loaded config: {config:#?}");

    Ok(config)
}

/// List form for CLI flags whose config counterpart is a TOML array. A comma
/// is neither valid in a `SocketAddr` nor sane in a socket path, so it can
/// never be part of one value.
fn comma_separated(value: &str) -> Vec<String> {
    value.split(',').map(str::to_owned).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_api_bind_flag_takes_one_value_or_a_comma_separated_list() {
        assert_eq!(comma_separated("0.0.0.0:5051"), ["0.0.0.0:5051"]);

        let binds = comma_separated("0.0.0.0:5051,[::1]:5052,/run/silver/beacon.sock")
            .iter()
            .map(String::as_str)
            .map(Bind::parse)
            .collect::<Vec<_>>();
        assert_eq!(binds, [
            Bind::Tcp("0.0.0.0:5051".parse().unwrap()),
            Bind::Tcp("[::1]:5052".parse().unwrap()),
            Bind::Unix("/run/silver/beacon.sock".into()),
        ]);
    }
}
