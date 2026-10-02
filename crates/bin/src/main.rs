use std::{
    error::Error,
    io,
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use flux::{
    tile::{TileConfig, attach_tile},
    utils::ThreadNiceness,
};
use mimalloc::MiMalloc;
use quinn_proto::{Endpoint, EndpointConfig};
use silver_application_boundary::ApplicationBoundaryTile;
use silver_beacon_state::{BeaconStateTile, SlotTicker};
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_columns::tile::DataColumnsTile;
#[cfg(feature = "alloc-profile")]
use silver_common::metrics::CountingAllocator;
use silver_common::{
    APP_NAME, GossipTopic, Keypair, MAX_BLOBS_PER_BLOCK, MAX_CLUSTER_MESSAGE_BYTES, ProtoIdentify,
    SilverSpine, TCache, TCacheId, TCacheProducer, TCacheReader, TCacheTable,
    cell_store::{CellStoreConfig, GOSSIP_DELIVERY_RETENTION},
    column_util::data_column_sidecar_len,
    profiler::enable_profiler,
    ssz_view::NUMBER_OF_COLUMNS,
    tracing::initialise_tracing_log,
};
use silver_config::Genesis;
use silver_control::{Controller, sync_engine::SyncEngine};
use silver_discovery::{DiscV5, Discovery};
use silver_gossip::GossipHandler;
use silver_httpcore::Bind;
use silver_network::{ClusterNodes, Context, NetworkTile, P2p};
use silver_peer::PeerManager;
use silver_storage::tile::StorageTile;

use crate::{args::Args, checkpoint::BootCheckpoint, cluster::ClusterStartup};

mod args;
mod checkpoint;
mod cluster;

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(feature = "alloc-profile")]
#[global_allocator]
static GLOBAL: CountingAllocator<MiMalloc> = CountingAllocator(MiMalloc);

/// Normal Raft protocol messages only.
const CLUSTER_MESSAGE_TCACHE_SIZE: usize = 1 << 22;

/// By-root request payloads: one root list per request.
const CONTROL_RPC_TCACHE_SIZE: usize = 1 << 20;

/// Attester shufflings, one `u32` per active validator: three epochs of a
/// two-million-validator set, so the two the validator API serves never wait
/// on the one being written.
const BEACON_STATE_TCACHE_SIZE: usize = 1 << 25;
/// Every column of a full block is about 6 MiB.
const PROPOSED_COLUMNS_TCACHE_SIZE: usize = 1 << 24;
const _: () = assert!(
    PROPOSED_COLUMNS_TCACHE_SIZE >=
        2 * NUMBER_OF_COLUMNS * data_column_sidecar_len(MAX_BLOBS_PER_BLOCK),
    "two held proposals must fit without wrapping"
);

/// The commit stays first: telemetry reads the first field as the commit.
const BUILD_INFO: &str = build_info::format!(
    "{} · v{} · {}",
    $.version_control?.git()?.commit_short_id,
    $.crate_info.version,
    $.timestamp
);

fn publish_build_info() -> io::Result<()> {
    let dir = flux::utils::directories::shmem_dir_queues(APP_NAME);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("build-info"), BUILD_INFO)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let build_info_log = format!("silver build info: {BUILD_INFO}");
    let _tracing = initialise_tracing_log("silver", 10, None, false, Some(&build_info_log));
    if let Err(e) = silver_log::counts::enable(APP_NAME) {
        silver_log::error!(%e, "log counts disabled");
    }
    silver_log::debug!("start");

    // `#[timed]` is inert until a process opts in.
    enable_profiler(APP_NAME);

    let config = args.config()?;

    let boot_checkpoint = BootCheckpoint::load(&config)
        .inspect_err(|e| silver_log::error!(%e, "no boot checkpoint"))?;
    let booting_from_local_checkpoint = !boot_checkpoint.is_empty();
    silver_log::info!("booting from local checkpoint: {booting_from_local_checkpoint}");

    let genesis = Genesis::from_state(boot_checkpoint.ssz())?;

    let chain_config = config.chain_config();
    let wall_epoch = chain_config.wall_epoch(&genesis);
    let fork_digest = chain_config.checked_fork_digest(wall_epoch, &genesis)?;
    silver_log::info!("loaded config with fork digest: {}", hex::encode(fork_digest));

    publish_build_info()?;
    chain_config.node_chain(&genesis).publish()?;

    // TCaches
    let network_ingress_producer =
        TCache::producer(TCacheId::NetworkIngress, config.incoming_gossip_tcache_size());
    let control_processing_producer =
        TCache::producer(TCacheId::ControlProcessing, config.incoming_gossip_ssz_tcache_size());
    let control_gossip_producer =
        TCache::producer(TCacheId::ControlGossip, config.outgoing_gossip_tcache_size());
    let network_processing_producer =
        TCache::producer(TCacheId::NetworkProcessing, config.incoming_rpc_tcache_size());
    let boundary_processing_producer = TCache::producer(
        TCacheId::BoundaryProcessing,
        config.engine_config().incoming_engine_resp_tcache_size,
    );
    let cluster_cache_bytes = if config.cluster_config().is_some() {
        4 * MAX_CLUSTER_MESSAGE_BYTES
    } else {
        CLUSTER_MESSAGE_TCACHE_SIZE
    };
    let cluster_inbound_producer = TCache::producer(TCacheId::ClusterInbound, cluster_cache_bytes);
    let cluster_outbound_producer =
        TCache::producer(TCacheId::ClusterOutbound, cluster_cache_bytes);
    let control_rpc_producer = TCache::producer(TCacheId::ControlRpc, CONTROL_RPC_TCACHE_SIZE);
    let storage_delivery_producer =
        TCache::producer(TCacheId::StorageDelivery, config.outgoing_rpc_tcache_size());
    let beacon_state_handoff_producer =
        TCache::producer(TCacheId::BeaconStateHandoff, BEACON_STATE_TCACHE_SIZE);
    let proposed_columns_producer =
        TCache::producer(TCacheId::ProposedColumns, PROPOSED_COLUMNS_TCACHE_SIZE);

    // Tiles.
    let keypair = Keypair::load_or_create(Path::new(config.data_storage_dir()))?;
    let enr_fork_id = chain_config.spec.enr_fork_id(wall_epoch, fork_digest);
    let mut local_enr = config.enr(&keypair, enr_fork_id)?;

    silver_log::info!(enr = local_enr.to_base64(), "local ENR on startup");

    let spec = Arc::new(chain_config.spec.clone());
    sleep_until_genesis(genesis.unix_secs);
    let ticker = SlotTicker::new(
        genesis.unix_secs,
        chain_config.slot_duration(),
        chain_config.playload_lookahead(),
    );

    // Long-lived subnets: advertised from boot (peer retention exempts us
    // from excess-peer pruning); the gossip subscriptions themselves
    // activate once Following — see `Controller::long_lived_pending`.
    let boot_wall_slot = ticker.current_slot();
    let boot_epoch = boot_wall_slot / SLOTS_PER_EPOCH;
    let attnet_count = config.attestation_subnet_count();
    let subnets = local_enr.node_id().attestation_subnets(boot_epoch, attnet_count);
    local_enr.set_attnets(subnets, keypair.secret_key())?;
    let mut gossip_topics = config.gossip_topics()?;
    let mut long_lived_attnets = u64::from_le_bytes(subnets);
    let mut long_lived_syncnets = config.sync_committee_subnets().long_lived();
    // Configured subnet topics subscribe at boot, so duties never leave them.
    for topic in &gossip_topics {
        match *topic {
            GossipTopic::BeaconAttestation(subnet) => long_lived_attnets |= 1 << subnet,
            GossipTopic::SyncCommittee(subnet) => long_lived_syncnets |= 1 << subnet,
            _ => {}
        }
    }
    local_enr.set_syncnets(long_lived_syncnets, keypair.secret_key())?;

    // Cluster configuration
    let cluster_startup = config
        .cluster_config()
        .map(|cluster| {
            ClusterStartup::new(cluster, &local_enr, Path::new(config.data_storage_dir()))
        })
        .transpose()?;
    let cluster_nodes = config.cluster_config().map(|cluster| cluster.nodes.clone());

    let discv5_addr = config.discovery_bind_addr().expect("no discovery port");
    let p2p_addr = config.p2p_bind_addr().expect("no p2p port");
    let mut discv5 =
        DiscV5::new(config.discovery_config(), *keypair.secret_key(), local_enr, fork_digest);

    // Cluster peers are added as trusted peers
    let cluster_peers = cluster_nodes
        .as_ref()
        .map(|m| m.values())
        .unwrap_or_default()
        .filter(|enr| enr.node_id() != local_enr.node_id());
    let trusted_peers =
        config.trusted_peers().iter().chain(cluster_peers).cloned().collect::<Vec<_>>();
    let trusted_ips = trusted_peers
        .iter()
        .filter_map(|enr| enr.ip4().map(IpAddr::from).or(enr.ip6().map(IpAddr::from)))
        .collect();

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
        trusted_ips,
    );
    let identify = config.identify(&keypair)?;

    let now = Instant::now();

    let bootnodes = &config.chain_config().bootstrap_enrs;

    for enr in bootnodes {
        discv5.add_enr(enr, now);
    }

    // cgc is floored at SAMPLES_PER_SLOT when the ENR is built (see Config::enr).
    let das_custody_groups = local_enr
        .node_id()
        .custody_groups(local_enr.cgc().unwrap_or(silver_common::SAMPLES_PER_SLOT as u64) as u8);
    for i in 0..128 {
        if das_custody_groups & (1 << i) != 0 {
            gossip_topics.push(GossipTopic::DataColumnSidecar(i));
        }
    }

    let partial_columns = config.partial_columns();

    let cell_config =
        CellStoreConfig::new(spec.clone(), das_custody_groups, GOSSIP_DELIVERY_RETENTION)
            .map_err(|error| format!("cell store configuration: {error:?}"))?;
    let control_slot_producer =
        TCache::producer(TCacheId::ControlSlot, cell_config.cache_capacity());
    let (cell_slot, cell_slot_start) = ticker.current_slot_start();

    // Every tile opens the consumers it reads through in `try_init`.
    let tcaches = TCacheTable::from_iter([
        network_ingress_producer.cache_ref(),
        control_processing_producer.cache_ref(),
        control_gossip_producer.cache_ref(),
        network_processing_producer.cache_ref(),
        boundary_processing_producer.cache_ref(),
        cluster_inbound_producer.cache_ref(),
        cluster_outbound_producer.cache_ref(),
        control_rpc_producer.cache_ref(),
        storage_delivery_producer.cache_ref(),
        beacon_state_handoff_producer.cache_ref(),
        control_slot_producer.cache_ref(),
        proposed_columns_producer.cache_ref(),
    ]);

    let p2p_context = Context {
        gossip_producer: network_ingress_producer,
        rpc_producer: network_processing_producer,
        identify: Some(ProtoIdentify::from((&identify, &keypair))),
        cluster_nodes: cluster_nodes.map(ClusterNodes::new),
        cluster_inbound_producer,
        partial_columns: partial_columns.supports_sending(),
        reader: TCacheReader::new(tcaches),
    };
    let network_tile = NetworkTile::new(discv5_addr, discv5, p2p_addr, p2p_endpoint, p2p_context)?;

    let gossip_handler = GossipHandler::new(
        tcaches,
        control_processing_producer,
        control_gossip_producer,
        Some(silver_common::GossipDomain::new(fork_digest, spec.fork_at_slot(boot_wall_slot))),
    )?;

    let mut control_tile = Controller::new(
        PeerManager::new(
            keypair.peer_id(),
            trusted_peers,
            gossip_topics,
            config.peer_score_params(),
            config.syncing_config(),
            fork_digest,
            local_enr.into(),
            das_custody_groups,
        ),
        gossip_handler,
        control_rpc_producer,
        tcaches,
        cluster_outbound_producer,
        cluster_startup.as_ref().map(|cluster| cluster.config.clone()),
        SyncEngine::new(
            config.syncing_config(),
            booting_from_local_checkpoint,
            das_custody_groups,
            spec.clone(),
        ),
        spec.clone(),
        long_lived_attnets,
        long_lived_syncnets,
    )?;
    control_tile = control_tile
        .with_data_columns_cache(
            cell_config.clone(),
            control_slot_producer,
            cell_slot,
            cell_slot_start,
            partial_columns,
        )
        .map_err(|error| format!("cell store construction: {error:?}"))?;

    let checkpoint = boot_checkpoint.decompose(&chain_config.spec);
    control_tile
        .set_gossip_clock(ticker.clone(), &checkpoint.state().immutable.genesis_validators_root);
    let beacon_state_tile = BeaconStateTile::new(
        ticker,
        spec.clone(),
        &config.syncing_config(),
        tcaches,
        beacon_state_handoff_producer,
        !config.disable_weak_subjectivity_check(),
        checkpoint,
        config.suggested_fee_recipient(),
        config.surround_epochs(),
    );
    let state_reader = beacon_state_tile.reader();

    let storage_tile = StorageTile::new(
        tcaches,
        storage_delivery_producer,
        state_reader,
        das_custody_groups,
        spec.clone(),
        config.data_storage_dir().into(),
        booting_from_local_checkpoint,
    );

    let state_reader = beacon_state_tile.reader();
    let data_columns_tile = DataColumnsTile::new(
        tcaches,
        state_reader,
        das_custody_groups,
        spec.clone(),
        SlotTicker::new(
            genesis.unix_secs,
            chain_config.slot_duration(),
            chain_config.playload_lookahead(),
        ),
        proposed_columns_producer,
    )
    .with_data_columns_cache(cell_config, cell_slot, cell_slot_start)
    .map_err(|error| format!("cell store construction: {error:?}"))?;

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
        tcaches,
        boundary_processing_producer,
    );

    // Spine
    let spine = SilverSpine::new(None);
    spine.start(None, None, |scoped_spine| {
        // Attach application_boundary_tiles first so its `on_attach` can subscribe to
        // peer events before their producers start.
        attach_tile(
            application_boundary_tile,
            scoped_spine,
            TileConfig::new(5, Some(ThreadNiceness::Highest)),
        );

        attach_tile(control_tile, scoped_spine, TileConfig::new(1, Some(ThreadNiceness::Highest)));
        attach_tile(network_tile, scoped_spine, TileConfig::new(2, Some(ThreadNiceness::Highest)));
        attach_tile(
            beacon_state_tile,
            scoped_spine,
            TileConfig::new(3, Some(ThreadNiceness::Highest)),
        );
        attach_tile(storage_tile, scoped_spine, TileConfig::new(4, Some(ThreadNiceness::Highest)));
        attach_tile(
            data_columns_tile,
            scoped_spine,
            TileConfig::new(6, Some(ThreadNiceness::Highest)),
        );
    });

    Ok(())
}

fn sleep_until_genesis(genesis_unix_secs: u64) {
    let genesis = UNIX_EPOCH + Duration::from_secs(genesis_unix_secs);
    let Ok(remaining) = genesis.duration_since(SystemTime::now()) else {
        return;
    };

    silver_log::info!("waiting {}s for genesis at {genesis_unix_secs}", remaining.as_secs());
    std::thread::sleep(remaining);
}
