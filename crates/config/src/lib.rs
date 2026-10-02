use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub use chain_config::{BootSource, ChainConfig, ChainOverrides};
pub use cluster_config::ClusterConfig;
pub use discovery_config::DiscoveryConfig;
pub use engine_config::EngineConfig;
pub use genesis::Genesis;
pub use network::Network;
pub use peer_score_params::ScoreParams;
use serde::{Deserialize, Serialize};
pub use silver_common::cell_store::PartialColumnsMode;
use silver_common::{
    Enr, Error, GossipTopic, Identify, Keypair, PeerId, SAMPLES_PER_SLOT, SYNC_COMMITTEE_SUBNETS,
    StreamProtocol,
};
pub use syncing_config::{PendingBounds, SyncingConfig};

mod chain_config;
mod cluster_config;
mod discovery_config;
mod engine_config;
mod genesis;
mod network;
mod peer_score_params;
mod syncing_config;

const fn default_usize<const N: usize>() -> usize {
    N
}

const fn default_u8<const V: u8>() -> u8 {
    V
}

const fn default_u32<const V: u32>() -> u32 {
    V
}

const fn default_u64<const V: u64>() -> u64 {
    V
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncCommitteeSubnets {
    #[default]
    All,
    OnDemand,
}

impl SyncCommitteeSubnets {
    pub fn long_lived(self) -> u8 {
        match self {
            Self::All => (1 << SYNC_COMMITTEE_SUBNETS) - 1,
            Self::OnDemand => 0,
        }
    }
}

fn default_beacon_api_bind() -> Vec<String> {
    vec!["0.0.0.0:5051".into()]
}

fn default_supported_protocols() -> Vec<String> {
    vec![
        StreamProtocol::Identity.multiselect_string(),
        StreamProtocol::GossipSub.multiselect_string(),
        StreamProtocol::GossipSubV13.multiselect_string(),
        StreamProtocol::StatusV1.multiselect_string(),
        StreamProtocol::StatusV2.multiselect_string(),
        StreamProtocol::Ping.multiselect_string(),
        StreamProtocol::Goodbye.multiselect_string(),
        StreamProtocol::Metadata.multiselect_string(),
        StreamProtocol::BeaconBlocksByRange.multiselect_string(),
        StreamProtocol::DataColumnSidecarsByRange.multiselect_string(),
        StreamProtocol::BeaconBlocksByRoot.multiselect_string(),
        StreamProtocol::DataColumnSidecarsByRoot.multiselect_string(),
    ]
}

fn default_gossip_topics() -> Vec<String> {
    vec![
        GossipTopic::BeaconBlock.to_string(),
        GossipTopic::BeaconAggregateAndProof.to_string(),
        GossipTopic::VoluntaryExit.to_string(),
        GossipTopic::ProposerSlashing.to_string(),
        GossipTopic::AttesterSlashing.to_string(),
        GossipTopic::BlsToExecutionChange.to_string(),
        GossipTopic::SyncCommitteeContributionAndProof.to_string(),
    ]
}

const fn default_discovery_port() -> Option<u16> {
    Some(31133)
}

const fn default_quic_port() -> Option<u16> {
    Some(31123)
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    network: Network,
    #[serde(default)]
    external_ip_v4: Option<Ipv4Addr>,
    #[serde(default)]
    external_ip_v6: Option<Ipv6Addr>,
    #[serde(default = "default_discovery_port")]
    discovery_port: Option<u16>,
    #[serde(default = "default_quic_port")]
    quic_port: Option<u16>,
    // Floored at `SAMPLES_PER_SLOT` (8) in `enr()`: silver custodies the full
    // sample set, so cgc < 8 is unsupported (see `enr`).
    #[serde(default = "default_u8::<8>")]
    data_column_custody_group_count: u8,
    #[serde(default = "default_u8::<2>")]
    attestation_subnet_count: u8,
    #[serde(default)]
    partial_columns: PartialColumnsMode,
    #[serde(default)]
    sync_committee_subnets: SyncCommitteeSubnets,
    /// Full multiselect protocol strings.
    #[serde(default = "default_supported_protocols")]
    supported_protocols: Vec<String>,
    #[serde(default = "default_gossip_topics")]
    gossip_topics: Vec<String>,
    #[serde(default)]
    chain_config: ChainOverrides,
    #[serde(default)]
    discovery_config: DiscoveryConfig,
    #[serde(default)]
    peer_score_params: ScoreParams,
    #[serde(default)]
    syncing: SyncingConfig,
    #[serde(default = "default_usize::<134217728>")] // 2 << 26
    incoming_gossip_tcache_size: usize,
    #[serde(default = "default_usize::<67108864>")] // 2 << 25
    outgoing_gossip_tcache_size: usize,
    /// Decompressed gossip SSZ. Parks handles too — see below, at tip volumes.
    #[serde(default = "default_usize::<134217728>")] // 2 << 26
    incoming_gossip_ssz_tcache_size: usize,
    /// Inbound RPC ring: block, column-sidecar and envelope chunks; the
    /// producer wraps when full. Beacon state parks its handles, so a block
    /// lapped while parked or staged is fetched again by root — symptom is
    /// `lapped in the tcache` in the beacon state log.
    ///
    /// Floor is the fetch window, `2 * BATCH` = 128 blocks (mainnet ~225 KB
    /// mean, ~476 KB max — see `crates/e2e/data/perf`). The rest is
    /// headroom for column traffic passing a parked block, which dominates
    /// and is why nothing asserts a static bound. Default is ~4× that
    /// floor.
    #[serde(default = "default_usize::<134217728>")] // 2 << 26
    incoming_rpc_tcache_size: usize,
    #[serde(default = "default_usize::<67108864>")] // 2 << 25
    outgoing_rpc_tcache_size: usize,
    /// Unset takes the network's default.
    #[serde(default)]
    data_storage_dir: Option<String>,
    #[serde(default)]
    engine_config: EngineConfig,
    /// Each entry is a TCP `addr:port` or a unix socket path; the API serves
    /// all of them at once.
    #[serde(default = "default_beacon_api_bind")]
    beacon_api_bind: Vec<String>,
    #[serde(default = "default_usize::<64>")]
    beacon_api_max_connections: usize,
    /// Refreshed by any byte read or written, so a slow but progressing
    /// transfer never trips it.
    #[serde(default = "default_u64::<75>")]
    beacon_api_idle_timeout_secs: u64,
    #[serde(default)]
    disable_weak_subjectivity_check: bool,
    #[serde(default)]
    trusted_peers: Vec<Enr>,
    #[serde(default)]
    cluster_config: Option<ClusterConfig>,
}

impl Config {
    fn apply(&mut self, overrides: Overrides) {
        if let Some(network) = overrides.network {
            self.network = network;
        }
        if let Some(url) = overrides.execution_endpoint {
            self.engine_config.execution_endpoint = url;
        }
        if let Some(path) = overrides.jwt_secret {
            self.engine_config.jwt_secret = path;
        }
        self.engine_config.unsafe_no_el |= overrides.unsafe_no_el;
    }
}

/// What the command line sets over the config file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub network: Option<Network>,
    pub execution_endpoint: Option<String>,
    pub jwt_secret: Option<String>,
    pub unsafe_no_el: bool,
}

impl Config {
    /// Every key is optional; an empty file is the mainnet node.
    pub fn load(file: Option<&str>, overrides: Overrides) -> Result<Self, Error> {
        let text = file.map(std::fs::read_to_string).transpose()?.unwrap_or_default();
        Self::from_toml(&text, overrides)
    }

    pub fn mainnet() -> Result<Self, Error> {
        Self::from_toml("", Overrides::default())
    }

    fn from_toml(text: &str, overrides: Overrides) -> Result<Self, Error> {
        let mut config: Self = toml::from_str(text)?;
        config.apply(overrides);
        Ok(config)
    }

    /// Reads a devnet's files, so resolve it once.
    pub fn chain(&self) -> Result<ChainConfig, Error> {
        let chain =
            ChainConfig::new(&self.network, &self.chain_config, self.data_storage_dir.as_deref())?;
        let spec = &chain.spec;
        silver_log::info!(
            network = %spec.network_name(),
            bootnodes = chain.bootstrap_enrs.len(),
            boot = ?chain.boot,
            data_dir = %chain.data_dir,
            "resolved chain"
        );
        if let Some(network) = spec.misnamed_network() {
            silver_log::warn!(
                config_name = %spec.network_name(),
                genesis_fork_version = %hex::encode(spec.genesis_fork_version),
                network,
                "CONFIG_NAME disagrees with the network GENESIS_FORK_VERSION names"
            );
        }

        if let BootSource::File { ssz, .. } = &chain.boot {
            let genesis = Genesis::from_state_file(ssz)?;
            chain.checked_fork_digest(chain.wall_epoch(&genesis), &genesis)?;
        }
        Ok(chain)
    }

    pub fn enr(&self, keypair: &Keypair, enr_fork_id: [u8; 16]) -> Result<Enr, Error> {
        let mut builder = Enr::builder();
        // Remotes only replace a cached record on a strictly higher seq, and
        // the node key (= node_id) is stable across restarts — a constant
        // seed pins the network to whatever record it saw first, so record
        // changes (tcp, attnets) never propagate. Boot time is monotonic
        // across restarts; in-boot `set_*` bumps of +1 stay far below the
        // next boot's seed.
        let boot_seq =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        builder.seq(boot_seq);
        builder.eth2(enr_fork_id);
        // Floor at SAMPLES_PER_SLOT: custody set must cover the sample set.
        builder.cgc(self.data_column_custody_group_count.max(SAMPLES_PER_SLOT) as u64);

        if let Some(ip) = self.external_ip_v4 {
            builder.ip4(ip);
        }
        if let Some(ip) = self.external_ip_v6 {
            builder.ip6(ip);
        }
        if let Some(dp) = self.discovery_port {
            builder.udp4(dp).udp6(dp);
        }
        if let Some(qp) = self.quic_port {
            builder.quic4(qp).quic6(qp);
            // Not served: lighthouse's discovery predicate (v8.x
            // `start_query`) drops ENRs without a tcp port, so QUIC-only
            // nodes are never dialed by it. Its dialer tries the quic
            // address first, so advertising tcp gets us QUIC-dialed.
            builder.tcp4(qp).tcp6(qp);
        }
        Ok(builder.build(keypair.secret_key())?)
    }

    pub fn supported_protocols(&self) -> Result<Vec<StreamProtocol>, Error> {
        self.supported_protocols
            .iter()
            .map(String::as_str)
            .map(StreamProtocol::from_multiselect_str)
            .map(|opt| opt.ok_or(Error::InvalidStreamProtocol))
            .collect()
    }

    pub fn gossip_topics(&self) -> Result<Vec<GossipTopic>, Error> {
        self.gossip_topics.iter().map(|t| GossipTopic::try_from(t.as_str())).collect()
    }

    #[allow(clippy::field_reassign_with_default)]
    pub fn identify(&self, keypair: &Keypair) -> Result<Identify, Error> {
        let mut identify = Identify::default();
        identify.peer_id = Some(PeerId::from_secp256k1_pubkey(keypair.public_key_compressed()));
        identify.public_key = *keypair.public_key_compressed();
        for protocol in self.supported_protocols()? {
            identify.protocols |= 1 << protocol.ordinal();
        }
        if let Some(v4) = self.external_ip_v4 &&
            let Some(qp) = self.quic_port
        {
            identify.udp_ipv4 = Some(SocketAddr::V4(SocketAddrV4::new(v4, qp)));
        }
        if let Some(v6) = self.external_ip_v6 &&
            let Some(qp) = self.quic_port
        {
            identify.udp_ipv6 = Some(SocketAddr::V6(SocketAddrV6::new(v6, qp, 0, 0)));
        }
        Ok(identify)
    }

    pub fn discovery_config(&self) -> DiscoveryConfig {
        self.discovery_config.clone()
    }

    /// Hard cap on transport connections — inbound accepts are refused at
    /// the QUIC layer beyond it. Sits above the peer manager's trim band
    /// (`max_priority_peers` + 10%) so score-based trimming has room to
    /// work inside it.
    pub fn max_connections(&self) -> usize {
        self.peer_score_params.max_priority_peers * 12 / 10
    }

    pub fn peer_score_params(&self) -> ScoreParams {
        self.peer_score_params.clone()
    }

    pub fn syncing_config(&self) -> SyncingConfig {
        self.syncing.clone()
    }

    pub fn discovery_bind_addr(&self) -> Option<SocketAddr> {
        self.discovery_port.map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
    }

    pub fn p2p_bind_addr(&self) -> Option<SocketAddr> {
        self.quic_port.map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
    }

    pub fn incoming_gossip_tcache_size(&self) -> usize {
        self.incoming_gossip_tcache_size
    }

    pub fn outgoing_gossip_tcache_size(&self) -> usize {
        self.outgoing_gossip_tcache_size
    }

    pub fn incoming_gossip_ssz_tcache_size(&self) -> usize {
        self.incoming_gossip_ssz_tcache_size
    }

    pub fn incoming_rpc_tcache_size(&self) -> usize {
        self.incoming_rpc_tcache_size
    }

    pub fn outgoing_rpc_tcache_size(&self) -> usize {
        self.outgoing_rpc_tcache_size
    }

    pub fn engine_config(&self) -> EngineConfig {
        self.engine_config.clone()
    }

    pub fn beacon_api_bind(&self) -> &[String] {
        &self.beacon_api_bind
    }

    pub fn beacon_api_max_connections(&self) -> usize {
        self.beacon_api_max_connections
    }

    pub fn beacon_api_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.beacon_api_idle_timeout_secs)
    }

    pub fn disable_weak_subjectivity_check(&self) -> bool {
        self.disable_weak_subjectivity_check
    }

    pub fn attestation_subnet_count(&self) -> u8 {
        self.attestation_subnet_count
    }

    pub fn partial_columns(&self) -> PartialColumnsMode {
        self.partial_columns
    }

    pub fn sync_committee_subnets(&self) -> SyncCommitteeSubnets {
        self.sync_committee_subnets
    }

    pub fn trusted_peers(&self) -> &[Enr] {
        &self.trusted_peers
    }

    pub fn cluster_config(&self) -> Option<&ClusterConfig> {
        self.cluster_config.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn default_dir() {
        println!("{}", Config::mainnet().unwrap().chain().unwrap().data_dir);
    }

    #[test]
    fn minimal_toml_populates_defaults() {
        // The lists fall back to their defaults (else a file config silently
        // advertises zero protocols/topics).
        let cfg = Config::from_toml("", Overrides::default()).unwrap();
        assert_eq!(cfg.supported_protocols().unwrap().len(), 12);
        assert!(cfg.supported_protocols().unwrap().contains(&StreamProtocol::GossipSubV13));
        assert_eq!(cfg.gossip_topics().unwrap().len(), 7);
        assert_eq!(cfg.beacon_api_bind(), ["0.0.0.0:5051"]);
        assert_eq!(cfg.beacon_api_max_connections(), 64);
        assert_eq!(cfg.beacon_api_idle_timeout(), Duration::from_secs(75));
        assert_eq!(cfg.partial_columns(), PartialColumnsMode::Off);
    }

    #[test]
    fn partial_columns_modes_are_validated() {
        let cfg =
            Config::from_toml("partial_columns = \"send_only\"", Overrides::default()).unwrap();
        assert_eq!(cfg.partial_columns(), PartialColumnsMode::SendOnly);
        let cfg = Config::from_toml("partial_columns = \"enabled\"", Overrides::default()).unwrap();
        assert_eq!(cfg.partial_columns(), PartialColumnsMode::Enabled);
    }

    /// A devnet copying mainnet's `CONFIG_NAME` still runs — `from_file`
    /// warns about the contradiction rather than rejecting the file, since
    /// only the operator can say which half is the typo.
    #[test]
    fn a_config_name_contradicting_its_fork_version_still_loads() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "config.yaml",
            "CONFIG_NAME: mainnet\nGENESIS_FORK_VERSION: 0x10000910\n",
        );
        std::fs::write(dir.path().join("genesis.ssz"), [0u8; 64]).unwrap();

        let devnet = Network::Devnet(dir.path().to_owned());
        let cfg = Config::load(None, Overrides { network: Some(devnet), ..Overrides::default() })
            .unwrap();

        let spec = cfg.chain().unwrap().spec;
        assert_eq!(spec.misnamed_network(), Some("hoodi"));
        assert_eq!(spec.network_name(), "mainnet");
    }

    #[test]
    fn beacon_api_bind_toml_array_keeps_every_entry() {
        let toml_str = r#"
            beacon_api_bind = ["0.0.0.0:5051", "127.0.0.1:5052", "/run/silver/beacon.sock"]
        "#;
        let cfg = Config::from_toml(toml_str, Overrides::default()).unwrap();
        assert_eq!(cfg.beacon_api_bind(), [
            "0.0.0.0:5051",
            "127.0.0.1:5052",
            "/run/silver/beacon.sock"
        ]);
    }

    /// discv5 peers silently drop records over 300 bytes — an oversized ENR
    /// makes the node invisible to discovery, not degraded.
    #[test]
    fn production_enr_fits_discv5_record_cap() {
        let key = Keypair::from_secret(&[1u8; 32]).unwrap();
        let toml = "external_ip_v4 = \"203.0.113.7\"\ndiscovery_port = 9000\nquic_port = 9001\n";
        let cfg = Config::from_toml(toml, Overrides::default()).unwrap();
        let mut enr = cfg.enr(&key, [0; 16]).unwrap();
        enr.set_attnets([0xff; 8], key.secret_key()).unwrap();
        enr.set_syncnets(SyncCommitteeSubnets::All.long_lived(), key.secret_key()).unwrap();
        // Unpadded base64: 4 chars per 3 bytes.
        let bytes = enr.size();
        assert!(bytes <= 300, "ENR is {bytes} bytes, discv5 caps records at 300");
    }

    /// A `[u8; 32]` root and a `u64` genesis time at the head of an anchor
    /// state, which is all `Genesis` reads.
    fn write_anchor(dir: &std::path::Path, genesis_unix_secs: u64, gvr: [u8; 32]) -> String {
        let path = dir.join("anchor.ssz");
        let mut bytes = genesis_unix_secs.to_le_bytes().to_vec();
        bytes.extend_from_slice(&gvr);
        bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn write_file(dir: &std::path::Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// The whole in-enclave contract: a config naming only the two files a
    /// network publishes resolves to the same digest a hand-written one
    /// spells out.
    #[test]
    fn spec_file_and_anchor_resolve_the_digest_and_genesis() {
        let dir = TempDir::new().unwrap();
        let gvr = [7u8; 32];
        let genesis = 1_600_000_000;
        let anchor = write_anchor(dir.path(), genesis, gvr);
        write_file(
            dir.path(),
            "config.yaml",
            "CONFIG_NAME: kurtosis\n\
             GENESIS_FORK_VERSION: 0x10000038\n\
             FULU_FORK_VERSION: 0x70000038\n\
             FULU_FORK_EPOCH: 0\n\
             ELECTRA_FORK_EPOCH: 0\n\
             MAX_BLOBS_PER_BLOCK_ELECTRA: 9\n\
             SECONDS_PER_SLOT: 12\n\
             GLOAS_FORK_EPOCH: 18446744073709551615\n",
        );
        let config_file = write_file(
            dir.path(),
            "silver.toml",
            &format!(
                "network = \"{}\"\n\
                 [chain_config]\n\
                 checkpoint_file = \"{anchor}\"\n",
                dir.path().display()
            ),
        );

        let cfg = Config::load(Some(&config_file), Overrides::default()).unwrap();
        let chain = cfg.chain().unwrap();
        assert_eq!(chain.spec.network_name(), "kurtosis", "the spec came from the YAML");
        assert_eq!(chain.spec.fulu_fork_version, [0x70, 0x00, 0x00, 0x38]);

        let state_genesis = Genesis::from_state_file(Path::new(&anchor)).unwrap();
        assert_eq!(state_genesis.unix_secs, genesis);
        let epoch = chain.wall_epoch(&state_genesis);
        assert_eq!(
            chain.checked_fork_digest(epoch, &state_genesis).unwrap(),
            chain.spec.fork_digest_at(epoch, &gvr)
        );
    }

    /// silver has no pre-Fulu state transition, and an unstated
    /// FULU_FORK_EPOCH silently inherits mainnet's — which is how a
    /// Fulu-from-genesis devnet reads as Electra and derives a digest no peer
    /// gossips on.
    #[test]
    fn spec_reading_earlier_than_fulu_is_refused() {
        let dir = TempDir::new().unwrap();
        // A genesis an hour ago, like a devnet's: the wall epoch is then far
        // below mainnet's fulu_fork_epoch, which is the default in force here.
        let recent = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 3600;
        let anchor = write_anchor(dir.path(), recent, [7u8; 32]);
        write_file(
            dir.path(),
            "config.yaml",
            "FULU_FORK_VERSION: 0x70000038\nELECTRA_FORK_EPOCH: 0\n",
        );
        let config_file = write_file(
            dir.path(),
            "silver.toml",
            &format!(
                "network = \"{}\"\n\
                 [chain_config]\n\
                 checkpoint_file = \"{anchor}\"\n",
                dir.path().display()
            ),
        );

        let cfg = Config::load(Some(&config_file), Overrides::default()).unwrap();
        let err = cfg.chain().unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("FULU_FORK_EPOCH"), "error should name the key: {text}");
    }

    #[test]
    fn network_names_the_chain() {
        let named = "network = \"hoodi\"\n";
        let chain = Config::from_toml(named, Overrides::default()).unwrap().chain().unwrap();
        assert_eq!(chain.spec.network_name(), "hoodi");
        assert!(chain.data_dir.ends_with("/hoodi"));
        assert!(!chain.bootstrap_enrs.is_empty());

        let overridden = "network = \"hoodi\"\n[chain_config]\nbootstrap_enrs = []\n";
        let chain = Config::from_toml(overridden, Overrides::default()).unwrap().chain().unwrap();
        assert_eq!(chain.spec.network_name(), "hoodi");
        assert!(chain.bootstrap_enrs.is_empty());
        assert!(matches!(&chain.boot, BootSource::Providers(urls) if !urls.is_empty()));
    }

    /// A devnet gets nothing of mainnet's, not even as a default.
    #[test]
    fn devnet_dir_supplies_the_chain() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "config.yaml",
            "GENESIS_FORK_VERSION: 0x10000038\nSECONDS_PER_SLOT: 6\n",
        );
        let enr = Network::Mainnet.bootnodes().unwrap()[0].to_base64();
        write_file(dir.path(), "bootstrap_nodes.yaml", &format!("- \"{enr}\"\n"));
        let mut genesis = vec![0u8; 8];
        genesis.extend_from_slice(&[0xab; 32]);
        std::fs::write(dir.path().join("genesis.ssz"), genesis).unwrap();

        let cfg = Config::load(None, Overrides {
            network: Some(Network::Devnet(dir.path().to_owned())),
            ..Overrides::default()
        })
        .unwrap();
        let chain = cfg.chain().unwrap();
        assert_eq!(chain.spec.seconds_per_slot(), 6);
        assert_eq!(chain.bootstrap_enrs.len(), 1);
        assert_eq!(chain.boot, BootSource::File {
            ssz: dir.path().join("genesis.ssz"),
            pubkeys: None
        });
        assert!(chain.data_dir.ends_with("/devnet-abababab"), "named after the genesis root");
    }
}
