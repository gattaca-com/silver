use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use chain_config::ChainConfig;
pub use discovery_config::DiscoveryConfig;
pub use peer_score_params::ScoreParams;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use silver_common::{
    Enr, Error, GossipTopic, Identify, Keypair, NodeId, PeerId, SAMPLES_PER_SLOT, StreamProtocol,
};
pub use syncing_config::SyncingConfig;

mod chain_config;
mod discovery_config;
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

fn default_data_dir() -> String {
    std::env::home_dir()
        .and_then(|mut b| {
            b = b.join(".local").join("silver");
            b.to_str().map(|s| s.to_owned())
        })
        .unwrap_or("/tmp/silver".into())
}

fn default_supported_protocols() -> Vec<String> {
    vec![
        StreamProtocol::Identity.multiselect_string(),
        StreamProtocol::GossipSub.multiselect_string(),
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
    vec![GossipTopic::BeaconBlock.to_string()]
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(with = "hex::serde")]
    secret_key: [u8; 32],
    #[serde(with = "hex::serde")]
    fork_digest: [u8; 4],
    #[serde(with = "hex::serde")]
    next_fork_version: [u8; 4],
    // FAR_FUTURE (u64::MAX) by default — exceeds TOML's i64 range, so configs
    // for a network with no scheduled next fork simply omit it.
    #[serde(default = "default_u64::<18446744073709551615>")]
    next_fork_epoch: u64,
    #[serde(default)]
    external_ip_v4: Option<Ipv4Addr>,
    #[serde(default)]
    external_ip_v6: Option<Ipv6Addr>,
    #[serde(default)]
    discovery_port: Option<u16>,
    #[serde(default)]
    quic_port: Option<u16>,
    // Floored at `SAMPLES_PER_SLOT` (8) in `enr()`: silver custodies the full
    // sample set, so cgc < 8 is unsupported (see `enr`).
    #[serde(default = "default_u8::<8>")]
    data_column_custody_group_count: u8,
    /// Full multiselect protocol strings.
    #[serde(default = "default_supported_protocols")]
    supported_protocols: Vec<String>,
    #[serde(default = "default_gossip_topics")]
    gossip_topics: Vec<String>,
    #[serde(default)]
    chain_config: ChainConfig,
    #[serde(default)]
    discovery_config: DiscoveryConfig,
    #[serde(default)]
    peer_score_params: ScoreParams,
    #[serde(default)]
    syncing: SyncingConfig,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    incoming_gossip_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    outgoing_gossip_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    incoming_gossip_ssz_tcache_size: usize,
    #[serde(default = "default_usize::<67108864>")] // 2 << 25
    incoming_rpc_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    outgoing_rpc_tcache_size: usize,
    #[serde(default = "default_data_dir")]
    data_storage_dir: String,
    #[serde(default)]
    disable_weak_subjectivity_check: bool,
}

impl Config {
    pub fn new(
        secret_key: [u8; 32],
        fork_digest: [u8; 4],
        next_fork_version: [u8; 4],
        next_fork_epoch: u64,
    ) -> Self {
        Self {
            secret_key,
            fork_digest,
            next_fork_version,
            next_fork_epoch,
            external_ip_v4: None,
            external_ip_v6: None,
            discovery_port: None,
            quic_port: None,
            data_column_custody_group_count: SAMPLES_PER_SLOT,
            supported_protocols: default_supported_protocols(),
            gossip_topics: default_gossip_topics(),
            chain_config: ChainConfig::default(),
            discovery_config: DiscoveryConfig::default(),
            peer_score_params: ScoreParams::default(),
            syncing: SyncingConfig::default(),
            incoming_gossip_tcache_size: 2 << 24,     // protobuf
            outgoing_gossip_tcache_size: 2 << 24,     // protobuf
            incoming_gossip_ssz_tcache_size: 2 << 24, // ssz
            incoming_rpc_tcache_size: 2 << 27,        // ssz
            outgoing_rpc_tcache_size: 2 << 24,        // ssz
            data_storage_dir: default_data_dir(),
            disable_weak_subjectivity_check: false,
        }
    }

    /// Load a full `Config` from a TOML file. Devnet runs supply every
    /// network-specific value (fork_digest, genesis, bootstrap ENRs,
    /// external IP, ports, secret key) here, so no source edits are needed.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn with_discovery_port(mut self, port: u16) -> Self {
        self.discovery_port = Some(port);
        self
    }

    pub fn with_external_ip_v4(mut self, ip: Ipv4Addr) -> Self {
        self.external_ip_v4 = Some(ip);
        self
    }

    pub fn with_genesis_unix_secs(mut self, secs: u64) -> Self {
        self.chain_config.genesis_unix_secs = secs;
        self
    }

    pub fn with_quic_port(mut self, port: u16) -> Self {
        self.quic_port = Some(port);
        self
    }

    pub fn with_checkpoint(mut self, path: String) -> Self {
        self.chain_config.checkpoint_file = Some(path);
        self
    }

    pub fn with_checkpoint_pubkeys(mut self, path: String) -> Self {
        self.chain_config.checkpoint_pubkeys_file = Some(path);
        self
    }

    pub fn with_disable_weak_subjectivity_check(mut self, disable: bool) -> Self {
        self.disable_weak_subjectivity_check = disable;
        self
    }

    pub fn keypair(&self) -> Result<Keypair, Error> {
        Keypair::from_secret(&self.secret_key)
    }

    pub fn fork_digest(&self) -> [u8; 4] {
        self.fork_digest
    }

    pub fn p2p_peer_id(&self) -> Result<PeerId, Error> {
        Ok(PeerId::from_secp256k1_pubkey(self.keypair()?.public_key_compressed()))
    }

    pub fn discv5_node_id(&self) -> Result<NodeId, Error> {
        Ok(PublicKey::from_slice(self.keypair()?.public_key_compressed())?.into())
    }

    pub fn enr(&self) -> Result<Enr, Error> {
        let mut builder = Enr::builder();
        let mut eth2 = [0u8; 16];
        eth2[..4].copy_from_slice(&self.fork_digest);
        eth2[4..8].copy_from_slice(&self.next_fork_version);
        eth2[8..].copy_from_slice(&self.next_fork_epoch.to_le_bytes());

        builder.eth2(eth2);
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
        }
        Ok(builder.build(self.keypair()?.secret_key())?)
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
    pub fn identify(&self) -> Result<Identify, Error> {
        let mut identify = Identify::default();
        identify.peer_id = Some(self.p2p_peer_id()?);
        identify.public_key = *self.keypair()?.public_key_compressed();
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

    pub fn chain_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    pub fn discovery_config(&self) -> DiscoveryConfig {
        self.discovery_config.clone()
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

    pub fn data_storage_dir(&self) -> &str {
        &self.data_storage_dir
    }

    pub fn disable_weak_subjectivity_check(&self) -> bool {
        self.disable_weak_subjectivity_check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir() {
        println!("{}", default_data_dir());
    }

    #[test]
    fn minimal_toml_populates_defaults() {
        // Only fork_digest / next_fork_version / secret_key are required;
        // next_fork_epoch defaults to FAR_FUTURE and the lists fall back to
        // the same values `Config::new` sets (else a file config silently
        // advertises zero protocols/topics).
        let toml_str = r#"
            secret_key = "1111111111111111111111111111111111111111111111111111111111111111"
            fork_digest = "8c9f62fe"
            next_fork_version = "06000000"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.fork_digest(), [0x8c, 0x9f, 0x62, 0xfe]);
        assert_eq!(cfg.next_fork_epoch, u64::MAX);
        assert_eq!(cfg.supported_protocols().unwrap().len(), 11);
        assert_eq!(cfg.gossip_topics().unwrap().len(), 1);
    }

    #[test]
    fn builders_set_external_ip_and_genesis() {
        let cfg = Config::new([1u8; 32], [0u8; 4], [0u8; 4], 0)
            .with_external_ip_v4(Ipv4Addr::new(172, 16, 0, 1))
            .with_genesis_unix_secs(1234);
        assert_eq!(cfg.external_ip_v4, Some(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(cfg.chain_config().genesis_unix_secs, 1234);
    }
}
