use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub use discovery_config::DiscoveryConfig;
pub use peer_score_params::ScoreParams;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    Enr, Error, GossipTopic, Identify, Keypair, NodeId, PeerId, StreamProtocol,
    config::chain_config::ChainConfig,
};

mod chain_config;
mod discovery_config;
mod peer_score_params;

const fn default_usize<const N: usize>() -> usize {
    N
}

const fn default_u32<const V: u32>() -> u32 {
    V
}

const fn default_u64<const V: u64>() -> u64 {
    V
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(with = "hex::serde")]
    secret_key: [u8; 32],
    #[serde(with = "hex::serde")]
    fork_digest: [u8; 4],
    #[serde(default)]
    external_ip_v4: Option<Ipv4Addr>,
    #[serde(default)]
    external_ip_v6: Option<Ipv6Addr>,
    #[serde(default)]
    discovery_port: Option<u16>,
    #[serde(default)]
    quic_port: Option<u16>,
    /// Full multiselect protocol strings.
    #[serde(default)]
    supported_protocols: Vec<String>,
    #[serde(default)]
    gossip_topics: Vec<String>,
    #[serde(default)]
    chain_config: ChainConfig,
    #[serde(default)]
    discovery_config: DiscoveryConfig,
    #[serde(default)]
    peer_score_params: ScoreParams,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    incoming_gossip_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    outgoing_gossip_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    incoming_gossip_ssz_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    incoming_rpc_tcache_size: usize,
    #[serde(default = "default_usize::<33554432>")] // 2 << 24
    outgoing_rpc_tcache_size: usize,
}

impl Config {
    pub fn new(secret_key: [u8; 32], fork_digest: [u8; 4]) -> Self {
        Self {
            secret_key,
            fork_digest,
            external_ip_v4: None,
            external_ip_v6: None,
            discovery_port: None,
            quic_port: None,
            supported_protocols: vec![
                StreamProtocol::Identity.multiselect_string(),
                StreamProtocol::GossipSub.multiselect_string(),
                StreamProtocol::StatusV1.multiselect_string(),
                StreamProtocol::StatusV2.multiselect_string(),
                StreamProtocol::Ping.multiselect_string(),
                StreamProtocol::Goodbye.multiselect_string(),
                StreamProtocol::Metadata.multiselect_string(),
            ],
            gossip_topics: vec![GossipTopic::BeaconBlock.to_string()],
            chain_config: ChainConfig::default(),
            discovery_config: DiscoveryConfig::default(),
            peer_score_params: ScoreParams::default(),
            incoming_gossip_tcache_size: 2 << 24,     // protobuf
            outgoing_gossip_tcache_size: 2 << 24,     // protobuf
            incoming_gossip_ssz_tcache_size: 2 << 24, // ssz
            incoming_rpc_tcache_size: 2 << 24,        // ssz
            outgoing_rpc_tcache_size: 2 << 24,        // ssz
        }
    }

    pub fn with_discovery_port(mut self, port: u16) -> Self {
        self.discovery_port = Some(port);
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

    pub fn chain_config(&self) -> ChainConfig {
        self.chain_config.clone()
    }

    pub fn discovery_config(&self) -> DiscoveryConfig {
        self.discovery_config.clone()
    }

    pub fn peer_score_params(&self) -> ScoreParams {
        self.peer_score_params.clone()
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
}
