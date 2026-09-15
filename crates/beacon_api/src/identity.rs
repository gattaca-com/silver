use serde::{Deserialize, Serialize};
use silver_common::{Enr, Eth2Addr, Identify, Keypair};

#[derive(Debug, Serialize)]
struct IdentityResponse<'a> {
    data: &'a Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    peer_id: String,
    enr: String,
    p2p_addresses: Vec<String>,
    discovery_addresses: Vec<String>,
    metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    seq_number: String,
    attnets: String,
    syncnets: String,
    custody_group_count: String,
}

pub(crate) fn build_identity_json(
    keypair: &Keypair,
    local_enr: &Enr,
    identify: &Identify,
) -> Vec<u8> {
    let pid_multiaddr = Eth2Addr::PeerId(keypair.peer_id()).to_string();
    let peer_id_str = pid_multiaddr.strip_prefix("/p2p/").unwrap_or(&pid_multiaddr);

    let mut p2p_addresses = Vec::new();
    if let Some(addr) = identify.tcp_ipv4 {
        p2p_addresses.push(format!("/ip4/{}/tcp/{}/p2p/{}", addr.ip(), addr.port(), peer_id_str));
    }
    if let Some(addr) = identify.tcp_ipv6 {
        p2p_addresses.push(format!("/ip6/{}/tcp/{}/p2p/{}", addr.ip(), addr.port(), peer_id_str));
    }
    if let Some(addr) = identify.udp_ipv4 {
        p2p_addresses.push(format!(
            "/ip4/{}/udp/{}/quic-v1/p2p/{}",
            addr.ip(),
            addr.port(),
            peer_id_str
        ));
    }
    if let Some(addr) = identify.udp_ipv6 {
        p2p_addresses.push(format!(
            "/ip6/{}/udp/{}/quic-v1/p2p/{}",
            addr.ip(),
            addr.port(),
            peer_id_str
        ));
    }

    let mut discovery_addresses = Vec::new();
    if let (Some(ip), Some(udp)) = (local_enr.ip4(), local_enr.udp4()) {
        discovery_addresses.push(format!("/ip4/{}/udp/{}/p2p/{}", ip, udp, peer_id_str));
    }
    if let (Some(ip), Some(udp)) = (local_enr.ip6(), local_enr.udp6()) {
        discovery_addresses.push(format!("/ip6/{}/udp/{}/p2p/{}", ip, udp, peer_id_str));
    }

    let identity = Identity {
        peer_id: peer_id_str.to_string(),
        enr: local_enr.to_base64(),
        p2p_addresses,
        discovery_addresses,
        metadata: Metadata {
            seq_number: local_enr.seq().to_string(),
            attnets: format!("0x{}", hex::encode(local_enr.attnets().unwrap_or([0u8; 8]))),
            syncnets: format!("0x{:02x}", local_enr.syncnets().unwrap_or(0)),
            custody_group_count: local_enr.cgc().unwrap_or(4).to_string(),
        },
    };

    serde_json::to_vec(&IdentityResponse { data: &identity }).unwrap()
}
