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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn identity_json_fields_present() {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let body = build_identity_json(&kp, &enr, &Identify::default());
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let data = &v["data"];
        assert!(data["peer_id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(data["enr"].as_str().is_some_and(|s| s.starts_with("enr:")));
        assert!(data["metadata"]["seq_number"].as_str().is_some());
        assert!(data["metadata"]["attnets"].as_str().is_some_and(|s| s.starts_with("0x")));
        assert!(data["metadata"]["syncnets"].as_str().is_some_and(|s| s.starts_with("0x")));
    }

    #[test]
    fn identity_p2p_address_format() {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let mut identify = Identify::default();
        identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
        let body = build_identity_json(&kp, &enr, &identify);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let addrs = v["data"]["p2p_addresses"].as_array().unwrap();
        assert_eq!(addrs.len(), 1);
        let addr = addrs[0].as_str().unwrap();
        assert!(addr.starts_with("/ip4/1.2.3.4/tcp/9000/p2p/"), "bad format: {addr}");
    }
}
