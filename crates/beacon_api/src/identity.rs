use silver_common::{Enr, Eth2Addr, Identify, Keypair};

use crate::json::Json;

pub(crate) fn identity_body(keypair: &Keypair, local_enr: &Enr, identify: &Identify) -> Vec<u8> {
    let multiaddr = Eth2Addr::PeerId(keypair.peer_id()).to_string();
    let peer_id = multiaddr.strip_prefix("/p2p/").unwrap_or(&multiaddr);

    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.data_envelope(|json| {
        json.begin_object();
        json.key("peer_id");
        json.string(peer_id);
        json.key("enr");
        json.string(&local_enr.to_base64());

        json.key("p2p_addresses");
        json.begin_array();
        if let Some(addr) = identify.tcp_ipv4 {
            json.string(&format!("/ip4/{}/tcp/{}/p2p/{peer_id}", addr.ip(), addr.port()));
        }
        if let Some(addr) = identify.tcp_ipv6 {
            json.string(&format!("/ip6/{}/tcp/{}/p2p/{peer_id}", addr.ip(), addr.port()));
        }
        if let Some(addr) = identify.udp_ipv4 {
            json.string(&format!("/ip4/{}/udp/{}/quic-v1/p2p/{peer_id}", addr.ip(), addr.port()));
        }
        if let Some(addr) = identify.udp_ipv6 {
            json.string(&format!("/ip6/{}/udp/{}/quic-v1/p2p/{peer_id}", addr.ip(), addr.port()));
        }
        json.end_array();

        json.key("discovery_addresses");
        json.begin_array();
        if let (Some(ip), Some(udp)) = (local_enr.ip4(), local_enr.udp4()) {
            json.string(&format!("/ip4/{ip}/udp/{udp}/p2p/{peer_id}"));
        }
        if let (Some(ip), Some(udp)) = (local_enr.ip6(), local_enr.udp6()) {
            json.string(&format!("/ip6/{ip}/udp/{udp}/p2p/{peer_id}"));
        }
        json.end_array();

        json.key("metadata");
        json.begin_object();
        json.key("seq_number");
        json.quoted_u64(local_enr.seq());
        json.key("attnets");
        json.hex(&local_enr.attnets().unwrap_or([0u8; 8]));
        json.key("syncnets");
        json.hex(&[local_enr.syncnets().unwrap_or(0)]);
        json.key("custody_group_count");
        json.quoted_u64(local_enr.cgc().unwrap_or(4));
        json.end_object();
        json.end_object();
    });
    out
}
