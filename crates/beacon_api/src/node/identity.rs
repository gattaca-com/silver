use silver_common::{Enr, Eth2Addr, Identify, Keypair};

use crate::{
    ctx::ApiCtx,
    http::{json::Json, response::Response, router::Request},
};

pub(crate) struct Identity {
    peer_id: String,
    identify: Identify,
    body: Vec<u8>,
}

impl Identity {
    pub(crate) fn new(keypair: &Keypair, local_enr: &Enr, identify: &Identify) -> Self {
        let multiaddr = Eth2Addr::PeerId(keypair.peer_id()).to_string();
        let peer_id = multiaddr.strip_prefix("/p2p/").unwrap_or(&multiaddr).to_owned();
        let mut identity = Self { peer_id, identify: *identify, body: Vec::new() };
        identity.set_enr(local_enr);
        identity
    }

    pub(crate) fn set_enr(&mut self, local_enr: &Enr) {
        self.body.clear();
        render(&mut self.body, &self.peer_id, &self.identify, local_enr);
    }
}

fn render(out: &mut Vec<u8>, peer_id: &str, identify: &Identify, local_enr: &Enr) {
    let mut json = Json::new(out);
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
}

pub(crate) fn identity(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.identity.body);
}

#[cfg(test)]
mod tests {
    use silver_common::{Enr, Keypair};

    use crate::{
        ctx::anchor_ctx,
        testing::{answer, request},
    };

    /// Wire bytes the pre-table implementation produced for these exact
    /// inputs (captured before the table dispatch landed).
    const GOLDEN_IDENTITY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 478\r\n\r\n{\"data\":{\"peer_id\":\"16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\",\"enr\":\"enr:-HW4QFVim6voTojjE-JbeUF0GPFRcqmWxgqgJ8-tXE5hh9PFTQSCwUJPHY_61U3Wvzi6OGrvJfb6KNjNpw4Q18sNL_sBgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48\",\"p2p_addresses\":[\"/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\"],\"discovery_addresses\":[],\"metadata\":{\"seq_number\":\"1\",\"attnets\":\"0x0000000000000000\",\"syncnets\":\"0x00\",\"custody_group_count\":\"4\"}}}";

    #[test]
    fn identity_wire_bytes_match_pre_table_implementation() {
        let resp = answer(&anchor_ctx(), &request("GET", "/eth/v1/node/identity"));
        assert_eq!(std::str::from_utf8(&resp).unwrap(), GOLDEN_IDENTITY);
    }

    #[test]
    fn new_local_enr_replaces_the_advertised_record() {
        let mut ctx = anchor_ctx();
        let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().cgc(32).build(keypair.secret_key()).unwrap();
        ctx.identity.set_enr(&enr);

        let resp = answer(&ctx, &request("GET", "/eth/v1/node/identity"));
        let body = std::str::from_utf8(&resp).unwrap();
        assert!(body.contains(&enr.to_base64()));
        assert!(body.contains(r#""custody_group_count":"32""#));
    }
}
