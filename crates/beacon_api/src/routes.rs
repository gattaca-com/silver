use std::sync::Arc;

#[cfg(test)]
use silver_beacon_state_data::BeaconStateOwner;
use silver_beacon_state_data::{BeaconStateReader, SpecConfig, StateReadView};
use silver_common::{Enr, Identify, Keypair};

use crate::{
    NodeStatus,
    identity::build_identity_json,
    response::Response,
    router::{Handler, Method, Request},
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub(crate) const ROUTES: &[(Method, &str, Handler)] =
    &[(Method::Get, "/eth/v1/node/identity", identity), (Method::Get, "/metrics", metrics)];

pub(crate) struct ApiCtx {
    pub(crate) identity_json: Vec<u8>,
    pub(crate) state: BeaconStateReader,
    // The config and node-status endpoints land after this; until then only
    // the owning tile writes `node_status`.
    #[allow(dead_code)]
    pub(crate) spec: Arc<SpecConfig>,
    #[allow(dead_code)]
    pub(crate) node_status: NodeStatus,
}

impl ApiCtx {
    pub(crate) fn new(
        keypair: &Keypair,
        local_enr: &Enr,
        identify: &Identify,
        spec: Arc<SpecConfig>,
        state: BeaconStateReader,
    ) -> Self {
        Self {
            identity_json: build_identity_json(keypair, local_enr, identify),
            state,
            spec,
            node_status: NodeStatus::default(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn read_state_or_503<R>(
        &self,
        resp: &mut Response<'_>,
        read: impl Fn(StateReadView<'_>) -> R,
    ) -> Option<R> {
        let result = self.state.read(&read);
        if result.is_none() {
            resp.error(503, "beacon node not initialized");
        }
        result
    }
}

fn identity(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.identity_json);
}

fn metrics(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.empty(METRICS_CONTENT_TYPE);
}

/// Never-published reader: `read` yields `None`, as on a node before
/// bootstrap.
#[cfg(test)]
pub(crate) fn preboot_ctx() -> ApiCtx {
    test_ctx(Vec::new(), BeaconStateOwner::empty_test(0).reader())
}

#[cfg(test)]
fn test_ctx(identity_json: Vec<u8>, state: BeaconStateReader) -> ApiCtx {
    ApiCtx {
        identity_json,
        state,
        spec: Arc::new(SpecConfig::mainnet()),
        node_status: NodeStatus::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use silver_beacon_state_data::BeaconState;
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::router::Router;

    /// Wire bytes the pre-table implementation produced for these exact
    /// inputs (captured before the table dispatch landed).
    const GOLDEN_IDENTITY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 478\r\n\r\n{\"data\":{\"peer_id\":\"16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\",\"enr\":\"enr:-HW4QFVim6voTojjE-JbeUF0GPFRcqmWxgqgJ8-tXE5hh9PFTQSCwUJPHY_61U3Wvzi6OGrvJfb6KNjNpw4Q18sNL_sBgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48\",\"p2p_addresses\":[\"/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\"],\"discovery_addresses\":[],\"metadata\":{\"seq_number\":\"1\",\"attnets\":\"0x0000000000000000\",\"syncnets\":\"0x00\",\"custody_group_count\":\"4\"}}}";

    fn fixture_ctx() -> ApiCtx {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let mut identify = Identify::default();
        identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
        ApiCtx::new(
            &kp,
            &enr,
            &identify,
            Arc::new(SpecConfig::mainnet()),
            BeaconStateOwner::empty_test(0).reader(),
        )
    }

    fn get(router: &Router, ctx: &ApiCtx, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let req = ParsedRequest {
            method: "GET",
            path,
            query: "",
            body: b"",
            accept: None,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        router.dispatch(&req, ctx, &mut out);
        out
    }

    fn body(response: &[u8]) -> &[u8] {
        let s = std::str::from_utf8(response).unwrap();
        &response[s.find("\r\n\r\n").unwrap() + 4..]
    }

    #[test]
    fn identity_wire_bytes_match_pre_table_implementation() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &fixture_ctx(), "/eth/v1/node/identity");
        assert_eq!(std::str::from_utf8(&resp).unwrap(), GOLDEN_IDENTITY);
    }

    #[test]
    fn identity_content_length_matches_body() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &fixture_ctx(), "/eth/v1/node/identity");
        let s = std::str::from_utf8(&resp).unwrap();
        let header_end = s.find("\r\n\r\n").unwrap();
        let cl: usize = s[..header_end]
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(cl, s[header_end + 4..].len());
    }

    #[test]
    fn metrics_response_valid_prometheus_format() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &preboot_ctx(), "/metrics");
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("text/plain; version=0.0.4; charset=utf-8"));
        assert_eq!(body(&resp), b"");
    }

    #[test]
    fn unknown_path_returns_404() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &preboot_ctx(), "/not/real");
        assert_eq!(resp, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn events_returns_404_v1_defers_sse_clients_poll() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &preboot_ctx(), "/eth/v1/events");
        assert_eq!(resp, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }

    fn genesis_root(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
        let Some(root) = ctx.read_state_or_503(resp, |view| view.imm.genesis_validators_root)
        else {
            return;
        };
        resp.json(hex::encode(root).as_bytes());
    }

    #[test]
    fn state_route_503_before_bootstrap() {
        let router = Router::new(&[(Method::Get, "/test/genesis_root", genesis_root)]);
        let resp = get(&router, &preboot_ctx(), "/test/genesis_root");
        assert!(resp.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert_eq!(body(&resp), br#"{"code":503,"message":"beacon node not initialized"}"#);
    }

    #[test]
    fn state_route_reads_published_state() {
        let mut owner = BeaconStateOwner::new(BeaconState::empty_test(0));
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let ctx = test_ctx(Vec::new(), owner.reader());

        let router = Router::new(&[(Method::Get, "/test/genesis_root", genesis_root)]);
        let resp = get(&router, &ctx, "/test/genesis_root");
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(body(&resp), hex::encode([0u8; 32]).as_bytes());
    }
}
