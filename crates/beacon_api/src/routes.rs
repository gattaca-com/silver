#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(test)]
use silver_beacon_state_data::BeaconStateOwner;
use silver_beacon_state_data::{BeaconStateReader, SpecConfig, StateReadView};
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::Query;

use crate::{
    NodeStatus,
    node_status::Health,
    response::Response,
    router::{Handler, Method, Request},
    statics::StaticBodies,
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The status a syncing node reports when the request names no other one.
const DEFAULT_SYNCING_STATUS: u16 = 206;

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Get, "/eth/v1/config/deposit_contract", deposit_contract),
    (Method::Get, "/eth/v1/config/fork_schedule", fork_schedule),
    (Method::Get, "/eth/v1/config/spec", spec),
    (Method::Get, "/eth/v1/node/health", health),
    (Method::Get, "/eth/v1/node/identity", identity),
    (Method::Get, "/eth/v1/node/version", version),
    (Method::Get, "/metrics", metrics),
];

pub(crate) struct ApiCtx {
    pub(crate) statics: StaticBodies,
    pub(crate) state: BeaconStateReader,
    pub(crate) node_status: NodeStatus,
}

impl ApiCtx {
    pub(crate) fn new(
        keypair: &Keypair,
        local_enr: &Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
    ) -> Self {
        Self {
            statics: StaticBodies::new(keypair, local_enr, identify, spec),
            state,
            node_status: NodeStatus::default(),
        }
    }

    // Live with the first endpoint that reads the published state.
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
    resp.json(&ctx.statics.identity);
}

fn version(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.statics.version);
}

fn spec(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.statics.spec);
}

fn fork_schedule(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.statics.fork_schedule);
}

fn deposit_contract(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.statics.deposit_contract);
}

/// Health is the status code and nothing else — the schema gives this
/// endpoint no response body at any code.
fn health(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(syncing_status) = syncing_status(req.query) else {
        resp.error(400, "invalid syncing_status");
        return;
    };
    let code = match ctx.node_status.health() {
        Health::Ready => 200,
        Health::Syncing => syncing_status,
        Health::Uninitialized => 503,
    };
    resp.status_only(code);
}

/// The optional `syncing_status` query parameter, which replaces the code a
/// syncing node reports. `None` for a value outside the 100..=599 the schema
/// allows, which the spec answers with a 400.
fn syncing_status(query: &str) -> Option<u16> {
    let named =
        Query::new(query).find_map(|(name, value)| (name == "syncing_status").then_some(value));
    match named {
        Some(value) => value.parse().ok().filter(|code| (100..=599).contains(code)),
        None => Some(DEFAULT_SYNCING_STATUS),
    }
}

fn metrics(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.empty(METRICS_CONTENT_TYPE);
}

/// Never-published reader: `read` yields `None`, as on a node before
/// bootstrap.
#[cfg(test)]
pub(crate) fn preboot_ctx() -> ApiCtx {
    test_ctx(&SpecConfig::mainnet(), BeaconStateOwner::empty_test(0).reader())
}

#[cfg(test)]
fn test_ctx(spec: &SpecConfig, state: BeaconStateReader) -> ApiCtx {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let enr = Enr::builder().build(keypair.secret_key()).unwrap();
    let mut identify = Identify::default();
    identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
    ApiCtx::new(&keypair, &enr, &identify, spec, state)
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::BeaconState;
    use silver_common::{AGENT_VERSION, ELSyncStatus};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{SlotStatus, router::Router};

    /// Wire bytes the pre-table implementation produced for these exact
    /// inputs (captured before the table dispatch landed).
    const GOLDEN_IDENTITY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 478\r\n\r\n{\"data\":{\"peer_id\":\"16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\",\"enr\":\"enr:-HW4QFVim6voTojjE-JbeUF0GPFRcqmWxgqgJ8-tXE5hh9PFTQSCwUJPHY_61U3Wvzi6OGrvJfb6KNjNpw4Q18sNL_sBgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48\",\"p2p_addresses\":[\"/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\"],\"discovery_addresses\":[],\"metadata\":{\"seq_number\":\"1\",\"attnets\":\"0x0000000000000000\",\"syncnets\":\"0x00\",\"custody_group_count\":\"4\"}}}";

    fn get(router: &Router, ctx: &ApiCtx, path: &str) -> Vec<u8> {
        query_get(router, ctx, path, "")
    }

    fn query_get(router: &Router, ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let req = ParsedRequest {
            method: "GET",
            path,
            query,
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
        let resp = get(&router, &preboot_ctx(), "/eth/v1/node/identity");
        assert_eq!(std::str::from_utf8(&resp).unwrap(), GOLDEN_IDENTITY);
    }

    #[test]
    fn identity_content_length_matches_body() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &preboot_ctx(), "/eth/v1/node/identity");
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
    fn version_body_carries_this_build_s_agent_version() {
        let router = Router::new(ROUTES);
        let resp = get(&router, &preboot_ctx(), "/eth/v1/node/version");
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"));
        assert_eq!(
            std::str::from_utf8(body(&resp)).unwrap(),
            format!("{{\"data\":{{\"version\":\"{AGENT_VERSION}\"}}}}")
        );
    }

    /// Config is boot-time data, so these three answer before the node has a
    /// state to read — a validator client polls them while silver is still
    /// syncing.
    #[test]
    fn config_endpoints_answer_before_bootstrap() {
        let router = Router::new(ROUTES);
        for path in [
            "/eth/v1/config/spec",
            "/eth/v1/config/fork_schedule",
            "/eth/v1/config/deposit_contract",
        ] {
            let resp = get(&router, &preboot_ctx(), path);
            assert!(
                resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
                "{path}"
            );
            let parsed: serde_json::Value = serde_json::from_slice(body(&resp)).expect(path);
            assert!(parsed.get("data").is_some(), "{path}");
            assert_eq!(parsed.as_object().unwrap().len(), 1, "{path}: bare data wrapper");
        }
    }

    fn ready() -> NodeStatus {
        NodeStatus {
            slots: Some(SlotStatus { head_slot: 100, wall_slot: 100 }),
            syncing: false,
            el: ELSyncStatus::Synced,
        }
    }

    fn health_response(status: NodeStatus, query: &str) -> Vec<u8> {
        let mut ctx = preboot_ctx();
        ctx.node_status = status;
        query_get(&Router::new(ROUTES), &ctx, "/eth/v1/node/health", query)
    }

    #[test]
    fn health_is_503_until_the_first_slot_status_arrives() {
        assert_eq!(
            health_response(NodeStatus::default(), ""),
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn health_is_200_only_when_both_layers_are_synced() {
        assert_eq!(health_response(ready(), ""), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        for el in [ELSyncStatus::Unknown, ELSyncStatus::Syncing, ELSyncStatus::Offline] {
            let resp = health_response(NodeStatus { el, ..ready() }, "");
            assert!(resp.starts_with(b"HTTP/1.1 206 Partial Content\r\n"), "{el:?}");
        }
        let resp = health_response(NodeStatus { syncing: true, ..ready() }, "");
        assert_eq!(resp, b"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn syncing_status_replaces_the_206_and_nothing_else() {
        let syncing = NodeStatus { syncing: true, ..ready() };
        assert!(health_response(syncing, "syncing_status=200").starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(health_response(syncing, "syncing_status=503").starts_with(b"HTTP/1.1 503 "));
        assert!(health_response(ready(), "syncing_status=503").starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            health_response(NodeStatus::default(), "syncing_status=200")
                .starts_with(b"HTTP/1.1 503 ")
        );
        assert!(health_response(syncing, "other=1").starts_with(b"HTTP/1.1 206 "));
    }

    /// A code the schema allows but this API has no phrase for still frames,
    /// with the empty reason phrase RFC 9112 §4.1 permits.
    #[test]
    fn a_syncing_status_with_no_reason_phrase_still_frames() {
        let syncing = NodeStatus { syncing: true, ..ready() };
        assert_eq!(
            health_response(syncing, "syncing_status=250"),
            b"HTTP/1.1 250 \r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn a_syncing_status_outside_the_schema_s_range_is_a_400() {
        for query in [
            "syncing_status=99",
            "syncing_status=600",
            "syncing_status=",
            "syncing_status=abc",
            "syncing_status=-1",
            "syncing_status=70000",
        ] {
            let resp = health_response(ready(), query);
            assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{query}");
            assert_eq!(
                body(&resp),
                br#"{"code":400,"message":"invalid syncing_status"}"#,
                "{query}"
            );
        }
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
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());

        let router = Router::new(&[(Method::Get, "/test/genesis_root", genesis_root)]);
        let resp = get(&router, &ctx, "/test/genesis_root");
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(body(&resp), hex::encode([0u8; 32]).as_bytes());
    }
}
