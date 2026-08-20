#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(test)]
use silver_beacon_state_data::BeaconStateOwner;
use silver_beacon_state_data::{BeaconStateReader, SpecConfig, StateReadView};
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::Query;

use crate::{
    NodeStatus,
    json::{FinalityCheckpoints, GenesisData, Json, StateFlags},
    node_status::Health,
    response::Response,
    router::{Handler, Method, Request},
    statics::StaticBodies,
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The status a syncing node reports when the request names no other one.
const DEFAULT_SYNCING_STATUS: u16 = 206;

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Get, "/eth/v1/beacon/genesis", genesis),
    (
        Method::Get,
        "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
        state_finality_checkpoints,
    ),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/fork", state_fork),
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

    /// The published state, or a 404 carrying `not_found` while the node has
    /// published none — the schemas of these endpoints declare no 503.
    pub(crate) fn read_state_or_404<R>(
        &self,
        resp: &mut Response<'_>,
        not_found: &str,
        read: impl Fn(StateReadView<'_>) -> R,
    ) -> Option<R> {
        let result = self.state.read(&read);
        if result.is_none() {
            resp.error(404, not_found);
        }
        result
    }

    /// Answers a `{state_id}` read in the envelope its schema requires. `read`
    /// runs under the seqlock and is re-run on retry, so it lifts scalars out
    /// and `render` writes them once, afterwards.
    pub(crate) fn state_response<R>(
        &self,
        req: &Request<'_>,
        resp: &mut Response<'_>,
        read: impl Fn(StateReadView<'_>) -> R,
        render: impl FnOnce(&mut Json<'_>, &R),
    ) {
        let state_id = req.params.get("state_id").expect("{state_id} in the route pattern");
        if state_id != "head" {
            if is_recognized_state_id(state_id) {
                resp.error(404, "state not found");
            } else {
                resp.error(400, "invalid state_id");
            }
            return;
        }

        let execution_optimistic = self.node_status.execution_optimistic();
        let read = |view: StateReadView<'_>| StateRead {
            flags: StateFlags {
                execution_optimistic,
                // Genesis is the only state that is its own finalized history:
                // finalization trails the current epoch, so past genesis the
                // finalized checkpoint is always behind the state's own slot.
                finalized: view.slot.state().slot == 0,
            },
            data: read(view),
        };
        let Some(state) = self.read_state_or_404(resp, "state not found", read) else {
            return;
        };

        resp.json_body(|json| json.state_envelope(state.flags, |json| render(json, &state.data)));
    }
}

/// One state read: the flags describe the snapshot `data` came from.
struct StateRead<R> {
    flags: StateFlags,
    data: R,
}

/// Whether `state_id` is one of the forms the schemas define — the `head`,
/// `genesis`, `justified` and `finalized` keywords, a slot, or a state root.
/// Anything else identifies no state at all, which the schemas answer 400,
/// where a recognized form silver cannot serve is a 404.
fn is_recognized_state_id(state_id: &str) -> bool {
    matches!(state_id, "head" | "genesis" | "justified" | "finalized") ||
        is_slot(state_id) ||
        state_id
            .strip_prefix("0x")
            .is_some_and(|root| root.len() == 64 && root.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `u64::from_str` alone also accepts a leading `+`, which the schemas call an
/// invalid `state_id` rather than a slot.
fn is_slot(state_id: &str) -> bool {
    state_id.bytes().all(|byte| byte.is_ascii_digit()) && state_id.parse::<u64>().is_ok()
}

fn genesis(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(genesis) =
        ctx.read_state_or_404(resp, "Chain genesis info is not yet known", |view| GenesisData {
            genesis_time: view.imm.genesis_time,
            genesis_validators_root: view.imm.genesis_validators_root,
            genesis_fork_version: view.imm.genesis_fork_version,
        })
    else {
        return;
    };
    resp.json_body(|json| {
        json.begin_object();
        json.key("data");
        json.genesis(&genesis);
        json.end_object();
    });
}

fn state_fork(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(req, resp, |view| *view.epoch.fork(), |json, fork| json.fork(fork));
}

fn state_finality_checkpoints(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(
        req,
        resp,
        |view| {
            let epoch = view.epoch.state();
            FinalityCheckpoints {
                previous_justified: epoch.previous_justified_checkpoint,
                current_justified: epoch.current_justified_checkpoint,
                finalized: epoch.finalized_checkpoint,
            }
        },
        |json, checkpoints| json.finality_checkpoints(checkpoints),
    );
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
    use silver_beacon_state_data::{
        BeaconState, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR, EpochState, EpochStateFinalized,
        Fork, SLOTS_PER_EPOCH,
    };
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
            slots: Some(SlotStatus { head_slot: 100, wall_slot: 100, head_optimistic: false }),
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

    /// First slot of the epoch two past [`epoch_state`]'s finalized
    /// checkpoint — normal operation, where head is not the finalized state.
    const HEAD_SLOT: u64 = 12_345 * SLOTS_PER_EPOCH;

    fn epoch_state() -> EpochState {
        EpochState {
            fork: Fork {
                previous_version: [0x05, 0x00, 0x00, 0x00],
                current_version: [0x06, 0x00, 0x00, 0x00],
                epoch: 269_568,
            },
            previous_justified_checkpoint: Checkpoint { epoch: 12_344, root: [0x01; 32] },
            current_justified_checkpoint: Checkpoint { epoch: 12_345, root: [0x02; 32] },
            finalized_checkpoint: Checkpoint { epoch: 12_343, root: [0x03; 32] },
            ..Default::default()
        }
    }

    /// A synced node with its one state published — every distinct value these
    /// endpoints read is set, so a golden catches a swapped field.
    fn published_ctx(epoch: EpochState, slot: u64) -> ApiCtx {
        let base = EpochStateFinalized::from_parts(
            epoch,
            vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
        );
        let mut state = BeaconState::for_test(base, &[], slot);
        state.immutable.genesis_time = 1_606_824_023;
        state.immutable.genesis_validators_root = [0x4b; 32];
        state.immutable.genesis_fork_version = [0x00, 0x00, 0x00, 0x01];

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);

        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status = ready();
        ctx
    }

    fn state_paths(state_id: &str) -> [String; 2] {
        [
            format!("/eth/v1/beacon/states/{state_id}/fork"),
            format!("/eth/v1/beacon/states/{state_id}/finality_checkpoints"),
        ]
    }

    fn state_body(ctx: &ApiCtx, path: &str) -> String {
        let resp = get(&Router::new(ROUTES), ctx, path);
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            "{path}: {}",
            String::from_utf8_lossy(&resp)
        );
        String::from_utf8(body(&resp).to_vec()).unwrap()
    }

    /// Body shape: `apis/beacon/genesis.yaml` — a bare `data` wrapper, the one
    /// state read that carries no envelope flags.
    #[test]
    fn genesis_body_is_a_bare_data_wrapper() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/genesis"),
            "{\"data\":{\"genesis_time\":\"1606824023\",\
             \"genesis_validators_root\":\"0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b\",\
             \"genesis_fork_version\":\"0x00000001\"}}"
        );
    }

    /// Body shape: `apis/beacon/states/fork.yaml`.
    #[test]
    fn state_fork_body_is_the_envelope_around_the_fork() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/states/head/fork"),
            "{\"execution_optimistic\":false,\"finalized\":false,\
             \"data\":{\"previous_version\":\"0x05000000\",\"current_version\":\"0x06000000\",\
             \"epoch\":\"269568\"}}"
        );
    }

    /// Body shape: `apis/beacon/states/finality_checkpoints.yaml`.
    #[test]
    fn finality_checkpoints_body_is_the_envelope_around_three_checkpoints() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        assert_eq!(
            state_body(&ctx, "/eth/v1/beacon/states/head/finality_checkpoints"),
            "{\"execution_optimistic\":false,\"finalized\":false,\"data\":{\
             \"previous_justified\":{\"epoch\":\"12344\",\
             \"root\":\"0x0101010101010101010101010101010101010101010101010101010101010101\"},\
             \"current_justified\":{\"epoch\":\"12345\",\
             \"root\":\"0x0202020202020202020202020202020202020202020202020202020202020202\"},\
             \"finalized\":{\"epoch\":\"12343\",\
             \"root\":\"0x0303030303030303030303030303030303030303030303030303030303030303\"}}}"
        );
    }

    fn assert_state_not_found(ctx: &ApiCtx, state_id: &str) {
        for path in state_paths(state_id) {
            let resp = get(&Router::new(ROUTES), ctx, &path);
            assert!(resp.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{path}");
            assert_eq!(body(&resp), br#"{"code":404,"message":"state not found"}"#, "{path}");
        }
    }

    /// Silver publishes one state, the head. `justified` and `finalized` name
    /// states it does not keep, and their checkpoints differ from the head's,
    /// so answering them with head data would be a wrong answer rather than a
    /// missing one.
    #[test]
    fn only_head_reads_the_published_state() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        for path in state_paths("head") {
            assert!(state_body(&ctx, &path).starts_with("{\"execution_optimistic\":false,"));
        }
        assert_state_not_found(&ctx, "justified");
        assert_state_not_found(&ctx, "finalized");
    }

    /// A state silver does not keep — no historical states, and the head is
    /// the only one published; a slot or root form is 404 even when it is the
    /// published state's own, which nothing here can check.
    #[test]
    fn a_state_id_naming_a_state_silver_does_not_keep_is_404() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let head_slot = HEAD_SLOT.to_string();
        for state_id in ["genesis", "0", &head_slot, &format!("0x{}", "ab".repeat(32))] {
            assert_state_not_found(&ctx, state_id);
        }
    }

    /// `Invalid state ID` in the schemas: a value that identifies no state at
    /// all is a 400, not the 404 an unavailable state gets.
    #[test]
    fn a_state_id_naming_no_state_at_all_is_400() {
        let ctx = published_ctx(epoch_state(), HEAD_SLOT);
        let short_root = format!("0x{}", "ab".repeat(31));
        let unhex_root = format!("0x{}", "zz".repeat(32));
        for state_id in
            ["current", "banana", "", "-1", "+5", "0x", "1.5", &short_root, &unhex_root, "HEAD"]
        {
            for path in state_paths(state_id) {
                let resp = get(&Router::new(ROUTES), &ctx, &path);
                assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
                assert_eq!(body(&resp), br#"{"code":400,"message":"invalid state_id"}"#, "{path}");
            }
        }
    }

    /// Neither endpoint's schema declares a 503, so a node with no state
    /// published answers 404 — genesis with the phrase its own schema names.
    #[test]
    fn state_reads_are_404_before_bootstrap() {
        let ctx = preboot_ctx();
        let resp = get(&Router::new(ROUTES), &ctx, "/eth/v1/beacon/genesis");
        assert!(resp.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        assert_eq!(body(&resp), br#"{"code":404,"message":"Chain genesis info is not yet known"}"#);
        assert_state_not_found(&ctx, "head");
    }

    /// The `state_id` verdict does not depend on there being a state to read.
    #[test]
    fn an_invalid_state_id_is_answered_before_the_state_is_read() {
        for path in state_paths("banana") {
            let resp = get(&Router::new(ROUTES), &preboot_ctx(), &path);
            assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
        }
    }

    fn with_head_optimistic(head_optimistic: bool) -> NodeStatus {
        let ready = ready();
        NodeStatus { slots: Some(SlotStatus { head_optimistic, ..ready.slots.unwrap() }), ..ready }
    }

    /// The envelope flag is the head's own execution status, not a reading of
    /// how far behind the node is: an unverified head is optimistic with both
    /// layers reporting themselves synced, and a verified one is not while they
    /// do not. A state read served before the first status announces a head is
    /// optimistic — nothing has vouched for that head's payload yet.
    #[test]
    fn execution_optimistic_is_the_head_s_own_status() {
        let mut ctx = published_ctx(epoch_state(), HEAD_SLOT);
        for (status, want) in [
            (with_head_optimistic(true), "true"),
            (with_head_optimistic(false), "false"),
            (NodeStatus { syncing: true, ..with_head_optimistic(false) }, "false"),
            (NodeStatus { el: ELSyncStatus::Offline, ..with_head_optimistic(false) }, "false"),
            (NodeStatus { syncing: true, ..with_head_optimistic(true) }, "true"),
            (NodeStatus::default(), "true"),
        ] {
            ctx.node_status = status;
            for path in state_paths("head") {
                assert!(
                    state_body(&ctx, &path)
                        .starts_with(&format!("{{\"execution_optimistic\":{want},")),
                    "{status:?} {path}"
                );
            }
        }
    }

    /// `finalized` describes the state served, and genesis is the only state
    /// that is its own finalized history.
    #[test]
    fn finalized_is_true_only_for_the_genesis_state() {
        let genesis_epoch = EpochState {
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            ..epoch_state()
        };
        let at_genesis = published_ctx(genesis_epoch, 0);
        let past_genesis = published_ctx(epoch_state(), HEAD_SLOT);
        for path in state_paths("head") {
            let flags = "{\"execution_optimistic\":false,\"finalized\":";
            assert!(state_body(&at_genesis, &path).starts_with(&format!("{flags}true,")));
            assert!(state_body(&past_genesis, &path).starts_with(&format!("{flags}false,")));
        }
    }
}
