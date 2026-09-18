#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(test)]
use silver_beacon_state_data::BeaconStateOwner;
use silver_beacon_state_data::{
    B256, BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig, StateReadView,
};
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::Query;

use crate::{
    NodeStatus,
    attester_duties::{PostedShufflings, post_attester_duties},
    blocks::{block, block_header, block_root},
    events::events,
    ids::is_recognized_id,
    json::{FinalityCheckpoints, GenesisData, Json, ReadFlags},
    node_status::Health,
    peers::{PeerFilter, PeerTable},
    proposer_duties::{proposer_duties, proposer_duties_v2},
    response::Response,
    router::{Handler, Method, Request},
    statics::StaticBodies,
    sync_duties::post_sync_duties,
    validator_api::{
        post_beacon_committee_subscriptions, post_prepare_beacon_proposer, post_register_validator,
        post_sync_committee_subscriptions,
    },
    validators::{get_state_validators, post_state_validators, state_validator},
};

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The status a syncing node reports when the request names no other one.
const DEFAULT_SYNCING_STATUS: u16 = 206;

pub(crate) const ROUTES: &[(Method, &str, Handler)] = &[
    (Method::Get, "/eth/v1/beacon/blocks/{block_id}/root", block_root),
    (Method::Get, "/eth/v1/beacon/genesis", genesis),
    (Method::Get, "/eth/v1/beacon/headers/{block_id}", block_header),
    (
        Method::Get,
        "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
        state_finality_checkpoints,
    ),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/fork", state_fork),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators", get_state_validators),
    (Method::Post, "/eth/v1/beacon/states/{state_id}/validators", post_state_validators),
    (Method::Get, "/eth/v1/beacon/states/{state_id}/validators/{validator_id}", state_validator),
    (Method::Get, "/eth/v1/config/deposit_contract", deposit_contract),
    (Method::Get, "/eth/v1/config/fork_schedule", fork_schedule),
    (Method::Get, "/eth/v1/config/spec", spec),
    (Method::Get, "/eth/v1/events", events),
    (Method::Get, "/eth/v1/node/health", health),
    (Method::Get, "/eth/v1/node/identity", identity),
    (Method::Get, "/eth/v1/node/peer_count", peer_count),
    (Method::Get, "/eth/v1/node/peers", peers),
    (Method::Get, "/eth/v1/node/syncing", syncing),
    (Method::Get, "/eth/v1/node/version", version),
    (
        Method::Post,
        "/eth/v1/validator/beacon_committee_subscriptions",
        post_beacon_committee_subscriptions,
    ),
    (Method::Post, "/eth/v1/validator/duties/attester/{epoch}", post_attester_duties),
    (Method::Get, "/eth/v1/validator/duties/proposer/{epoch}", proposer_duties),
    (Method::Post, "/eth/v1/validator/duties/sync/{epoch}", post_sync_duties),
    (Method::Post, "/eth/v1/validator/liveness/{epoch}", not_implemented),
    (Method::Post, "/eth/v1/validator/prepare_beacon_proposer", post_prepare_beacon_proposer),
    (Method::Post, "/eth/v1/validator/register_validator", post_register_validator),
    (
        Method::Post,
        "/eth/v1/validator/sync_committee_subscriptions",
        post_sync_committee_subscriptions,
    ),
    (Method::Get, "/eth/v2/beacon/blocks/{block_id}", block),
    (Method::Get, "/eth/v2/validator/duties/proposer/{epoch}", proposer_duties_v2),
    (Method::Get, "/metrics", metrics),
];

pub(crate) struct ApiCtx {
    pub(crate) statics: StaticBodies,
    pub(crate) spec: SpecConfig,
    pub(crate) state: BeaconStateReader,
    pub(crate) node_status: NodeStatus,
    pub(crate) peers: PeerTable,
    pub(crate) shufflings: PostedShufflings,
}

impl ApiCtx {
    pub(crate) fn new(
        keypair: &Keypair,
        local_enr: &Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
        anchor_root: B256,
    ) -> Self {
        let (head_slot, anchor_epoch) = state
            .read(|view: StateReadView<'_>| {
                let slot = view.slot.state();
                (slot.latest_block_header.slot, slot.slot / SLOTS_PER_EPOCH)
            })
            .expect("beacon api needs the anchor state published");
        Self {
            statics: StaticBodies::new(keypair, local_enr, identify, spec),
            spec: spec.clone(),
            state,
            node_status: NodeStatus::at_anchor(head_slot, anchor_root, anchor_epoch),
            peers: PeerTable::new(),
            shufflings: PostedShufflings::default(),
        }
    }

    pub(crate) fn read_state<R>(&self, read: impl FnMut(StateReadView<'_>) -> R) -> R {
        self.state.read(read).expect("beacon api needs the anchor state published")
    }

    /// Resolves `{state_id}` and reads from the state it names, alongside the
    /// flags those schemas require beside `data`. `read` runs under the seqlock
    /// and is re-run whole on retry, so it lifts out what the body needs and
    /// rendering happens afterwards.
    pub(crate) fn state_read<R>(
        &self,
        req: &Request<'_>,
        resp: &mut Response<'_>,
        mut read: impl FnMut(StateReadView<'_>) -> R,
    ) -> Option<StateRead<R>> {
        if !self.serves_state(req, resp) {
            return None;
        }
        let node_status = self.node_status;
        let read = |view: StateReadView<'_>| StateRead {
            flags: read_flags(node_status, &view),
            data: read(view),
        };
        Some(self.read_state(read))
    }

    /// A `{state_id}` read whose body is the envelope around `render`, written
    /// under the read straight into the response. `render` runs again from an
    /// empty body on retry.
    pub(crate) fn state_response(
        &self,
        req: &Request<'_>,
        resp: &mut Response<'_>,
        mut render: impl FnMut(&StateReadView<'_>, &mut Json<'_>),
    ) {
        if !self.serves_state(req, resp) {
            return;
        }
        let node_status = self.node_status;
        resp.json_body(|json| {
            self.read_state(|view| {
                json.restart();
                json.flagged_envelope(read_flags(node_status, &view), |json| render(&view, json));
            });
        });
    }

    pub(crate) fn follows_chain(&self, resp: &mut Response<'_>) -> bool {
        if self.node_status.is_following() {
            return true;
        }
        resp.error(503, "api unavailable while the node is syncing");
        false
    }

    /// Whether `{state_id}` names the one state silver serves, having answered
    /// the request when it does not.
    fn serves_state(&self, req: &Request<'_>, resp: &mut Response<'_>) -> bool {
        let state_id = req.params.get("state_id").expect("{state_id} in the route pattern");
        if state_id == "head" {
            return true;
        }
        if is_recognized_id(state_id) {
            resp.error(404, "state not found");
        } else {
            resp.error(400, "invalid state_id");
        }
        false
    }
}

/// One state read: the flags describe the snapshot `data` came from.
pub(crate) struct StateRead<R> {
    pub(crate) flags: ReadFlags,
    pub(crate) data: R,
}

fn read_flags(node_status: NodeStatus, view: &StateReadView<'_>) -> ReadFlags {
    ReadFlags {
        execution_optimistic: node_status.execution_optimistic(),
        finalized: node_status.is_finalized(view.slot.state().latest_block_header.slot),
    }
}

/// The surface a request can name ahead of what silver serves: each of these
/// routes needs data the node does not yet keep (a block store, duty
/// shuffling, liveness tracking), so
/// the honest answer is the 501 that tells the client to look elsewhere,
/// rather than a partial answer assembled from the wrong data.
fn not_implemented(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.error(501, "endpoint not implemented by this beacon node");
}

fn genesis(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let genesis = ctx.read_state(|view| GenesisData {
        genesis_time: view.imm.genesis_time,
        genesis_validators_root: view.imm.genesis_validators_root,
        genesis_fork_version: view.imm.genesis_fork_version,
    });
    resp.json_body(|json| json.data_envelope(|json| json.genesis(&genesis)));
}

fn syncing(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let syncing = ctx.node_status.syncing_data();
    resp.json_body(|json| json.data_envelope(|json| json.syncing(&syncing)));
}

fn state_fork(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(req, resp, |view, json| json.fork(view.epoch.fork()));
}

fn state_finality_checkpoints(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    ctx.state_response(req, resp, |view, json| {
        let epoch = view.epoch.state();
        json.finality_checkpoints(&FinalityCheckpoints {
            previous_justified: epoch.previous_justified_checkpoint,
            current_justified: epoch.current_justified_checkpoint,
            finalized: epoch.finalized_checkpoint,
        })
    });
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

fn peers(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    match PeerFilter::parse(req.query) {
        Some(filter) => resp.json_body(|json| json.peers(ctx.peers.matching(&filter))),
        None => resp.error(400, "invalid state or direction"),
    }
}

fn peer_count(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let connected = ctx.peers.len() as u64;
    resp.json_body(|json| json.data_envelope(|json| json.peer_count(connected)));
}

fn metrics(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.empty(METRICS_CONTENT_TYPE);
}

/// A node right after bootstrap: an empty anchor published at slot 0.
#[cfg(test)]
pub(crate) fn anchor_ctx() -> ApiCtx {
    test_ctx(&SpecConfig::mainnet(), BeaconStateOwner::published_empty_test(0).reader())
}

#[cfg(test)]
pub(crate) fn test_ctx(spec: &SpecConfig, state: BeaconStateReader) -> ApiCtx {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let enr = Enr::builder().build(keypair.secret_key()).unwrap();
    let mut identify = Identify::default();
    identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
    ApiCtx::new(&keypair, &enr, &identify, spec, state, B256::default())
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconBlockHeader, BeaconState, Checkpoint, EpochState, EpochStateFinalized, Fork,
        SlotState, SlotStateFinalized, SlotStateGroup,
    };
    use silver_common::{AGENT_VERSION, ELSyncStatus, IpBytes, SyncUpdate};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        HeadStatus,
        peers::Peer,
        testing::{answer, body, posting, request},
    };

    /// Wire bytes the pre-table implementation produced for these exact
    /// inputs (captured before the table dispatch landed).
    const GOLDEN_IDENTITY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 478\r\n\r\n{\"data\":{\"peer_id\":\"16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\",\"enr\":\"enr:-HW4QFVim6voTojjE-JbeUF0GPFRcqmWxgqgJ8-tXE5hh9PFTQSCwUJPHY_61U3Wvzi6OGrvJfb6KNjNpw4Q18sNL_sBgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48\",\"p2p_addresses\":[\"/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmEWQnHq2jLKJypwVnVoQeFCULuyop6atvq2eWjYSUjzNi\"],\"discovery_addresses\":[],\"metadata\":{\"seq_number\":\"1\",\"attnets\":\"0x0000000000000000\",\"syncnets\":\"0x00\",\"custody_group_count\":\"4\"}}}";

    fn get(ctx: &ApiCtx, path: &str) -> Vec<u8> {
        query_get(ctx, path, "")
    }

    fn query_get(ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
        answer(ctx, &ParsedRequest { query, ..request("GET", path) })
    }

    #[test]
    fn identity_wire_bytes_match_pre_table_implementation() {
        let resp = get(&anchor_ctx(), "/eth/v1/node/identity");
        assert_eq!(std::str::from_utf8(&resp).unwrap(), GOLDEN_IDENTITY);
    }

    #[test]
    fn version_body_carries_this_build_s_agent_version() {
        let resp = get(&anchor_ctx(), "/eth/v1/node/version");
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
        for path in [
            "/eth/v1/config/spec",
            "/eth/v1/config/fork_schedule",
            "/eth/v1/config/deposit_contract",
        ] {
            let resp = get(&anchor_ctx(), path);
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
            head: HeadStatus { slot: 100, optimistic: false },
            head_root: [0x11; 32],
            finalized_epoch: 12_343,
            target: Some(SyncUpdate::Following),
            el: ELSyncStatus::Synced,
        }
    }

    fn at_head(slot: u64) -> NodeStatus {
        NodeStatus { head: HeadStatus { slot, optimistic: false }, ..ready() }
    }

    fn chasing(head_slot: u64) -> Option<SyncUpdate> {
        Some(SyncUpdate::SyncingHead { head_root: [0; 32], head_slot })
    }

    fn health_response(status: NodeStatus, query: &str) -> Vec<u8> {
        let mut ctx = anchor_ctx();
        ctx.node_status = status;
        query_get(&ctx, "/eth/v1/node/health", query)
    }

    #[test]
    fn health_is_200_only_when_both_layers_are_synced() {
        assert_eq!(health_response(ready(), ""), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        for el in [ELSyncStatus::Unknown, ELSyncStatus::Syncing, ELSyncStatus::Offline] {
            let resp = health_response(NodeStatus { el, ..ready() }, "");
            assert!(resp.starts_with(b"HTTP/1.1 206 Partial Content\r\n"), "{el:?}");
        }
        let resp = health_response(NodeStatus { target: chasing(200), ..ready() }, "");
        assert_eq!(resp, b"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn syncing_status_replaces_the_206_and_nothing_else() {
        let syncing = NodeStatus { target: chasing(200), ..ready() };
        assert!(health_response(syncing, "syncing_status=200").starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(health_response(syncing, "syncing_status=503").starts_with(b"HTTP/1.1 503 "));
        assert!(health_response(ready(), "syncing_status=503").starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(health_response(syncing, "other=1").starts_with(b"HTTP/1.1 206 "));
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

    /// Both node-status endpoints answer from `NodeStatus` alone, so the
    /// anchor context is all they need.
    fn status_body(status: NodeStatus, path: &str) -> String {
        let mut ctx = anchor_ctx();
        ctx.node_status = status;
        let resp = get(&ctx, path);
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            "{path}: {}",
            String::from_utf8_lossy(&resp)
        );
        String::from_utf8(body(&resp).to_vec()).unwrap()
    }

    fn syncing_data(status: NodeStatus) -> serde_json::Value {
        let body = status_body(status, "/eth/v1/node/syncing");
        let mut parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        parsed["data"].take()
    }

    /// Body shape: `apis/node/syncing.yaml` — five required fields, slots
    /// quoted and flags bare.
    #[test]
    fn syncing_body_reports_the_head_and_both_layers() {
        assert_eq!(
            status_body(ready(), "/eth/v1/node/syncing"),
            "{\"data\":{\"head_slot\":\"100\",\"sync_distance\":\"0\",\"is_syncing\":false,\
             \"is_optimistic\":false,\"el_offline\":false}}"
        );
    }

    /// Right after bootstrap the head is the anchor, no target exists to
    /// measure a distance to, and neither layer has vouched for anything.
    #[test]
    fn syncing_answers_at_the_anchor_before_any_tile_reports() {
        let ctx = anchor_ctx();
        assert_eq!(
            status_body(ctx.node_status, "/eth/v1/node/syncing"),
            "{\"data\":{\"head_slot\":\"0\",\"sync_distance\":\"18446744073709551615\",\
             \"is_syncing\":true,\"is_optimistic\":false,\"el_offline\":true}}"
        );
    }

    /// The sync engine owns "at the head": the API answers from its target
    /// and never from a slot tolerance of its own.
    #[test]
    fn is_syncing_is_whether_the_engine_is_following() {
        assert_eq!(
            syncing_data(NodeStatus { target: chasing(200), ..ready() })["is_syncing"],
            true
        );
        assert_eq!(syncing_data(at_head(10))["is_syncing"], false, "following");
        let no_target = NodeStatus { target: None, ..ready() };
        assert_eq!(syncing_data(no_target)["is_syncing"], true, "before the first target");
    }

    /// The same flag the state envelopes carry: the head's own execution
    /// status, not a constant and not a reading of the node's sync state.
    #[test]
    fn syncing_is_optimistic_is_the_head_s_own_status() {
        assert_eq!(syncing_data(with_head_optimistic(true))["is_optimistic"], true);
        assert_eq!(syncing_data(with_head_optimistic(false))["is_optimistic"], false);
        let syncing_node = NodeStatus { target: chasing(200), ..with_head_optimistic(false) };
        assert_eq!(syncing_data(syncing_node)["is_optimistic"], false);
        let offline_el = NodeStatus { el: ELSyncStatus::Offline, ..with_head_optimistic(false) };
        assert_eq!(syncing_data(offline_el)["is_optimistic"], false);
    }

    /// An EL that answered a healthcheck is reachable whatever it answered;
    /// one that has never answered is no more reachable than a failed one.
    #[test]
    fn el_offline_is_true_only_while_the_el_has_answered_nothing() {
        for (el, offline) in [
            (ELSyncStatus::Unknown, true),
            (ELSyncStatus::Offline, true),
            (ELSyncStatus::Syncing, false),
            (ELSyncStatus::Synced, false),
        ] {
            let data = syncing_data(NodeStatus { el, ..ready() });
            assert_eq!(data["el_offline"], offline, "{el:?}");
            assert_eq!(data["is_syncing"], false, "{el:?}: the EL is not the node's own sync");
        }
    }

    /// The distance is to the target the engine reports: zero once following,
    /// and never an underflow when the target sits below the head.
    #[test]
    fn sync_distance_is_to_the_sync_target() {
        assert_eq!(syncing_data(at_head(90))["sync_distance"], "0", "following");
        let to_head = NodeStatus { target: chasing(150), ..at_head(100) };
        assert_eq!(syncing_data(to_head)["sync_distance"], "50");
        let finalized = SyncUpdate::SyncingFinalized { target_epoch: 4, target_root: [0; 32] };
        let to_finalized = NodeStatus { target: Some(finalized), ..at_head(100) };
        assert_eq!(syncing_data(to_finalized)["sync_distance"], "28");
        let reached = NodeStatus { target: chasing(90), ..at_head(100) };
        assert_eq!(syncing_data(reached)["sync_distance"], "0", "target below the head");
    }

    /// Every stubbed route answers 501 whatever the node's state: routed, so
    /// a client can tell "this node does not serve it" (501) from "no such
    /// endpoint exists" (404).
    #[test]
    fn stubbed_routes_answer_501_not_404() {
        let ctx = anchor_ctx();
        for (method, path) in [("POST", "/eth/v1/validator/liveness/0")] {
            let out = answer(&ctx, &ParsedRequest { method, ..posting(path, "[]") });
            assert!(out.starts_with(b"HTTP/1.1 501 Not Implemented\r\n"), "{method} {path}");
            assert_eq!(
                body(&out),
                br#"{"code":501,"message":"endpoint not implemented by this beacon node"}"#,
                "{method} {path}"
            );
        }
    }

    fn two_peer_ctx() -> ApiCtx {
        let mut ctx = anchor_ctx();
        for (connection, inbound) in [(1, true), (2, false)] {
            ctx.peers.insert(connection, Peer {
                id: Keypair::from_secret(&[connection as u8; 32]).unwrap().peer_id(),
                ip: IpBytes::V4([10, 0, 0, connection as u8]),
                port: 9000,
                inbound,
            });
        }
        ctx
    }

    fn peers_json(query: &str) -> serde_json::Value {
        let resp = query_get(&two_peer_ctx(), "/eth/v1/node/peers", query);
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"));
        serde_json::from_slice(body(&resp)).unwrap()
    }

    #[test]
    fn peers_list_every_connection_and_honour_the_filters() {
        let all = peers_json("");
        assert_eq!(all["meta"]["count"], 2);
        let inbound = peers_json("direction=inbound&state=connected&state=connecting");
        assert_eq!(inbound["meta"]["count"], 1);
        let peer = &inbound["data"][0];
        let id = peer["peer_id"].as_str().unwrap();
        assert!(peer["enr"].is_null());
        assert_eq!(
            peer["last_seen_p2p_address"],
            format!("/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{id}")
        );
        assert_eq!(peer["state"], "connected");
        assert_eq!(peer["direction"], "inbound");
        assert_eq!(peers_json("state=disconnected")["meta"]["count"], 0);

        let resp = query_get(&two_peer_ctx(), "/eth/v1/node/peers", "state=x");
        assert_eq!(body(&resp), br#"{"code":400,"message":"invalid state or direction"}"#);
    }

    #[test]
    fn peer_count_reports_connected_peers_only() {
        let resp = get(&two_peer_ctx(), "/eth/v1/node/peer_count");
        assert_eq!(
            body(&resp),
            br#"{"data":{"disconnected":"0","connecting":"0","connected":"2","disconnecting":"0"}}"#
        );
    }

    #[test]
    fn metrics_response_valid_prometheus_format() {
        let resp = get(&anchor_ctx(), "/metrics");
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("text/plain; version=0.0.4; charset=utf-8"));
        assert_eq!(body(&resp), b"");
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
        let mut state = BeaconState::for_test(EpochStateFinalized::from_state(epoch), &[], slot);
        state.slot_states = SlotStateGroup::new(SlotStateFinalized::new(SlotState {
            slot,
            latest_block_header: BeaconBlockHeader { slot, ..Default::default() },
            ..Default::default()
        }));
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
        let resp = get(ctx, path);
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
            let resp = get(ctx, &path);
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
                let resp = get(&ctx, &path);
                assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
                assert_eq!(body(&resp), br#"{"code":400,"message":"invalid state_id"}"#, "{path}");
            }
        }
    }

    /// The `state_id` verdict does not depend on there being a state to read.
    #[test]
    fn an_invalid_state_id_is_answered_before_the_state_is_read() {
        for path in state_paths("banana") {
            let resp = get(&anchor_ctx(), &path);
            assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{path}");
        }
    }

    fn with_head_optimistic(optimistic: bool) -> NodeStatus {
        NodeStatus { head: HeadStatus { optimistic, ..ready().head }, ..ready() }
    }

    /// The envelope flag is the head's own execution status, not a reading of
    /// how far behind the node is: an unverified head is optimistic with both
    /// layers reporting themselves synced, and a verified one is not while they
    /// do not.
    #[test]
    fn execution_optimistic_is_the_head_s_own_status() {
        let mut ctx = published_ctx(epoch_state(), HEAD_SLOT);
        for (status, want) in [
            (with_head_optimistic(true), "true"),
            (with_head_optimistic(false), "false"),
            (NodeStatus { target: chasing(200), ..with_head_optimistic(false) }, "false"),
            (NodeStatus { el: ELSyncStatus::Offline, ..with_head_optimistic(false) }, "false"),
            (NodeStatus { target: chasing(200), ..with_head_optimistic(true) }, "true"),
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

    #[test]
    fn finalized_is_whether_the_head_block_is_at_or_before_the_checkpoint() {
        let genesis_epoch = EpochState {
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            ..epoch_state()
        };
        let mut at_genesis = published_ctx(genesis_epoch, 0);
        at_genesis.node_status.finalized_epoch = 0;
        let mut at_anchor = published_ctx(epoch_state(), HEAD_SLOT);
        at_anchor.node_status.finalized_epoch = HEAD_SLOT / SLOTS_PER_EPOCH;
        let past_finality = published_ctx(epoch_state(), HEAD_SLOT);
        for path in state_paths("head") {
            let flags = "{\"execution_optimistic\":false,\"finalized\":";
            assert!(state_body(&at_genesis, &path).starts_with(&format!("{flags}true,")));
            assert!(state_body(&at_anchor, &path).starts_with(&format!("{flags}true,")));
            assert!(state_body(&past_finality, &path).starts_with(&format!("{flags}false,")));
        }
    }
}
