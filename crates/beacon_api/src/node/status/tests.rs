use silver_common::{AGENT_VERSION, ELSyncStatus, PayloadResolution, SyncUpdate};
use silver_httpcore::ParsedRequest;

use super::*;
use crate::{
    HeadStatus,
    ctx::anchor_ctx,
    testing::{answer, body, request},
};

fn get(ctx: &ApiCtx, path: &str) -> Vec<u8> {
    query_get(ctx, path, "")
}

fn query_get(ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
    answer(ctx, &ParsedRequest { query, ..request("GET", path) })
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

pub(crate) fn ready() -> NodeStatus {
    NodeStatus {
        head: HeadStatus { slot: 100, optimistic: false },
        head_root: [0x11; 32],
        head_payload: PayloadResolution::Full,
        wall_slot: 100,
        finalized_epoch: 12_343,
        target: Some(SyncUpdate::Following),
        el: ELSyncStatus::Synced,
    }
}

fn at_head(slot: u64) -> NodeStatus {
    NodeStatus { head: HeadStatus { slot, optimistic: false }, ..ready() }
}

pub(crate) fn chasing(head_slot: u64) -> Option<SyncUpdate> {
    Some(SyncUpdate::SyncingHead { head_root: [0; 32], head_slot })
}

pub(crate) fn with_head_optimistic(optimistic: bool) -> NodeStatus {
    NodeStatus { head: HeadStatus { optimistic, ..ready().head }, ..ready() }
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
    assert_eq!(syncing_data(NodeStatus { target: chasing(200), ..ready() })["is_syncing"], true);
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

/// Stalled distance uses the wall slot; sync status still comes from
/// Control.
#[test]
fn stalled_is_syncing_at_the_distance_to_the_wall_clock() {
    let stalled = NodeStatus { target: Some(SyncUpdate::Stalled), wall_slot: 130, ..ready() };
    let data = syncing_data(stalled);
    assert_eq!(data["is_syncing"], true);
    assert_eq!(data["sync_distance"], "30");

    assert_eq!(
        health_response(stalled, ""),
        b"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n"
    );
    assert!(health_response(stalled, "syncing_status=200").starts_with(b"HTTP/1.1 200 OK\r\n"));

    let following = NodeStatus { wall_slot: 130, ..ready() };
    assert_eq!(
        syncing_data(following)["is_syncing"],
        false,
        "wall lag does not override Following"
    );
    assert_eq!(syncing_data(following)["sync_distance"], "0");
}

#[test]
fn syncing_status_outside_the_schema_s_range_is_a_400() {
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
        assert_eq!(body(&resp), br#"{"code":400,"message":"invalid syncing_status"}"#, "{query}");
    }
}
