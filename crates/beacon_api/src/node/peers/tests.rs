use silver_common::{IpBytes, Keypair};
use silver_httpcore::ParsedRequest;

use super::*;
use crate::{
    ctx::anchor_ctx,
    testing::{answer, body, request},
};

fn get(ctx: &ApiCtx, path: &str) -> Vec<u8> {
    query_get(ctx, path, "")
}

fn query_get(ctx: &ApiCtx, path: &str, query: &str) -> Vec<u8> {
    answer(ctx, &ParsedRequest { query, ..request("GET", path) })
}

fn peer(connection: usize, secret: u8, inbound: bool) -> Peer {
    Peer {
        id: Keypair::from_secret(&[secret; 32]).unwrap().peer_id(),
        ip: IpBytes::V4([10, 0, 0, connection as u8]),
        port: 9000,
        inbound,
    }
}

fn two_peer_ctx() -> ApiCtx {
    let mut ctx = anchor_ctx();
    for (connection, inbound) in [(1, true), (2, false)] {
        ctx.peers.insert(connection, peer(connection, connection as u8, inbound));
    }
    ctx
}

fn peers_response(ctx: &ApiCtx, query: &str) -> Vec<u8> {
    query_get(ctx, "/eth/v1/node/peers", query)
}

fn json_ok(resp: &[u8]) -> serde_json::Value {
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&resp[..head_end]).unwrap();
    assert!(headers.lines().any(|l| l == "Content-Type: application/json"), "{headers}");
    serde_json::from_slice(body(resp)).unwrap()
}

fn peers_json(ctx: &ApiCtx, query: &str) -> serde_json::Value {
    json_ok(&peers_response(ctx, query))
}

fn peer_count_json(ctx: &ApiCtx) -> serde_json::Value {
    json_ok(&get(ctx, "/eth/v1/node/peer_count"))
}

fn address(listed: &serde_json::Value) -> &str {
    listed["data"][0]["last_seen_p2p_address"].as_str().unwrap()
}

#[test]
fn peers_list_every_connection_and_honour_the_filters() {
    let ctx = two_peer_ctx();
    let all = peers_json(&ctx, "");
    assert_eq!(all["meta"]["count"], 2);
    assert_eq!(all["data"].as_array().unwrap().len(), 2);

    let inbound = peers_json(&ctx, "direction=inbound&state=connected&state=connecting");
    assert_eq!(inbound["meta"]["count"], 1);
    let peer = &inbound["data"][0];
    let id = peer["peer_id"].as_str().unwrap();
    assert!(peer["enr"].is_null());
    assert_eq!(peer["last_seen_p2p_address"], format!("/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{id}"));
    assert_eq!(peer["state"], "connected");
    assert_eq!(peer["direction"], "inbound");
    assert_eq!(peers_json(&ctx, "state=disconnected")["meta"]["count"], 0);
}

#[test]
fn unknown_state_or_direction_is_a_400() {
    let resp = peers_response(&two_peer_ctx(), "state=x");
    assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    let error: serde_json::Value = serde_json::from_slice(body(&resp)).unwrap();
    assert_eq!(error["code"], 400);
    assert!(error["message"].is_string());
}

#[test]
fn peer_count_reports_connected_peers_only() {
    let count = peer_count_json(&two_peer_ctx());
    assert_eq!(count["data"]["connected"], "2");
    for state in ["disconnected", "connecting", "disconnecting"] {
        assert_eq!(count["data"][state], "0", "{state}");
    }
}

/// A reused handle can be smaller than an older connection's handle.
#[test]
fn duplicate_connections_count_one_peer() {
    let mut ctx = anchor_ctx();
    ctx.peers.insert(20, peer(20, 7, true));
    ctx.peers.insert(3, peer(3, 7, false));
    assert_eq!(peer_count_json(&ctx)["data"]["connected"], "1");

    let listed = peers_json(&ctx, "");
    assert_eq!(listed["meta"]["count"], 1);
    assert!(address(&listed).starts_with("/ip4/10.0.0.3/"), "{}", address(&listed));
    assert_eq!(listed["data"][0]["direction"], "outbound");
}

#[test]
fn closing_one_duplicate_connection_keeps_the_peer() {
    for closed in [20, 3] {
        let mut ctx = anchor_ctx();
        let older = peer(20, 7, true);
        let newer = peer(3, 7, false);
        let survivor = if closed == 20 { &newer } else { &older };
        let expected_address = survivor.multiaddr();
        let expected_direction = survivor.direction();
        let peer_id = survivor.id;
        ctx.peers.insert(20, older);
        ctx.peers.insert(3, newer);

        ctx.peers.remove(peer_id, closed);
        let listed = peers_json(&ctx, "");
        assert_eq!(listed["meta"]["count"], 1, "closed {closed}");
        assert_eq!(address(&listed), expected_address, "closed {closed}");
        assert_eq!(listed["data"][0]["direction"], expected_direction, "closed {closed}");
        assert_eq!(peer_count_json(&ctx)["data"]["connected"], "1");
        for direction in ["inbound", "outbound"] {
            let count = peers_json(&ctx, &format!("direction={direction}"))["meta"]["count"]
                .as_u64()
                .unwrap();
            assert_eq!(count, u64::from(direction == expected_direction), "closed {closed}");
        }

        ctx.peers.remove(peer_id, 23 - closed);
        assert_eq!(peers_json(&ctx, "")["meta"]["count"], 0, "closed both");
        assert_eq!(peer_count_json(&ctx)["data"]["connected"], "0");
    }
}

#[test]
fn removing_older_connections_preserves_arrival_order() {
    let mut ctx = anchor_ctx();
    let middle = peer(3, 7, false);
    let newest = peer(11, 7, true);
    let peer_id = newest.id;
    let middle_address = middle.multiaddr();
    let newest_address = newest.multiaddr();
    ctx.peers.insert(20, peer(20, 7, true));
    ctx.peers.insert(3, middle);
    ctx.peers.insert(11, newest);

    ctx.peers.remove(peer_id, 20);
    let listed = peers_json(&ctx, "");
    assert_eq!(listed["meta"]["count"], 1);
    assert_eq!(address(&listed), newest_address);
    assert_eq!(listed["data"][0]["direction"], "inbound");

    ctx.peers.remove(peer_id, 11);
    let listed = peers_json(&ctx, "");
    assert_eq!(listed["meta"]["count"], 1);
    assert_eq!(address(&listed), middle_address);
    assert_eq!(listed["data"][0]["direction"], "outbound");
}

#[test]
fn unknown_or_repeated_disconnect_keeps_surviving_connections() {
    let mut ctx = anchor_ctx();
    let survivor = peer(3, 7, false);
    let peer_id = survivor.id;
    let expected_address = survivor.multiaddr();
    ctx.peers.insert(3, survivor);

    ctx.peers.remove(peer_id, 20);
    assert_eq!(peer_count_json(&ctx)["data"]["connected"], "1");
    assert_eq!(address(&peers_json(&ctx, "")), expected_address);

    ctx.peers.insert(20, peer(20, 7, true));
    ctx.peers.remove(peer_id, 20);
    ctx.peers.remove(peer_id, 20);
    assert_eq!(peer_count_json(&ctx)["data"]["connected"], "1");
    assert_eq!(address(&peers_json(&ctx, "")), expected_address);

    ctx.peers.remove(peer_id, 3);
    assert_eq!(peer_count_json(&ctx)["data"]["connected"], "0");
}

#[test]
fn repeated_connection_replaces_its_details() {
    let mut ctx = anchor_ctx();
    let replacement = Peer { port: 9001, ..peer(3, 7, false) };
    let peer_id = replacement.id;
    let expected_address = replacement.multiaddr();
    ctx.peers.insert(3, peer(3, 7, true));
    ctx.peers.insert(3, replacement);
    let listed = peers_json(&ctx, "");
    assert_eq!(listed["meta"]["count"], 1);
    assert_eq!(address(&listed), expected_address);
    assert_eq!(listed["data"][0]["direction"], "outbound");

    ctx.peers.remove(peer_id, 3);
    assert_eq!(peer_count_json(&ctx)["data"]["connected"], "0");
    assert_eq!(peers_json(&ctx, "")["meta"]["count"], 0);
}
