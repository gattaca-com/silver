use silver_beacon_state_data::{B256, BLSPubkey, BlockRootsGroup, SLOTS_PER_HISTORICAL_ROOT};
use silver_httpcore::ParsedRequest;

use crate::{
    ctx::ApiCtx,
    http::router::{Outcome, Router},
    routes::ROUTES,
};

/// A request with every field a route ignores at its default, so a caller
/// names only what it varies.
pub(crate) fn request<'a>(method: &'a str, path: &'a str) -> ParsedRequest<'a> {
    ParsedRequest {
        method,
        path,
        query: "",
        body: b"",
        accept: None,
        content_type: None,
        eth_consensus_version: None,
        version: 1,
        keep_alive: true,
    }
}

/// [`request`] carrying the JSON body every POST route takes.
pub(crate) fn posting<'a>(path: &'a str, body: &'a str) -> ParsedRequest<'a> {
    ParsedRequest {
        body: body.as_bytes(),
        content_type: Some("application/json"),
        ..request("POST", path)
    }
}

pub(crate) fn dispatch(ctx: &ApiCtx, req: &ParsedRequest<'_>) -> (Outcome, Vec<u8>) {
    let mut out = Vec::new();
    let outcome = Router::new(ROUTES).dispatch(req, ctx, &mut out);
    (outcome, out)
}

/// What a route that answers in one response wrote.
pub(crate) fn answer(ctx: &ApiCtx, req: &ParsedRequest<'_>) -> Vec<u8> {
    let (outcome, out) = dispatch(ctx, req);
    assert_eq!(outcome, Outcome::Response);
    out
}

pub(crate) fn body(response: &[u8]) -> &[u8] {
    let text = std::str::from_utf8(response).unwrap();
    &response[text.find("\r\n\r\n").unwrap() + 4..]
}

pub(crate) fn status_code(response: &[u8]) -> &str {
    std::str::from_utf8(response).unwrap().split(' ').nth(1).unwrap()
}

/// The body of a 200, parsed.
pub(crate) fn json(response: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    serde_json::from_slice(body(response)).unwrap()
}

/// A quoted `Uint64` field, as every duty spells its numbers.
pub(crate) fn field(value: &serde_json::Value, name: &str) -> u64 {
    value[name].as_str().unwrap().parse().unwrap()
}

/// The pubkey a test registry holds for `validator_index`, which spells the
/// index itself so a body can be read back from a response.
pub(crate) fn pubkey(validator_index: u64) -> BLSPubkey {
    let mut pubkey = [0u8; 48];
    pubkey[..8].copy_from_slice(&validator_index.to_le_bytes());
    pubkey
}

/// The `["1","2"]` array of quoted `Uint64`s every duties POST takes.
pub(crate) fn indices_body(indices: impl Iterator<Item = u64>) -> String {
    let quoted: Vec<_> = indices.map(|index| format!("\"{index}\"")).collect();
    format!("[{}]", quoted.join(","))
}

/// The block root the ring holds for `slot`, distinct per slot.
pub(crate) fn ring_root(slot: u64) -> B256 {
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&slot.to_le_bytes());
    root
}

/// A ring whose every entry is [`ring_root`] of the slot it holds, for a state
/// at `state_slot`.
pub(crate) fn block_roots_ring(state_slot: u64) -> BlockRootsGroup {
    let ring_len = SLOTS_PER_HISTORICAL_ROOT as u64;
    let roots: Vec<u8> =
        (0..ring_len).flat_map(|i| ring_root(state_slot - state_slot % ring_len + i)).collect();
    BlockRootsGroup::vector(&roots).unwrap()
}
