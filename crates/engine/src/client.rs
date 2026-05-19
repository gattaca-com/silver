use std::time::Duration;

use mio::{Events, Poll};
use rustc_hash::FxHashMap;

use crate::{
    EngineError, JwtSecret,
    http::{HttpPool, POOL_SIZE, http_pool_enqueue, poll_http_pool},
    ipc::{IpcPool, ipc_pool_enqueue, poll_ipc_pool},
    types::{B256, ExecutionPayload, ForkchoiceState, PayloadAttributesV3},
};

const EVENTS_CAPACITY: usize = 16;

const OUR_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV4",
    "engine_getPayloadV4",
    "engine_getBlobsV2",
    "engine_getPayloadBodiesByHashV1",
    "engine_getPayloadBodiesByRangeV1",
    "engine_getClientVersionV1",
];

#[derive(Clone, Copy)]
pub enum ReqKind {
    Capabilities,
    ClientVersion,
    Syncing,
    Fcu(u64),
    NewPayload(u64),
    GetPayloadFcu(u64),
    GetPayloadFetch(u64),
    GetBlobs(u64),
    GetPayloadBodiesByHash(u64),
    GetPayloadBodiesByRange(u64),
}

enum Transport {
    Http(HttpPool),
    Ipc(IpcPool),
}

pub struct EngineClient {
    transport: Transport,
    poll: Poll,
    events: Events,
    id: u64,
    pending_requests: FxHashMap<u64, ReqKind>,
}

impl EngineClient {
    pub fn new(endpoint: impl Into<String>, jwt: JwtSecret) -> Self {
        Self {
            transport: Transport::Http(HttpPool::new(endpoint.into(), jwt, POOL_SIZE)),
            poll: Poll::new().expect("mio Poll::new failed"),
            events: Events::with_capacity(EVENTS_CAPACITY),
            id: 1,
            pending_requests: FxHashMap::default(),
        }
    }

    pub fn new_ipc(path: impl Into<String>) -> Self {
        Self {
            transport: Transport::Ipc(IpcPool::new(path.into(), POOL_SIZE)),
            poll: Poll::new().expect("mio Poll::new failed"),
            events: Events::with_capacity(EVENTS_CAPACITY),
            id: 1,
            pending_requests: FxHashMap::default(),
        }
    }
}

fn next_id(id: &mut u64) -> u64 {
    let v = *id;
    *id += 1;
    v
}

fn make_rpc_body(
    id: &mut u64,
    method: &str,
    params: serde_json::Value,
) -> (u64, serde_json::Value) {
    let rpc_id = next_id(id);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  method,
        "params":  params,
        "id":      rpc_id,
    });
    (rpc_id, body)
}

fn enqueue(c: &mut EngineClient, rpc_id: u64, body: &serde_json::Value) {
    match &mut c.transport {
        Transport::Http(p) => http_pool_enqueue(p, rpc_id, body, &mut c.poll),
        Transport::Ipc(p) => ipc_pool_enqueue(p, rpc_id, body, &mut c.poll),
    }
}

pub fn send_fcu(
    c: &mut EngineClient,
    state: ForkchoiceState,
    attrs: Option<PayloadAttributesV3>,
    req_id: u64,
) {
    let (id, body) =
        make_rpc_body(&mut c.id, "engine_forkchoiceUpdatedV3", serde_json::json!([state, attrs]));
    enqueue(c, id, &body);
    if attrs.is_some() {
        c.pending_requests.insert(id, ReqKind::Fcu(req_id));
    } else {
        c.pending_requests.insert(id, ReqKind::GetPayloadFcu(req_id));
    }
}

pub fn send_new_payload(
    c: &mut EngineClient,
    payload: ExecutionPayload,
    versioned_hashes: Vec<B256>,
    parent_beacon_block_root: B256,
    execution_requests: Vec<Vec<u8>>,
    req_id: u64,
) {
    let hashes: Vec<String> =
        versioned_hashes.iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    let parent = format!("0x{}", hex::encode(parent_beacon_block_root));
    let requests: Vec<String> =
        execution_requests.iter().map(|r| format!("0x{}", hex::encode(r))).collect();
    let (id, body) = make_rpc_body(
        &mut c.id,
        "engine_newPayloadV4",
        serde_json::json!([payload, hashes, parent, requests]),
    );
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::NewPayload(req_id));
}

pub fn get_payload(c: &mut EngineClient, payload_id: [u8; 8], req_id: u64) {
    let id_hex = format!("0x{}", hex::encode(payload_id));
    let (id, body) = make_rpc_body(&mut c.id, "engine_getPayloadV4", serde_json::json!([id_hex]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadFetch(req_id));
}

pub fn get_blobs(c: &mut EngineClient, params: serde_json::Value, req_id: u64) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getBlobsV2", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetBlobs(req_id));
}

pub fn get_payload_bodies_by_hash(c: &mut EngineClient, params: serde_json::Value, req_id: u64) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getPayloadBodiesByHashV1", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadBodiesByHash(req_id));
}

pub fn get_payload_bodies_by_range(c: &mut EngineClient, params: serde_json::Value, req_id: u64) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getPayloadBodiesByRangeV1", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadBodiesByRange(req_id));
}

pub fn get_sync_status(c: &mut EngineClient) {
    let (id, body) = make_rpc_body(&mut c.id, "eth_syncing", serde_json::json!([]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::Syncing);
}

pub fn exchange_capabilities(c: &mut EngineClient) {
    let (id, body) = make_rpc_body(
        &mut c.id,
        "engine_exchangeCapabilities",
        serde_json::json!(OUR_CAPABILITIES),
    );
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::Capabilities);
}

pub fn get_client_version(c: &mut EngineClient) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getClientVersionV1", serde_json::json!([{}]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::ClientVersion);
}

/// Drive I/O, calling `on_complete(req_kind, response)` for each finished RPC.
pub fn poll<F>(c: &mut EngineClient, mut on_complete: F)
where
    F: FnMut(ReqKind, Result<serde_json::Value, EngineError>),
{
    c.poll.poll(&mut c.events, Some(Duration::ZERO)).ok();
    let EngineClient { transport, events, poll, pending_requests, .. } = c;
    match transport {
        Transport::Http(p) => poll_http_pool(p, events, poll, &mut |rpc_id, res| {
            if let Some(req_kind) = pending_requests.remove(&rpc_id) {
                on_complete(req_kind, res.and_then(extract_result));
            }
        }),
        Transport::Ipc(p) => poll_ipc_pool(p, events, poll, &mut |rpc_id, res| {
            if let Some(req_kind) = pending_requests.remove(&rpc_id) {
                on_complete(req_kind, res.and_then(extract_result));
            }
        }),
    }
}

fn extract_result(resp: serde_json::Value) -> Result<serde_json::Value, EngineError> {
    if let Some(err) = resp.get("error") {
        return Err(EngineError::Rpc(err.clone()));
    }
    resp.get("result").cloned().ok_or(EngineError::MissingResult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_id_returns_current_then_increments() {
        let mut id = 1u64;
        assert_eq!(next_id(&mut id), 1);
        assert_eq!(next_id(&mut id), 2);
        assert_eq!(id, 3);
    }

    #[test]
    fn next_id_starts_from_arbitrary_value() {
        let mut id = 100u64;
        assert_eq!(next_id(&mut id), 100);
        assert_eq!(id, 101);
    }

    #[test]
    fn make_rpc_body_has_correct_structure() {
        let mut id = 1u64;
        let (rpc_id, body) = make_rpc_body(&mut id, "eth_test", serde_json::json!(["param"]));
        assert_eq!(rpc_id, 1);
        assert_eq!(id, 2);
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "eth_test");
        assert_eq!(body["params"], serde_json::json!(["param"]));
        assert_eq!(body["id"], 1);
    }

    #[test]
    fn make_rpc_body_ids_increase_across_calls() {
        let mut id = 5u64;
        let (id1, body1) = make_rpc_body(&mut id, "m1", serde_json::json!([]));
        let (id2, body2) = make_rpc_body(&mut id, "m2", serde_json::json!([]));
        assert_eq!(id1, 5);
        assert_eq!(id2, 6);
        assert_eq!(body1["id"], 5);
        assert_eq!(body2["id"], 6);
    }

    #[test]
    fn extract_result_returns_result_field() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"key": "value"}});
        assert_eq!(extract_result(resp).unwrap(), serde_json::json!({"key": "value"}));
    }

    #[test]
    fn extract_result_returns_rpc_error_when_error_present() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "bad"}});
        assert!(matches!(extract_result(resp), Err(EngineError::Rpc(_))));
    }

    #[test]
    fn extract_result_error_contains_error_payload() {
        let error_val = serde_json::json!({"code": -32700, "message": "parse error"});
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": error_val});
        match extract_result(resp) {
            Err(EngineError::Rpc(v)) => assert_eq!(v["code"], -32700),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn extract_result_error_takes_precedence_over_result() {
        let resp =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1}, "result": "ok"});
        assert!(matches!(extract_result(resp), Err(EngineError::Rpc(_))));
    }

    #[test]
    fn extract_result_missing_result_when_neither_field_present() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        assert!(matches!(extract_result(resp), Err(EngineError::MissingResult)));
    }

    #[test]
    fn extract_result_null_result_is_ok() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": null});
        assert_eq!(extract_result(resp).unwrap(), serde_json::Value::Null);
    }
}
