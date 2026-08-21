use std::{path::PathBuf, time::Duration};

use mio::{Events, Registry};
use rustc_hash::FxHashMap;
use silver_common::merkle::B256;
use silver_httpcore::TokenRange;

use crate::{
    EngineError, JwtSecret,
    pool::{Endpoint, HttpPool},
    types::{
        ForkchoiceState, PayloadAttributesV3, write_new_payload_params_fulu,
        write_new_payload_params_gloas,
    },
};

// Sized for the largest expected outgoing request: newPayload with a full block
// (~30M gas of transactions, hex-encoded in JSON).
const SCRATCH_CAPACITY: usize = 10 * 1024 * 1024;

const OUR_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV4",
    "engine_newPayloadV5",
    "engine_getPayloadV3",
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
    Fcu(B256),        // head beacon block root, zeros for prepare-payload
    NewPayload(B256), // block root
    GetPayloadFetch(u64),
    GetBlobs(u64),
    GetPayloadBodiesByHash(u64),
    GetPayloadBodiesByRange(u64),
}

pub struct EngineClient {
    pool: HttpPool,
    registry: Registry,
    id: u64,
    pending_requests: FxHashMap<u64, ReqKind>,
    pub get_payload_method: &'static str,
    scratch: Vec<u8>,
}

impl EngineClient {
    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        endpoint: &str,
        jwt: &str,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Self {
        Self::with_endpoint(
            registry,
            tokens,
            parse_endpoint(endpoint),
            jwt,
            max_connections,
            request_timeout,
        )
    }

    pub fn new_uds(
        registry: &Registry,
        tokens: TokenRange,
        path: impl Into<PathBuf>,
        jwt: &str,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Self {
        Self::with_endpoint(
            registry,
            tokens,
            Endpoint::Uds(path.into()),
            jwt,
            max_connections,
            request_timeout,
        )
    }

    fn with_endpoint(
        registry: &Registry,
        tokens: TokenRange,
        endpoint: Endpoint,
        jwt: &str,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Self {
        let jwt = JwtSecret::from_file(jwt).unwrap_or_else(|e| panic!("invalid JWT secret: {e}"));
        Self {
            pool: HttpPool::new(endpoint, jwt, tokens, max_connections, request_timeout),
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            id: 1,
            pending_requests: FxHashMap::default(),
            get_payload_method: "engine_getPayloadV3",
            scratch: Vec::with_capacity(SCRATCH_CAPACITY),
        }
    }

    pub fn has_capacity(&self) -> bool {
        self.pool.has_capacity()
    }

    /// Drives the I/O the batch reports ready, calling
    /// `on_complete(req_kind, raw_body)` for each RPC it finishes. Raw bytes
    /// are the full HTTP response body; handlers parse them as needed.
    pub fn dispatch<F>(&mut self, events: &Events, mut on_complete: F)
    where
        F: FnMut(ReqKind, Result<&mut [u8], EngineError>),
    {
        let Self { pool, registry, pending_requests, .. } = self;
        pool.dispatch_events(events, registry, &mut |rpc_id, res| {
            if let Some(req_kind) = pending_requests.remove(&rpc_id) {
                on_complete(req_kind, res);
            }
        });
    }
}

fn parse_endpoint(endpoint: &str) -> Endpoint {
    if endpoint.starts_with("http://") {
        Endpoint::Http(endpoint.to_string())
    } else if endpoint.contains("://") {
        panic!(
            "unsupported execution_endpoint scheme (only http:// or a unix socket path): \
             {endpoint}"
        )
    } else {
        Endpoint::Uds(PathBuf::from(endpoint))
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
    params: simd_json::OwnedValue,
) -> (u64, simd_json::OwnedValue) {
    let rpc_id = next_id(id);
    let body = simd_json::json!({
        "jsonrpc": "2.0",
        "method":  method,
        "params":  params,
        "id":      rpc_id,
    });
    (rpc_id, body)
}

fn enqueue(c: &mut EngineClient, rpc_id: u64, body: &simd_json::OwnedValue) {
    c.scratch.clear();
    if let Err(e) = simd_json::to_writer(&mut c.scratch, body) {
        tracing::warn!("failed to serialize RPC body: {e}");
        return;
    }
    c.pool.enqueue(rpc_id, &c.scratch, &c.registry);
}

pub fn send_fcu(
    c: &mut EngineClient,
    block_root: B256,
    state: ForkchoiceState,
    attrs: Option<PayloadAttributesV3>,
) {
    let (id, body) =
        make_rpc_body(&mut c.id, "engine_forkchoiceUpdatedV3", simd_json::json!([state, attrs]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::Fcu(block_root));
}

pub fn send_new_payload(
    c: &mut EngineClient,
    data: &[u8],
    block_root: [u8; 32],
) -> Result<(), EngineError> {
    send_new_payload_request_impl(c, block_root, "engine_newPayloadV4", |out| {
        write_new_payload_params_fulu(data, out)
    })
}

pub fn send_new_payload_envelope(
    c: &mut EngineClient,
    data: &[u8],
    versioned_hashes: &[[u8; 32]],
    block_root: [u8; 32],
) -> Result<(), EngineError> {
    send_new_payload_request_impl(c, block_root, "engine_newPayloadV5", |out| {
        write_new_payload_params_gloas(data, versioned_hashes, out)
    })
}

fn send_new_payload_request_impl(
    c: &mut EngineClient,
    block_root: [u8; 32],
    method: &str,
    write_params: impl FnOnce(&mut Vec<u8>) -> Result<(), EngineError>,
) -> Result<(), EngineError> {
    let rpc_id = next_id(&mut c.id);
    c.scratch.clear();
    c.scratch.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"");
    c.scratch.extend_from_slice(method.as_bytes());
    c.scratch.extend_from_slice(b"\",\"params\":");
    write_params(&mut c.scratch)?;
    c.scratch.extend_from_slice(b",\"id\":");
    append_decimal_u64(rpc_id, &mut c.scratch);
    c.scratch.push(b'}');
    c.pool.enqueue(rpc_id, &c.scratch, &c.registry);
    c.pending_requests.insert(rpc_id, ReqKind::NewPayload(block_root));
    Ok(())
}

fn append_decimal_u64(v: u64, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    let mut tmp = v;
    while tmp > 0 {
        buf[19 - n] = b'0' + (tmp % 10) as u8;
        tmp /= 10;
        n += 1;
    }
    out.extend_from_slice(&buf[20 - n..]);
}

pub fn get_payload(c: &mut EngineClient, payload_id: [u8; 8], req_id: u64) {
    let id_hex = format!("0x{}", hex::encode(payload_id));
    let (id, body) = make_rpc_body(&mut c.id, c.get_payload_method, simd_json::json!([id_hex]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadFetch(req_id));
}

pub fn get_blobs(c: &mut EngineClient, params: simd_json::OwnedValue, req_id: u64) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getBlobsV2", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetBlobs(req_id));
}

pub fn get_payload_bodies_by_hash(
    c: &mut EngineClient,
    params: simd_json::OwnedValue,
    req_id: u64,
) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getPayloadBodiesByHashV1", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadBodiesByHash(req_id));
}

pub fn get_payload_bodies_by_range(
    c: &mut EngineClient,
    params: simd_json::OwnedValue,
    req_id: u64,
) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getPayloadBodiesByRangeV1", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetPayloadBodiesByRange(req_id));
}

pub fn get_sync_status(c: &mut EngineClient) {
    let (id, body) = make_rpc_body(&mut c.id, "eth_syncing", simd_json::json!([]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::Syncing);
}

pub fn exchange_capabilities(c: &mut EngineClient) {
    // Spec: params = [capabilitiesArray] — the array is wrapped in an outer params
    // array.
    let (id, body) = make_rpc_body(
        &mut c.id,
        "engine_exchangeCapabilities",
        simd_json::json!([OUR_CAPABILITIES]),
    );
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::Capabilities);
}

pub fn get_client_version(c: &mut EngineClient) {
    // Spec: params = [ClientVersionV1] with required fields
    // code/name/version/commit.
    let (id, body) = make_rpc_body(
        &mut c.id,
        "engine_getClientVersionV1",
        simd_json::json!([{"code": "GE", "name": "silver", "version": "0.1.0", "commit": "00000000"}]),
    );
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::ClientVersion);
}

#[cfg(test)]
mod tests {
    use simd_json::prelude::ValueAsScalar;

    use super::*;

    #[test]
    fn endpoint_http_scheme_parses_to_http() {
        assert!(matches!(
            parse_endpoint("http://localhost:8551"),
            Endpoint::Http(e) if e == "http://localhost:8551"
        ));
    }

    #[test]
    fn endpoint_bare_path_parses_to_uds() {
        assert!(matches!(
            parse_endpoint("/run/reth/engine.sock"),
            Endpoint::Uds(p) if p == std::path::Path::new("/run/reth/engine.sock")
        ));
    }

    #[test]
    #[should_panic(expected = "unsupported execution_endpoint scheme")]
    fn endpoint_unknown_scheme_panics() {
        parse_endpoint("https://localhost:8551");
    }

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
        let (rpc_id, body) = make_rpc_body(&mut id, "eth_test", simd_json::json!(["param"]));
        assert_eq!(rpc_id, 1);
        assert_eq!(id, 2);
        assert_eq!(body["jsonrpc"].as_str(), Some("2.0"));
        assert_eq!(body["method"].as_str(), Some("eth_test"));
        assert_eq!(body["params"], simd_json::json!(["param"]));
        assert_eq!(body["id"].as_u64(), Some(1));
    }

    #[test]
    fn make_rpc_body_ids_increase_across_calls() {
        let mut id = 5u64;
        let (id1, body1) = make_rpc_body(&mut id, "m1", simd_json::json!([]));
        let (id2, body2) = make_rpc_body(&mut id, "m2", simd_json::json!([]));
        assert_eq!(id1, 5);
        assert_eq!(id2, 6);
        assert_eq!(body1["id"].as_u64(), Some(5));
        assert_eq!(body2["id"].as_u64(), Some(6));
    }
}
