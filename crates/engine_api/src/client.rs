use std::{convert::Infallible, path::PathBuf, time::Duration};

use mio::{Events, Registry};
use rustc_hash::FxHashMap;
use silver_common::merkle::B256;
use silver_httpcore::{BufferCapacity, ClientRequest, Endpoint, HttpPool, Method, TokenRange};

use crate::{
    EngineError, JwtSecret,
    types::{
        ForkchoiceState, PayloadAttributesV3, write_new_payload_params_fulu,
        write_new_payload_params_gloas,
    },
};

// Sized for the largest expected outgoing request: newPayload with a full block
// (~30M gas of transactions, hex-encoded in JSON).
const SCRATCH_CAPACITY: usize = 10 * 1024 * 1024;

const CONNECTION_CAPACITY: BufferCapacity = BufferCapacity {
    // The largest expected EL response: getPayload with a full blobsBundle
    // (~21 blobs × 256 KB hex-encoded + execution payload transactions).
    read: 10 * 1024 * 1024,
    // newPayload's scratch plus HTTP headers.
    write: SCRATCH_CAPACITY,
};

/// The first-run healthcheck trio issues three requests against one
/// `has_capacity` gate, so the pool can exceed `max_connections` by two
/// connections, once.
pub(crate) const HEALTHCHECK_OVERSHOOT: usize = 2;

const OUR_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV4",
    "engine_newPayloadV5",
    "engine_getPayloadV5",
    "engine_getBlobsV3",
    "engine_getClientVersionV1",
];

#[derive(Clone, Copy)]
pub enum ReqKind {
    Capabilities,
    ClientVersion,
    Syncing,
    Fcu(B256),           // head beacon block root
    PreparePayload(u64), // spine request id
    NewPayload(B256),    // block root
    GetPayloadFetch(u64),
    GetBlobs { block_root: B256, slot: u64 },
}

pub struct EngineClient {
    pool: HttpPool,
    jwt: JwtSecret,
    registry: Registry,
    id: u64,
    pending_requests: FxHashMap<u64, ReqKind>,
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
        let tokens_needed = max_connections.checked_add(HEALTHCHECK_OVERSHOOT);
        assert!(
            tokens_needed.is_some_and(|needed| needed <= tokens.span()),
            "engine api needs a token per pooled connection: a cap of {max_connections} plus the \
             healthcheck's overshoot of {HEALTHCHECK_OVERSHOOT} does not fit a span of {}",
            tokens.span()
        );
        let jwt = JwtSecret::from_file(jwt).unwrap_or_else(|e| panic!("invalid JWT secret: {e}"));
        Self {
            pool: HttpPool::new(
                endpoint,
                tokens,
                CONNECTION_CAPACITY,
                max_connections,
                request_timeout,
            ),
            jwt,
            registry: registry.try_clone().expect("mio Registry::try_clone failed"),
            id: 1,
            pending_requests: FxHashMap::default(),
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
                let res = res
                    .map(|response| response.body)
                    .map_err(|msg| EngineError::Http(msg.to_owned()));
                on_complete(req_kind, res);
            }
        });
    }

    fn enqueue_scratch(&mut self, rpc_id: u64) {
        let request = ClientRequest {
            method: Method::Post,
            path: "/",
            body: &self.scratch,
            authorization: Some(self.jwt.bearer_token()),
        };
        self.pool.enqueue(rpc_id, &request, &self.registry);
    }
}

fn parse_endpoint(endpoint: &str) -> Endpoint {
    if endpoint.starts_with("http://") {
        Endpoint::Http(endpoint.to_string())
    } else if endpoint.contains("://") {
        panic!("unsupported execution_endpoint scheme (only http:// is served): {endpoint}")
    } else {
        panic!(
            "execution_endpoint {endpoint} is a Unix socket path: an EL's IPC socket speaks \
             raw newline-framed JSON-RPC, which this HTTP client cannot yet produce; use the \
             EL's http:// engine endpoint"
        )
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
        silver_log::warn!("failed to serialize RPC body: {e}");
        return;
    }
    c.enqueue_scratch(rpc_id);
}

pub fn send_fcu(c: &mut EngineClient, block_root: B256, state: ForkchoiceState) {
    send_forkchoice_updated(c, ReqKind::Fcu(block_root), state, None);
}

pub fn send_prepare_payload(
    c: &mut EngineClient,
    spine_id: u64,
    state: ForkchoiceState,
    attrs: PayloadAttributesV3,
) {
    send_forkchoice_updated(c, ReqKind::PreparePayload(spine_id), state, Some(attrs));
}

fn send_forkchoice_updated(
    c: &mut EngineClient,
    kind: ReqKind,
    state: ForkchoiceState,
    attrs: Option<PayloadAttributesV3>,
) {
    let (id, body) =
        make_rpc_body(&mut c.id, "engine_forkchoiceUpdatedV3", simd_json::json!([state, attrs]));
    enqueue(c, id, &body);
    c.pending_requests.insert(id, kind);
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
    enqueue_with(c, method, ReqKind::NewPayload(block_root), write_params)
}

fn enqueue_with<E>(
    c: &mut EngineClient,
    method: &str,
    kind: ReqKind,
    write_params: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
) -> Result<(), E> {
    let rpc_id = next_id(&mut c.id);
    c.scratch.clear();
    c.scratch.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"");
    c.scratch.extend_from_slice(method.as_bytes());
    c.scratch.extend_from_slice(b"\",\"params\":");
    write_params(&mut c.scratch)?;
    c.scratch.extend_from_slice(b",\"id\":");
    append_decimal_u64(rpc_id, &mut c.scratch);
    c.scratch.push(b'}');
    c.enqueue_scratch(rpc_id);
    c.pending_requests.insert(rpc_id, kind);
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
    let mut params = *b"[\"0x0000000000000000\"]";
    hex::encode_to_slice(payload_id, &mut params[4..20]).expect("8 bytes are 16 hex digits");
    let kind = ReqKind::GetPayloadFetch(req_id);
    let Ok(()) = enqueue_with::<Infallible>(c, "engine_getPayloadV5", kind, |out| {
        out.extend_from_slice(&params);
        Ok(())
    });
}

pub fn get_blobs(c: &mut EngineClient, params: simd_json::OwnedValue, block_root: B256, slot: u64) {
    let (id, body) = make_rpc_body(&mut c.id, "engine_getBlobsV3", params);
    enqueue(c, id, &body);
    c.pending_requests.insert(id, ReqKind::GetBlobs { block_root, slot });
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
    use std::time::Instant;

    use silver_httpcore::Readiness;
    use simd_json::prelude::{ValueAsArray, ValueAsScalar};

    use super::*;
    use crate::test_el::{FakeEl, write_jwt};

    #[test]
    fn get_blobs_uses_and_advertises_v3() {
        let dir = tempfile::tempdir().unwrap();
        let jwt = write_jwt(dir.path());
        let socket = dir.path().join("engine.sock");
        let mut el = FakeEl::uds(&socket);
        let mut readiness = Readiness::new(16);
        let mut client = EngineClient::new_uds(
            readiness.registry(),
            TokenRange::whole(),
            &socket,
            jwt.to_str().unwrap(),
            2,
            Duration::from_secs(10),
        );
        let params = simd_json::json!([[format!("0x{}", hex::encode([1; 32]))]]);
        exchange_capabilities(&mut client);
        get_blobs(&mut client, params.clone(), [2; 32], 42);

        let deadline = Instant::now() + Duration::from_secs(10);
        while el.requests.len() < 2 {
            assert!(Instant::now() < deadline, "timeout waiting for engine requests");
            readiness.wait(Duration::from_millis(1));
            client.dispatch(readiness.events(), |_, response| {
                panic!("unexpected response before the EL replied: {response:?}");
            });
            el.pump();
        }

        let request = el.requests.iter().find(|r| r.method == "engine_getBlobsV3").unwrap();
        let mut body = request.body.as_bytes().to_vec();
        let body = simd_json::to_owned_value(&mut body).unwrap();
        assert_eq!(body["params"], params);
        assert!(matches!(
            client.pending_requests.get(&request.id),
            Some(ReqKind::GetBlobs { block_root, slot: 42 }) if *block_root == [2; 32]
        ));

        let request =
            el.requests.iter().find(|r| r.method == "engine_exchangeCapabilities").unwrap();
        let mut body = request.body.as_bytes().to_vec();
        let body = simd_json::to_borrowed_value(&mut body).unwrap();
        let capabilities = body["params"][0].as_array().unwrap();
        assert!(capabilities.iter().any(|v| v.as_str() == Some("engine_getBlobsV3")));
        assert!(!capabilities.iter().any(|v| v.as_str() == Some("engine_getBlobsV2")));
    }

    #[test]
    fn get_payload_body_names_the_payload_id() {
        let dir = tempfile::tempdir().unwrap();
        let jwt = write_jwt(dir.path());
        let socket = dir.path().join("engine.sock");
        let _el = FakeEl::uds(&socket);
        let readiness = Readiness::new(16);
        let mut client = EngineClient::new_uds(
            readiness.registry(),
            TokenRange::whole(),
            &socket,
            jwt.to_str().unwrap(),
            2,
            Duration::from_secs(10),
        );

        get_payload(&mut client, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], 7);

        let id = client.id - 1;
        let expected = format!(
            r#"{{"jsonrpc":"2.0","method":"engine_getPayloadV5","params":["0x0123456789abcdef"],"id":{id}}}"#
        );
        assert_eq!(client.scratch, expected.as_bytes());
        assert!(matches!(client.pending_requests.get(&id), Some(ReqKind::GetPayloadFetch(7))));
    }

    #[test]
    fn prepare_payload_is_correlated_by_spine_id() {
        let dir = tempfile::tempdir().unwrap();
        let jwt = write_jwt(dir.path());
        let socket = dir.path().join("engine.sock");
        let mut el = FakeEl::uds(&socket);
        let mut readiness = Readiness::new(16);
        let mut client = EngineClient::new_uds(
            readiness.registry(),
            TokenRange::whole(),
            &socket,
            jwt.to_str().unwrap(),
            2,
            Duration::from_secs(10),
        );
        let state = ForkchoiceState {
            head_block_hash: [1; 32],
            safe_block_hash: [2; 32],
            finalized_block_hash: [3; 32],
        };
        let attrs = PayloadAttributesV3 {
            timestamp: 12,
            prev_randao: [4; 32],
            suggested_fee_recipient: [5; 20],
            withdrawals: Vec::new(),
            parent_beacon_block_root: [6; 32],
        };
        exchange_capabilities(&mut client);
        send_prepare_payload(&mut client, 7, state, attrs);

        let deadline = Instant::now() + Duration::from_secs(10);
        while el.requests.len() < 2 {
            assert!(Instant::now() < deadline, "timeout waiting for engine requests");
            readiness.wait(Duration::from_millis(1));
            client.dispatch(readiness.events(), |_, response| {
                panic!("unexpected response before the EL replied: {response:?}");
            });
            el.pump();
        }

        let request =
            el.requests.iter().find(|r| r.method == "engine_forkchoiceUpdatedV3").unwrap();
        let token = request.authorization.as_deref().and_then(|auth| auth.strip_prefix("Bearer "));
        assert_eq!(token.expect("JWT bearer header").split('.').count(), 3, "three-part JWT");
        let mut body = request.body.as_bytes().to_vec();
        let body = simd_json::to_borrowed_value(&mut body).unwrap();
        assert_eq!(body["params"][1]["timestamp"].as_str(), Some("0xc"));
        assert!(matches!(
            client.pending_requests.get(&request.id),
            Some(ReqKind::PreparePayload(7))
        ));

        let request =
            el.requests.iter().find(|r| r.method == "engine_exchangeCapabilities").unwrap();
        let mut body = request.body.as_bytes().to_vec();
        let body = simd_json::to_borrowed_value(&mut body).unwrap();
        let capabilities = body["params"][0].as_array().unwrap();
        assert!(capabilities.iter().any(|v| v.as_str() == Some("engine_getPayloadV5")));
        assert!(!capabilities.iter().any(|v| v.as_str() == Some("engine_getPayloadV4")));
    }

    #[test]
    fn endpoint_http_scheme_parses_to_http() {
        assert!(matches!(
            parse_endpoint("http://localhost:8551"),
            Endpoint::Http(e) if e == "http://localhost:8551"
        ));
    }

    /// Connecting would succeed and every request would then be HTTP framing
    /// on a raw JSON-RPC socket, so the path is refused before any connect.
    #[test]
    #[should_panic(expected = "is a Unix socket path")]
    fn endpoint_bare_path_is_refused_at_startup() {
        parse_endpoint("/run/reth/engine.sock");
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
