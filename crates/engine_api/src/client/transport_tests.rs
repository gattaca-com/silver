use std::{
    path::Path,
    time::{Duration, Instant},
};

use silver_httpcore::{Readiness, TokenRange};
use tempfile::TempDir;

use crate::{
    EngineClient, EngineError,
    client::{ReqKind, get_blobs, send_fcu},
    test_el::{FCU_VALID_RESULT, FakeEl, write_jwt},
    types::ForkchoiceState,
};

/// Longer than any test's 10 s spin deadline: the sweep never fires.
const LONG_TIMEOUT: Duration = Duration::from_secs(60);

/// The sole tenant of its readiness loop, which the tile shares with the
/// beacon-api server in production and each test here owns for itself.
struct Client {
    readiness: Readiness,
    engine: EngineClient,
}

impl Client {
    fn uds(socket: &Path, jwt: &Path, max_connections: usize, request_timeout: Duration) -> Self {
        let readiness = Readiness::new(16);
        let engine = EngineClient::new_uds(
            readiness.registry(),
            TokenRange::whole(),
            socket,
            jwt.to_str().unwrap(),
            max_connections,
            request_timeout,
        );
        Self { readiness, engine }
    }

    fn poll<F>(&mut self, on_complete: F)
    where
        F: FnMut(ReqKind, Result<&mut [u8], EngineError>),
    {
        self.readiness.wait(Duration::ZERO);
        self.engine.dispatch(self.readiness.events(), on_complete);
    }
}

fn fcu_state(byte: u8) -> ForkchoiceState {
    ForkchoiceState {
        head_block_hash: [byte; 32],
        safe_block_hash: [byte; 32],
        finalized_block_hash: [byte; 32],
    }
}

fn spin_until(deadline_msg: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timeout: {deadline_msg}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn uds_round_trip_resolves_correlation_with_jwt() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);

    let mut client = Client::uds(&socket, &jwt_path, 32, LONG_TIMEOUT);
    let block_root = [7u8; 32];
    send_fcu(&mut client.engine, block_root, fcu_state(1));

    let mut responded = false;
    let mut completed: Option<([u8; 32], Vec<u8>)> = None;
    spin_until("fcu round trip over uds", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            completed = Some((root, response.expect("fcu response").to_vec()));
        });
        el.pump();
        if !responded && !el.requests.is_empty() {
            let request = &el.requests[0];
            assert_eq!(request.method, "engine_forkchoiceUpdatedV3");
            let auth = request.authorization.as_deref().expect("JWT header sent over UDS");
            let token = auth.strip_prefix("Bearer ").expect("bearer scheme");
            assert_eq!(token.split('.').count(), 3, "three-part JWT");
            assert!(request.body.contains(&format!("\"headBlockHash\":\"0x{}\"", "01".repeat(32))));
            el.respond(0, FCU_VALID_RESULT);
            responded = true;
        }
        completed.is_some()
    });

    let (root, body) = completed.unwrap();
    assert_eq!(root, block_root, "completion correlated to the issued request");
    assert!(String::from_utf8(body).unwrap().contains("VALID"));
}

#[test]
fn connect_failure_fails_rpc_and_frees_connection() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let missing_socket = dir.path().join("missing.sock");

    // max_connections = 1: after the failure, has_capacity() can only be
    // true again if the zombie connection was actually freed.
    let mut client = Client::uds(&missing_socket, &jwt_path, 1, LONG_TIMEOUT);
    let block_root = [3u8; 32];
    send_fcu(&mut client.engine, block_root, fcu_state(3));
    assert!(!client.engine.has_capacity(), "request occupies the only connection");

    let mut failed: Option<[u8; 32]> = None;
    spin_until("connect failure surfaces as rpc error", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            assert!(response.is_err(), "unstartable connect must fail the rpc");
            failed = Some(root);
        });
        failed.is_some()
    });

    assert_eq!(failed.unwrap(), block_root);
    assert!(client.engine.has_capacity(), "failed connection must be reusable");
}

#[test]
fn transport_error_fails_in_flight_request() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);

    let mut client = Client::uds(&socket, &jwt_path, 32, LONG_TIMEOUT);
    let block_root = [9u8; 32];
    send_fcu(&mut client.engine, block_root, fcu_state(2));

    let mut request_seen = false;
    let mut failure: Option<[u8; 32]> = None;
    spin_until("in-flight request failed on connection close", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            assert!(response.is_err(), "closed connection must fail the rpc");
            failure = Some(root);
        });
        el.pump();
        if !request_seen && !el.requests.is_empty() {
            el.close_connection_of(0);
            request_seen = true;
        }
        failure.is_some()
    });

    assert_eq!(failure.unwrap(), block_root);
}

#[test]
fn unanswered_request_times_out_and_frees_connection() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);

    let mut client = Client::uds(&socket, &jwt_path, 1, Duration::from_millis(200));
    send_fcu(&mut client.engine, [1u8; 32], fcu_state(1));

    let mut timed_out: Option<[u8; 32]> = None;
    spin_until("unanswered request times out", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            assert!(response.is_err(), "unanswered request must fail the rpc");
            timed_out = Some(root);
        });
        el.pump();
        timed_out.is_some()
    });

    assert_eq!(timed_out.unwrap(), [1u8; 32]);
    assert_eq!(el.requests.len(), 1, "the EL received the request it never answered");
    assert!(client.engine.has_capacity(), "timed-out connection must be reusable");

    send_fcu(&mut client.engine, [2u8; 32], fcu_state(2));
    let mut answered = false;
    let mut completed: Option<[u8; 32]> = None;
    spin_until("next request served on the freed connection", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            assert!(response.is_ok(), "answered request must succeed");
            completed = Some(root);
        });
        el.pump();
        if !answered && el.requests.len() == 2 {
            el.respond(1, FCU_VALID_RESULT);
            answered = true;
        }
        completed.is_some()
    });
    assert_eq!(completed.unwrap(), [2u8; 32]);
}

#[test]
fn request_answered_within_the_deadline_does_not_time_out() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);

    let mut client = Client::uds(&socket, &jwt_path, 1, Duration::from_secs(2));
    send_fcu(&mut client.engine, [4u8; 32], fcu_state(4));

    let answer_at = Instant::now() + Duration::from_millis(400);
    let mut answered = false;
    let mut completed: Option<[u8; 32]> = None;
    spin_until("slow but in-deadline response succeeds", || {
        client.poll(|kind, response| {
            let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
            assert!(response.is_ok(), "response inside the deadline must not fail");
            completed = Some(root);
        });
        el.pump();
        if !answered && !el.requests.is_empty() && Instant::now() >= answer_at {
            el.respond(0, FCU_VALID_RESULT);
            answered = true;
        }
        completed.is_some()
    });
    assert_eq!(completed.unwrap(), [4u8; 32]);
}

#[test]
fn chunked_response_completes_the_rpc_with_the_decoded_body() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let socket = dir.path().join("engine.sock");
    let mut el = FakeEl::uds(&socket);

    let mut client = Client::uds(&socket, &jwt_path, 32, LONG_TIMEOUT);
    let block_root = [5u8; 32];
    // A response the socket buffer holds in one write: `respond_chunked`
    // blocks, and this single-threaded harness cannot drain concurrently.
    let blob = format!("0x{}", "ab".repeat(2048));
    get_blobs(&mut client.engine, simd_json::json!([["0x00"]]), block_root, 11);

    let mut responded = false;
    let mut completed: Option<Vec<u8>> = None;
    spin_until("chunked getBlobs round trip", || {
        client.poll(|kind, response| {
            let ReqKind::GetBlobs { block_root: root, slot } = kind else {
                panic!("unexpected completion")
            };
            assert_eq!((root, slot), (block_root, 11));
            completed = Some(response.expect("getBlobs response").to_vec());
        });
        el.pump();
        if !responded && !el.requests.is_empty() {
            assert_eq!(el.requests[0].method, "engine_getBlobsV3");
            let result = format!(r#"[{{"blob":"{blob}"}}]"#);
            el.respond_chunked(0, &result, 1 << 10);
            responded = true;
        }
        completed.is_some()
    });

    let body = String::from_utf8(completed.unwrap()).unwrap();
    assert!(body.starts_with(r#"{"jsonrpc":"2.0","id":"#), "framing stripped from the body");
    assert!(body.ends_with(&format!(r#""result":[{{"blob":"{blob}"}}]}}"#)));
}

/// A range with no room for the healthcheck's overshoot would have the
/// pool allocating into a neighbouring tenant's tokens, so it is refused
/// at construction.
#[test]
#[should_panic(expected = "does not fit a span")]
fn a_range_too_small_for_the_connection_cap_is_rejected() {
    let dir = TempDir::new().unwrap();
    let jwt_path = write_jwt(dir.path());
    let readiness = Readiness::new(1);
    EngineClient::new_uds(
        readiness.registry(),
        TokenRange::new(0, 8),
        dir.path().join("engine.sock"),
        jwt_path.to_str().unwrap(),
        8,
        LONG_TIMEOUT,
    );
}
