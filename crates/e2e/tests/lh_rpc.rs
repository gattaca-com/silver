//! Eth2 RPC round-trip tests through the libp2p test client. Each
//! protocol (Ping / StatusV2 / MetaData) is exercised twice: once with
//! silver as the responder, once as the requester. The libp2p side wraps
//! the real eth2 RPC framing (`varint(ssz_len) || snappy_frames`) via
//! `Eth2RpcCodec` so any drift between silver's encoder and the spec
//! shows up here.

mod lh_common;

use std::time::{Duration, Instant};

use lh_common::{
    DUMMY_METADATA, DUMMY_STATUS, build_silver_listener, drive_until, inject_silver_rpc_request,
    libp2p_to_silver_peer_id, wait_for_silver_connect,
};
use silver_common::{
    RpcRequest,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE},
};
use silver_e2e::{LhClient, lh_client};

const PING_PROTOCOL: &str = lh_client::PING_PROTOCOL;
const STATUS_V2_PROTOCOL: &str = lh_client::STATUS_V2_PROTOCOL;
const METADATA_V3_PROTOCOL: &str = lh_client::METADATA_V3_PROTOCOL;

// ─── silver-as-server tests ────────────────────────────────────────────
//
// libp2p dials silver, sends an RPC request, asserts the response.

#[test]
fn silver_responds_to_ping() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(20);
    silver.controller.set_metadata(DUMMY_METADATA);
    let mut client = LhClient::new_dialer_for(PING_PROTOCOL);
    client.dial(silver.addr).expect("dial");

    let connected = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.connected_peer().is_some()
    });
    assert!(connected, "no connection");

    let peer = client.connected_peer().expect("connected");
    let req_id = client.send_ping(peer, 0xdeadbeef);

    let mut response = None;
    drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        response = c.take_response(req_id);
        response.is_some()
    });
    let (result, body) = response.expect("no Pong response");
    assert_eq!(result, 0, "expected success result byte, got {result}");
    assert_eq!(body.len(), 8, "Pong body must be 8 bytes (u64 LE)");
    // Silver echoes its metadata seq_number; with DUMMY_METADATA it's 0.
    assert_eq!(body, [0u8; 8]);
}

#[test]
fn silver_responds_to_status_v2() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(21);
    let mut canned = DUMMY_STATUS;
    canned[0] = 0xab;
    silver.controller.set_status(canned);

    let mut client = LhClient::new_dialer_for(STATUS_V2_PROTOCOL);
    client.dial(silver.addr).expect("dial");

    drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.connected_peer().is_some()
    });
    let peer = client.connected_peer().expect("connected");

    let req_id = client.send_status(peer, DUMMY_STATUS.to_vec());

    let mut response = None;
    drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        response = c.take_response(req_id);
        response.is_some()
    });
    let (result, body) = response.expect("no Status response");
    assert_eq!(result, 0);
    assert_eq!(body.len(), STATUS_V2_SIZE);
    assert_eq!(&body[..], &canned[..]);
}

#[test]
fn silver_responds_to_metadata() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(22);
    let mut canned = DUMMY_METADATA;
    canned[0] = 0x77;
    silver.controller.set_metadata(canned);

    let mut client = LhClient::new_dialer_for(METADATA_V3_PROTOCOL);
    client.dial(silver.addr).expect("dial");

    drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.connected_peer().is_some()
    });
    let peer = client.connected_peer().expect("connected");

    let req_id = client.send_metadata(peer);

    let mut response = None;
    drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        response = c.take_response(req_id);
        response.is_some()
    });
    let (result, body) = response.expect("no MetaData response");
    assert_eq!(result, 0);
    assert_eq!(body.len(), METADATA_SIZE);
    assert_eq!(&body[..], &canned[..]);
}

// ─── silver-as-client tests ────────────────────────────────────────────
//
// libp2p listens. Silver dials it, then we inject an outbound RPC
// request onto silver's spine and assert the libp2p side observed the
// request bytes correctly. libp2p auto-responds with canned bytes so
// silver's stream completes — silver's reception of that response is
// covered separately by controller unit tests.

fn drive_silver_dialer(
    seed: u8,
) -> (silver_e2e::PublisherStack, LhClient, usize, tempfile::TempDir) {
    let (mut silver, td) = build_silver_listener(seed);
    let mut client = LhClient::new_listener();
    client.set_auto_response(PING_PROTOCOL, vec![0u8; 8]);
    client.set_auto_response(STATUS_V2_PROTOCOL, vec![0u8; STATUS_V2_SIZE]);
    client.set_auto_response(METADATA_V3_PROTOCOL, vec![0u8; METADATA_SIZE]);

    let lh_addr = client.listen_addr().expect("lh listening");
    let lh_silver_pid = libp2p_to_silver_peer_id(client.local_peer_id());
    silver.network.p2p_mut().connect(lh_silver_pid, lh_addr, Instant::now()).expect("connect");

    let peer = wait_for_silver_connect(&mut silver, &mut client, Duration::from_secs(5))
        .expect("silver never observed PeerConnected");
    (silver, client, peer, td)
}

#[test]
fn silver_sends_ping_to_libp2p() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, mut client, peer, _td) = drive_silver_dialer(30);
    inject_silver_rpc_request(
        &mut silver,
        peer,
        /* application_id */ 1,
        RpcRequest::Ping(0xcafebabeu64.to_le_bytes()),
    );

    let received = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.received_requests().iter().any(|r| r.protocol.as_ref() == PING_PROTOCOL)
    });
    assert!(received, "libp2p never observed Ping request");

    let req = client
        .received_requests()
        .iter()
        .find(|r| r.protocol.as_ref() == PING_PROTOCOL)
        .expect("ping req");
    assert_eq!(req.body.len(), 8);
    assert_eq!(req.body, 0xcafebabeu64.to_le_bytes());
}

#[test]
fn silver_sends_status_to_libp2p() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, mut client, peer, _td) = drive_silver_dialer(31);
    let mut sent_status = DUMMY_STATUS;
    sent_status[10] = 0xee;
    inject_silver_rpc_request(
        &mut silver,
        peer,
        /* application_id */ 2,
        RpcRequest::StatusV2(sent_status),
    );

    let received = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.received_requests().iter().any(|r| r.protocol.as_ref() == STATUS_V2_PROTOCOL)
    });
    assert!(received, "libp2p never observed Status request");

    let req = client
        .received_requests()
        .iter()
        .find(|r| r.protocol.as_ref() == STATUS_V2_PROTOCOL)
        .expect("status req");
    assert_eq!(req.body.len(), STATUS_V2_SIZE);
    assert_eq!(&req.body[..], &sent_status[..]);
}

#[test]
fn silver_sends_metadata_to_libp2p() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, mut client, peer, _td) = drive_silver_dialer(32);
    inject_silver_rpc_request(&mut silver, peer, /* application_id */ 3, RpcRequest::MetaData);

    let received = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        c.received_requests().iter().any(|r| r.protocol.as_ref() == METADATA_V3_PROTOCOL)
    });
    assert!(received, "libp2p never observed MetaData request");

    let req = client
        .received_requests()
        .iter()
        .find(|r| r.protocol.as_ref() == METADATA_V3_PROTOCOL)
        .expect("metadata req");
    assert!(req.body.is_empty(), "MetaData body should be empty, got {} bytes", req.body.len());
}
