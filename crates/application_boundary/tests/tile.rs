use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::net::UnixStream,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_application_boundary::ApplicationBoundaryTile;
use silver_beacon_api::{PeerCounts, SlotStatus};
use silver_beacon_state_data::{BeaconStateOwner, SpecConfig};
use silver_common::{
    BeaconStateEvent, ELSyncStatus, EngineFcuReq, EngineReq, EngineResp, Enr, Identify, Keypair,
    PayloadValidationStatus, SilverSpine, SyncUpdate, TCache, TCacheProducer,
    ssz_view::STATUS_V2_SIZE,
};
use silver_config::EngineConfig;
use silver_engine_api::test_el::{FCU_VALID_RESULT, FakeEl, write_jwt};
use silver_httpcore::Bind;
use silver_peer::PeerCounters;
use tempfile::TempDir;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

fn boundary_tile(
    bind: &Bind,
    engine_config: EngineConfig,
    tcache_names: [&'static str; 3],
) -> ApplicationBoundaryTile {
    // Every `loop_body` below samples the peer gauges; left at the default
    // base that is the counter file a node running on this machine serves.
    PeerCounters::init_with_base(
        std::env::temp_dir()
            .join(format!("silver_application_boundary_test_{}", std::process::id())),
        "silver",
    )
    .unwrap();

    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    let gossip_p = TCache::producer(tcache_names[0], 1 << 12);
    let rpc_p = TCache::producer(tcache_names[1], 1 << 12);
    let resp_p = TCache::producer(tcache_names[2], 1 << 12);
    ApplicationBoundaryTile::new(
        std::slice::from_ref(bind),
        64,
        Duration::from_secs(75),
        &keypair,
        local_enr,
        &Identify::default(),
        &SpecConfig::mainnet(),
        BeaconStateOwner::empty_test(0).reader(),
        engine_config,
        gossip_p.cache_ref().random_access("t", true).unwrap(),
        rpc_p.cache_ref().random_access("t", true).unwrap(),
        resp_p,
    )
}

fn identity_client(addr: SocketAddr) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        http_get(stream, "/eth/v1/node/identity")
    })
}

/// A keep-alive client that hangs up the moment it has its answer, leaving a
/// half-closed peer on a connection the server still has registered.
fn identity_client_that_hangs_up(addr: SocketAddr) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream, "GET /eth/v1/node/identity HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut answer = Vec::new();
        let mut chunk = [0u8; 4096];
        while !whole_response(&answer) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "server closed a keep-alive connection before answering");
            answer.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8(answer).unwrap()
    })
}

fn whole_response(received: &[u8]) -> bool {
    let text = String::from_utf8_lossy(received);
    let Some(headers_end) = text.find("\r\n\r\n") else { return false };
    let declared: usize = text[..headers_end]
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("beacon api frames every answer with its length")
        .parse()
        .unwrap();
    received.len() >= headers_end + "\r\n\r\n".len() + declared
}

fn no_el() -> EngineConfig {
    EngineConfig { unsafe_no_el: true, ..EngineConfig::default() }
}

fn http_get(mut stream: impl Read + Write, path: &str) -> String {
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8(response).unwrap()
}

fn assert_identity_ok(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {response}");
    let body = &response[response.find("\r\n\r\n").unwrap() + 4..];
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(json["data"]["peer_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(json["data"]["enr"].as_str().unwrap().starts_with("enr:"));
    assert!(json["data"]["metadata"]["seq_number"].is_string());
}

fn fcu_req(byte: u8) -> EngineReq {
    EngineReq::Fcu(EngineFcuReq {
        block_root: [byte; 32],
        head_block_hash: [byte; 32],
        safe_block_hash: [0u8; 32],
        finalized_block_hash: [0u8; 32],
    })
}

fn head_block_hash_json(byte: u8) -> String {
    format!("\"headBlockHash\":\"0x{}\"", hex::encode([byte; 32]))
}

fn drain_fcu_completions(
    inj: &mut SpineAdapter<SilverSpine>,
    out: &mut Vec<([u8; 32], PayloadValidationStatus)>,
) {
    inj.consume(|resp: EngineResp, _| {
        if let EngineResp::Fcu(r) = resp {
            out.push((r.block_root, r.status));
        }
    });
}

fn status_event(head_slot: u64, wall_slot: u64, head_optimistic: bool) -> BeaconStateEvent {
    BeaconStateEvent::Status {
        ssz: [0u8; STATUS_V2_SIZE],
        head_optimistic,
        latest_block_slot: head_slot,
        wall_slot,
        enr_fork_id: [0u8; 16],
    }
}

#[test]
fn serves_identity_over_tcp() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_tcp_gossip",
        "cs_tcp_rpc",
        "cs_tcp_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    assert_ne!(addr.port(), 0, "port-0 bind must resolve to an ephemeral port");

    let client = identity_client(addr);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() {
        assert!(Instant::now() < deadline, "timeout: identity over tcp");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_identity_ok(&client.join().unwrap());
}

#[test]
fn serves_identity_over_uds() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let socket = base.path().join("beacon_api.sock");
    let mut tile = boundary_tile(&Bind::Unix(socket.clone()), no_el(), [
        "cs_uds_gossip",
        "cs_uds_rpc",
        "cs_uds_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    assert_eq!(tile.beacon.local_addrs(), [Bind::Unix(socket.clone())]);

    let client = std::thread::spawn(move || {
        let stream = UnixStream::connect(&socket).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        http_get(stream, "/eth/v1/node/identity")
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() {
        assert!(Instant::now() < deadline, "timeout: identity over uds");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_identity_ok(&client.join().unwrap());
}

/// ADR 0004's core claim: all pumps are non-blocking, so an unanswered EL
/// call never stalls beacon-api serving, and the EL completion still lands
/// once the response arrives.
#[test]
fn serves_beacon_api_while_engine_call_in_flight() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());

    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        ..EngineConfig::default()
    };
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), config, [
        "cs_flight_gossip",
        "cs_flight_rpc",
        "cs_flight_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        el.pump();
        std::thread::sleep(Duration::from_millis(1));
    };

    // Crank until the startup healthcheck trio is on the wire: the tile's
    // EngineReq cursor initializes on its first consume, so injecting before
    // the first loop_body would be skipped. The trio stays unanswered — three
    // more in-flight EL calls.
    while el.requests.len() < 3 {
        crank(&mut tile, &mut el, "startup healthcheck trio");
    }

    inj.produce(fcu_req(42));
    let fcu_on_wire =
        |el: &FakeEl| el.requests.iter().position(|r| r.method == "engine_forkchoiceUpdatedV3");
    while fcu_on_wire(&el).is_none() {
        crank(&mut tile, &mut el, "fcu on the wire");
    }

    // The FCU (and the startup healthcheck trio) sit unanswered on the EL;
    // the API request must be served anyway.
    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let client = identity_client(addr);
    while !client.is_finished() {
        crank(&mut tile, &mut el, "identity served while fcu in flight");
    }
    assert_identity_ok(&client.join().unwrap());

    let mut completed = Vec::new();
    inj.consume(|resp: EngineResp, _| {
        if let EngineResp::Fcu(r) = resp {
            completed.push(r.block_root);
        }
    });
    assert!(completed.is_empty(), "engine call must still be in flight after the API response");

    el.respond(fcu_on_wire(&el).unwrap(), FCU_VALID_RESULT);
    while completed.is_empty() {
        crank(&mut tile, &mut el, "fcu completion on the spine");
        inj.consume(|resp: EngineResp, _| {
            if let EngineResp::Fcu(r) = resp {
                completed.push(r.block_root);
            }
        });
    }
    assert_eq!(completed, vec![[42u8; 32]]);
}

/// (cap+1) concurrent spine requests with `max_connections = cap`: the
/// last one must stay queued on the spine until a completion frees a
/// connection, and completions must correlate out of order.
#[test]
fn pool_cap_gates_spine_intake() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());

    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        max_connections: 3,
        ..EngineConfig::default()
    };
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), config, [
        "cs_cap_gossip",
        "cs_cap_rpc",
        "cs_cap_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        el.pump();
        std::thread::sleep(Duration::from_millis(1));
    };

    // First loop_body fires the startup healthcheck trio; answer it so all
    // three pooled connections are free before the capped scenario.
    while el.requests.len() < 3 {
        crank(&mut tile, &mut el, "startup healthcheck trio");
    }
    for i in 0..3 {
        el.respond(i, "false");
    }

    for byte in [11u8, 12, 13, 14] {
        inj.produce(fcu_req(byte));
    }

    let fcu_count = |el: &FakeEl| {
        el.requests.iter().filter(|r| r.method == "engine_forkchoiceUpdatedV3").count()
    };
    while fcu_count(&el) < 3 {
        crank(&mut tile, &mut el, "first three FCUs sent");
    }
    for _ in 0..50 {
        crank(&mut tile, &mut el, "cap holds");
        assert_eq!(fcu_count(&el), 3, "4th request must wait while pool is at cap");
    }

    // Free one connection by answering the SECOND fcu; the gated request
    // must then be sent, and the completion must carry the responded
    // request's block root.
    let second = el
        .requests
        .iter()
        .position(|r| r.body.contains(&head_block_hash_json(12)))
        .expect("fcu for root 12 on the wire");
    el.respond(second, FCU_VALID_RESULT);

    while fcu_count(&el) < 4 {
        crank(&mut tile, &mut el, "gated FCU sent after a connection freed");
    }

    let mut completed = Vec::new();
    inj.consume(|resp: EngineResp, _| {
        if let EngineResp::Fcu(r) = resp {
            completed.push(r.block_root);
        }
    });
    assert_eq!(completed, vec![[12u8; 32]], "out-of-order completion correlated");
}

/// Taking a request off the spine flips its pooled connection's readiness
/// interest to WRITABLE, so the wait feeding the engine's dispatch has to run
/// after that intake: a request reaches the EL in the iteration that took it,
/// not the one after.
#[test]
fn an_engine_request_reaches_the_el_in_the_iteration_that_takes_it() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());

    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        ..EngineConfig::default()
    };
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), config, [
        "cs_same_iter_gossip",
        "cs_same_iter_rpc",
        "cs_same_iter_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        el.pump();
        std::thread::sleep(Duration::from_millis(1));
    };

    // Answering the startup trio leaves the pooled connections connected and
    // free, so the requests below wait on nothing but the interest change.
    while el.requests.len() < 3 {
        crank(&mut tile, &mut el, "startup healthcheck trio");
    }
    for i in 0..3 {
        el.respond(i, "false");
    }
    while tile.beacon.node_status_mut().el != ELSyncStatus::Synced {
        crank(&mut tile, &mut el, "startup healthcheck answered");
    }
    for _ in 0..20 {
        crank(&mut tile, &mut el, "pooled connections idle again");
    }

    let fcu_count = |el: &FakeEl| {
        el.requests.iter().filter(|r| r.method == "engine_forkchoiceUpdatedV3").count()
    };
    let mut produce_to_wire = Vec::new();
    for byte in [51u8, 52, 53, 54, 55] {
        let already_sent = fcu_count(&el);
        inj.produce(fcu_req(byte));

        let mut iterations = 0;
        while fcu_count(&el) == already_sent {
            crank(&mut tile, &mut el, "fcu on the wire");
            iterations += 1;
        }
        produce_to_wire.push(iterations);

        let on_wire = el
            .requests
            .iter()
            .position(|r| r.body.contains(&head_block_hash_json(byte)))
            .expect("fcu on the wire");
        el.respond(on_wire, FCU_VALID_RESULT);
        let mut completed = Vec::new();
        while completed.is_empty() {
            crank(&mut tile, &mut el, "fcu completion frees its connection");
            drain_fcu_completions(&mut inj, &mut completed);
        }
    }
    assert_eq!(produce_to_wire, [1; 5], "iterations from produce to wire, per request");
}

/// A broadcast consumer's cursor jumps to the producer's write head on its
/// first read, so anything published before the tile's first `loop_body` is
/// gone — which is why the tile reads these queues unconditionally from that
/// first iteration on.
#[test]
fn node_status_tracks_the_spine_once_the_cursor_snaps() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_status_gossip",
        "cs_status_rpc",
        "cs_status_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);

    inj.produce(status_event(1, 1, true));
    tile.loop_body(&mut adapter);
    assert!(
        tile.beacon.node_status_mut().slots.is_none(),
        "a status published before the first consume is skipped, not delivered"
    );

    inj.produce(status_event(7, 9, true));
    inj.produce(SyncUpdate::SyncingHead { head_root: [3u8; 32], head_slot: 9 });
    tile.loop_body(&mut adapter);

    let status = *tile.beacon.node_status_mut();
    assert_eq!(
        status.slots,
        Some(SlotStatus { head_slot: 7, wall_slot: 9, head_optimistic: true })
    );
    assert_eq!(status.slots.unwrap().sync_distance(), 2);
    assert!(status.syncing);

    inj.produce(status_event(9, 9, false));
    inj.produce(SyncUpdate::Following);
    tile.loop_body(&mut adapter);
    let status = *tile.beacon.node_status_mut();
    assert_eq!(
        status.slots,
        Some(SlotStatus { head_slot: 9, wall_slot: 9, head_optimistic: false }),
        "each status replaces the last, execution status included"
    );
    assert!(!status.syncing, "reaching the target clears the syncing flag");
}

/// The engine's spine intake is gated on free pool connections; node status
/// must not be. A queue left unread for a few iterations does not stall — it
/// loses its whole backlog.
#[test]
fn node_status_updates_while_the_engine_pool_is_at_cap() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());

    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        max_connections: 3,
        ..EngineConfig::default()
    };
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), config, [
        "cs_sat_gossip",
        "cs_sat_rpc",
        "cs_sat_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        el.pump();
        std::thread::sleep(Duration::from_millis(1));
    };

    while el.requests.len() < 3 {
        crank(&mut tile, &mut el, "startup healthcheck trio");
    }
    // `eth_syncing: false` is the EL reporting itself synced; the trio also
    // frees all three pooled connections.
    for i in 0..3 {
        el.respond(i, "false");
    }
    while tile.beacon.node_status_mut().el != ELSyncStatus::Synced {
        crank(&mut tile, &mut el, "EL sync status reaches the api");
    }

    for byte in [11u8, 12, 13, 14] {
        inj.produce(fcu_req(byte));
    }
    let fcu_count = |el: &FakeEl| {
        el.requests.iter().filter(|r| r.method == "engine_forkchoiceUpdatedV3").count()
    };
    while fcu_count(&el) < 3 {
        crank(&mut tile, &mut el, "pool saturated with unanswered FCUs");
    }

    inj.produce(status_event(7, 9, false));
    inj.produce(SyncUpdate::Following);
    while tile.beacon.node_status_mut().slots.is_none() {
        crank(&mut tile, &mut el, "status consumed while the pool is at cap");
        assert_eq!(fcu_count(&el), 3, "the 4th request must stay gated on the spine");
    }

    let status = *tile.beacon.node_status_mut();
    assert_eq!(
        status.slots,
        Some(SlotStatus { head_slot: 7, wall_slot: 9, head_optimistic: false })
    );
    assert!(!status.syncing);
    assert_eq!(status.el, ELSyncStatus::Synced);
}

/// Peer counts reach the api through shared memory, not the spine: the peer
/// manager sets its gauges on its own tick, in another tile.
#[test]
fn node_status_tracks_the_peer_gauges() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_peers_gossip",
        "cs_peers_rpc",
        "cs_peers_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    PeerCounters::PeersConnected.set(56);
    PeerCounters::PeersConnecting.set(3);
    tile.loop_body(&mut adapter);
    assert_eq!(tile.beacon.node_status_mut().peers, PeerCounts { connected: 56, connecting: 3 });

    PeerCounters::PeersConnected.set(55);
    tile.loop_body(&mut adapter);
    assert_eq!(tile.beacon.node_status_mut().peers.connected, 55, "refreshed every iteration");
}

/// Both tenants register into one readiness loop, where a token either could
/// allocate would deliver one's socket to the other's dispatch. Every socket
/// here is well past its tenant's first token, and every one of them is live
/// at the same time.
#[test]
fn concurrent_clients_and_engine_calls_keep_their_own_sockets() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());

    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        max_connections: 4,
        ..EngineConfig::default()
    };
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), config, [
        "cs_alias_gossip",
        "cs_alias_rpc",
        "cs_alias_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        el.pump();
        std::thread::sleep(Duration::from_millis(1));
    };

    // The startup healthcheck trio takes three pooled connections; answering
    // it leaves all three registered and free for the FCUs below.
    while el.requests.len() < 3 {
        crank(&mut tile, &mut el, "startup healthcheck trio");
    }
    for i in 0..3 {
        el.respond(i, "false");
    }

    let roots = [21u8, 22, 23, 24];
    for byte in roots {
        inj.produce(fcu_req(byte));
    }
    let fcu_count = |el: &FakeEl| {
        el.requests.iter().filter(|r| r.method == "engine_forkchoiceUpdatedV3").count()
    };
    while fcu_count(&el) < roots.len() {
        crank(&mut tile, &mut el, "four engine calls on the wire");
    }

    // Each client hangs up on its own connection while the engine calls are
    // still in flight: a shared token would deliver that hangup to the engine
    // pool, which would fail the call it is waiting on.
    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let clients = roots.map(|_| identity_client_that_hangs_up(addr));
    while !clients.iter().all(JoinHandle::is_finished) {
        crank(&mut tile, &mut el, "four api clients served while the engine calls wait");
    }
    for client in clients {
        assert_identity_ok(&client.join().unwrap());
    }
    for _ in 0..10 {
        crank(&mut tile, &mut el, "hangups delivered");
    }

    let mut completed = Vec::new();
    drain_fcu_completions(&mut inj, &mut completed);
    assert!(completed.is_empty(), "a client hanging up must not complete an engine call");

    for byte in roots {
        let on_wire = el
            .requests
            .iter()
            .position(|r| r.body.contains(&head_block_hash_json(byte)))
            .expect("fcu on the wire");
        el.respond(on_wire, FCU_VALID_RESULT);
    }
    while completed.len() < roots.len() {
        crank(&mut tile, &mut el, "every engine completion on the spine");
        drain_fcu_completions(&mut inj, &mut completed);
    }
    completed.sort_by_key(|(root, _)| *root);
    assert_eq!(
        completed,
        roots.map(|byte| ([byte; 32], PayloadValidationStatus::Valid)),
        "each call must carry its own EL answer, not a transport failure"
    );
}

/// In unsafe no-EL mode the engine has no client and registers nothing, so the
/// beacon-api server is the only tenant of the loop and must serve as if it
/// had one to itself.
#[test]
fn serves_concurrent_clients_with_no_engine_registered() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_noel_gossip",
        "cs_noel_rpc",
        "cs_noel_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let clients = [(); 3].map(|()| identity_client(addr));

    let deadline = Instant::now() + Duration::from_secs(10);
    while !clients.iter().all(JoinHandle::is_finished) {
        assert!(Instant::now() < deadline, "timeout: three clients served with no engine");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    }
    for client in clients {
        assert_identity_ok(&client.join().unwrap());
    }
}
