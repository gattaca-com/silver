use std::{
    io::{Read, Write},
    net::TcpStream,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::BeaconApi;
use silver_beacon_state_data::BeaconStateOwner;
use silver_client_server::ClientServerTile;
use silver_common::{
    EngineFcuReq, EngineReq, EngineResp, Enr, Identify, Keypair, SilverSpine, TCache,
    TCacheProducer,
};
use silver_config::EngineConfig;
use silver_engine_api::{
    EngineApi,
    test_el::{FCU_VALID_RESULT, FakeEl, write_jwt},
};
use silver_httpcore::Bind;
use tempfile::TempDir;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

fn beacon(bind: &Bind) -> BeaconApi {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    BeaconApi::new(
        bind,
        &keypair,
        local_enr,
        &Identify::default(),
        BeaconStateOwner::empty_test(0).reader(),
    )
}

fn engine(config: EngineConfig, tcache_names: [&'static str; 3]) -> EngineApi {
    let gossip_p = TCache::producer(tcache_names[0], 1 << 12);
    let rpc_p = TCache::producer(tcache_names[1], 1 << 12);
    let resp_p = TCache::producer(tcache_names[2], 1 << 12);
    EngineApi::new(
        config,
        gossip_p.cache_ref().random_access("t", true).unwrap(),
        rpc_p.cache_ref().random_access("t", true).unwrap(),
        resp_p,
    )
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

#[test]
fn serves_identity_over_tcp() {
    let base = TempDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = ClientServerTile {
        beacon: beacon(&Bind::parse("127.0.0.1:0")),
        engine: engine(no_el(), ["cs_tcp_gossip", "cs_tcp_rpc", "cs_tcp_resp"]),
    };
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    let Bind::Tcp(addr) = tile.beacon.local_addr() else { panic!("expected tcp bind") };
    assert_ne!(addr.port(), 0, "port-0 bind must resolve to an ephemeral port");

    let client = std::thread::spawn(move || {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        http_get(stream, "/eth/v1/node/identity")
    });

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
    let mut tile = ClientServerTile {
        beacon: beacon(&Bind::Unix(socket.clone())),
        engine: engine(no_el(), ["cs_uds_gossip", "cs_uds_rpc", "cs_uds_resp"]),
    };
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);

    assert_eq!(tile.beacon.local_addr(), Bind::Unix(socket.clone()));

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
    let mut tile = ClientServerTile {
        beacon: beacon(&Bind::parse("127.0.0.1:0")),
        engine: engine(config, ["cs_flight_gossip", "cs_flight_rpc", "cs_flight_resp"]),
    };
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ClientServerTile, el: &mut FakeEl, msg: &str| {
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
    let Bind::Tcp(addr) = tile.beacon.local_addr() else { panic!("expected tcp bind") };
    let client = std::thread::spawn(move || {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        http_get(stream, "/eth/v1/node/identity")
    });
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
    let mut tile = ClientServerTile {
        beacon: beacon(&Bind::parse("127.0.0.1:0")),
        engine: engine(config, ["cs_cap_gossip", "cs_cap_rpc", "cs_cap_resp"]),
    };
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    inj.consume(|_: EngineResp, _| {});

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ClientServerTile, el: &mut FakeEl, msg: &str| {
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
