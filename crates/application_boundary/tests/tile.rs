use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile, timing::Nanos};
use serde_json::{Value, json};
use silver_application_boundary::ApplicationBoundaryTile;
use silver_beacon_api::HeadStatus;
use silver_beacon_state_data::{BeaconStateOwner, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BeaconApiRequest, BeaconApiResponse, BeaconStateEvent, BlockLookup, BlockSource, BlockStage,
    ColumnSource, DataColumnsEvent, ELSyncStatus, EngineFcuReq, EngineReq, EngineResp, Enr,
    GossipTopic, HeadChange, HeadRoots, Identify, IpBytes, Keypair, MessageId, P2pStreamId,
    PayloadResolution, PayloadValidationStatus, PeerEvent, ServedBlock, SilverSpine,
    StreamProtocol, SyncUpdate, TCache, TCacheProducer, TCacheRead, TProducer, block_root_fulu,
    ssz_view::{BEACON_BLOCK_BODY_FIXED, SIGNED_BEACON_BLOCK_MIN, STATUS_V2_SIZE},
    test_util::ShmemDir,
};
use silver_config::EngineConfig;
use silver_engine_api::test_el::{FCU_VALID_RESULT, FakeEl, write_jwt};
use silver_httpcore::Bind;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

fn boundary_tile(
    bind: &Bind,
    engine_config: EngineConfig,
    tcache_names: [&'static str; 3],
) -> ApplicationBoundaryTile {
    boundary_tile_with_spec(bind, engine_config, tcache_names, &SpecConfig::mainnet()).0
}

fn boundary_tile_with_objects(
    bind: &Bind,
    engine_config: EngineConfig,
    tcache_names: [&'static str; 3],
) -> (ApplicationBoundaryTile, TProducer, TProducer) {
    boundary_tile_with_spec(bind, engine_config, tcache_names, &SpecConfig::mainnet())
}

fn boundary_tile_with_spec(
    bind: &Bind,
    engine_config: EngineConfig,
    tcache_names: [&'static str; 3],
    spec: &SpecConfig,
) -> (ApplicationBoundaryTile, TProducer, TProducer) {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    let gossip_p = TCache::producer(tcache_names[0], 1 << 16);
    let rpc_p = TCache::producer(tcache_names[1], 1 << 16);
    let resp_p = TCache::producer(tcache_names[2], 1 << 12);
    let tile = ApplicationBoundaryTile::new(
        std::slice::from_ref(bind),
        64,
        Duration::from_secs(75),
        &keypair,
        local_enr,
        &Identify::default(),
        spec,
        BeaconStateOwner::published_empty_test(0).reader(),
        [0u8; 32],
        engine_config,
        gossip_p.cache_ref().random_access("t", true).unwrap(),
        rpc_p.cache_ref().random_access("t", true).unwrap(),
        resp_p,
        gossip_p.cache_ref().random_access("t_events", true).unwrap(),
        rpc_p.cache_ref().random_access("t_storage", true).unwrap(),
    );
    (tile, gossip_p, rpc_p)
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

fn block_received(slot: u64, byte: u8, stage: BlockStage) -> BeaconStateEvent {
    BeaconStateEvent::BlockReceived {
        slot,
        block_root: [byte; 32],
        stage,
        source: BlockSource::Gossip,
        parent_slot: Some(slot - 1),
    }
}

fn write_object(producer: &mut TProducer, bytes: &[u8]) -> TCacheRead {
    let mut reservation = producer.reserve(bytes.len(), false).unwrap();
    reservation.write_all(bytes).unwrap();
    reservation.flush().unwrap();
    reservation.read()
}

/// Synthetic block for field extraction, not consensus validation. The fixed
/// body prefix exercises fork-specific hashing instead of the short-body
/// fallback. Varying the state root gives fixtures distinct block roots.
fn block_bytes(slot: u64, byte: u8) -> Vec<u8> {
    let mut body = vec![0u8; BEACON_BLOCK_BODY_FIXED];
    for offset in [200, 204, 208, 212, 216, 380, 384, 388, 392] {
        body[offset..offset + 4].copy_from_slice(&(BEACON_BLOCK_BODY_FIXED as u32).to_le_bytes());
    }
    let mut block = vec![0u8; SIGNED_BEACON_BLOCK_MIN];
    block[0..4].copy_from_slice(&100u32.to_le_bytes());
    block[100..108].copy_from_slice(&slot.to_le_bytes());
    block[148..180].copy_from_slice(&[byte; 32]);
    block[180..184].copy_from_slice(&84u32.to_le_bytes());
    block.extend_from_slice(&body);
    block
}

fn send_gossip(topic: GossipTopic, byte: u8, ssz: TCacheRead) -> PeerEvent {
    PeerEvent::SendGossip {
        originator_stream_id: P2pStreamId::new(0, 0, StreamProtocol::GossipSub, false),
        topic,
        domain: silver_common::GossipDomain::new([0; 4], silver_common::ForkName::Fulu),
        ssz_cache: silver_common::SszCache::Gossip,
        msg_hash: MessageId { id: [byte; 20] },
        recv_ts: Nanos::now(),
        // The boundary does not read protobuf, so no encoded payload is needed.
        protobuf: ssz,
        ssz,
    }
}

fn block_relay(gossip: &mut TProducer, slot: u64, byte: u8) -> (PeerEvent, SseEvent) {
    let block = block_bytes(slot, byte);
    let event = send_gossip(GossipTopic::BeaconBlock, byte, write_object(gossip, &block));
    (event, SseEvent::block_gossip(slot, &block_root_fulu(&block)))
}

fn validated_column(
    origin: ColumnOrigin,
    slot: u64,
    byte: u8,
    index: u64,
) -> (DataColumnsEvent, SseEvent) {
    let block_root = [byte; 32];
    let event = DataColumnsEvent::Validated { block_root, column_index: index, slot, origin };
    (event, SseEvent::column(slot, &block_root, index))
}

fn gossip_column(slot: u64, byte: u8, index: u64) -> (DataColumnsEvent, SseEvent) {
    validated_column(ColumnOrigin::Gossip, slot, byte, index)
}

fn rpc_column(slot: u64, byte: u8, index: u64) -> (DataColumnsEvent, SseEvent) {
    validated_column(ColumnOrigin::Rpc, slot, byte, index)
}

#[derive(Clone, Debug)]
struct SseEvent {
    name: String,
    data: Value,
}

impl SseEvent {
    fn block(slot: u64, byte: u8) -> Self {
        Self {
            name: "block".to_owned(),
            data: json!({"slot": slot.to_string(), "block": format!("0x{}", hex::encode([byte; 32]))}),
        }
    }

    fn block_gossip(slot: u64, block_root: &[u8; 32]) -> Self {
        Self {
            name: "block_gossip".to_owned(),
            data: json!({"slot": slot.to_string(), "block": format!("0x{}", hex::encode(block_root))}),
        }
    }

    fn column(slot: u64, block_root: &[u8; 32], index: u64) -> Self {
        Self {
            name: "data_column_sidecar".to_owned(),
            data: json!({"block_root": format!("0x{}", hex::encode(block_root)), "index": index.to_string(), "slot": slot.to_string()}),
        }
    }

    fn assert_matches(&self, expected: &Self) {
        assert_eq!(self.name, expected.name);
        for (key, value) in expected.data.as_object().unwrap() {
            assert_eq!(self.data.get(key), Some(value), "field {key} in {}", self.name);
        }
    }

    fn assert_block(&self, name: &str, slot: u64, byte: u8) {
        assert_eq!(self.name, name);
        assert_eq!(self.data["slot"], slot.to_string());
        assert_eq!(self.data["block"], format!("0x{}", hex::encode([byte; 32])));
    }
}

struct EventsSubscriber {
    client: JoinHandle<()>,
    events: Receiver<SseEvent>,
}

impl EventsSubscriber {
    fn new(addr: SocketAddr, topics: &str, count: usize, pump: impl FnMut()) -> Self {
        let (subscribed, on_subscribed) = mpsc::channel();
        let (send, events) = mpsc::channel();
        let url = format!("http://{addr}/eth/v1/events?topics={topics}");
        let client = std::thread::spawn(move || {
            let response = ureq::get(&url).timeout(Duration::from_secs(10)).call().unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.content_type(), "text/event-stream");
            subscribed.send(()).unwrap();

            let mut name = String::new();
            let mut data = String::new();
            let mut received = 0;
            for line in BufReader::new(response.into_reader()).lines() {
                let line = line.unwrap();
                if line.is_empty() {
                    if !data.is_empty() {
                        send.send(SseEvent {
                            name: if name.is_empty() { "message".to_owned() } else { name.clone() },
                            data: serde_json::from_str(&data).expect("event data is JSON"),
                        })
                        .unwrap();
                        received += 1;
                        if received == count {
                            return;
                        }
                    }
                    name.clear();
                    data.clear();
                } else if let Some((field, value)) = line.split_once(':') {
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    match field {
                        "event" => name = value.to_owned(),
                        "data" => {
                            data.push_str(value);
                            data.push('\n');
                        }
                        _ => {}
                    }
                }
            }
            panic!("event stream closed before {count} events arrived");
        });
        receive_while_pumping(&on_subscribed, pump);
        Self { client, events }
    }

    fn next(&self, pump: impl FnMut()) -> SseEvent {
        receive_while_pumping(&self.events, pump)
    }

    fn assert_topic_sequences(&self, expected: &[SseEvent], mut pump: impl FnMut()) {
        let mut actual = (0..expected.len()).map(|_| self.next(&mut pump)).collect::<Vec<_>>();
        let mut expected = expected.iter().collect::<Vec<_>>();
        // Stable sorting preserves each topic's sequence without fixing their
        // interleaving.
        actual.sort_by(|a, b| a.name.cmp(&b.name));
        expected.sort_by(|a, b| a.name.cmp(&b.name));
        for (actual, expected) in actual.iter().zip(expected) {
            actual.assert_matches(expected);
        }
    }
}

fn receive_while_pumping<T>(receiver: &Receiver<T>, mut pump: impl FnMut()) -> T {
    loop {
        match receiver.try_recv() {
            Ok(value) => return value,
            Err(TryRecvError::Empty) => pump(),
            Err(TryRecvError::Disconnected) => {
                panic!("subscriber stopped before sending its result")
            }
        }
    }
}

fn status_event(head_slot: u64, wall_slot: u64, head_optimistic: bool) -> BeaconStateEvent {
    let mut ssz = [0u8; STATUS_V2_SIZE];
    ssz[36..44].copy_from_slice(&3u64.to_le_bytes());
    BeaconStateEvent::Status {
        ssz,
        latest_block_slot: head_slot,
        wall_slot,
        head_optimistic,
        enr_fork_id: [0u8; 16],
        head_roots: HeadRoots::default(),
        head_payload: PayloadResolution::Full,
        head_change: HeadChange::None,
        epoch_transition: false,
    }
}

fn head_roots() -> HeadRoots {
    HeadRoots {
        state_root: [0x60; 32],
        previous_duty_dependent_root: [0x5e; 32],
        current_duty_dependent_root: [0x91; 32],
    }
}

fn head_status(
    slot: u64,
    block_root: u8,
    optimistic: bool,
    payload: PayloadResolution,
    head_change: HeadChange,
) -> BeaconStateEvent {
    let mut ssz = [0u8; STATUS_V2_SIZE];
    ssz[44..76].copy_from_slice(&[block_root; 32]);
    ssz[76..84].copy_from_slice(&slot.to_le_bytes());
    BeaconStateEvent::Status {
        ssz,
        latest_block_slot: slot,
        wall_slot: slot,
        head_optimistic: optimistic,
        enr_fork_id: [0u8; 16],
        head_roots: head_roots(),
        head_payload: payload,
        head_change,
        epoch_transition: false,
    }
}

fn head_events_subscriber(
    addr: SocketAddr,
    topic: &str,
    sentinel_slot: u64,
) -> (JoinHandle<Vec<Value>>, Receiver<()>) {
    let (subscribed, on_subscribed) = mpsc::channel();
    let topic = topic.to_string();
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream, "GET /eth/v1/events?topics={topic} HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.split_whitespace().nth(1), Some("200"));
        let mut headers = HashMap::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.trim_end().split_once(':').unwrap();
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers["content-type"], "text/event-stream");
        assert_eq!(headers["transfer-encoding"], "chunked");
        subscribed.send(()).unwrap();

        let mut events = Vec::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
            assert!(size > 0, "subscription ended before the sentinel");
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).unwrap();
            let mut end = [0; 2];
            reader.read_exact(&mut end).unwrap();
            assert_eq!(end, *b"\r\n");
            let frame = std::str::from_utf8(&chunk).unwrap().strip_suffix("\n\n").unwrap();
            if frame.starts_with(':') {
                continue;
            }
            let (name, data) =
                frame.strip_prefix("event: ").unwrap().split_once("\ndata: ").unwrap();
            assert_eq!(name, topic);
            let body: Value = serde_json::from_str(data).unwrap();
            let data = if topic == "head_v2" { &body["data"] } else { &body };
            if data["slot"] == sentinel_slot.to_string() {
                return events;
            }
            events.push(body);
        }
    });
    (client, on_subscribed)
}

/// ADR 0004's core claim: all pumps are non-blocking, so an unanswered EL
/// call never stalls beacon-api serving, and the EL completion still lands
/// once the response arrives.
#[test]
fn serves_beacon_api_while_engine_call_in_flight() {
    let base = ShmemDir::new().unwrap();
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
    let base = ShmemDir::new().unwrap();
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
    let base = ShmemDir::new().unwrap();
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
    while tile.beacon.node_status().el != ELSyncStatus::Synced {
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

#[test]
fn peer_table_follows_connections_and_disconnects() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_peers_gossip",
        "cs_peers_rpc",
        "cs_peers_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let peer_id = |secret: u8| Keypair::from_secret(&[secret; 32]).unwrap().peer_id();
    for (p2p_peer_id, local_dial) in [(3, false), (4, true)] {
        inj.produce(PeerEvent::P2pNewConnection {
            p2p_peer_id,
            peer_id_full: peer_id(p2p_peer_id as u8),
            ip: IpBytes::V4([10, 0, 0, p2p_peer_id as u8]),
            port: 9000,
            local_dial,
        });
    }
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let peers = |tile: &mut ApplicationBoundaryTile,
                 adapter: &mut SpineAdapter<SilverSpine>,
                 query: &str|
     -> Value {
        let path = format!("/eth/v1/node/peers{query}");
        let client = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            http_get(stream, &path)
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !client.is_finished() {
            assert!(Instant::now() < deadline, "timeout: peers answered");
            tile.loop_body(adapter);
            std::thread::sleep(Duration::from_millis(1));
        }
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {response}");
        serde_json::from_str(&response[response.find("\r\n\r\n").unwrap() + 4..]).unwrap()
    };

    assert_eq!(peers(&mut tile, &mut adapter, "")["meta"]["count"], 2);
    let outbound = peers(&mut tile, &mut adapter, "?direction=outbound");
    assert_eq!(outbound["meta"]["count"], 1);
    assert!(
        outbound["data"][0]["last_seen_p2p_address"]
            .as_str()
            .unwrap()
            .starts_with("/ip4/10.0.0.4/udp/9000/quic-v1/p2p/")
    );

    inj.produce(PeerEvent::P2pDisconnect { p2p_peer: 4, peer_id: peer_id(4) });
    tile.loop_body(&mut adapter);
    assert_eq!(peers(&mut tile, &mut adapter, "")["meta"]["count"], 1);
}

/// A broadcast consumer's cursor jumps to the producer's write head on its
/// first read, so anything published before the tile's first `loop_body` is
/// gone — which is why the tile reads these queues unconditionally from that
/// first iteration on.
#[test]
fn node_status_tracks_the_spine_once_the_cursor_snaps() {
    let base = ShmemDir::new().unwrap();
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
    assert_eq!(
        tile.beacon.node_status().head,
        HeadStatus { slot: 0, optimistic: false },
        "a status published before the first consume is skipped, not delivered"
    );

    inj.produce(status_event(7, 9, true));
    inj.produce(SyncUpdate::SyncingHead { head_root: [3u8; 32], head_slot: 9 });
    tile.loop_body(&mut adapter);

    let status = *tile.beacon.node_status();
    assert_eq!(status.head, HeadStatus { slot: 7, optimistic: true });
    assert_eq!(status.finalized_epoch, 3);
    assert_eq!(status.target, Some(SyncUpdate::SyncingHead { head_root: [3u8; 32], head_slot: 9 }));

    inj.produce(status_event(9, 9, false));
    inj.produce(SyncUpdate::Following);
    tile.loop_body(&mut adapter);
    let status = *tile.beacon.node_status();
    assert_eq!(
        status.head,
        HeadStatus { slot: 9, optimistic: false },
        "each status replaces the last, execution status included"
    );
    assert_eq!(
        status.target,
        Some(SyncUpdate::Following),
        "reaching the target clears the syncing flag"
    );
}

/// The engine's spine intake is gated on free pool connections; node status
/// must not be. A queue left unread for a few iterations does not stall — it
/// loses its whole backlog.
#[test]
fn node_status_updates_while_the_engine_pool_is_at_cap() {
    let base = ShmemDir::new().unwrap();
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
    while tile.beacon.node_status().el != ELSyncStatus::Synced {
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
    while tile.beacon.node_status().head.slot != 7 {
        crank(&mut tile, &mut el, "status consumed while the pool is at cap");
        assert_eq!(fcu_count(&el), 3, "the 4th request must stay gated on the spine");
    }

    let status = *tile.beacon.node_status();
    assert_eq!(status.head, HeadStatus { slot: 7, optimistic: false });
    assert_eq!(status.target, Some(SyncUpdate::Following));
    assert_eq!(status.el, ELSyncStatus::Synced);
}

/// Both tenants register into one readiness loop, where a token either could
/// allocate would deliver one's socket to the other's dispatch. Every socket
/// here is well past its tenant's first token, and every one of them is live
/// at the same time.
#[test]
fn concurrent_clients_and_engine_calls_keep_their_own_sockets() {
    let base = ShmemDir::new().unwrap();
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
    let base = ShmemDir::new().unwrap();
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

#[test]
fn an_applied_block_on_the_spine_reaches_an_events_subscriber() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_sse_gossip",
        "cs_sse_rpc",
        "cs_sse_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = || {
        assert!(Instant::now() < deadline, "timeout: block subscription");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    };
    let client = EventsSubscriber::new(addr, "block", 1, &mut crank);

    inj.produce(block_received(7, 0x07, BlockStage::AlreadyKnown));
    inj.produce(block_received(8, 0x08, BlockStage::AwaitParent));
    inj.produce(block_received(9, 0x09, BlockStage::AwaitData));
    inj.produce(block_received(10, 0xab, BlockStage::Applied));
    let event = client.next(&mut crank);
    event.assert_block("block", 10, 0xab);
    assert_eq!(event.data["execution_optimistic"], true);
    client.client.join().unwrap();
}

#[test]
fn subscriptions_select_their_topics_and_preserve_repeated_requests() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut tile, mut gossip, _rpc) =
        boundary_tile_with_objects(&Bind::parse("127.0.0.1:0"), no_el(), [
            "cs_subscriptions_gossip",
            "cs_subscriptions_rpc",
            "cs_subscriptions_resp",
        ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = || {
        assert!(Instant::now() < deadline, "timeout: subscription routing");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    };
    let block = EventsSubscriber::new(addr, "block", 2, &mut crank);
    let block_gossip = EventsSubscriber::new(addr, "block_gossip", 3, &mut crank);
    let column = EventsSubscriber::new(addr, "data_column_sidecar", 5, &mut crank);
    let mixed =
        EventsSubscriber::new(addr, "block,block_gossip,data_column_sidecar", 10, &mut crank);

    // Topic selection must exclude this request even though its bytes resemble a
    // block.
    let unrelated = write_object(&mut gossip, &block_bytes(9, 0xaf));
    inj.produce(send_gossip(GossipTopic::BeaconAttestation(0), 0xaf, unrelated));
    inj.produce(PeerEvent::EarliestSlot(99));

    let (relay, relayed) = gossip_column(10, 0xac, 3);
    let (published, publication) = rpc_column(11, 0xad, 5);
    let (block_relayed, relayed_block) = block_relay(&mut gossip, 12, 0xae);
    inj.produce(relay);
    inj.produce(relay);
    inj.produce(published);
    inj.produce(block_relayed);
    inj.produce(block_relayed);
    inj.produce(block_received(13, 0xab, BlockStage::Applied));

    // Observe every topic before sending sentinels, so leaks remain inside the
    // events read.
    mixed.assert_topic_sequences(
        &[
            SseEvent::block(13, 0xab),
            relayed_block.clone(),
            relayed_block.clone(),
            relayed.clone(),
            relayed.clone(),
            publication.clone(),
        ],
        &mut crank,
    );
    inj.produce(relay);
    let (sentinel, sentinel_publication) = rpc_column(14, 0xaf, 7);
    inj.produce(sentinel);
    let (last_block, last_relayed_block) = block_relay(&mut gossip, 15, 0xb0);
    inj.produce(last_block);
    inj.produce(block_received(16, 0xb1, BlockStage::Applied));

    block.assert_topic_sequences(
        &[SseEvent::block(13, 0xab), SseEvent::block(16, 0xb1)],
        &mut crank,
    );
    block_gossip.assert_topic_sequences(
        &[relayed_block.clone(), relayed_block.clone(), last_relayed_block.clone()],
        &mut crank,
    );
    column.assert_topic_sequences(
        &[
            relayed.clone(),
            relayed.clone(),
            publication.clone(),
            relayed.clone(),
            sentinel_publication.clone(),
        ],
        &mut crank,
    );
    mixed.assert_topic_sequences(
        &[SseEvent::block(16, 0xb1), last_relayed_block, relayed, sentinel_publication],
        &mut crank,
    );
    for subscriber in [block, block_gossip, column, mixed] {
        subscriber.client.join().unwrap();
    }
}

#[test]
fn a_late_subscriber_receives_only_relay_requests_published_after_it() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut tile, mut gossip, _rpc) =
        boundary_tile_with_objects(&Bind::parse("127.0.0.1:0"), no_el(), [
            "cs_late_gossip",
            "cs_late_rpc",
            "cs_late_resp",
        ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = || {
        assert!(Instant::now() < deadline, "timeout: late subscription");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    };
    let topics = "block_gossip,data_column_sidecar";
    let early = EventsSubscriber::new(addr, topics, 4, &mut crank);
    let (block, relayed_block) = block_relay(&mut gossip, 20, 0x11);
    let (relay, relayed) = gossip_column(20, 0x11, 3);
    let (dc_relay, dc_relayed) = gossip_column(20, 0x11, 4);
    let (published, publication) = rpc_column(21, 0x12, 5);
    inj.produce(block);
    inj.produce(relay);
    inj.produce(dc_relay);
    inj.produce(published);
    early.assert_topic_sequences(&[relayed_block, relayed, dc_relayed, publication], &mut crank);
    early.client.join().unwrap();

    let late = EventsSubscriber::new(addr, topics, 3, &mut crank);
    let (block, relayed_block) = block_relay(&mut gossip, 22, 0x22);
    let (relay, relayed) = gossip_column(22, 0x22, 7);
    let (published, publication) = rpc_column(23, 0x23, 9);
    inj.produce(block);
    inj.produce(relay);
    inj.produce(published);
    late.assert_topic_sequences(&[relayed_block, relayed, publication], &mut crank);
    late.client.join().unwrap();
}

#[test]
fn an_idle_boundary_lets_the_object_rings_evict_its_consumers() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut tile, mut gossip, mut rpc) =
        boundary_tile_with_objects(&Bind::parse("127.0.0.1:0"), no_el(), [
            "cs_idle_gossip",
            "cs_idle_rpc",
            "cs_idle_resp",
        ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    tile.loop_body(&mut adapter);

    let chunk = [0u8; 1 << 10];
    let fill = |producer: &mut TProducer| {
        let mut written = 0;
        while let Some(mut reservation) = producer.reserve(chunk.len(), false) {
            reservation.write_all(&chunk).unwrap();
            reservation.flush().unwrap();
            written += 1;
            assert!(written < 1_000, "the ring never filled");
        }
    };
    fill(&mut gossip);
    fill(&mut rpc);

    // Tail advancement requires inactivity beyond the cache's five-second idle
    // interval.
    std::thread::sleep(Duration::from_millis(5_100));
    tile.loop_body(&mut adapter);
    assert!(gossip.reserve(chunk.len(), false).is_some(), "the gossip ring is held by the tile");
    assert!(rpc.reserve(chunk.len(), false).is_some(), "the RPC ring is held by the tile");
}

#[test]
fn gossip_events_are_served_while_the_engine_pool_is_saturated() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut el, endpoint) = FakeEl::tcp();
    let jwt_path = write_jwt(base.path());
    let capacity = 8;
    let config = EngineConfig {
        execution_endpoint: endpoint,
        jwt_secret: jwt_path.to_str().unwrap().to_string(),
        max_connections: capacity,
        ..EngineConfig::default()
    };
    let (mut tile, mut gossip, _rpc) =
        boundary_tile_with_objects(&Bind::parse("127.0.0.1:0"), config, [
            "cs_gsat_gossip",
            "cs_gsat_rpc",
            "cs_gsat_resp",
        ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);
    for byte in 0..capacity {
        inj.produce(fcu_req(byte as u8));
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut handled = 0;
    let mut pending = 0;
    let mut crank = |tile: &mut ApplicationBoundaryTile, el: &mut FakeEl| {
        assert!(Instant::now() < deadline, "timeout: saturated engine pool");
        tile.loop_body(&mut adapter);
        el.pump();
        for i in handled..el.requests.len() {
            let method = el.requests[i].method.as_str();
            if method.starts_with("engine_forkchoiceUpdated") {
                pending += 1;
            } else {
                el.respond(i, if method == "eth_syncing" { "false" } else { "[]" });
            }
        }
        handled = el.requests.len();
        std::thread::sleep(Duration::from_millis(1));
        pending
    };
    while crank(&mut tile, &mut el) < capacity {}
    inj.produce(fcu_req(0xff));

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let mut pump = || {
        crank(&mut tile, &mut el);
    };
    let client = EventsSubscriber::new(addr, "block_gossip,data_column_sidecar", 3, &mut pump);
    let (block, relayed_block) = block_relay(&mut gossip, 30, 0x33);
    let (relay, relayed) = gossip_column(31, 0x34, 7);
    let (published, publication) = rpc_column(32, 0x35, 9);
    inj.produce(block);
    inj.produce(relay);
    inj.produce(published);
    client.assert_topic_sequences(&[relayed_block, relayed, publication], &mut pump);
    client.client.join().unwrap();
    assert_eq!(pending, capacity, "the additional FCU stays queued while SSE is served");
}

#[test]
fn head_subscribers_receive_changes_for_their_topics() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut spec = SpecConfig::mainnet();
    spec.gloas_fork_epoch = spec.fulu_fork_epoch + 2;
    let (mut tile, _gossip, _rpc) = boundary_tile_with_spec(
        &Bind::parse("127.0.0.1:0"),
        no_el(),
        ["cs_head_v2_gossip", "cs_head_v2_rpc", "cs_head_v2_resp"],
        &spec,
    );
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let gloas = spec.gloas_fork_epoch * SLOTS_PER_EPOCH;
    let slot = gloas + 8;
    let sentinel_slot = slot + 1;
    let (legacy, legacy_subscribed) = head_events_subscriber(addr, "head", sentinel_slot);
    let (v2, v2_subscribed) = head_events_subscriber(addr, "head_v2", sentinel_slot);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    };
    for subscribed in [legacy_subscribed, v2_subscribed] {
        while subscribed.try_recv().is_err() {
            crank(&mut tile, "both stream heads reach their subscribers");
        }
    }
    inj.produce(SyncUpdate::Following);
    crank(&mut tile, "the node is following");

    for status in [
        head_status(slot, 0xab, true, PayloadResolution::Empty, HeadChange::Head),
        head_status(slot, 0xab, true, PayloadResolution::Empty, HeadChange::None),
        head_status(slot, 0xab, true, PayloadResolution::Full, HeadChange::Payload),
        head_status(slot, 0xab, false, PayloadResolution::Full, HeadChange::Head),
    ] {
        inj.produce(status);
    }
    crank(&mut tile, "head observations update node status");
    assert_eq!(tile.beacon.node_status().head, HeadStatus { slot, optimistic: false });

    // A later head delimits all preceding frames, including unwanted repeats.
    inj.produce(head_status(sentinel_slot, 0xcd, false, PayloadResolution::Full, HeadChange::Head));
    while !legacy.is_finished() || !v2.is_finished() {
        crank(&mut tile, "every frame reaches its subscriber");
    }
    let legacy = legacy.join().unwrap();
    let v2 = v2.join().unwrap();
    assert_eq!(legacy.len(), 1);
    assert_eq!(v2.len(), 3);
    let roots = head_roots();
    for (events, is_v2) in [(&legacy, false), (&v2, true)] {
        for (index, body) in events.iter().enumerate() {
            let data = if is_v2 {
                assert_eq!(body["version"], "gloas");
                assert_eq!(
                    body["data"]["payload_status"],
                    if index == 0 { "empty" } else { "full" }
                );
                &body["data"]
            } else {
                body
            };
            assert_eq!(data["slot"], slot.to_string());
            assert_eq!(data["block"], format!("0x{}", hex::encode([0xab; 32])));
            assert_eq!(data["state"], format!("0x{}", hex::encode(roots.state_root)));
            assert_eq!(data["epoch_transition"], false);
            assert_eq!(data["execution_optimistic"], index + 1 < events.len());
            let (previous, current) = if is_v2 {
                ("current_epoch_dependent_root", "next_epoch_dependent_root")
            } else {
                ("previous_duty_dependent_root", "current_duty_dependent_root")
            };
            assert_eq!(
                data[previous],
                format!("0x{}", hex::encode(roots.previous_duty_dependent_root))
            );
            assert_eq!(
                data[current],
                format!("0x{}", hex::encode(roots.current_duty_dependent_root))
            );
        }
    }
}

/// Head events describe changes observed while following. Observations in
/// any other mode update node status silently.
#[test]
fn head_events_describe_changes_observed_while_following() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let mut tile = boundary_tile(&Bind::parse("127.0.0.1:0"), no_el(), [
        "cs_follow_gossip",
        "cs_follow_rpc",
        "cs_follow_resp",
    ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let sentinel_slot = 40;
    let (client, on_subscribed) = head_events_subscriber(addr, "head_v2", sentinel_slot);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut crank = |tile: &mut ApplicationBoundaryTile, msg: &str| {
        assert!(Instant::now() < deadline, "timeout: {msg}");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    };
    while on_subscribed.try_recv().is_err() {
        crank(&mut tile, "stream head reaches the subscriber");
    }

    // Restoration and catch-up: Control has not concluded, so heads move silently.
    inj.produce(head_status(33, 0xaa, true, PayloadResolution::Full, HeadChange::Head));
    inj.produce(head_status(34, 0xab, true, PayloadResolution::Full, HeadChange::Head));
    crank(&mut tile, "observations outside following update node status");
    assert_eq!(tile.beacon.node_status().head, HeadStatus { slot: 34, optimistic: true });

    // Following: the latest observation is already the baseline, so the next
    // change is reported at once.
    inj.produce(SyncUpdate::Following);
    crank(&mut tile, "the mode change is consumed");
    inj.produce(head_status(35, 0xac, true, PayloadResolution::Full, HeadChange::Head));
    inj.produce(head_status(35, 0xac, false, PayloadResolution::Full, HeadChange::Head));
    crank(&mut tile, "changes while following are reported");

    // Falling behind silences the stream while the head keeps moving.
    inj.produce(SyncUpdate::SyncingHead { head_root: [0xff; 32], head_slot: 100 });
    crank(&mut tile, "the mode change is consumed");
    inj.produce(head_status(36, 0xad, true, PayloadResolution::Full, HeadChange::Head));
    crank(&mut tile, "changes while syncing are silent");

    // Following again: a repeat of the head reached while syncing is no change.
    inj.produce(SyncUpdate::Following);
    crank(&mut tile, "the mode change is consumed");
    inj.produce(head_status(36, 0xad, true, PayloadResolution::Full, HeadChange::None));
    inj.produce(head_status(37, 0xae, true, PayloadResolution::Full, HeadChange::Head));
    inj.produce(head_status(sentinel_slot, 0xcd, true, PayloadResolution::Full, HeadChange::Head));
    while !client.is_finished() {
        crank(&mut tile, "every frame reaches the subscriber");
    }

    let events = client.join().unwrap();
    assert_eq!(events.len(), 3);
    for (event, (slot, optimistic)) in events.iter().zip([(35, true), (35, false), (37, true)]) {
        assert_eq!(event["data"]["slot"], slot.to_string());
        assert_eq!(event["data"]["execution_optimistic"], optimistic);
    }
}

/// The request leaves on `beacon_api_requests` in the pass that parks the
/// connection, and the answer on `beacon_api_responses` frees it.
#[test]
fn block_by_root_round_trips_over_the_storage_queues() {
    let base = ShmemDir::new().unwrap();
    let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
    let (mut tile, _gossip, mut served) =
        boundary_tile_with_objects(&Bind::parse("127.0.0.1:0"), no_el(), [
            "cs_block_gossip",
            "cs_block_rpc",
            "cs_block_resp",
        ]);
    let mut adapter = SpineAdapter::connect_tile(&tile, &mut *spine);
    let mut inj = SpineAdapter::connect_tile(&Injector, &mut *spine);
    tile.loop_body(&mut adapter);
    inj.consume(|_: BeaconApiRequest, _| {});

    let [Bind::Tcp(addr)] = tile.beacon.local_addrs()[..] else { panic!("expected one tcp bind") };
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            stream,
            "GET /eth/v2/beacon/blocks/0x{} HTTP/1.1\r\nHost: localhost\r\n\
             Accept: application/octet-stream\r\nConnection: close\r\n\r\n",
            "ab".repeat(32)
        )
        .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut request = None;
    while request.is_none() {
        assert!(Instant::now() < deadline, "timeout: block request on the spine");
        tile.loop_body(&mut adapter);
        inj.consume(|r: BeaconApiRequest, _| request = Some(r));
        std::thread::sleep(Duration::from_millis(1));
    }
    let Some(BeaconApiRequest::Block { request_id, lookup, with_bytes: true }) = request else {
        panic!("expected a block request, got {request:?}");
    };
    assert_eq!(lookup, BlockLookup::Root([0xab; 32]));
    assert!(!client.is_finished(), "the connection waits on storage");

    let block = block_bytes(10, 0xab);
    let ssz = write_object(&mut served, &block);
    inj.produce(BeaconApiResponse::Block {
        request_id,
        block: Some(ServedBlock {
            slot: 10,
            root: [0xab; 32],
            finalized: true,
            canonical: true,
            ssz: Some(ssz),
        }),
    });
    while !client.is_finished() {
        assert!(Instant::now() < deadline, "timeout: block response");
        tile.loop_body(&mut adapter);
        std::thread::sleep(Duration::from_millis(1));
    }
    let response = client.join().unwrap();
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Eth-Consensus-Version: phase0\r\n";
    assert!(response.starts_with(head), "{}", String::from_utf8_lossy(&response));
    assert!(response.ends_with(&block), "the body is the served bytes verbatim");
}
