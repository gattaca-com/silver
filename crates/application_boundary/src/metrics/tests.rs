use std::{
    fs,
    io::Read,
    net::TcpStream as ClientSocket,
    os::unix::fs::FileExt,
    process::{Command, Stdio},
    thread,
};

use flux::{
    Timer,
    communication::queue::{Producer, Queue, QueueType},
    tile::metrics::TileSample,
    timing::Nanos,
    utils::directories::shmem_dir_queues_with_base,
};
use silver_common::{SLOTS_PER_EPOCH, test_util::ShmemDir};
use silver_observe::{consume_elapsed, names_for, sample_reader};

use super::*;

fn scrape(addr: SocketAddr) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut stream = ClientSocket::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        assert!(head.contains("text/plain; version=0.0.4"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        body.to_owned()
    })
}

#[test]
fn independent_readers_and_simultaneous_scrapes() {
    let base = ShmemDir::new().unwrap();
    let timer = Timer::new_with_base_dir(base.path(), "node", "roundtrip");
    let dir = shmem_dir_queues_with_base(base.path(), "node");
    let tiles: Producer<TileSample> =
        Queue::create_or_open_shared(dir.join("tilemetrics-test"), 64, QueueType::SPMC).into();
    fs::write(dir.join("build-info"), "test · v1 · now").unwrap();
    fs::write(dir.join("counters-tcache-test"), [1024u64, 64, 32].map(u64::to_ne_bytes).concat())
        .unwrap();
    let mut names = [0; 32];
    names[..4].copy_from_slice(b"peer");
    fs::write(dir.join("tcache-names-test"), names).unwrap();
    fs::write(dir.join("counters-untyped"), 77u64.to_ne_bytes()).unwrap();
    let peer = dir.join("counters-peer");
    let mut counts = vec![0u64; names_for("peer", 0).0.len()];
    let index =
        names_for("peer", counts.len()).0.iter().position(|n| n == "PeersConnected").unwrap();
    counts[index] = 12;
    fs::write(&peer, counts.iter().flat_map(|v| v.to_ne_bytes()).collect::<Vec<_>>()).unwrap();
    let mut other = sample_reader(&dir.join("latency-roundtrip"), "dashboard-test").unwrap();
    consume_elapsed(&mut other, |_| {});

    let mut sources = Collector::new(dir.clone());
    let now = Instant::now();
    let pump = |sources: &mut Collector, secs| {
        sources.pump(now + Duration::from_secs(secs), Instant::now() + Duration::from_secs(1));
    };
    pump(&mut sources, 0);
    let undiscovered = sources.snapshot.clone().unwrap();
    assert_eq!(undiscovered.len, 0, "nothing is collected before discovery");
    let first_buffer = Arc::as_ptr(&undiscovered);
    drop(undiscovered);
    let mut status = [0; STATUS_V2_SIZE];
    status[76..84].copy_from_slice(&4u64.to_le_bytes());
    sources.on_status(&status, 6);
    pump(&mut sources, 1);

    timer.emit_latency_from_nanos_without_first(Nanos(100), Nanos(5100));
    timer.emit_processing_from_nanos_without_first(Nanos(100), Nanos(2100));
    assert!(consume_elapsed(&mut other, |_| {}));
    let mut tile = TileSample::default();
    tile.window_end = Nanos(100);
    tile.busy_ticks = 50;
    tile.busy_count = 2;
    tile.busy_max = 35;
    tiles.produce_without_first(&tile);
    pump(&mut sources, 2);
    let previous = sources.snapshot.as_ref().unwrap().parts.concat();
    assert!(previous.lines().any(|line| line == "beacon_head_slot 4"));
    assert!(previous.contains(&format!(
        "silver_current_value{{source=\"peer\",slot=\"{index}\",name=\"PeersConnected\"}} 12"
    )));
    fs::OpenOptions::new()
        .write(true)
        .open(&peer)
        .unwrap()
        .write_at(&5u64.to_ne_bytes(), (index * 8) as u64)
        .unwrap();
    pump(&mut sources, 3);
    assert_eq!(
        Arc::as_ptr(sources.snapshot.as_ref().unwrap()),
        first_buffer,
        "an unshared snapshot is rendered into again"
    );

    fs::write(dir.join("counters-late"), 9u64.to_ne_bytes()).unwrap();
    let late = "silver_slot{source=\"late\",slot=\"0\",name=\"slot_0\"} 9";
    status[76..84].copy_from_slice(&3u64.to_le_bytes());
    sources.on_status(&status, 7);
    pump(&mut sources, 4);
    pump(&mut sources, 5);
    let same_epoch = sources.snapshot.as_ref().unwrap().parts.concat();
    assert!(same_epoch.lines().any(|line| line == "beacon_head_slot 3"));
    assert!(!same_epoch.contains(late), "one pass per epoch");
    sources.on_status(&status, SLOTS_PER_EPOCH);
    pump(&mut sources, 6);
    pump(&mut sources, 7);
    let rescanned = sources.snapshot.as_ref().unwrap().parts.concat();
    assert!(rescanned.contains(late), "the next epoch's pass opens the new source");
    assert_eq!(
        rescanned.matches("silver_build_info{").count(),
        1,
        "known sources stay opened once"
    );

    let mut readiness = Readiness::new(SOCKETS);
    let mut endpoint =
        MetricsEndpoint::bind(([127, 0, 0, 1], 0).into(), dir, readiness.registry()).unwrap();
    endpoint.sources = sources;
    let addr = endpoint.listener.local_addr().unwrap();
    let clients = [scrape(addr), scrape(addr)];
    while clients.iter().any(|c| !c.is_finished()) {
        readiness.wait(Duration::from_millis(1));
        endpoint.pump(&readiness);
    }
    let [a, b] = clients.map(|c| c.join().unwrap());
    assert_eq!(a, b);
    assert!(a.lines().any(|line| line == "# TYPE beacon_head_slot gauge"));
    assert_eq!(
        a.lines().filter(|line| line.starts_with("beacon_head_slot")).collect::<Vec<_>>(),
        ["beacon_head_slot 3"]
    );
    for sample in [
        "silver_timer_duration_seconds_count{source=\"roundtrip\",channel=\"latency\"} 1",
        "silver_timer_duration_seconds_count{source=\"roundtrip\",channel=\"processing\"} 1",
        "silver_tile_busy_iterations_total{tile=\"test\"} 2",
        "silver_tcache_tail_sequence{cache=\"test\",slot=\"0\",consumer=\"peer\"} 32",
        "silver_slot{source=\"untyped\",slot=\"0\",name=\"slot_0\"} 77",
        &format!(
            "silver_current_value{{source=\"peer\",slot=\"{index}\",name=\"PeersConnected\"}} 5"
        ),
    ] {
        assert!(a.contains(sample), "{sample} missing");
    }
    if let Some(tool) = std::env::var_os("PROMTOOL") {
        let mut child =
            Command::new(tool).args(["check", "metrics"]).stdin(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(a.as_bytes()).unwrap();
        assert!(child.wait().unwrap().success());
    }
}

#[test]
fn histogram_includes_boundaries_and_overflow() {
    let mut h = exposition::Histogram::default();
    for ns in [0, 1_000, 1_001, 60_000_000_001] {
        h.record(ns);
    }
    let mut t = Snapshot::default();
    h.encode(&mut t, "source=\"q\"");
    let body = t.parts.concat();
    for line in
        ["le=\"0.000001\"} 2", "le=\"0.00001\"} 3", "le=\"+Inf\"} 4", "_count{source=\"q\"} 4"]
    {
        assert!(body.contains(line));
    }
}

#[test]
fn an_undiscovered_endpoint_serves_an_empty_body() {
    let base = ShmemDir::new().unwrap();
    let mut readiness = Readiness::new(SOCKETS);
    let mut endpoint = MetricsEndpoint::bind(
        ([127, 0, 0, 1], 0).into(),
        base.path().to_owned(),
        readiness.registry(),
    )
    .unwrap();
    endpoint.pump(&readiness);
    let client = scrape(endpoint.local_addr().unwrap());
    while !client.is_finished() {
        readiness.wait(Duration::from_millis(1));
        endpoint.pump(&readiness);
    }
    assert_eq!(client.join().unwrap(), "");
}

#[test]
fn stalled_client_is_removed_at_deadline() {
    let base = ShmemDir::new().unwrap();
    let mut readiness = Readiness::new(SOCKETS);
    let mut endpoint = MetricsEndpoint::bind(
        ([127, 0, 0, 1], 0).into(),
        base.path().to_owned(),
        readiness.registry(),
    )
    .unwrap();
    let _stalled = ClientSocket::connect(endpoint.local_addr().unwrap()).unwrap();
    readiness.wait(Duration::from_secs(1));
    endpoint.pump(&readiness);
    let client = endpoint.clients.iter_mut().flatten().next().unwrap();
    client.expires = Instant::now();
    endpoint.pump(&readiness);
    assert!(endpoint.clients.iter().all(Option::is_none));
}
