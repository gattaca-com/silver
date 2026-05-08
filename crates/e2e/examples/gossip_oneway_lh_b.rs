//! One-way gossip latency: libp2p (rust-libp2p gossipsub) publisher →
//! silver receiver. Variant B of the lh_gossip family.
//!
//! Threaded layout (matches the original / A / C examples):
//!   - silver echo on a spawned thread (`echo_thread`) running its tile
//!     `loop_body`s continuously. The echo thread also injects
//!     `PeerControl::P2pGossipSubscribe` on the first observed
//!     `P2pNewConnection` event so libp2p sees silver as a topic peer (libp2p's
//!     `publish` only forwards to peers whose `peer.topics` contains the topic,
//!     even with `flood_publish` enabled).
//!   - libp2p publisher on the main thread.
//!   - mpsc for the echo's `addr` handshake and final `Stats`; `publisher_done:
//!     AtomicBool` plus `expected_count: AtomicU64` for early-exit on drain.
//!
//! Usage:
//!   cargo run -p silver_e2e --features lh-client --example \
//!     gossip_oneway_lh_b -- --duration 5 --rate 500 --payload-size 1024

use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use flux::{tile::Tile, timing::Nanos};
use rand::RngCore;
use silver_common::{
    GossipTopic, Keypair, NewGossipMsg, PeerControl, PeerEvent, PeerId, TRandomAccess,
};
use silver_e2e::{EchoStack, LhGossipClient, Stats, keypair_from_seed};
use tempfile::TempDir;

const DEFAULT_DURATION_S: u64 = 3;
const DEFAULT_RATE_HZ: u64 = 500;
const DEFAULT_PAYLOAD_SIZE: usize = 1024;
const FORK_DIGEST_HEX: &str = "abcd1234";
const TOPIC: GossipTopic = GossipTopic::BeaconBlock;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();
    let args = parse_args();
    assert!(args.payload_size >= 8, "payload-size must be >= 8 for the timestamp prefix");

    let tempdir = TempDir::new().expect("tempdir");
    let echo_addr = loopback_ephemeral().expect("port");
    let echo_disc_addr = loopback_ephemeral().expect("port");
    let echo_kp = keypair_from_seed(12);

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (stats_tx, stats_rx) = mpsc::channel::<Stats>();
    let publisher_done = Arc::new(AtomicBool::new(false));
    let expected_count = Arc::new(AtomicU64::new(0));

    let pd = publisher_done.clone();
    let ec = expected_count.clone();
    let path = tempdir.path().to_path_buf();
    let echo_handle = thread::spawn(move || {
        echo_thread(path, echo_addr, echo_disc_addr, echo_kp, ready_tx, stats_tx, pd, ec);
    });
    ready_rx.recv().expect("echo ready");

    let mut lh = LhGossipClient::new();
    lh.subscribe(TOPIC, FORK_DIGEST_HEX).expect("pub subscribe");
    lh.dial(echo_addr).expect("libp2p dial silver");

    // Wait for libp2p to record silver as topic-subscribed. The echo
    // thread auto-injects `PeerControl::P2pGossipSubscribe` on first
    // `P2pNewConnection`, so this just blocks until silver's SUBSCRIBE
    // RPC has been processed by libp2p.
    let sub_deadline = Instant::now() + Duration::from_secs(10);
    while lh.subscribed_peer_count(TOPIC, FORK_DIGEST_HEX) == 0 && Instant::now() < sub_deadline {
        lh.tick(Duration::from_millis(1));
    }
    if lh.subscribed_peer_count(TOPIC, FORK_DIGEST_HEX) == 0 {
        eprintln!("libp2p never observed silver as topic-subscribed");
        std::process::exit(1);
    }

    println!("connected; publishing for {}s at {} Hz", args.duration_s, args.rate_hz);

    let total_msgs = args.duration_s * args.rate_hz;
    let tick_interval = Duration::from_nanos(1_000_000_000 / args.rate_hz.max(1));
    let start = Instant::now();
    let mut sent = 0u64;
    let mut rng = rand::thread_rng();
    let mut payload = vec![0u8; args.payload_size];

    while sent < total_msgs {
        rng.fill_bytes(&mut payload);
        payload[..8].copy_from_slice(&Nanos::now().0.to_le_bytes());
        match lh.publish(TOPIC, FORK_DIGEST_HEX, payload.clone()) {
            Ok(_) => sent += 1,
            Err(libp2p::gossipsub::PublishError::Duplicate) => sent += 1,
            Err(e) => {
                eprintln!("publish failed at {sent}: {e:?}");
                break;
            }
        }

        // Single-threaded executor on this side — between publishes,
        // give tokio whatever wall-clock remains until the next publish
        // to drive QUIC writes. `tick` returns early on a ready event.
        let next = start + tick_interval * sent as u32;
        while Instant::now() < next {
            let remaining = next.saturating_duration_since(Instant::now());
            lh.tick(remaining.min(Duration::from_millis(1)));
        }
    }

    println!("sent {sent} msgs; draining for up to {:?}", DRAIN_TIMEOUT);

    expected_count.store(sent, Ordering::Release);
    publisher_done.store(true, Ordering::Release);
    echo_handle.join().expect("echo thread panicked");
    let stats = stats_rx.recv().expect("echo stats");

    let elapsed = start.elapsed();
    let publish_window = args.duration_s as f64;
    println!("---");
    println!("elapsed:       {:.3}s (incl. drain)", elapsed.as_secs_f64());
    println!("sent:          {sent}");
    println!("received:      {}", stats.gossip_received);
    println!("invalid:       {}", stats.invalid_msgs);
    println!("throughput:    {:.1} msg/s received", stats.gossip_received as f64 / publish_window);
    let h = &stats.latency_ns;
    if h.len() > 0 {
        let us = |ns: u64| ns as f64 / 1000.0;
        println!("latency (μs):  samples={}", h.len());
        println!("  p10:         {:.1}", us(h.value_at_quantile(0.10)));
        println!("  p50:         {:.1}", us(h.value_at_quantile(0.50)));
        println!("  p90:         {:.1}", us(h.value_at_quantile(0.90)));
        println!("  p99:         {:.1}", us(h.value_at_quantile(0.99)));
    }
}

fn echo_thread(
    path: PathBuf,
    addr: SocketAddr,
    disc_addr: SocketAddr,
    kp: Keypair,
    ready_tx: mpsc::Sender<()>,
    stats_tx: mpsc::Sender<Stats>,
    publisher_done: Arc<AtomicBool>,
    expected_count: Arc<AtomicU64>,
) {
    let mut echo =
        EchoStack::new(&path, "_lh_gossip_b", addr, disc_addr, kp, FORK_DIGEST_HEX.into())
            .expect("echo stack");
    echo.controller.set_auto_ping(false);
    ready_tx.send(()).expect("ready");

    let mut subscribed = false;
    let mut drain_deadline: Option<Instant> = None;
    loop {
        spin_echo(&mut echo);
        drain_echo_stats(&mut echo);

        if !subscribed {
            let mut new_handle: Option<(PeerId, usize)> = None;
            let nh = &mut new_handle;
            echo.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
                if let PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. } = event {
                    *nh = Some((peer_id_full, p2p_peer_id));
                }
            });
            if let Some((p2p, p2p_connection)) = new_handle {
                echo.injector_adapter.produce(PeerControl::P2pGossipSubscribe {
                    p2p,
                    p2p_connection,
                    topic: TOPIC,
                });
                subscribed = true;
            }
        }

        if publisher_done.load(Ordering::Acquire) {
            let expected = expected_count.load(Ordering::Acquire);
            if expected != 0 && echo.stats.gossip_received >= expected {
                break;
            }
            let dd = *drain_deadline.get_or_insert_with(|| Instant::now() + DRAIN_TIMEOUT);
            if Instant::now() >= dd {
                break;
            }
        }
    }
    stats_tx.send(echo.stats).expect("send stats");
}

fn spin_echo(e: &mut EchoStack) {
    e.network.loop_body(&mut e.network_adapter);
    e.compression.loop_body(&mut e.compression_adapter);
    e.controller.loop_body(&mut e.controller_adapter);
}

fn drain_echo_stats(e: &mut EchoStack) {
    let stats = &mut e.stats;
    let consumer = &mut e.ssz_consumer;
    e.stats_adapter.consume::<NewGossipMsg, _>(|new_msg, _p| {
        let _ = stats.receive_ns.record(new_msg.recv_ts.elapsed_saturating().0);
        let now_wall = Instant::now();
        stats.gossip_received += 1;
        stats.first_seen_at.get_or_insert(now_wall);
        stats.last_seen_at = Some(now_wall);
        record_latency(consumer, &new_msg, stats);
    });
    e.stats_adapter.consume::<PeerEvent, _>(|event, _p| {
        if let PeerEvent::P2pGossipInvalidMsg { .. } = event {
            stats.invalid_msgs += 1;
        }
    });
}

fn record_latency(consumer: &mut TRandomAccess, msg: &NewGossipMsg, stats: &mut Stats) {
    if let Ok((bytes, _)) = consumer.read_at(msg.ssz.seq()) {
        stats.gossip_decompressed_bytes += bytes.len() as u64;
        if bytes.len() >= 8 {
            let sent_ns = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
            let _ = stats.latency_ns.record(Nanos(sent_ns).elapsed_saturating().0);
        }
    }
}

fn loopback_ephemeral() -> io::Result<SocketAddr> {
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?))
}

fn pick_free_port() -> io::Result<u16> {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    s.local_addr().map(|a| a.port())
}

struct Args {
    duration_s: u64,
    rate_hz: u64,
    payload_size: usize,
}

fn parse_args() -> Args {
    let mut duration_s = DEFAULT_DURATION_S;
    let mut rate_hz = DEFAULT_RATE_HZ;
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;

    let argv: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--duration" => {
                duration_s = argv[i + 1].parse().expect("--duration: u64 seconds");
                i += 2;
            }
            "--rate" => {
                rate_hz = argv[i + 1].parse().expect("--rate: u64 Hz");
                i += 2;
            }
            "--payload-size" => {
                payload_size = argv[i + 1].parse().expect("--payload-size: bytes");
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    Args { duration_s, rate_hz, payload_size }
}
