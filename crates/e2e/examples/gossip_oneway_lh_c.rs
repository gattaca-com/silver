//! One-way gossip latency: libp2p publisher → libp2p receiver. Variant C
//! of the lh_gossip family — pure libp2p baseline, no silver in the timer.
//!
//! Each `LhGossipClient` runs on its own thread with its own tokio
//! `current_thread` runtime: subscriber on a spawned thread driving its
//! swarm continuously, publisher on the main thread ticking between
//! publishes. The threads share nothing beyond the subscriber's
//! `listen_addr` (sent over an mpsc once at startup), a `publisher_done`
//! atomic flag (so the subscriber knows when to start its drain
//! timeout), and the final `Stats` (sent back over an mpsc when the
//! subscriber thread shuts down).
//!
//! Useful as the reference floor when reading variants A/B —
//! `B - C` ≈ silver-receive overhead vs libp2p,
//! `A - C` ≈ silver-publish overhead vs libp2p.
//!
//! Caveat: wire path is libp2p-quic ↔ libp2p-quic, whereas A/B use
//! silver-quic ↔ libp2p-quic. QUIC stack overhead is not strictly
//! shared across variants.
//!
//! Usage:
//!   cargo run -p silver_e2e --features lh-client --example \
//!     gossip_oneway_lh_c -- --duration 5 --rate 500 --payload-size 1024

use std::{
    env,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use flux::timing::Nanos;
use rand::RngCore;
use silver_common::GossipTopic;
use silver_e2e::{LhGossipClient, Stats};

const DEFAULT_DURATION_S: u64 = 3;
const DEFAULT_RATE_HZ: u64 = 500;
const DEFAULT_PAYLOAD_SIZE: usize = 1024;
const FORK_DIGEST_HEX: &str = "abcd1234";
const TOPIC: GossipTopic = GossipTopic::BeaconBlock;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();
    let args = parse_args();

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let (stats_tx, stats_rx) = mpsc::channel::<Stats>();
    let publisher_done = Arc::new(AtomicBool::new(false));

    let pub_done_sub = publisher_done.clone();
    let expected = args.duration_s * args.rate_hz;
    let sub_handle =
        thread::spawn(move || subscriber_thread(addr_tx, stats_tx, pub_done_sub, expected));

    let sub_addr = addr_rx.recv().expect("subscriber listen_addr");

    let mut p = LhGossipClient::new();
    p.subscribe(TOPIC, FORK_DIGEST_HEX).expect("pub subscribe");
    p.dial(sub_addr).expect("pub dial sub");

    // `flood_publish(true)` (set in `LhGossipClient::new`) bypasses
    // mesh-formation; we only need to wait for the SUBSCRIBE exchange to
    // populate the publisher's view of the subscriber's topics.
    let connect_deadline = Instant::now() + Duration::from_secs(10);
    while p.subscribed_peer_count(TOPIC, FORK_DIGEST_HEX) == 0 && Instant::now() < connect_deadline
    {
        p.tick(Duration::from_millis(1));
    }
    if p.subscribed_peer_count(TOPIC, FORK_DIGEST_HEX) == 0 {
        eprintln!("publisher never observed subscriber as topic peer");
        std::process::exit(1);
    }

    println!("connected; publishing for {}s at {} Hz", args.duration_s, args.rate_hz);

    let total_msgs = args.duration_s * args.rate_hz;
    let tick_interval = Duration::from_nanos(1_000_000_000 / args.rate_hz.max(1));
    let start = Instant::now();
    let mut sent = 0u64;
    let mut rng = rand::thread_rng();
    let mut payload = vec![0u8; args.payload_size];
    assert!(args.payload_size >= 8, "payload-size must be >= 8 for the timestamp prefix");

    while sent < total_msgs {
        rng.fill_bytes(&mut payload);
        payload[..8].copy_from_slice(&Nanos::now().0.to_le_bytes());
        match p.publish(TOPIC, FORK_DIGEST_HEX, payload.clone()) {
            Ok(_) => sent += 1,
            Err(libp2p::gossipsub::PublishError::Duplicate) => sent += 1,
            Err(e) => {
                eprintln!("publish failed at {sent}: {e:?}");
                break;
            }
        }

        // Single-threaded executor on this side — between publishes, give
        // tokio whatever wall-clock remains until the next publish to
        // drive QUIC writes. `tick` returns early on a ready event, so
        // the long budget doesn't add latency under load.
        let next = start + tick_interval * sent as u32;
        while Instant::now() < next {
            let remaining = next.saturating_duration_since(Instant::now());
            p.tick(remaining.min(Duration::from_millis(1)));
        }
    }

    println!("sent {sent} msgs; draining for up to {:?}", DRAIN_TIMEOUT);
    publisher_done.store(true, Ordering::Release);

    sub_handle.join().expect("subscriber thread panicked");
    let stats = stats_rx.recv().expect("subscriber stats");

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

/// Subscriber thread: build an `LhGossipClient`, send its bound
/// `listen_addr` back to the main thread, then tick continuously until
/// the publisher signals done + a drain window has elapsed. Final stats
/// flow back over `stats_tx`.
fn subscriber_thread(
    addr_tx: mpsc::Sender<SocketAddr>,
    stats_tx: mpsc::Sender<Stats>,
    publisher_done: Arc<AtomicBool>,
    expected: u64,
) {
    let mut sub = LhGossipClient::new();
    sub.subscribe(TOPIC, FORK_DIGEST_HEX).expect("sub subscribe");
    addr_tx.send(sub.listen_addr().expect("sub listener bound")).expect("send addr");

    let mut drain_deadline: Option<Instant> = None;
    loop {
        // 10 ms is large enough that an idle subscriber doesn't busy-spin
        // and small enough that the `publisher_done` poll stays
        // responsive. `tick` returns early on a ready event, so the
        // active path isn't slowed.
        sub.tick(Duration::from_millis(10));
        if publisher_done.load(Ordering::Acquire) {
            if sub.stats.gossip_received >= expected {
                break;
            }
            let dd = *drain_deadline.get_or_insert_with(|| Instant::now() + DRAIN_TIMEOUT);
            if Instant::now() >= dd {
                break;
            }
        }
    }
    stats_tx.send(sub.stats).expect("send stats");
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
