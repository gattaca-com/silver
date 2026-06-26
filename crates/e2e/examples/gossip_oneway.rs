//! One-way gossip latency: silver publisher → silver echo. The echo
//! side runs its network tile and its gossip handler on **separate
//! threads** — the spine's lock-free MPMC queues and the shmem-backed
//! TCaches make this safe. Publisher runs on the main thread.
//!
//! Threading layout:
//!   - main thread: silver publisher.
//!   - echo "network" thread: `NetworkTile::loop_body` +
//!     `Controller::loop_body`. Reads inbound QUIC, writes raw gossip bytes
//!     into the gossip-in TCache.
//!   - echo "compression" thread: `GossipHandler::loop_body`. Reads gossip-in,
//!     decompresses, computes msg-id, dedupes, emits `NewGossipMsg`. Drains
//!     stats locally on this thread.
//!
//! mpsc + atomics:
//!   - `stats_tx`: compression thread sends final `Stats` back to main.
//!   - `publisher_done: AtomicBool`: set by main when publish loop done.
//!   - `expected_count: AtomicU64`: set by main to the unique sent count so the
//!     compression thread can early-exit after draining.
//!   - `compression_done: AtomicBool`: set by compression thread when it's
//!     about to exit; the network thread spins until this so QUIC stays alive
//!     long enough to deliver the last bytes.
//!
//! Usage:
//!   cargo run -p silver_e2e --example gossip_oneway -- \
//!     --duration 5 --rate 500 --payload-size 1024 --dup-pct 10

use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use flux::{tile::Tile, timing::Nanos};
use rand::{Rng, RngCore};
use silver_common::{GossipMsgOut, GossipTopic, NewGossipMsg, P2pSend, PeerEvent, TRandomAccess};
use silver_e2e::{
    EchoCompressionHalf, EchoNetworkHalf, EchoStack, PublisherStack, Stats,
    inject::{build_publish_frame, snappy_compress},
    keypair_from_seed,
};
use tempfile::TempDir;

const DEFAULT_DURATION_S: u64 = 3;
const DEFAULT_RATE_HZ: u64 = 500;
const DEFAULT_PAYLOAD_SIZE: usize = 1024;
const DEFAULT_DUP_PCT: u8 = 0;
const FORK_DIGEST_HEX: &str = "abcd1234";
const TOPIC: GossipTopic = GossipTopic::BeaconBlock;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

// #[cfg(not(feature = "alloc-profile"))]
// #[global_allocator]
// static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    #[cfg(feature = "alloc-profile")]
    let _alloc_profile_guard = silver_common::allocator::init_allocator_trace();

    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();
    let args = parse_args();
    assert!(args.payload_size >= 8, "payload-size must be >= 8 for the timestamp prefix");

    let tempdir = TempDir::new().expect("tempdir");
    let echo_addr = loopback_ephemeral();
    let echo_disc_addr = loopback_ephemeral();
    let pub_addr = loopback_ephemeral();
    let pub_disc_addr = loopback_ephemeral();
    let echo_kp = keypair_from_seed(2);
    let pub_kp = keypair_from_seed(1);
    let echo_peer_id = echo_kp.peer_id();

    // Build EchoStack on main so the QUIC socket is bound before we
    // spawn anything; then split into network + compression halves and
    // move each onto its own thread.
    let mut echo = EchoStack::new(
        tempdir.path(),
        "_echo",
        echo_addr,
        echo_disc_addr,
        echo_kp,
        FORK_DIGEST_HEX.into(),
    )
    .expect("echo stack");
    echo.controller.set_auto_ping(false);
    let (net_half, comp_half) = echo.split();

    let (stats_tx, stats_rx) = mpsc::channel::<Stats>();
    let publisher_done = Arc::new(AtomicBool::new(false));
    let expected_count = Arc::new(AtomicU64::new(0));
    let compression_done = Arc::new(AtomicBool::new(false));

    let cd_net = compression_done.clone();
    let net_handle = thread::spawn(move || network_thread(net_half, cd_net));

    let pd_comp = publisher_done.clone();
    let ec_comp = expected_count.clone();
    let cd_comp = compression_done.clone();
    let comp_handle =
        thread::spawn(move || compression_thread(comp_half, pd_comp, ec_comp, cd_comp, stats_tx));

    let mut publisher =
        PublisherStack::new(tempdir.path(), "_pub", pub_addr, pub_disc_addr, pub_kp)
            .expect("publisher stack");
    publisher.controller.set_auto_ping(false);
    publisher.network.p2p_mut().connect(echo_peer_id, echo_addr, Instant::now()).expect("connect");

    let mut handle: Option<usize> = None;
    let connect_deadline = Instant::now() + Duration::from_secs(10);
    while handle.is_none() && Instant::now() < connect_deadline {
        spin_publisher(&mut publisher);
        let h = &mut handle;
        publisher.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
            if let PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. } = event &&
                peer_id_full == echo_peer_id
            {
                *h = Some(p2p_peer_id);
            }
        });
    }
    let Some(handle) = handle else {
        eprintln!("publisher failed to handshake with echo");
        std::process::exit(1);
    };

    println!(
        "connected; publishing for {}s at {} Hz, dup-pct={}",
        args.duration_s, args.rate_hz, args.dup_pct
    );

    let total_msgs = args.duration_s * args.rate_hz;
    let tick_interval = Duration::from_nanos(1_000_000_000 / args.rate_hz.max(1));
    let start = Instant::now();
    let mut sent_new = 0u64;
    let mut sent_dup = 0u64;
    let mut last_msg: Option<GossipMsgOut> = None;
    let mut rng = rand::thread_rng();
    let mut payload = vec![0u8; args.payload_size];
    let wire_topic = TOPIC.to_wire(FORK_DIGEST_HEX);

    while sent_new + sent_dup < total_msgs {
        let is_dup = args.dup_pct > 0 && rng.gen_range(0..100) < args.dup_pct as u32;
        let msg = if is_dup && last_msg.is_some() {
            sent_dup += 1;
            last_msg.expect("just checked")
        } else {
            rng.fill_bytes(&mut payload);
            payload[..8].copy_from_slice(&Nanos::now().0.to_le_bytes());
            let snappy = snappy_compress(&payload);
            let tcache = build_publish_frame(&mut publisher.mcache_producer, &wire_topic, &snappy)
                .expect("publish frame");
            let msg = GossipMsgOut { peer_id: handle, tcache };
            last_msg = Some(msg);
            sent_new += 1;
            msg
        };
        publisher.injector_adapter.produce(P2pSend::Gossip(msg));

        let next = start + tick_interval * (sent_new + sent_dup) as u32;
        while Instant::now() < next {
            spin_publisher(&mut publisher);
        }
    }

    let sent_total = sent_new + sent_dup;
    println!(
        "sent {sent_total} msgs ({sent_new} new + {sent_dup} dup); draining for up to {:?}",
        DRAIN_TIMEOUT
    );

    expected_count.store(sent_new, Ordering::Release);
    publisher_done.store(true, Ordering::Release);
    comp_handle.join().expect("compression thread panicked");
    net_handle.join().expect("network thread panicked");
    let stats = stats_rx.recv().expect("compression stats");

    let elapsed = start.elapsed();
    let publish_window = args.duration_s as f64;
    println!("---");
    println!("elapsed:       {:.3}s (incl. drain)", elapsed.as_secs_f64());
    println!("sent new:      {sent_new}");
    println!("sent dup:      {sent_dup}");
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
    let h = &stats.receive_ns;
    if h.len() > 0 {
        let us = |ns: u64| ns as f64 / 1000.0;
        println!("receive latency (μs):  samples={}", h.len());
        println!("  p10:         {:.1}", us(h.value_at_quantile(0.10)));
        println!("  p50:         {:.1}", us(h.value_at_quantile(0.50)));
        println!("  p90:         {:.1}", us(h.value_at_quantile(0.90)));
        println!("  p99:         {:.1}", us(h.value_at_quantile(0.99)));
    }
}

fn spin_publisher(p: &mut PublisherStack) {
    p.network.loop_body(&mut p.network_adapter);
    p.controller.loop_body(&mut p.controller_adapter);
}

/// Runs the echo's network + controller tiles. Exits once the
/// compression thread signals it's done draining — keeps QUIC alive
/// long enough to deliver the last bytes.
fn network_thread(mut net: EchoNetworkHalf, compression_done: Arc<AtomicBool>) {
    while !compression_done.load(Ordering::Acquire) {
        net.network.loop_body(&mut net.network_adapter);
        net.controller.loop_body(&mut net.controller_adapter);
    }
}

/// Runs the echo's gossip handler tile and drains stats locally. Sends
/// final `Stats` back to main via mpsc on exit.
fn compression_thread(
    mut comp: EchoCompressionHalf,
    publisher_done: Arc<AtomicBool>,
    expected_count: Arc<AtomicU64>,
    compression_done: Arc<AtomicBool>,
    stats_tx: mpsc::Sender<Stats>,
) {
    let mut drain_deadline: Option<Instant> = None;
    loop {
        comp.compression.loop_body(&mut comp.compression_adapter);
        drain_compression_stats(&mut comp);
        if publisher_done.load(Ordering::Acquire) {
            let expected = expected_count.load(Ordering::Acquire);
            if expected != 0 && comp.stats.gossip_received >= expected {
                break;
            }
            let dd = *drain_deadline.get_or_insert_with(|| Instant::now() + DRAIN_TIMEOUT);
            if Instant::now() >= dd {
                break;
            }
        }
    }
    compression_done.store(true, Ordering::Release);
    stats_tx.send(comp.stats).expect("send stats");
}

fn drain_compression_stats(c: &mut EchoCompressionHalf) {
    let stats = &mut c.stats;
    let consumer = &mut c.ssz_consumer;
    c.stats_adapter.consume::<NewGossipMsg, _>(|new_msg, _p| {
        let _ = stats.receive_ns.record(new_msg.recv_ts.elapsed_saturating().0);
        let now_wall = Instant::now();
        stats.gossip_received += 1;
        stats.first_seen_at.get_or_insert(now_wall);
        stats.last_seen_at = Some(now_wall);
        record_latency(consumer, &new_msg, stats);
    });
    c.stats_adapter.consume::<PeerEvent, _>(|event, _p| {
        if let PeerEvent::P2pGossipInvalidMsg { .. } = event {
            stats.invalid_msgs += 1;
        }
    });
}

fn record_latency(consumer: &mut TRandomAccess, msg: &NewGossipMsg, stats: &mut Stats) {
    let acquired = consumer.acquire(msg.ssz);
    if let Ok((bytes, _)) = acquired.buffer() {
        stats.gossip_decompressed_bytes += bytes.len() as u64;
        if bytes.len() >= 8 {
            let sent_ns = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
            let _ = stats.latency_ns.record(Nanos(sent_ns).elapsed_saturating().0);
        }
    }
}

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port().expect("port"))
}

fn pick_free_port() -> io::Result<u16> {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    s.local_addr().map(|a| a.port())
}

struct Args {
    duration_s: u64,
    rate_hz: u64,
    payload_size: usize,
    dup_pct: u8,
}

fn parse_args() -> Args {
    let mut duration_s = DEFAULT_DURATION_S;
    let mut rate_hz = DEFAULT_RATE_HZ;
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;
    let mut dup_pct = DEFAULT_DUP_PCT;

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
            "--dup-pct" => {
                let v: u32 = argv[i + 1].parse().expect("--dup-pct: u8 in 0..=100");
                assert!(v <= 100, "--dup-pct must be in 0..=100");
                dup_pct = v as u8;
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    Args { duration_s, rate_hz, payload_size, dup_pct }
}
