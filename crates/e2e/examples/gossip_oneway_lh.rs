//! One-way gossip latency: silver publisher → libp2p (rust-libp2p
//! gossipsub) receiver. Variant A of the lh_gossip family.
//!
//! Threaded layout (matches the original / B / C examples):
//!   - subscriber on a spawned thread (`subscriber_thread`) running the libp2p
//!     swarm continuously with its own tokio current_thread runtime.
//!   - silver publisher on the main thread (mio-based, synchronous).
//!   - mpsc for the subscriber's `(listen_addr, peer_id)` handshake and final
//!     `Stats`; `publisher_done: AtomicBool` plus `expected_count: AtomicU64`
//!     for early-exit on drain.
//!
//! Usage:
//!   cargo run -p silver_e2e --features lh-client --example \
//!     gossip_oneway_lh -- --duration 5 --rate 500 --payload-size 1024

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
use silver_common::{GossipMsgOut, GossipTopic, P2pSend, PeerEvent, PeerId};
use silver_e2e::{
    LhGossipClient, PublisherStack, Stats,
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

fn main() {
    #[cfg(feature = "alloc-profile")]
    let _alloc_profile_guard = silver_common::allocator::init_allocator_trace();

    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();
    let args = parse_args();
    assert!(args.payload_size >= 8, "payload-size must be >= 8 for the timestamp prefix");

    let (addr_tx, addr_rx) = mpsc::channel::<(SocketAddr, libp2p::PeerId)>();
    let (stats_tx, stats_rx) = mpsc::channel::<Stats>();
    let publisher_done = Arc::new(AtomicBool::new(false));
    let expected_count = Arc::new(AtomicU64::new(0));

    let pd = publisher_done.clone();
    let ec = expected_count.clone();
    let sub_handle = thread::spawn(move || subscriber_thread(addr_tx, stats_tx, pd, ec));

    let (sub_addr, sub_lp_pid) = addr_rx.recv().expect("subscriber listen_addr");
    let sub_silver_pid = libp2p_to_silver_peer_id(sub_lp_pid);

    let (mut publisher, _td) = build_silver_publisher().expect("silver publisher");
    publisher
        .network
        .p2p_mut()
        .connect(sub_silver_pid, sub_addr, Instant::now())
        .expect("silver connect");

    let mut handle: Option<usize> = None;
    let connect_deadline = Instant::now() + Duration::from_secs(10);
    while handle.is_none() && Instant::now() < connect_deadline {
        spin_publisher(&mut publisher);
        let h = &mut handle;
        publisher.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
            if let PeerEvent::P2pNewConnection { p2p_peer_id, .. } = event {
                *h = Some(p2p_peer_id);
            }
        });
    }
    let Some(handle) = handle else {
        eprintln!("silver failed to handshake with libp2p");
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
    sub_handle.join().expect("subscriber thread panicked");
    let stats = stats_rx.recv().expect("subscriber stats");

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
}

fn spin_publisher(p: &mut PublisherStack) {
    p.network.loop_body(&mut p.network_adapter);
    p.controller.loop_body(&mut p.controller_adapter);
}

fn subscriber_thread(
    addr_tx: mpsc::Sender<(SocketAddr, libp2p::PeerId)>,
    stats_tx: mpsc::Sender<Stats>,
    publisher_done: Arc<AtomicBool>,
    expected_count: Arc<AtomicU64>,
) {
    let mut sub = LhGossipClient::new();
    sub.subscribe(TOPIC, FORK_DIGEST_HEX).expect("sub subscribe");
    let addr = sub.listen_addr().expect("sub listener bound");
    let pid = sub.local_peer_id();
    addr_tx.send((addr, pid)).expect("send addr");

    let mut drain_deadline: Option<Instant> = None;
    loop {
        sub.tick(Duration::from_millis(10));
        if publisher_done.load(Ordering::Acquire) {
            let expected = expected_count.load(Ordering::Acquire);
            if expected != 0 && sub.stats.gossip_received >= expected {
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

fn build_silver_publisher() -> io::Result<(PublisherStack, TempDir)> {
    let tempdir = TempDir::new()?;
    let addr = loopback_ephemeral()?;
    let disc_addr = loopback_ephemeral()?;
    let kp = keypair_from_seed(11);
    let mut p = PublisherStack::new(tempdir.path(), "_lh_gossip", addr, disc_addr, kp)
        .map_err(io::Error::other)?;
    p.controller.set_auto_ping(false);
    Ok((p, tempdir))
}

fn loopback_ephemeral() -> io::Result<SocketAddr> {
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?))
}

fn pick_free_port() -> io::Result<u16> {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    s.local_addr().map(|a| a.port())
}

fn libp2p_to_silver_peer_id(pid: libp2p::PeerId) -> PeerId {
    PeerId::from_multihash_bytes(&pid.to_bytes()).expect("multihash fits")
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
