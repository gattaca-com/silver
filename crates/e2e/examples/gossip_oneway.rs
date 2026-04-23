//! Runnable demo of the one-way gossip profile.
//!
//! Publisher dials echo over loopback QUIC, then publishes synthetic
//! beacon_block payloads at a fixed rate for a fixed duration. Echo side
//! runs the full compression tile and counts inbound messages.
//!
//! Usage:
//!   cargo run -p silver_e2e --example gossip_oneway -- \
//!     --duration 5 --rate 500 --payload-size 1024 --dup-pct 10
//!
//! All arguments are optional; defaults below.

use std::{
    env,
    time::{Duration, Instant},
};

use flux::timing::Nanos;
use rand::{Rng, RngCore};
use silver_common::GossipTopic;
use silver_e2e::TwoStackHarness;

const DEFAULT_DURATION_S: u64 = 3;
const DEFAULT_RATE_HZ: u64 = 500;
const DEFAULT_PAYLOAD_SIZE: usize = 1024;
const DEFAULT_DUP_PCT: u8 = 0;
const FORK_DIGEST_HEX: &str = "abcd1234";

fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();

    let args = parse_args();

    let mut harness = TwoStackHarness::new(FORK_DIGEST_HEX).expect("harness");
    harness.connect();

    let connected = harness.spin_until(|h| h.is_connected(), Duration::from_secs(5));
    if !connected {
        eprintln!("publisher failed to handshake with echo");
        std::process::exit(1);
    }
    println!(
        "connected; publishing for {}s at {} Hz, dup-pct={}",
        args.duration_s, args.rate_hz, args.dup_pct
    );

    let total_msgs = args.duration_s * args.rate_hz;
    let tick_interval = Duration::from_nanos(1_000_000_000 / args.rate_hz.max(1));
    let start = Instant::now();
    let mut sent_new = 0u64;
    let mut sent_dup = 0u64;
    let mut rng = rand::thread_rng();
    let mut payload = vec![0u8; args.payload_size];

    assert!(args.payload_size >= 8, "payload-size must be >= 8 for the timestamp prefix");

    while sent_new + sent_dup < total_msgs {
        let is_dup = args.dup_pct > 0 && rng.gen_range(0..100) < args.dup_pct as u32;
        if is_dup && harness.republish_last() {
            sent_dup += 1;
        } else {
            rng.fill_bytes(&mut payload);
            // Stamp nanosecond timestamp into the first 8 bytes — echo side
            // reads this back to compute one-way latency.
            payload[..8].copy_from_slice(&Nanos::now().0.to_le_bytes());
            let _ = harness.publish_synthetic(GossipTopic::BeaconBlock, &payload);
            sent_new += 1;
        }

        // Keep both stacks ticking while we publish.
        let next = start + tick_interval * (sent_new + sent_dup) as u32;
        while Instant::now() < next {
            harness.spin_once();
        }
    }
    let sent_total = sent_new + sent_dup;
    println!("sent {sent_total} msgs ({sent_new} new + {sent_dup} dup); draining for up to 2s");

    // Drain: spin until received catches up to the unique count or a short
    // timeout. Duplicates are deduped by the echo side and don't count.
    let _ =
        harness.spin_until(|h| h.echo.stats.gossip_received >= sent_new, Duration::from_secs(2));

    let stats = harness.echo.stats;
    let elapsed = start.elapsed();
    println!("---");
    println!("elapsed:       {:.3}s", elapsed.as_secs_f64());
    println!("sent new:      {sent_new}");
    println!("sent dup:      {sent_dup}");
    println!("received:      {}", stats.gossip_received);
    println!("invalid:       {}", stats.invalid_msgs);
    println!(
        "throughput:    {:.1} msg/s received",
        stats.gossip_received as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
    );
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
