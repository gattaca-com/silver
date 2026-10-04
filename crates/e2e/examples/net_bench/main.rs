//! Two-host network benchmark: a sender publishes timestamped gossip probes
//! at a fixed rate to an echo, which returns each probe with its own
//! turnaround time. Latency is measured on the sender clock only:
//!
//!   rtt = sender ingress commit - scheduled send - echo turnaround
//!
//! Probes are stamped with their scheduled time, so a stalled sender shows up
//! as latency. Ingress timestamps are taken when the network tile commits the
//! frame to its gossip-in TCache.
//!
//! ```sh
//! # host B
//! cargo run --release -p silver_e2e --features io-uring --example net_bench -- \
//!   --role echo --listen 0.0.0.0:9000 --backend io-uring
//! # host A
//! cargo run --release -p silver_e2e --features io-uring --example net_bench -- \
//!   --role sender --listen 0.0.0.0:9000 --peer B:9000 --backend io-uring \
//!   --sqpoll-cpu 3 --rate 20000 --payload-size 1024 --json runs.jsonl
//! ```

mod args;
mod node;
mod probe;
mod report;

use std::{
    net::SocketAddr,
    process,
    time::{Duration, Instant},
};

use args::{Args, Role};
use mimalloc::MiMalloc;
use node::Node;
use probe::{Probe, ProbeEncoder};
use report::Latency;
use serde::Serialize;
use silver_common::{GossipTopic, Nanos, test_util::ShmemDir};
use silver_e2e::keypair_from_seed;
use tracing_subscriber::filter::LevelFilter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const FORK_DIGEST_HEX: &str = "abcd1234";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SEND_BURST: u64 = 64;
const SENDER_SEED: u8 = 1;
const ECHO_SEED: u8 = 2;

fn main() {
    tracing_subscriber::fmt().with_max_level(LevelFilter::WARN).try_init().ok();
    let args = Args::parse();

    let tempdir = ShmemDir::new().expect("tempdir");
    let (seed, peer_seed) = match args.role {
        Role::Sender => (SENDER_SEED, ECHO_SEED),
        Role::Echo => (ECHO_SEED, SENDER_SEED),
    };
    let mut node = Node::new(
        tempdir.path(),
        args.listen,
        keypair_from_seed(seed),
        keypair_from_seed(peer_seed).peer_id(),
        &args.network,
    )
    .unwrap_or_else(|error| {
        eprintln!("network node: {error}");
        process::exit(1);
    });

    match args.role {
        Role::Sender => {
            let results = Sender::new(&args).run(&mut node, args.peer.expect("checked"));
            report::emit(&args, &results);
        }
        Role::Echo => {
            let results = Echo::new().run(&mut node, &args);
            report::emit(&args, &results);
        }
    }
}

#[derive(Serialize)]
struct SenderResults {
    connections: usize,
    disconnects: u64,
    scheduled: u64,
    sent: u64,
    publish_failures: u64,
    received: u64,
    received_per_connection_min: u64,
    received_per_connection_max: u64,
    lost: u64,
    send_rate_hz: f64,
    receive_rate_hz: f64,
    receive_bytes_per_s: f64,
    rtt: report::LatencySummary,
    rtt_with_turnaround: report::LatencySummary,
    echo_turnaround: report::LatencySummary,
    send_lag: report::LatencySummary,
}

struct Sender {
    encoder: ProbeEncoder,
    interval_ns: u64,
    warmup_probes: u64,
    total_probes: u64,
    payload_size: usize,
    sent: u64,
    publish_failures: u64,
    received: u64,
    received_per_connection: Vec<u64>,
    rtt: Latency,
    rtt_with_turnaround: Latency,
    echo_turnaround: Latency,
    send_lag: Latency,
}

impl Sender {
    fn new(args: &Args) -> Self {
        let interval_ns = 1_000_000_000 / args.rate_hz;
        let probes = |window: Duration| (window.as_nanos() / u128::from(interval_ns)) as u64;
        let wire_topic = GossipTopic::BeaconBlock.to_wire(FORK_DIGEST_HEX);
        Self {
            encoder: ProbeEncoder::new(args.payload_size, wire_topic),
            interval_ns,
            warmup_probes: probes(args.warmup),
            total_probes: probes(args.warmup + args.duration),
            payload_size: args.payload_size,
            sent: 0,
            publish_failures: 0,
            received: 0,
            received_per_connection: vec![0; args.connections],
            rtt: Latency::new(),
            rtt_with_turnaround: Latency::new(),
            echo_turnaround: Latency::new(),
            send_lag: Latency::new(),
        }
    }

    fn run(mut self, node: &mut Node, peer: SocketAddr) -> SenderResults {
        let count = self.received_per_connection.len();
        let now = Instant::now();
        for _ in 0..count {
            let peer_id = node.peer_id;
            node.network.p2p_mut().connect(peer_id, peer, now).expect("connect");
        }
        node.wait_for_connections(count, Some(CONNECT_TIMEOUT));
        // Fixed for the run: probe n always uses connection n % count.
        let connections = node.connections.clone();

        let start = Nanos::now().0;
        let send_deadline = Instant::now() +
            Duration::from_nanos(self.interval_ns * self.total_probes) +
            DRAIN_TIMEOUT;
        let mut seq = 0;
        while seq < self.total_probes && Instant::now() < send_deadline && node.disconnects == 0 {
            node.spin(|_, inbound| self.record(inbound.frame.probe(), inbound.committed_ns));

            let now = Nanos::now().0;
            let mut burst = 0;
            while seq < self.total_probes && burst < MAX_SEND_BURST {
                let scheduled = start + seq * self.interval_ns;
                if scheduled > now {
                    break;
                }
                let Ok(tcache) = self.encoder.publish(node.outbound(), seq, scheduled) else {
                    self.publish_failures += 1;
                    break;
                };
                node.send(connections[(seq % count as u64) as usize], tcache);
                if seq >= self.warmup_probes {
                    self.sent += 1;
                    self.send_lag.record(now - scheduled);
                }
                seq += 1;
                burst += 1;
            }
        }

        let expected = self.total_probes - self.warmup_probes;
        let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
        while self.received < expected && Instant::now() < drain_deadline {
            node.spin(|_, inbound| self.record(inbound.frame.probe(), inbound.committed_ns));
        }
        node.disconnect_all();
        for _ in 0..1000 {
            node.spin(|_, _| {});
        }

        let window = (expected * self.interval_ns) as f64 / 1e9;
        SenderResults {
            connections: count,
            disconnects: node.disconnects,
            scheduled: expected,
            sent: self.sent,
            publish_failures: self.publish_failures,
            received: self.received,
            received_per_connection_min: *self.received_per_connection.iter().min().unwrap(),
            received_per_connection_max: *self.received_per_connection.iter().max().unwrap(),
            lost: expected - self.received.min(expected),
            send_rate_hz: self.sent as f64 / window,
            receive_rate_hz: self.received as f64 / window,
            receive_bytes_per_s: (self.received * self.payload_size as u64) as f64 / window,
            rtt: self.rtt.summary(),
            rtt_with_turnaround: self.rtt_with_turnaround.summary(),
            echo_turnaround: self.echo_turnaround.summary(),
            send_lag: self.send_lag.summary(),
        }
    }

    fn record(&mut self, probe: Probe, committed_ns: u64) {
        if probe.seq < self.warmup_probes {
            return;
        }
        let round_trip = committed_ns.saturating_sub(probe.scheduled_ns);
        let connection = probe.seq % self.received_per_connection.len() as u64;
        self.received += 1;
        self.received_per_connection[connection as usize] += 1;
        self.rtt.record(round_trip.saturating_sub(probe.turnaround_ns));
        self.rtt_with_turnaround.record(round_trip);
        self.echo_turnaround.record(probe.turnaround_ns);
    }
}

#[derive(Serialize)]
struct EchoResults {
    peak_connections: usize,
    disconnects: u64,
    received: u64,
    echoed: u64,
    echo_failures: u64,
    receive_rate_hz: f64,
    turnaround: report::LatencySummary,
}

struct Echo {
    received: u64,
    echoed: u64,
    echo_failures: u64,
    window: Option<(u64, u64)>,
    turnaround: Latency,
}

impl Echo {
    fn new() -> Self {
        Self { received: 0, echoed: 0, echo_failures: 0, window: None, turnaround: Latency::new() }
    }

    fn run(mut self, node: &mut Node, args: &Args) -> EchoResults {
        node.wait_for_connections(1, None);
        let warmup_ns = args.warmup.as_nanos() as u64;
        let idle_ns = args.idle_exit.as_nanos() as u64;
        let mut first_rx = None;
        let mut last_rx = Nanos::now().0;
        let mut peak_connections = 0;
        let mut replies = Vec::new();

        while !node.connections.is_empty() && Nanos::now().0 - last_rx < idle_ns {
            peak_connections = peak_connections.max(node.connections.len());
            node.spin(|outbound, inbound| {
                let now = Nanos::now().0;
                let turnaround = now.saturating_sub(inbound.committed_ns);
                match inbound.frame.echo(outbound, turnaround) {
                    Ok(tcache) => replies.push((inbound.connection, tcache)),
                    Err(_) => self.echo_failures += 1,
                }
                last_rx = now;
                let first = *first_rx.get_or_insert(now);
                if now - first >= warmup_ns {
                    self.received += 1;
                    self.turnaround.record(turnaround);
                    let window = self.window.get_or_insert((now, now));
                    window.1 = now;
                }
            });
            self.echoed += replies.len() as u64;
            for (connection, tcache) in replies.drain(..) {
                node.send(connection, tcache);
            }
        }

        let window_s = self.window.map_or(0.0, |(first, last)| (last - first) as f64 / 1e9);
        EchoResults {
            peak_connections,
            disconnects: node.disconnects,
            received: self.received,
            echoed: self.echoed,
            echo_failures: self.echo_failures,
            receive_rate_hz: if window_s > 0.0 { self.received as f64 / window_s } else { 0.0 },
            turnaround: self.turnaround.summary(),
        }
    }
}
