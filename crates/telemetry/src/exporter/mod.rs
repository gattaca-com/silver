//! Streams the node's metrics to the dashboard as `silver_observe_wire`
//! datagrams: shmem sources as one bucket per second, spine peer stats and
//! stage events as they arrive, descriptors every ten seconds. A node restart
//! reopens every shmem source under a new `boot_id`.

use std::{
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
};

use flux::spine::SpineAdapter;
use flux_profiler::published_pid;
use silver_common::{APP_NAME, Nanos, NodeChain, SilverSpine};
use silver_common::{APP_NAME, Nanos, SilverSpine};
use silver_config::ChainConfig;
use silver_log::info;
use silver_observe_wire::{Encoder, Header, Kind};
use silver_stages::StageEvent;

use crate::exporter::{
    sources::ExportSources,
    streams::{drain_peer_stats, encode_stage},
};

mod sources;
mod streams;

const BUCKET: Nanos = Nanos::from_secs(1);
/// Cadence of the `fast:` sources; the loop runs every 10 ms, so a sample
/// lands up to that late, and each carries its own timestamp.
const FAST_BUCKET: Nanos = Nanos::from_millis(50);
/// Also the rediscovery and measurement-log cadence.
const DESCRIBE: Nanos = Nanos::from_secs(10);
const KINDS: usize = Kind::LAST as usize + 1;

/// UDP send accounting between measurement logs.
struct Sink {
    socket: UdpSocket,
    bytes: [u64; KINDS],
    datagrams: u64,
    dropped: u64,
}

impl Sink {
    /// Nonblocking: a full send buffer or an absent dashboard drops the
    /// datagram rather than stalling the drain.
    fn send(&mut self, dgram: &[u8]) {
        match self.socket.send(dgram) {
            Ok(_) => {
                let kind = Header::parse(dgram).expect("encoder output parses").kind;
                self.bytes[kind as usize] += dgram.len() as u64;
                self.datagrams += 1;
            }
            Err(_) => self.dropped += 1,
        }
    }
}

pub struct Exporter {
    base_dir: PathBuf,
    label: String,
    instance_id: u64,
    genesis_unix_secs: u64,
    slot_ms: u64,
    node_pid: Option<u32>,
    encoder: Encoder,
    sources: ExportSources,
    sink: Sink,
    next_bucket: Nanos,
    next_fast: Nanos,
    next_describe: Nanos,
}

impl Exporter {
    pub fn open(dest: SocketAddr, label: String, chain: &NodeChain) -> Result<Self, String> {
        let bind: SocketAddr =
            if dest.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
        socket.connect(dest).map_err(|e| format!("connect {dest}: {e}"))?;
        socket.set_nonblocking(true).map_err(|e| format!("nonblocking: {e}"))?;
        info!(%dest, label, "exporting to dashboard");

        let instance_id = fnv1a(label.as_bytes());
        let now = Nanos::now();
        Ok(Self {
            base_dir: flux::utils::directories::local_share_dir(),
            label,
            instance_id,
            genesis_unix_secs: chain.genesis_unix_secs,
            slot_ms: chain.slot_ms,
            node_pid: None,
            encoder: Encoder::new(instance_id, now.0),
            sources: ExportSources::default(),
            sink: Sink { socket, bytes: [0; KINDS], datagrams: 0, dropped: 0 },
            next_bucket: now,
            next_fast: now,
            next_describe: now,
        })
    }

    /// Streamed into the open datagram; `spin` flushes it.
    pub fn on_stage(&mut self, event: &StageEvent) {
        let Self { encoder, sink, .. } = self;
        encode_stage(encoder, Nanos::now().0, event, &mut |d| sink.send(d));
    }

    pub fn spin(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.sources.drain();

        let now = Nanos::now();
        let Self { encoder, sink, .. } = self;
        drain_peer_stats(adapter, encoder, now.0, &mut |d| sink.send(d));

        if now >= self.next_bucket {
            self.follow_node(now);
            let Self { encoder, sources, sink, .. } = self;
            sources.encode_bucket(encoder, now.0, &mut |d| sink.send(d));
            self.next_bucket = now + BUCKET;
        }
        if now >= self.next_fast {
            let Self { encoder, sources, sink, .. } = self;
            sources.encode_fast(encoder, now.0, &mut |d| sink.send(d));
            self.next_fast = now + FAST_BUCKET;
        }
        if now >= self.next_describe {
            self.describe(now);
            self.next_describe = now + DESCRIBE;
        }
        let Self { encoder, sink, .. } = self;
        encoder.flush(&mut |d| sink.send(d));
    }

    /// Stale mmaps and queue cursors of the departed node are dropped with the
    /// old source set; the new `boot_id` tells the dashboard to restart
    /// deltas and forget the old ids.
    fn follow_node(&mut self, now: Nanos) {
        let pid = published_pid(APP_NAME);
        if pid == self.node_pid {
            return;
        }
        info!(was = ?self.node_pid, pid = ?pid, "export sources reset");
        self.node_pid = pid;
        let Self { encoder, sink, .. } = self;
        encoder.flush(&mut |d| sink.send(d));
        self.encoder = Encoder::new(self.instance_id, now.0);
        self.sources = ExportSources::default();
        self.next_describe = now;
    }

    fn describe(&mut self, now: Nanos) {
        let Self { base_dir, label, genesis_unix_secs, slot_ms, encoder, sources, sink, .. } = self;
        sources.discover(base_dir, APP_NAME);

        let emit = &mut |d: &[u8]| sink.send(d);
        encoder.instance(now.0, label, emit);
        encoder.chain(now.0, *genesis_unix_secs, *slot_ms, emit);
        sources.encode_descriptors(encoder, now.0, emit);

        let series = sources.series_counts();
        let rate = |kind: Kind| sink.bytes[kind as usize] / DESCRIBE.as_secs_u64();
        info!(
            counter_slots = series.counter_slots,
            tcache_slots = series.tcache_slots,
            timing_channels = series.timing_channels,
            tiles = series.tiles,
            counter_bps = rate(Kind::CounterValues),
            tile_bps = rate(Kind::TileUtils),
            timing_bps = rate(Kind::Timings),
            peer_bps = rate(Kind::PeerP2p) + rate(Kind::PeerScores) + rate(Kind::PeerTopic),
            stage_bps = rate(Kind::Stages),
            descriptor_bps = rate(Kind::Sources) +
                rate(Kind::SlotNames) +
                rate(Kind::BuildInfo) +
                rate(Kind::Instance) +
                rate(Kind::Chain),
            datagrams = sink.datagrams,
            dropped = sink.dropped,
            "exported"
        );
        sink.bytes = [0; KINDS];
        sink.datagrams = 0;
        sink.dropped = 0;
    }
}

/// Stable across runs and builds, unlike `DefaultHasher`, so a restarted
/// exporter keeps its dashboard identity.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silver_common::BlockSource;
    use silver_observe_wire::{HEADER_LEN, MAX_DATAGRAM};
    use silver_stages::Stage;

    use super::*;

    /// The collector hands each event from its single `StageReader` to the
    /// exporter; it must reach the wire once the open datagram is flushed.
    #[test]
    fn handed_stage_event_is_sent() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut exporter =
            Exporter::open(rx.local_addr().unwrap(), "test".into(), &ChainConfig::default())
                .unwrap();

        let root = [7u8; 32];
        exporter.on_stage(&StageEvent {
            stage: Stage::Received { source: BlockSource::Gossip },
            ts: Nanos(1),
            block_root: root,
            slot: Some(42),
        });
        let Exporter { encoder, sink, .. } = &mut exporter;
        encoder.flush(&mut |d| sink.send(d));

        let mut buf = [0u8; MAX_DATAGRAM];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(Header::parse(&buf[..n]).unwrap().kind, Kind::Stages);
        let entry = &buf[HEADER_LEN + 8..n];
        assert_eq!(entry[..32], root);
        assert_eq!(entry[40..48], 42u64.to_le_bytes(), "slot");
    }
}
