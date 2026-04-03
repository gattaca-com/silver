use std::{
    collections::VecDeque,
    fmt::Debug,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use flux::timing::Instant;
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig, StreamId, VarInt};
use rand::{Rng, RngCore, SeedableRng};
use silver_common::{Keypair, PeerId};
use silver_network::{NetworkTile, P2p, RemotePeer};

const BATCH_SIZE: usize = 8192 * 10;

pub fn broadcast(c: &mut Criterion) {
    let _guard = tracing_subscriber::fmt().init();

    let group_name = format!("quic_ping_pong_{}", BATCH_SIZE);
    let mut group = c.benchmark_group(group_name);

    let (data, total) = random_data();
    tracing::info!("total: {total}");

    let mut rng = rand::rngs::OsRng::default();

    let criterion_batch_size = BatchSize::PerIteration;
    let throughput = Throughput::Elements((total) as u64);

    group.throughput(throughput.clone()).bench_function(
        format!("quic_ping_pong_{BATCH_SIZE}"),
        |x| {
            x.iter_batched(
                || {
                    let recv_counter = Arc::new(AtomicUsize::default());
                    let client_counter = Arc::new(AtomicUsize::default());

                    let (mut server_tile, server_id) = {
                        let secret = k256::ecdsa::SigningKey::random(&mut rng);
                        let key_bytes: [u8; 32] = secret.to_bytes().into();
                        let keypair = Keypair::from_secret(&key_bytes).unwrap();
                        let server_id = keypair.peer_id();
                        let server_config = silver_network::create_server_config(&keypair).unwrap();
                        let server_endpoint = Endpoint::new(
                            Arc::new(EndpointConfig::default()),
                            Some(Arc::new(server_config)),
                            false,
                            None,
                        );
                        let p2p = P2p::new(keypair, server_endpoint, ServerHandler {
                            counter: recv_counter.clone(),
                            connection: 0,
                            stream_id: StreamId::from(VarInt::MAX),
                            to_send: VecDeque::with_capacity(8 * 1024),
                            offset: 0,
                            total: 0,
                        });
                        (
                            NetworkTile::new("0.0.0.0:20001".parse().unwrap(), p2p).unwrap(),
                            server_id,
                        )
                    };

                    let counter = client_counter.clone();
                    let server_handle = std::thread::spawn(move || {
                        loop {
                            server_tile.spin();
                            //tracing::info!(srv_recv=recv_counter.load(Ordering::Relaxed),
                            // client_recv=counter.load(Ordering::Relaxed), "srv");
                            if counter.load(Ordering::Relaxed) >= total {
                                tracing::info!("server completed");
                                break;
                            }
                        }
                    });

                    let data = data.clone();
                    let secret = k256::ecdsa::SigningKey::random(&mut rng);
                    let key_bytes: [u8; 32] = secret.to_bytes().into();
                    let keypair = Keypair::from_secret(&key_bytes).unwrap();
                    let client_endpoint =
                        Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);

                    let client_data = ClientData {
                        server_id: Some(server_id.clone()),
                        server_addr: "127.0.0.1:20001".parse().unwrap(),
                        remote_peer: None,
                        remote_stream: None,
                        data,
                        offset: 0,
                        read_remaining: 0,
                        did_stream: false,
                        histogram: hdrhistogram::Histogram::<u64>::new_with_max(1000, 3).unwrap(),
                        count: client_counter.clone(),
                        recv: Vec::with_capacity(16),
                        last_send: Instant::now(),
                    };

                    let addr = "127.0.0.1:20002";
                    let p2p = P2p::new(keypair, client_endpoint, client_data);

                    let client = NetworkTile::new(addr.parse().unwrap(), p2p).unwrap();

                    std::thread::sleep(Duration::from_millis(200));
                    (server_handle, client, client_counter)
                },
                |(handle, mut client, counter)| {
                    while counter.load(Ordering::Relaxed) < total {
                        client.spin();
                        //tracing::info!(client_recv=counter.
                        // load(Ordering::Relaxed),
                        // server_finished=handle.is_finished(), "client");
                    }
                    tracing::info!("client spun out");
                    handle.join().unwrap();
                },
                criterion_batch_size,
            );
        },
    );
}

fn random_data() -> (Vec<Vec<u8>>, usize) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(23);
    let mut data = Vec::with_capacity(BATCH_SIZE);
    let mut total = 0;
    for _ in 0..BATCH_SIZE {
        let len = rng.gen_range(256..2048);
        total += len;
        let mut vec = vec![0u8; len];
        rng.fill_bytes(&mut vec);
        data.push(vec);
    }
    (data, total)
}

struct ServerHandler {
    counter: Arc<AtomicUsize>,
    connection: usize,
    stream_id: StreamId,
    to_send: VecDeque<Vec<u8>>,
    offset: usize,
    total: usize,
}

impl silver_network::NetworkSend for ServerHandler {
    fn new_peer(&mut self) -> Option<(silver_common::PeerId, std::net::SocketAddr)> {
        None
    }

    fn to_send(&mut self) -> Option<(usize, quinn_proto::StreamId, &[u8])> {
        match self.to_send.front() {
            Some(data) => Some((self.connection, self.stream_id, &data[self.offset..])),
            None => {
                //tracing::info!("srv nothing to send");
                None
            }
        }
    }

    fn new_streams(&mut self) -> Option<(RemotePeer, silver_network::StreamProtocol)> {
        None
    }

    fn sent(&mut self, _peer: &RemotePeer, _stream: &quinn_proto::StreamId, sent: usize) {
        self.total += sent;
        self.offset += sent;

        let pop = self.to_send.front().map(|v| self.offset >= v.len()).unwrap_or_default();
        if pop {
            let buf = self.to_send.pop_front();
            self.offset -= buf.map(|b| b.len()).unwrap_or_default();
        }
        //tracing::info!(offset=self.offset, sent, total=self.total, "sent");
    }
}

impl silver_network::NetworkRecv for ServerHandler {
    fn new_connection(&mut self, remote_peer: silver_network::RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new remote peer from: {remote_addr:?} {remote_peer:?}");
    }

    fn new_stream(&mut self, peer: &silver_network::RemotePeer, stream_id: &quinn_proto::StreamId) {
        tracing::info!("new stream: {stream_id:?}");
        self.connection = peer.connection;
        self.stream_id = *stream_id;
    }

    fn recv(
        &mut self,
        _peer: &silver_network::RemotePeer,
        _stream_id: &quinn_proto::StreamId,
        data: &[u8],
    ) {
        let was = self.counter.fetch_add(data.len(), Ordering::Relaxed);
        //tracing::info!(was, "src recv");
        self.to_send.push_back(data.to_vec());
        //self.buffer.write_all(data).inspect_err(|e| tracing::error!("buffer
        // write failed: {e:?}")).unwrap(); tracing::info!("recv: {},
        // total: {}", data.len(), was + data.len());
    }
}

struct ClientData {
    server_id: Option<PeerId>,
    server_addr: SocketAddr,
    remote_peer: Option<RemotePeer>,
    remote_stream: Option<quinn_proto::StreamId>,
    data: Vec<Vec<u8>>,
    offset: usize,
    read_remaining: usize,
    did_stream: bool,
    histogram: hdrhistogram::Histogram<u64>,
    count: Arc<AtomicUsize>,
    recv: Vec<u8>,
    last_send: Instant,
}

impl Drop for ClientData {
    fn drop(&mut self) {
        let p10 = self.histogram.value_at_quantile(0.1);
        let p50 = self.histogram.value_at_quantile(0.5);
        let p60 = self.histogram.value_at_quantile(0.6);
        let p70 = self.histogram.value_at_quantile(0.7);
        let p80 = self.histogram.value_at_quantile(0.8);
        let p90 = self.histogram.value_at_quantile(0.9);
        let p99 = self.histogram.value_at_quantile(0.99);
        let count = self.count.load(Ordering::Relaxed);
        println!(
            "{count}: p10: {p10}, p50: {p50}, p60: {p60}, p70: {p70}, p80: {p80}, p90: {p90}, p99: {p99}"
        );
    }
}

impl silver_network::NetworkSend for ClientData {
    fn new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        self.server_id.take().map(|id| (id, self.server_addr))
    }

    fn to_send(&mut self) -> Option<(usize, quinn_proto::StreamId, &[u8])> {
        if self.last_send.elapsed().as_micros_u64() < 10 {
            return None;
        }
        if let Some(remote_peer) = self.remote_peer.as_ref() &&
            let Some(remote_stream) = self.remote_stream.as_ref()
        {
            if let Some(data) = self.data.last_mut() {
                self.last_send = Instant::now();
                let len = data.len();
                data[0..8].copy_from_slice(len.to_le_bytes().as_slice());
                data[8..16].copy_from_slice(Instant::now().0.to_le_bytes().as_slice());
                return Some((remote_peer.connection, remote_stream.clone(), &data[self.offset..]));
            }
        }
        None
    }

    fn new_streams(&mut self) -> Option<(RemotePeer, silver_network::StreamProtocol)> {
        if let Some(remote_peer) = self.remote_peer.as_ref() &&
            self.remote_stream.is_none() &&
            !self.did_stream
        {
            self.did_stream = true;
            return Some((remote_peer.clone(), silver_network::StreamProtocol::GossipSub));
        }
        None
    }

    fn sent(&mut self, _peer: &RemotePeer, _stream: &quinn_proto::StreamId, sent: usize) {
        self.offset += sent;
        let pop = self.data.last().map(|v| self.offset >= v.len()).unwrap_or_default();
        if pop {
            self.data.pop();
            self.offset = 0;
        }
    }
}

impl silver_network::NetworkRecv for ClientData {
    fn new_connection(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new connection to {remote_addr:?}");
        self.remote_peer = Some(remote_peer);
    }

    fn new_stream(&mut self, _peer: &RemotePeer, stream_id: &quinn_proto::StreamId) {
        tracing::info!("new client stream {stream_id:?}");
        self.remote_stream = Some(*stream_id);
    }

    fn recv(&mut self, _peer: &RemotePeer, _stream_id: &quinn_proto::StreamId, data: &[u8]) {
        let was = self.count.fetch_add(data.len(), Ordering::Relaxed);
        let mut buf = data;

        let mut scratch = vec![];
        if !self.recv.is_empty() {
            scratch.extend_from_slice(&self.recv);
            scratch.extend_from_slice(data);
            self.recv.clear();
            buf = scratch.as_slice();
        }

        while !buf.is_empty() {
            if self.read_remaining > 0 {
                if self.read_remaining >= buf.len() {
                    self.read_remaining -= buf.len();
                    return;
                } else {
                    buf = &data[self.read_remaining..];
                    self.read_remaining = 0;
                }
            }

            if buf.len() >= 16 {
                let instant = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                let elapsed = Instant(instant).elapsed().as_micros_u64();
                //println!("{elapsed}");
                let _ = self.histogram.record(elapsed);

                let full_len = usize::from_le_bytes(buf[0..8].try_into().unwrap());
                //std::thread::sleep(Duration::from_millis(200));
                //tracing::info!(full_len, was, remain=self.read_remaining, buf=buf.len(),
                // data=data.len());
                if full_len > buf.len() {
                    self.read_remaining = full_len - buf.len();
                    buf = &[];
                } else if full_len <= buf.len() {
                    buf = &buf[full_len..];
                    self.read_remaining = 0;
                }
            } else {
                self.recv.clear();
                self.recv.extend_from_slice(buf);
                break;
            }
        }
    }
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);

use std::io::{Read, Write};

/// Circular buffer.
struct Buffer<const N: usize> {
    buffer: Box<[u8; N]>,
    head: usize,
    tail: usize,
}

impl<const N: usize> Debug for Buffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buffer")
            .field("buffer", &N)
            .field("head", &self.head)
            .field("tail", &self.tail)
            .finish()
    }
}

impl<const N: usize> Buffer<N> {
    fn new() -> Self {
        assert!(N.is_power_of_two());
        Self { buffer: Box::new([0u8; N]), head: 0, tail: 0 }
    }

    fn data(&self, seq: usize, len: usize) -> &[u8] {
        let position = seq & (N - 1);
        if self.head >= self.tail {
            if position >= self.tail && position <= self.head {
                &self.buffer[position..self.head.min(position + len)]
            } else {
                &[]
            }
        } else {
            if position >= self.tail {
                // return 'end buffer'
                &self.buffer[position..N.min(position + len)]
            } else if position < self.head {
                &self.buffer[position..self.head.min(position + len)]
            } else {
                &[]
            }
        }
    }

    fn set_tail(&mut self, min_seq: usize) {
        self.tail = min_seq & (N - 1);
    }

    fn write_capacity(&self) -> usize {
        if self.tail > self.head { self.tail - self.head } else { N - self.head + self.tail }
    }
}

impl<const N: usize> Write for Buffer<N> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let start = self.head;
        let mut end = (start + buf.len()) & N - 1;

        if end > start {
            end = (self.tail > start).then(|| end.min(self.tail)).unwrap_or(end);
            self.buffer[start..end].copy_from_slice(&buf[..(end - start)]);
            self.head = end;
            Ok(end - start)
        } else {
            // Would wrap end of buffer
            end = (self.tail <= start).then(|| end.min(self.tail)).unwrap_or(self.tail);
            if end > start {
                self.buffer[start..end].copy_from_slice(&buf[..(end - start)]);
                self.head = end;
                Ok(end - start)
            } else if end < start {
                let first = N - start;
                self.buffer[start..N].copy_from_slice(&buf[..first]);
                self.buffer[..end].copy_from_slice(&buf[first..(first + end)]);
                self.head = end;
                Ok(N - start + end)
            } else {
                Ok(0)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

impl<const N: usize> Read for Buffer<N> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = self.tail;
        let mut end = (start + buf.len()) & N - 1;

        if end > start {
            end = (self.head > start).then(|| end.min(self.head)).unwrap_or(end);
            buf[..(end - start)].copy_from_slice(&self.buffer[start..end]);
            self.tail = end;
            Ok(end - start)
        } else {
            end = (self.head < start).then(|| end.min(self.head)).unwrap_or(self.head);
            if end > start {
                buf[..(end - start)].copy_from_slice(&self.buffer[start..end]);
                self.tail = end;
                Ok(end - start)
            } else {
                buf[..(N - start)].copy_from_slice(&self.buffer[start..N]);
                buf[(N - start)..].copy_from_slice(&self.buffer[..end]);
                self.tail = end;
                Ok(N - start + end)
            }
        }
    }
}
