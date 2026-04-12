use std::{
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
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, SeedableRng};
use silver_common::{Keypair, PeerId, StreamProtocol};
use silver_network::{NetworkTile, P2p, PeerHandler, RemotePeer, StreamHandler};

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
                        let p2p =
                            P2p::new(keypair, server_endpoint, ServerPeerHandler, ServerHandler {
                                counter: recv_counter.clone(),
                                to_send: Vec::with_capacity(BATCH_SIZE),
                                recv: vec![],
                                recv_length: 0,
                                send_offset: 0,
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
                        data,
                        read_remaining: 0,
                        histogram: hdrhistogram::Histogram::<u64>::new_with_max(1000, 3).unwrap(),
                        count: client_counter.clone(),
                        last_send: Instant::now(),
                        stream: Some(StreamProtocol::GossipSub),
                        send_offset: 0,
                        read: vec![],
                    };

                    let addr = "127.0.0.1:20002";
                    let p2p = P2p::new(
                        keypair,
                        client_endpoint,
                        ClientPeerHandler {
                            server: Some((server_id.clone(), "127.0.0.1:20001".parse().unwrap())),
                        },
                        client_data,
                    );

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
        let vec = vec![0u8; len];
        //rng.fill_bytes(&mut vec[varint_len..]);
        data.push(vec);
    }
    (data, total)
}

struct ServerHandler {
    counter: Arc<AtomicUsize>,
    to_send: Vec<Vec<u8>>,
    recv: Vec<u8>,
    recv_length: usize,
    send_offset: usize,
}

struct ServerPeerHandler;

impl PeerHandler for ServerPeerHandler {
    fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        None
    }

    fn new_peer(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new remote peer from: {remote_addr:?} {remote_peer:?}");
    }
}

impl StreamHandler for ServerHandler {
    type BufferId = usize;

    fn recv_new(
        &mut self,
        length: usize,
        _stream: silver_common::P2pStreamId,
    ) -> Result<Self::BufferId, std::io::Error> {
        self.recv = Vec::with_capacity(length);
        self.recv_length = length;
        Ok(0)
    }

    fn recv(&mut self, _buffer_id: &Self::BufferId, data: &[u8]) -> Result<usize, std::io::Error> {
        let _was = self.counter.fetch_add(data.len(), Ordering::Relaxed);
        self.recv.extend_from_slice(data);

        if self.recv.len() == self.recv_length {
            let recv = std::mem::take(&mut self.recv);
            self.to_send.push(recv);
        }

        Ok(data.len())
    }

    fn poll_new_stream(&mut self, _peer: usize) -> Option<silver_common::StreamProtocol> {
        None
    }

    fn poll_new_send(
        &mut self,
        _stream: &silver_common::P2pStreamId,
    ) -> Option<(Self::BufferId, usize)> {
        if self.send_offset < self.to_send.len() {
            let id = self.send_offset;
            self.send_offset += 1;
            //tracing::info!(id, len=self.to_send[id].len(), "srv rsp");
            Some((id, self.to_send[id].len()))
        } else {
            None
        }
    }

    fn poll_send(&mut self, buffer_id: &Self::BufferId, offset: usize) -> Option<&[u8]> {
        self.to_send.get(*buffer_id).map(|v| &v[offset..])
    }
    
    fn recv_buffer(&mut self, _buffer_id: &Self::BufferId) -> Result<&mut [u8], std::io::Error> {
        todo!()
    }
    
    fn recv_buffer_written(&mut self, _buffer_id: &Self::BufferId, _written: usize) -> Result<(), std::io::Error> {
        todo!()
    }
}

struct ClientPeerHandler {
    server: Option<(PeerId, SocketAddr)>,
}

impl PeerHandler for ClientPeerHandler {
    fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        self.server.take()
    }

    fn new_peer(&mut self, _remote_peer: RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new connection to {remote_addr:?}");
    }
}

struct ClientData {
    stream: Option<StreamProtocol>,
    data: Vec<Vec<u8>>,
    send_offset: usize,
    read: Vec<u8>,
    read_remaining: usize,
    histogram: hdrhistogram::Histogram<u64>,
    count: Arc<AtomicUsize>,
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

impl StreamHandler for ClientData {
    type BufferId = usize;

    fn recv_new(
        &mut self,
        length: usize,
        _stream: silver_common::P2pStreamId,
    ) -> Result<Self::BufferId, std::io::Error> {
        self.read.clear();
        self.read_remaining = length;
        Ok(0)
    }

    fn recv(&mut self, _buffer_id: &Self::BufferId, data: &[u8]) -> Result<usize, std::io::Error> {
        self.read.extend_from_slice(data);
        if self.read.len() == self.read_remaining {
            let instant = u64::from_le_bytes(self.read[8..16].try_into().unwrap());
            let elapsed = Instant(instant).elapsed().as_micros_u64();
            let _ = self.histogram.record(elapsed);

            let full_len = usize::from_le_bytes(self.read[0..8].try_into().unwrap());
            assert_eq!(full_len, self.read.len(), "length mismatch: {:?}", &self.read[..24]);
        }
        let _was = self.count.fetch_add(data.len(), Ordering::Relaxed);
        //tracing::info!(count=was + data.len());
        Ok(data.len())
    }

    fn poll_new_stream(&mut self, _peer: usize) -> Option<silver_common::StreamProtocol> {
        self.stream.take()
    }

    fn poll_new_send(
        &mut self,
        _stream: &silver_common::P2pStreamId,
    ) -> Option<(Self::BufferId, usize)> {
        if self.last_send.elapsed().as_micros_u64() < 10 {
            return None;
        }
        self.last_send = Instant::now();

        if self.send_offset < self.data.len() {
            let id = self.send_offset;
            self.send_offset += 1;

            // write length and timestamp into the buffer
            let len = self.data[id].len();
            let now = Instant::now().0;
            self.data[id][..8].copy_from_slice(&len.to_le_bytes());
            self.data[id][8..16].copy_from_slice(&now.to_le_bytes());

            //tracing::info!(id, len, "client send");
            Some((id, len))
        } else {
            None
        }
    }

    fn poll_send(&mut self, buffer_id: &Self::BufferId, offset: usize) -> Option<&[u8]> {
        self.data.get(*buffer_id).map(|v| &v[offset..])
    }
    
    fn recv_buffer(&mut self, _buffer_id: &Self::BufferId) -> Result<&mut [u8], std::io::Error> {
        todo!()
    }
    
    fn recv_buffer_written(&mut self, _buffer_id: &Self::BufferId, _written: usize) -> Result<(), std::io::Error> {
        todo!()
    }
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);
