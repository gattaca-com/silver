use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, RngCore, SeedableRng};
use silver_common::{Keypair, PeerId};
use silver_network::{NetworkTile, RemotePeer};

const BATCH_SIZE: usize = 8192 * 10;

pub fn broadcast(c: &mut Criterion) {
    //let _guard = tracing_subscriber::fmt().init();

    let group_name = format!("quic_basic_{}", BATCH_SIZE);
    let mut group = c.benchmark_group(group_name);

    let (data, total) = random_data();
    tracing::info!("total: {total}");

    let mut rng = rand::rngs::OsRng::default();

    for i in 1..=3 {
        let criterion_batch_size = BatchSize::PerIteration;
        let throughput = Throughput::Elements((total * i) as u64);

        group.throughput(throughput.clone()).bench_function(
            format!("quic_basic_{BATCH_SIZE}_{i}"),
            |x| {
                x.iter_batched(
                    || {
                        let recv_counter = Arc::new(AtomicUsize::default());

                        let (mut server_tile, server_id) = {
                            let secret = k256::ecdsa::SigningKey::random(&mut rng);
                            let key_bytes: [u8; 32] = secret.to_bytes().into();
                            let keypair = Keypair::from_secret(&key_bytes).unwrap();
                            let server_id = keypair.peer_id();
                            let server_config =
                                silver_network::create_server_config(&keypair).unwrap();
                            let server_endpoint = Endpoint::new(
                                Arc::new(EndpointConfig::default()),
                                Some(Arc::new(server_config)),
                                false,
                                None,
                            );
                            (
                                NetworkTile::new(
                                    keypair,
                                    server_endpoint,
                                    "0.0.0.0:20001".parse().unwrap(),
                                    ServerHandler(recv_counter.clone()),
                                )
                                .unwrap(),
                                server_id,
                            )
                        };

                        let server_handle = std::thread::spawn(move || {
                            loop {
                                server_tile.spin();
                                if recv_counter.load(Ordering::Relaxed) == (total * i) {
                                    tracing::info!("server completed");
                                    break;
                                }
                            }
                        });

                        let mut clients = vec![];
                        for n in 0..i {
                            let data = data.clone();

                            let secret = k256::ecdsa::SigningKey::random(&mut rng);
                            let key_bytes: [u8; 32] = secret.to_bytes().into();
                            let keypair = Keypair::from_secret(&key_bytes).unwrap();
                            let client_endpoint = Endpoint::new(
                                Arc::new(EndpointConfig::default()),
                                None,
                                false,
                                None,
                            );

                            let client_data = ClientData {
                                server_id: Some(server_id.clone()),
                                server_addr: "127.0.0.1:20001".parse().unwrap(),
                                remote_peer: None,
                                remote_stream: None,
                                data,
                                offset: 0,
                                did_stream: false,
                            };

                            let addr = format!("127.0.0.1:{}", 20002 + n);

                            clients.push(
                                NetworkTile::new(
                                    keypair,
                                    client_endpoint,
                                    addr.parse().unwrap(),
                                    client_data,
                                )
                                .unwrap(),
                            );
                        }

                        std::thread::sleep(Duration::from_millis(200));
                        (server_handle, clients)
                    },
                    |(handle, mut clients)| {
                        while !handle.is_finished() {
                            for client in &mut clients {
                                client.spin();
                            }
                        }
                        handle.join().unwrap();
                    },
                    criterion_batch_size,
                );
            },
        );
    }
}

fn random_data() -> (Vec<Vec<u8>>, usize) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(23);
    let mut data = Vec::with_capacity(BATCH_SIZE);
    let mut total = 0;
    for _ in 0..BATCH_SIZE {
        let len = rng.gen_range(1024..4096);
        total += len;
        let mut vec = vec![0u8; len];
        rng.fill_bytes(&mut vec);
        data.push(vec);
    }
    (data, total)
}

struct ServerHandler(Arc<AtomicUsize>);
impl silver_network::NetworkSend for ServerHandler {
    fn new_peer(&mut self) -> Option<(silver_common::PeerId, std::net::SocketAddr)> {
        None
    }

    fn to_send(&mut self) -> Option<(silver_network::RemotePeer, quinn_proto::StreamId, &[u8])> {
        None
    }

    fn new_streams(&mut self) -> Option<(RemotePeer, quinn_proto::Dir)> {
        None
    }

    fn sent(&mut self, _peer: &RemotePeer, _stream: &quinn_proto::StreamId, _sent: usize) {}
}

impl silver_network::NetworkRecv for ServerHandler {
    fn new_connection(&mut self, remote_peer: silver_network::RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new remote peer from: {remote_addr:?} {remote_peer:?}");
    }

    fn new_stream(
        &mut self,
        _peer: &silver_network::RemotePeer,
        stream_id: &quinn_proto::StreamId,
    ) {
        tracing::info!("new stream: {stream_id:?}");
    }

    fn recv(
        &mut self,
        _peer: &silver_network::RemotePeer,
        _stream_id: &quinn_proto::StreamId,
        data: &[u8],
    ) {
        let _was = self.0.fetch_add(data.len(), Ordering::Relaxed);
        //tracing::info!("recv: {}, total: {}", data.len(), was + data.len());
    }
}

struct ClientData {
    server_id: Option<PeerId>,
    server_addr: SocketAddr,
    remote_peer: Option<RemotePeer>,
    remote_stream: Option<quinn_proto::StreamId>,
    data: Vec<Vec<u8>>,
    offset: usize,
    did_stream: bool,
}

impl silver_network::NetworkSend for ClientData {
    fn new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        self.server_id.take().map(|id| (id, self.server_addr))
    }

    fn to_send(&mut self) -> Option<(silver_network::RemotePeer, quinn_proto::StreamId, &[u8])> {
        if let Some(remote_peer) = self.remote_peer.as_ref() &&
            let Some(remote_stream) = self.remote_stream.as_ref()
        {
            if let Some(data) = self.data.last() {
                return Some((remote_peer.clone(), remote_stream.clone(), &data[self.offset..]));
            }
        }
        None
    }

    fn new_streams(&mut self) -> Option<(RemotePeer, quinn_proto::Dir)> {
        if let Some(remote_peer) = self.remote_peer.as_ref() &&
            self.remote_stream.is_none() &&
            !self.did_stream
        {
            self.did_stream = true;
            return Some((remote_peer.clone(), quinn_proto::Dir::Bi));
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

    fn recv(&mut self, _peer: &RemotePeer, _stream_id: &quinn_proto::StreamId, _data: &[u8]) {
        tracing::warn!("unexpected data!");
    }
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);
