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
use quinn_proto::{ConnectionHandle, Endpoint, EndpointConfig};
use rand::{Rng, RngCore, SeedableRng};
use silver_common::{Keypair, PeerId, StreamProtocol};
use silver_network::{NetworkTile, P2p, PeerHandler, RemotePeer, StreamHandler};

const BATCH_SIZE: usize = 8192 * 10;

pub fn broadcast(c: &mut Criterion) {
    let _guard = tracing_subscriber::fmt().init();

    let group_name = format!("quic_basic_{}", BATCH_SIZE);
    let mut group = c.benchmark_group(group_name);

    let (data, total) = random_data();
    tracing::info!("total: {total}");

    let mut rng = rand::rngs::OsRng::default();

    for i in 1..3 {
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
                            let p2p = P2p::new(
                                keypair,
                                server_endpoint,
                                ServerPeerHandler,
                                ServerHandler {
                                    counter: recv_counter.clone(),
                                    total,
                                    offsets: vec![0; i],
                                    data: data.iter().map(|v| v.len()).collect(),
                                },
                            );
                            (
                                NetworkTile::new("0.0.0.0:20001".parse().unwrap(), p2p).unwrap(),
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

                            let client_peer_handler = ClientPeerHandler {
                                peer: Some((server_id.clone(), "127.0.0.1:20001".parse().unwrap())),
                                remote_peer: None,
                            };

                            let client_data = ClientData {
                                stream: Some(StreamProtocol::GossipSub),
                                data,
                                offset: 0,
                            };

                            let addr = format!("127.0.0.1:{}", 20002 + n);
                            let p2p = P2p::new(
                                keypair,
                                client_endpoint,
                                client_peer_handler,
                                client_data,
                            );

                            clients.push(NetworkTile::new(addr.parse().unwrap(), p2p).unwrap());
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

struct ServerPeerHandler;
impl PeerHandler for ServerPeerHandler {
    fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        None
    }

    fn new_peer(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new remote peer from: {remote_addr:?} {remote_peer:?}");
    }
}

struct ServerHandler {
    counter: Arc<AtomicUsize>,
    total: usize,
    offsets: Vec<usize>,
    data: Vec<usize>,
}
impl silver_network::StreamHandler for ServerHandler {
    type BufferId = usize;

    fn recv_new(
        &mut self,
        length: usize,
        stream: silver_common::P2pStreamId,
    ) -> Result<Self::BufferId, std::io::Error> {
        let id = self.offsets[ConnectionHandle::from(&stream).0];
        self.offsets[ConnectionHandle::from(&stream).0] += 1;
        assert_eq!(length, self.data[id], "length mismatch at {id}");
        Ok(id)
    }

    fn recv(&mut self, buffer_id: &Self::BufferId, data: &[u8]) -> Result<usize, std::io::Error> {
        let _was = self.counter.fetch_add(data.len(), Ordering::Relaxed);
        //assert!(data.len() <= self.data[*buffer_id]);
        //self.data[*buffer_id] -= data.len();
        //tracing::info!(buffer_id, len=data.len(), was, total=self.total, "srv recv");
        Ok(data.len())
    }

    fn poll_new_stream(&mut self, _peer: usize) -> Option<StreamProtocol> {
        None
    }

    fn poll_new_send(
        &mut self,
        _stream: &silver_common::P2pStreamId,
    ) -> Option<(Self::BufferId, usize)> {
        None
    }

    fn poll_send(&mut self, _buffer_id: &Self::BufferId, _offset: usize) -> Option<&[u8]> {
        None
    }
}

struct ClientData {
    stream: Option<StreamProtocol>,
    data: Vec<Vec<u8>>,
    offset: usize,
}

struct ClientPeerHandler {
    peer: Option<(PeerId, SocketAddr)>,
    remote_peer: Option<RemotePeer>,
}

impl PeerHandler for ClientPeerHandler {
    fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
        self.peer.take()
    }

    fn new_peer(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr) {
        tracing::info!("new connection to {remote_addr:?}");
        self.remote_peer = Some(remote_peer);
    }
}

impl StreamHandler for ClientData {
    type BufferId = usize;

    fn recv_new(
        &mut self,
        _length: usize,
        _stream: silver_common::P2pStreamId,
    ) -> Result<Self::BufferId, std::io::Error> {
        Ok(0)
    }

    fn recv(&mut self, _buffer_id: &Self::BufferId, _data: &[u8]) -> Result<usize, std::io::Error> {
        Ok(0)
    }

    fn poll_new_stream(&mut self, _peer: usize) -> Option<StreamProtocol> {
        self.stream.take()
    }

    fn poll_new_send(
        &mut self,
        _stream: &silver_common::P2pStreamId,
    ) -> Option<(Self::BufferId, usize)> {
        let id = self.offset;
        self.offset += 1;
        if id >= self.data.len() {
            return None;
        } else {
            //tracing::info!("client send new: {id}");
            return Some((id, self.data[id].len()))
        }
    }

    fn poll_send(&mut self, buffer_id: &Self::BufferId, offset: usize) -> Option<&[u8]> {
        self.data.get(*buffer_id).map(|v| {
            //tracing::info!(buffer_id, offset, "client send {} bytes", v.len());
            &v[offset..]
        })
    }
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);
