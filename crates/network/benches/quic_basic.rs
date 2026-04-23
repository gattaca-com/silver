use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, RngCore, SeedableRng};
use silver_common::{Keypair, P2pStreamId, StreamProtocol};
use silver_discovery::Discovery;
use silver_network::{NetEvent, NetworkTileEvent, NetworkTileInner, P2p, RemotePeer, StreamData};

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
                            let secret = secp256k1::SecretKey::new(&mut rng);
                            let key_bytes: [u8; 32] = secret.secret_bytes();
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
                            let p2p = P2p::new(keypair, server_endpoint);
                            (
                                NetworkTileInner::new(
                                    "0.0.0.0:20001".parse().unwrap(),
                                    p2p,
                                    ServerHandler {
                                        counter: recv_counter.clone(),
                                        streams: HashMap::new(),
                                    },
                                    "0.0.0.0:12345".parse().unwrap(),
                                    DummyDisc,
                                )
                                .unwrap(),
                                server_id,
                            )
                        };

                        let server_handle = std::thread::spawn(move || {
                            loop {
                                server_tile.spin(&mut |_: NetworkTileEvent| {});
                                if recv_counter.load(Ordering::Relaxed) == (total * i) {
                                    tracing::info!("server completed");
                                    break;
                                }
                            }
                        });

                        let mut clients = vec![];
                        for n in 0..i {
                            let data = data.clone();

                            let secret = secp256k1::SecretKey::new(&mut rng);
                            let key_bytes: [u8; 32] = secret.secret_bytes();
                            let keypair = Keypair::from_secret(&key_bytes).unwrap();
                            let client_endpoint = Endpoint::new(
                                Arc::new(EndpointConfig::default()),
                                None,
                                false,
                                None,
                            );

                            let client_data = ClientData { data, next_idx: 0, current: None };

                            let addr = format!("127.0.0.1:{}", 20002 + n);
                            let mut p2p = P2p::new(keypair, client_endpoint);
                            p2p.connect(server_id.clone(), "127.0.0.1:20001".parse().unwrap());

                            // Pending actions accumulated by the event callback, drained
                            // and applied by the main loop after each spin.
                            let pending: Arc<Mutex<Vec<(usize, StreamProtocol)>>> =
                                Arc::new(Mutex::new(Vec::new()));
                            let pending_cb = pending.clone();
                            let on_event = move |event: NetworkTileEvent| {
                                if let NetworkTileEvent::P2pNet(NetEvent::PeerConnected {
                                    peer,
                                    ..
                                }) = event
                                {
                                    pending_cb
                                        .lock()
                                        .unwrap()
                                        .push((peer.connection, StreamProtocol::GossipSub));
                                }
                            };

                            let tile = NetworkTileInner::new(
                                addr.parse().unwrap(),
                                p2p,
                                client_data,
                                format!("0.0.0.0:{}", 12346 + n).parse().unwrap(),
                                DummyDisc,
                            )
                            .unwrap();
                            clients.push((tile, pending, on_event));
                        }

                        std::thread::sleep(Duration::from_millis(200));
                        (server_handle, clients)
                    },
                    |(handle, mut clients)| {
                        while !handle.is_finished() {
                            for (client, pending, on_event) in &mut clients {
                                client.spin(on_event);
                                // Apply any queued actions.
                                let todo: Vec<_> = pending.lock().unwrap().drain(..).collect();
                                for (peer, proto) in todo {
                                    let _ = client.p2p_mut().open_stream(peer, proto);
                                }
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

/// Server-side: accumulates received bytes per stream.
struct ServerHandler {
    counter: Arc<AtomicUsize>,
    streams: HashMap<P2pStreamId, StreamRecv>,
}

struct StreamRecv {
    buf: Vec<u8>,
    offset: usize,
}

impl StreamData for ServerHandler {
    fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
    fn stream_closed(&mut self, _stream: &P2pStreamId) {}

    fn alloc_recv(&mut self, stream: &P2pStreamId, length: usize) -> Result<(), std::io::Error> {
        self.streams.insert(*stream, StreamRecv { buf: vec![0u8; length], offset: 0 });
        Ok(())
    }

    fn recv_buf(&mut self, stream: &P2pStreamId) -> Result<&mut [u8], std::io::Error> {
        let s = self.streams.get_mut(stream).ok_or_else(|| std::io::Error::other("no alloc"))?;
        Ok(&mut s.buf[s.offset..])
    }

    fn recv_advance(&mut self, stream: &P2pStreamId, written: usize) -> Result<(), std::io::Error> {
        let s = self.streams.get_mut(stream).ok_or_else(|| std::io::Error::other("no alloc"))?;
        s.offset += written;
        self.counter.fetch_add(written, Ordering::Relaxed);
        if s.offset >= s.buf.len() {
            self.streams.remove(stream);
        }
        Ok(())
    }

    fn poll_send(&mut self, _stream: &P2pStreamId) -> Option<usize> {
        None
    }

    fn send_data(&mut self, _stream: &P2pStreamId, _offset: usize) -> Option<&[u8]> {
        None
    }

    fn send_complete(&mut self, _stream: &P2pStreamId) {}
}

/// Client-side: sends pre-computed messages sequentially.
struct ClientData {
    data: Vec<Vec<u8>>,
    next_idx: usize,
    current: Option<usize>,
}

impl StreamData for ClientData {
    fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
    fn stream_closed(&mut self, _stream: &P2pStreamId) {}

    fn alloc_recv(&mut self, _stream: &P2pStreamId, _length: usize) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn recv_buf(&mut self, _stream: &P2pStreamId) -> Result<&mut [u8], std::io::Error> {
        Err(std::io::Error::other("client does not receive"))
    }

    fn recv_advance(
        &mut self,
        _stream: &P2pStreamId,
        _written: usize,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn poll_send(&mut self, _stream: &P2pStreamId) -> Option<usize> {
        if self.current.is_some() {
            return None;
        }
        if self.next_idx >= self.data.len() {
            return None;
        }
        let idx = self.next_idx;
        self.next_idx += 1;
        let len = self.data[idx].len();
        self.current = Some(idx);
        Some(len)
    }

    fn send_data(&mut self, _stream: &P2pStreamId, offset: usize) -> Option<&[u8]> {
        let idx = self.current?;
        Some(&self.data[idx][offset..])
    }

    fn send_complete(&mut self, _stream: &P2pStreamId) {
        self.current = None;
    }
}

struct DummyDisc;
impl Discovery for DummyDisc {
    fn local_id(&self) -> silver_common::NodeId {
        silver_common::NodeId::random()
    }

    fn add_enr(&mut self, _enr: &silver_common::Enr, _now: std::time::Instant) {}

    fn find_nodes(&mut self) {}

    fn ban_node(&mut self, _id: silver_common::NodeId, _duration: Option<Duration>) {}

    fn ban_ip(&mut self, _ip: std::net::IpAddr, _duration: Option<Duration>) {}

    fn teardown(&self) {}
    fn handle(&mut self, _src_addr: std::net::SocketAddr, _data: &[u8], _now: std::time::Instant) {}

    fn poll<F: FnMut(silver_discovery::DiscoveryEvent)>(&mut self, _f: F) {}
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);
