use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use flux::timing::Instant;
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, SeedableRng};
use silver_common::{Keypair, P2pStreamId, StreamProtocol};
use silver_discovery::Discovery;
use silver_network::{NetEvent, NetworkTileEvent, NetworkTileInner, P2p, RemotePeer, StreamData};

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
                        let secret = secp256k1::SecretKey::new(&mut rng);
                        let key_bytes: [u8; 32] = secret.secret_bytes();
                        let keypair = Keypair::from_secret(&key_bytes).unwrap();
                        let server_id = keypair.peer_id();
                        let server_config = silver_network::create_server_config(&keypair).unwrap();
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
                                    to_send: Vec::with_capacity(BATCH_SIZE),
                                    recv_buf: vec![],
                                    recv_offset: 0,
                                    send_offset: 0,
                                    send_current: None,
                                },
                                "0.0.0.0:12345".parse().unwrap(),
                                DummyDisc,
                            )
                            .unwrap(),
                            server_id,
                        )
                    };

                    let counter = client_counter.clone();
                    let server_handle = std::thread::spawn(move || {
                        loop {
                            server_tile.spin(&mut |_: NetworkTileEvent| {});
                            if counter.load(Ordering::Relaxed) >= total {
                                tracing::info!("server completed");
                                break;
                            }
                        }
                    });

                    let data = data.clone();
                    let secret = secp256k1::SecretKey::new(&mut rng);
                    let key_bytes: [u8; 32] = secret.secret_bytes();
                    let keypair = Keypair::from_secret(&key_bytes).unwrap();
                    let client_endpoint =
                        Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);

                    let client_data = ClientData {
                        data,
                        histogram: hdrhistogram::Histogram::<u64>::new_with_max(1000, 3).unwrap(),
                        count: client_counter.clone(),
                        last_send: Instant::now(),
                        send_offset: 0,
                        send_current: None,
                        read_buf: vec![],
                        read_offset: 0,
                    };

                    let addr = "127.0.0.1:20002";
                    let mut p2p = P2p::new(keypair, client_endpoint);
                    p2p.connect(server_id.clone(), "127.0.0.1:20001".parse().unwrap());

                    let pending: Arc<Mutex<Vec<(usize, StreamProtocol)>>> =
                        Arc::new(Mutex::new(Vec::new()));
                    let pending_cb = pending.clone();
                    let on_event = move |event: NetworkTileEvent| {
                        if let NetworkTileEvent::P2pNet(NetEvent::PeerConnected { peer, .. }) =
                            event
                        {
                            pending_cb
                                .lock()
                                .unwrap()
                                .push((peer.connection, StreamProtocol::GossipSub));
                        }
                    };

                    let client = NetworkTileInner::new(
                        addr.parse().unwrap(),
                        p2p,
                        client_data,
                        "0.0.0.0:12346".parse().unwrap(),
                        DummyDisc,
                    )
                    .unwrap();

                    std::thread::sleep(Duration::from_millis(200));
                    (server_handle, client, client_counter, pending, on_event)
                },
                |(handle, mut client, counter, pending, mut on_event)| {
                    while counter.load(Ordering::Relaxed) < total {
                        client.spin(&mut on_event);
                        let todo: Vec<_> = pending.lock().unwrap().drain(..).collect();
                        for (peer, proto) in todo {
                            let _ = client.p2p_mut().open_stream(peer, proto);
                        }
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
        data.push(vec);
    }
    (data, total)
}

/// Server echoes received messages back. Accumulates a received message
/// into `recv_buf`, then pushes it onto `to_send` when complete.
struct ServerHandler {
    counter: Arc<AtomicUsize>,
    to_send: Vec<Vec<u8>>,
    recv_buf: Vec<u8>,
    recv_offset: usize,
    send_offset: usize,
    send_current: Option<usize>,
}

impl StreamData for ServerHandler {
    fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
    fn stream_closed(&mut self, _stream: &P2pStreamId) {}

    fn alloc_recv(&mut self, _stream: &P2pStreamId, length: usize) -> Result<(), std::io::Error> {
        self.recv_buf.clear();
        self.recv_buf.resize(length, 0);
        self.recv_offset = 0;
        Ok(())
    }

    fn recv_buf(&mut self, _stream: &P2pStreamId) -> Result<&mut [u8], std::io::Error> {
        Ok(&mut self.recv_buf[self.recv_offset..])
    }

    fn recv_advance(
        &mut self,
        _stream: &P2pStreamId,
        written: usize,
    ) -> Result<(), std::io::Error> {
        self.recv_offset += written;
        self.counter.fetch_add(written, Ordering::Relaxed);
        if self.recv_offset >= self.recv_buf.len() {
            let msg = std::mem::take(&mut self.recv_buf);
            self.to_send.push(msg);
        }
        Ok(())
    }

    fn poll_send(&mut self, _stream: &P2pStreamId) -> Option<usize> {
        if self.send_current.is_some() {
            return None;
        }
        if self.send_offset >= self.to_send.len() {
            return None;
        }
        let id = self.send_offset;
        self.send_offset += 1;
        let len = self.to_send[id].len();
        self.send_current = Some(id);
        Some(len)
    }

    fn send_data(&mut self, _stream: &P2pStreamId, offset: usize) -> Option<&[u8]> {
        let id = self.send_current?;
        Some(&self.to_send[id][offset..])
    }

    fn send_complete(&mut self, _stream: &P2pStreamId) {
        self.send_current = None;
    }
}

struct ClientData {
    data: Vec<Vec<u8>>,
    send_offset: usize,
    send_current: Option<usize>,
    read_buf: Vec<u8>,
    read_offset: usize,
    histogram: hdrhistogram::Histogram<u64>,
    count: Arc<AtomicUsize>,
    last_send: Instant,
}

impl Drop for ClientData {
    fn drop(&mut self) {
        let p10 = self.histogram.value_at_quantile(0.1);
        let p50 = self.histogram.value_at_quantile(0.5);
        let p99 = self.histogram.value_at_quantile(0.99);
        let count = self.count.load(Ordering::Relaxed);
        println!("{count}: p10: {p10}, p50: {p50}, p99: {p99}");
    }
}

impl StreamData for ClientData {
    fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
    fn stream_closed(&mut self, _stream: &P2pStreamId) {}

    fn alloc_recv(&mut self, _stream: &P2pStreamId, length: usize) -> Result<(), std::io::Error> {
        self.read_buf.clear();
        self.read_buf.resize(length, 0);
        self.read_offset = 0;
        Ok(())
    }

    fn recv_buf(&mut self, _stream: &P2pStreamId) -> Result<&mut [u8], std::io::Error> {
        Ok(&mut self.read_buf[self.read_offset..])
    }

    fn recv_advance(
        &mut self,
        _stream: &P2pStreamId,
        written: usize,
    ) -> Result<(), std::io::Error> {
        self.read_offset += written;
        self.count.fetch_add(written, Ordering::Relaxed);
        if self.read_offset >= self.read_buf.len() && self.read_buf.len() >= 16 {
            let full_len = usize::from_le_bytes(self.read_buf[0..8].try_into().unwrap());
            let instant = u64::from_le_bytes(self.read_buf[8..16].try_into().unwrap());
            let elapsed = Instant(instant).elapsed().as_micros_u64();
            let _ = self.histogram.record(elapsed);
            assert_eq!(full_len, self.read_buf.len());
        }
        Ok(())
    }

    fn poll_send(&mut self, _stream: &P2pStreamId) -> Option<usize> {
        if self.send_current.is_some() {
            return None;
        }
        if self.last_send.elapsed().as_micros_u64() < 10 {
            return None;
        }
        self.last_send = Instant::now();

        if self.send_offset >= self.data.len() {
            return None;
        }
        let id = self.send_offset;
        self.send_offset += 1;

        let len = self.data[id].len();
        let now = Instant::now().0;
        self.data[id][..8].copy_from_slice(&len.to_le_bytes());
        self.data[id][8..16].copy_from_slice(&now.to_le_bytes());

        self.send_current = Some(id);
        Some(len)
    }

    fn send_data(&mut self, _stream: &P2pStreamId, offset: usize) -> Option<&[u8]> {
        let id = self.send_current?;
        Some(&self.data[id][offset..])
    }

    fn send_complete(&mut self, _stream: &P2pStreamId) {
        self.send_current = None;
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
