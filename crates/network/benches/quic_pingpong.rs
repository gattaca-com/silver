use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use flux::timing::Instant;
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, SeedableRng};
use silver_common::{GossipMsgOut, Keypair, P2pStreamId, TCache, TCacheProducer};
use silver_discovery::Discovery;
use silver_network::{Context, NetEvent, NetworkTileEvent, NetworkTileInner, P2p, SendResult};
use tracing::Level;

const BATCH_SIZE: usize = 8192 * 10;

pub fn broadcast(c: &mut Criterion) {
    let _guard = tracing_subscriber::fmt().with_max_level(Level::DEBUG).init();

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
                    let running = Arc::new(AtomicBool::new(true));
                    let gi_producer = TCache::producer(2 << 24);
                    let mut gi_consumer = gi_producer.cache_ref().consumer().unwrap();
                    let mut go_producer = TCache::producer(2 << 24);
                    let go_consumer = go_producer.cache_ref().random_access(false).unwrap();
                    let rpc_in = TCache::producer(32);
                    let rpc_out = rpc_in.cache_ref().random_access(false).unwrap();

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

                        let context = Context {
                            gossip_producer: gi_producer,
                            gossip_consumer: go_consumer,
                            rpc_producer: rpc_in,
                            rpc_consumer: rpc_out,
                            identify: None,
                        };

                        (
                            NetworkTileInner::new(
                                "0.0.0.0:20001".parse().unwrap(),
                                p2p,
                                context,
                                "0.0.0.0:12345".parse().unwrap(),
                                DummyDisc,
                            )
                            .unwrap(),
                            server_id,
                        )
                    };

                    let r = running.clone();
                    let server_handle = std::thread::spawn(move || {
                        while r.load(Ordering::Relaxed) {
                            server_tile.spin(&mut |_: NetworkTileEvent| {});
                            while let Ok((read, _)) = gi_consumer.read() {
                                for _ in 0..2 {
                                    if let Some(mut reservation) = go_producer
                                        .reserve(read.len() - size_of::<P2pStreamId>(), true)
                                    {
                                        let id: &P2pStreamId = read.into();
                                        reservation
                                            .write_all(&read[size_of::<P2pStreamId>()..])
                                            .unwrap();
                                        if server_tile.enqueue_gossip(GossipMsgOut {
                                            peer_id: id.peer(),
                                            tcache: reservation.read(),
                                        }) != SendResult::Ok
                                        {
                                            println!("send failed!");
                                        }
                                        break;
                                    } else {
                                        // try again
                                    }
                                }
                                gi_consumer.free();
                            }
                        }
                    });

                    let data = data.clone();
                    let secret = secp256k1::SecretKey::new(&mut rng);
                    let key_bytes: [u8; 32] = secret.secret_bytes();
                    let keypair = Keypair::from_secret(&key_bytes).unwrap();
                    let client_endpoint =
                        Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);

                    let gi_producer = TCache::producer(2 << 24);
                    let gi_consumer = gi_producer.cache_ref().consumer().unwrap();
                    let go_producer = TCache::producer(2 << 28);
                    let go_consumer = go_producer.cache_ref().random_access(false).unwrap();
                    let rpc_in = TCache::producer(32);
                    let rpc_out = rpc_in.cache_ref().random_access(false).unwrap();

                    let context = Context {
                        gossip_producer: gi_producer,
                        gossip_consumer: go_consumer,
                        rpc_producer: rpc_in,
                        rpc_consumer: rpc_out,
                        identify: None,
                    };

                    let addr = "127.0.0.1:20002";
                    let mut p2p = P2p::new(keypair, client_endpoint);
                    p2p.connect(
                        server_id.clone(),
                        "127.0.0.1:20001".parse().unwrap(),
                        StdInstant::now(),
                    )
                    .unwrap();

                    let client = NetworkTileInner::new(
                        addr.parse().unwrap(),
                        p2p,
                        context,
                        "0.0.0.0:12346".parse().unwrap(),
                        DummyDisc,
                    )
                    .unwrap();

                    let h = hdrhistogram::Histogram::<u64>::new_with_max(1000000, 3).unwrap();
                    std::thread::sleep(Duration::from_millis(200));
                    (server_handle, client, h, go_producer, gi_consumer, running, data)
                },
                |(handle, mut client, mut h, mut producer, mut consumer, running, mut data)| {
                    let mut count = 0;
                    let mut r_peer = None;

                    while count < total {
                        client.spin(&mut |evt| match evt {
                            NetworkTileEvent::P2pNet(net_event) => match net_event {
                                NetEvent::PeerConnected { peer, .. } => {
                                    r_peer.replace(peer);
                                }
                                _ => {}
                            },
                            NetworkTileEvent::Discovery(_) => {}
                        });

                        while let Ok((read, _)) = consumer.read() {
                            let buf = &read[size_of::<P2pStreamId>()..];
                            count += buf.len();
                            let instant = u64::from_le_bytes(buf[..8].try_into().unwrap());
                            let elapsed = Instant(instant).elapsed().as_micros_u64();
                            let _ = h.record(elapsed);
                            consumer.free();
                        }

                        // Try to send a msg
                        if r_peer.is_some() &&
                            !client.p2p_mut().has_pending_outbound(0) &&
                            let Some(mut datum) = data.pop()
                        {
                            let now = Instant::now().0;
                            datum[..8].copy_from_slice(&now.to_le_bytes());
                            let mut reservation = match producer.reserve(datum.len(), true) {
                                Some(r) => r,
                                None => {
                                    println!("failed to reserve");
                                    continue;
                                }
                            };
                            match reservation.write(&datum.as_slice()) {
                                Ok(x) if x == datum.len() => {}
                                Ok(n) => {
                                    println!("only wrote {n} of {}", datum.len());
                                    continue;
                                }
                                Err(e) => {
                                    println!("failed to write {e:}");
                                    continue;
                                }
                            };
                            let msg = GossipMsgOut { peer_id: 0, tcache: reservation.read() };
                            match client.enqueue_gossip(msg) {
                                SendResult::Ok => {}
                                other => {
                                    println!("send failed! {other:?}");
                                }
                            }
                        };
                    }
                    running.store(false, Ordering::Relaxed);
                    let p10 = h.value_at_quantile(0.1);
                    let p50 = h.value_at_quantile(0.5);
                    let p99 = h.value_at_quantile(0.99);

                    println!("{count}: p10: {p10}, p50: {p50}, p99: {p99}");
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

struct DummyDisc;
impl Discovery for DummyDisc {
    fn local_id(&self) -> silver_common::NodeId {
        silver_common::NodeId::random()
    }

    fn add_enr(&mut self, _enr: &silver_common::Enr, _now: std::time::Instant) {}

    fn find_nodes(&mut self) {}

    fn ban_node(&mut self, _id: silver_common::NodeId) {}

    fn ban_ip(&mut self, _ip: std::net::IpAddr, _duration: Option<Duration>) {}

    fn teardown(&self) {}
    fn handle(&mut self, _src_addr: std::net::SocketAddr, _data: &[u8], _now: std::time::Instant) {}

    fn poll<F: FnMut(silver_discovery::DiscoveryEvent)>(&mut self, _f: F) {}

    fn unban_node(&mut self, _id: silver_common::NodeId) {}

    fn unban_ip(&mut self, _ip: std::net::IpAddr) {}
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = broadcast
}
criterion_main!(benchmark);
