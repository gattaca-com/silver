use std::{
    io::Write,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    thread,
    time::{Duration, Instant},
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use quinn_proto::{Endpoint, EndpointConfig};
use rand::{Rng, RngCore, SeedableRng};
use silver_common::{GossipMsgOut, Keypair, P2pStreamId, TCache, TCacheProducer};
use silver_discovery::Discovery;
use silver_network::{Context, NetEvent, NetworkTileEvent, NetworkTileInner, P2p, SendResult};
use tracing::Level;

const BATCH_SIZE: usize = 8192 * 10;

pub fn broadcast(c: &mut Criterion) {
    let _guard = tracing_subscriber::fmt().with_max_level(Level::WARN).init();

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
                        let gi_producer = TCache::producer(2 << 24);
                        let mut gi_consumer = gi_producer.cache_ref().consumer().unwrap();
                        let go_producer = TCache::producer(32);
                        let go_consumer = go_producer.cache_ref().random_access().unwrap();
                        let rpc_in = TCache::producer(32);
                        let rpc_out = rpc_in.cache_ref().random_access().unwrap();

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

                            let context = Context {
                                gossip_producer: gi_producer,
                                gossip_consumer: go_consumer,
                                rpc_producer: rpc_in,
                                rpc_consumer: rpc_out,
                                identify: None,
                            };

                            let p2p = P2p::new(keypair, server_endpoint);
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

                        let server_handle = std::thread::spawn(move || {
                            let mut recv = 0;
                            loop {
                                server_tile.spin(&mut |_: NetworkTileEvent| {});
                                while let Ok((read, _)) = gi_consumer.read() {
                                    recv += read.len() - size_of::<P2pStreamId>();
                                    gi_consumer.free();
                                }

                                if recv == (total * i) {
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

                            let gi_producer = TCache::producer(32);
                            let mut go_producer = TCache::producer(2 << 28);
                            let go_consumer = go_producer.cache_ref().random_access().unwrap();
                            let rpc_in = TCache::producer(32);
                            let rpc_out = rpc_in.cache_ref().random_access().unwrap();

                            let context = Context {
                                gossip_producer: gi_producer,
                                gossip_consumer: go_consumer,
                                rpc_producer: rpc_in,
                                rpc_consumer: rpc_out,
                                identify: None,
                            };

                            let addr = format!("127.0.0.1:{}", 20002 + n);
                            let mut p2p = P2p::new(keypair, client_endpoint);
                            p2p.connect(
                                server_id.clone(),
                                "127.0.0.1:20001".parse().unwrap(),
                                Instant::now(),
                            )
                            .unwrap();

                            let tile = NetworkTileInner::new(
                                addr.parse().unwrap(),
                                p2p,
                                context,
                                format!("0.0.0.0:{}", 12346 + n).parse().unwrap(),
                                DummyDisc,
                            )
                            .unwrap();

                            // stage msgs
                            let mut msgs = vec![];
                            for datum in &data {
                                let mut reservation =
                                    go_producer.reserve(datum.len(), true).unwrap();
                                reservation.write_all(datum.as_slice()).unwrap();

                                msgs.push(GossipMsgOut { peer_id: 0, tcache: reservation.read() });
                            }
                            msgs.reverse();

                            clients.push((tile, msgs));
                        }

                        std::thread::sleep(Duration::from_millis(200));
                        (server_handle, clients)
                    },
                    |(handle, clients)| {
                        let run = Arc::new(AtomicBool::new(true));
                        for (mut client, mut msgs) in clients {
                            let run = run.clone();
                            thread::spawn(move || {
                                while run.load(Ordering::Relaxed) {
                                    let mut r_peer = None;
                                    client.spin(&mut |evt| match evt {
                                        NetworkTileEvent::P2pNet(net_event) => match net_event {
                                            NetEvent::PeerConnected { peer, .. } => {
                                                r_peer.replace(peer);
                                            }
                                            _ => {}
                                        },
                                        NetworkTileEvent::Discovery(_) => {}
                                    });
                                    if client.p2p_mut().pending(0) < 1000 &&
                                        let Some(msg) = msgs.last()
                                    {
                                        let result = client.p2p_mut().enqueue_gossip(*msg);
                                        if result == SendResult::Ok {
                                            msgs.pop();
                                            //println!("enqueue_gossip failed:
                                            // {result:?}");
                                        };
                                    }
                                }
                            });
                        }

                        while !handle.is_finished() {
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        handle.join().unwrap();
                        run.store(false, Ordering::Relaxed);
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
