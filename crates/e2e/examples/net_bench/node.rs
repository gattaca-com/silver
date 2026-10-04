use std::{
    io,
    net::SocketAddr,
    path::Path,
    process,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    Enr, GossipMsgIn, GossipMsgOut, Identify, Keypair, P2pSend, PeerEvent, PeerId, ProtoIdentify,
    SilverSpine, TCache, TCacheId, TCacheProducer, TCacheRead, TCacheReader, TCacheTable,
    TProducer, TReadMode,
};
use silver_config::{DiscoveryConfig, NetworkConfig};
use silver_discovery::DiscV5;
use silver_network::{Context, NetworkTile, P2p, create_endpoint, create_server_config};

use crate::probe::InboundFrame;

const GOSSIP_CACHE_SIZE: usize = 1 << 25;

/// Spine identity for the bench's own adapter.
struct Bench;

impl Tile<SilverSpine> for Bench {
    fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {}
}

/// A network tile driven directly: the bench writes outbound gossip frames
/// and reads inbound ones, standing in for every other tile.
pub struct Node {
    pub network: NetworkTile,
    network_adapter: SpineAdapter<SilverSpine>,
    bench_adapter: SpineAdapter<SilverSpine>,
    outbound: TProducer,
    ingress: TCacheReader,
    pub peer_id: PeerId,
    /// Live connections to `peer_id`, in connect order.
    pub connections: Vec<usize>,
    pub disconnects: u64,
    // The network tile reads these; nothing writes them.
    _unused_outbound: [TProducer; 3],
    _spine: SilverSpine,
}

impl Node {
    pub fn new(
        base_dir: &Path,
        listen: SocketAddr,
        keypair: Keypair,
        peer_id: PeerId,
        network_config: &NetworkConfig,
    ) -> io::Result<Self> {
        let ingress_producer = TCache::producer(TCacheId::NetworkIngress, GOSSIP_CACHE_SIZE);
        let ingress =
            TCacheReader::single(ingress_producer.cache_ref(), "bench", TReadMode::Sliding)
                .map_err(io::Error::other)?;
        let outbound = TCache::producer(TCacheId::ControlGossip, GOSSIP_CACHE_SIZE);
        let unused_outbound = [
            TCache::producer(TCacheId::StorageDelivery, 1 << 12),
            TCache::producer(TCacheId::ControlRpc, 1 << 12),
            TCache::producer(TCacheId::ClusterOutbound, 1 << 12),
        ];
        let reader = TCacheReader::new(TCacheTable::from_iter(
            std::iter::once(&outbound).chain(&unused_outbound).map(|p| p.cache_ref()),
        ));
        let context = Context {
            gossip_producer: ingress_producer,
            rpc_producer: TCache::producer(TCacheId::NetworkProcessing, 1 << 12),
            identify: Some(ProtoIdentify::from((&Identify::default(), &keypair))),
            cluster_nodes: None,
            cluster_inbound_producer: TCache::producer(TCacheId::ClusterInbound, 1 << 12),
            partial_columns: false,
            reader,
        };

        let discovery_addr = SocketAddr::new(listen.ip(), listen.port() + 1);
        let discovery = DiscV5::new(
            DiscoveryConfig::default(),
            *keypair.secret_key(),
            Enr::empty(keypair.secret_key()).map_err(io::Error::other)?,
            [0, 0, 0, 0],
        );
        let server_config = create_server_config(&keypair)?;
        let endpoint = create_endpoint(Some(Arc::new(server_config)))?;
        let p2p = P2p::new(keypair, endpoint, 1024, Default::default());
        let mut network =
            NetworkTile::new(discovery_addr, discovery, listen, p2p, context, network_config)
                .map_err(io::Error::other)?;
        network.open_tcaches().map_err(io::Error::other)?;

        let mut spine = SilverSpine::new_with_base_dir(base_dir, Some("_bench"));
        let network_adapter = SpineAdapter::connect_tile(&network, &mut spine);
        let bench_adapter = SpineAdapter::connect_tile(&Bench, &mut spine);
        Ok(Self {
            network,
            network_adapter,
            bench_adapter,
            outbound,
            ingress,
            peer_id,
            connections: Vec::new(),
            disconnects: 0,
            _unused_outbound: unused_outbound,
            _spine: spine,
        })
    }

    /// One network pass, then each inbound probe.
    pub fn spin(&mut self, mut on_probe: impl FnMut(&mut TProducer, &Inbound)) {
        self.outbound.loop_start();
        self.network.loop_body(&mut self.network_adapter);

        let (peer_id, connections, disconnects) =
            (self.peer_id, &mut self.connections, &mut self.disconnects);
        self.bench_adapter.consume::<PeerEvent, _>(|event, _| match event {
            PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. }
                if peer_id_full == peer_id =>
            {
                connections.push(p2p_peer_id);
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => {
                if let Some(index) = connections.iter().position(|c| *c == p2p_peer) {
                    connections.remove(index);
                    *disconnects += 1;
                }
            }
            _ => {}
        });

        let (ingress, outbound) = (&mut self.ingress, &mut self.outbound);
        self.bench_adapter.consume::<GossipMsgIn, _>(|msg, _| {
            let acquired = ingress.acquire(msg.tcache);
            let Ok((frame, committed)) = acquired.buffer() else { return };
            if let Some(frame) = InboundFrame::parse(frame) {
                let connection = msg.p2p_id.peer();
                on_probe(outbound, &Inbound { connection, committed_ns: committed.0, frame });
            }
        });
        self.ingress.free();
    }

    pub fn wait_for_connections(&mut self, count: usize, timeout: Option<Duration>) {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        while self.connections.len() < count {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                eprintln!(
                    "{} of {count} connections to {:?} before the deadline",
                    self.connections.len(),
                    self.peer_id
                );
                process::exit(1);
            }
            self.spin(|_, _| {});
        }
    }

    pub fn disconnect_all(&mut self) {
        let now = Instant::now();
        for &connection in &self.connections {
            self.network.p2p_mut().disconnect(connection, now);
        }
    }

    pub fn outbound(&mut self) -> &mut TProducer {
        &mut self.outbound
    }

    pub fn send(&mut self, connection: usize, tcache: TCacheRead) {
        self.bench_adapter.produce(P2pSend::Gossip(GossipMsgOut { peer_id: connection, tcache }));
    }
}

pub struct Inbound<'a> {
    pub connection: usize,
    /// When the network tile committed the frame to NetworkIngress.
    pub committed_ns: u64,
    pub frame: InboundFrame<'a>,
}
