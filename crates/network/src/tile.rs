use std::{
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use flux_profiler::timed;
use quinn_proto::Transmit;
use secp256k1::PublicKey;
use silver_common::{
    BeaconStateEvent, ClusterIn, ClusterMsgIn, ClusterMsgOut, GossipMsgIn, GossipMsgOut,
    IngestionTime, P2pSend, PeerControl, PeerEvent, PeerStats, RpcOutbound, SLOTS_PER_EPOCH,
    SilverSpine, TCacheError,
};
use silver_config::NetworkConfig;
use silver_discovery::{DiscV5, Discovery, DiscoveryEvent};

use crate::{
    NetEvent, NetworkCounters, SendResult,
    network_io::{NetworkIo, SocketId},
    p2p::{Context, P2p},
};

const MAX_PENDING_OUTBOUND_GOSSIP_MSGS: usize = 1024;
const MAX_PENDING_OUTBOUND_RPC_MSGS: usize = 128;

#[cfg(feature = "thread_park")]
const POLL_TIMEOUT: Duration = Duration::from_millis(10);
#[cfg(not(feature = "thread_park"))]
const POLL_TIMEOUT: Duration = Duration::ZERO;

const PEER_STATS_INTERVAL: Duration = Duration::from_millis(100);
const PEER_STATS_BATCH: usize = 8;

pub struct NetworkTile {
    inner: NetworkTileInner<DiscV5>,
    last_peer_stats: Instant,
    last_fork_epoch: Option<u64>,
}

impl NetworkTile {
    pub fn new(
        discv5_addr: SocketAddr,
        discv5: DiscV5,
        p2p_addr: SocketAddr,
        p2p_endpoint: P2p,
        p2p_context: Context,
        config: &NetworkConfig,
    ) -> Result<Self, Error> {
        let inner = NetworkTileInner::new(
            p2p_addr,
            p2p_endpoint,
            p2p_context,
            discv5_addr,
            discv5,
            config,
        )?;
        Ok(Self { inner, last_peer_stats: Instant::now(), last_fork_epoch: None })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        self.inner.p2p_mut()
    }

    #[timed]
    fn handle_peer_control(&mut self, peer_control: PeerControl, now: Instant) {
        match peer_control {
            PeerControl::Ban { p2p } => {
                if let Ok(pubkey) = PublicKey::from_slice(p2p.pubkey()) {
                    self.inner.discovery.ban_node(pubkey.into());
                }
                self.inner.p2p_endpoint.ban_peer(p2p, now);
            }
            PeerControl::Unban { p2p } => {
                if let Ok(pubkey) = PublicKey::from_slice(p2p.pubkey()) {
                    self.inner.discovery.unban_node(pubkey.into());
                }
                self.inner.p2p_endpoint.unban_peer(p2p);
            }
            PeerControl::BanIp { ip } => {
                self.inner.io.ban(ip);
            }
            PeerControl::UnbanIp { ip } => {
                self.inner.io.unban(ip);
            }
            PeerControl::DiscoverNodes => self.inner.discovery.find_nodes(),
            PeerControl::UpdateEnrForkId { epoch, enr_fork_id } => {
                self.update_enr_fork_id(epoch, enr_fork_id)
            }
            PeerControl::UpdateEnrSyncnets { syncnets } => {
                self.inner.discovery.update_enr_syncnets(syncnets)
            }
            PeerControl::P2pDial { p2p, enr } => {
                let addr = enr.quic4_socket().or(enr.quic6_socket());
                if let Some(addr) = addr {
                    crate::NetworkCounters::DialAttempts.inc();
                    silver_log::info!(peer_id=?p2p, ?addr, "dialling p2p peer");
                    if let Err(e) = self.inner.p2p_endpoint.connect(p2p, addr, now) {
                        silver_log::error!(?e, ?p2p, ?addr, "failed to initiate p2p to peer");
                    }
                } else {
                    silver_log::warn!(?enr, "cannot dial peer with no quic endpoint");
                }
            }
            PeerControl::P2pDisconnect { p2p: _, p2p_connection } => {
                self.inner.p2p_endpoint.disconnect(p2p_connection, now);
            }
            _ => {} // no-ops for this tile
        }
    }

    fn update_enr_fork_id(&mut self, epoch: u64, enr_fork_id: [u8; 16]) {
        if self.last_fork_epoch.is_none_or(|previous| epoch >= previous) {
            self.last_fork_epoch = Some(epoch);
            self.inner.update_enr_fork_id(enr_fork_id);
        }
    }

    fn body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.inner.context.loop_start();
        // Consume peer control messages
        let now = Instant::now();
        adapter.consume(|peer_control: PeerControl, _producers| {
            self.handle_peer_control(peer_control, now);
        });

        adapter.consume(|beacon_event: BeaconStateEvent, _producers| {
            if let BeaconStateEvent::Status { enr_fork_id, wall_slot, .. } = beacon_event {
                self.update_enr_fork_id(wall_slot / SLOTS_PER_EPOCH, enr_fork_id);
            }
        });

        adapter.consume(|cluster_event: ClusterMsgOut, producers| {
            match self.inner.enqueue_cluster_out(cluster_event) {
                SendResult::Ok => {}
                other => {
                    silver_log::warn!(?other, "cluster node unreachable");
                    producers
                        .cluster_inbound
                        .produce(&ClusterIn::NodeUnreachable(cluster_event.to).into());
                }
            }
        });

        if now.duration_since(self.last_peer_stats) >= PEER_STATS_INTERVAL {
            self.last_peer_stats = now;
            self.inner.p2p_endpoint.sample_stats(now, PEER_STATS_BATCH, &mut |stats| {
                adapter.produce(PeerStats::P2p(stats));
            });
        }

        let mut on_event = |event| {
            on_event(event, adapter);
        };

        let network_work = self.inner.spin(&mut on_event);

        let mut rpcs = 0;
        let mut gossips = 0;
        self.inner.send_drained = false;

        loop {
            if rpcs > MAX_PENDING_OUTBOUND_RPC_MSGS || gossips > MAX_PENDING_OUTBOUND_GOSSIP_MSGS {
                break;
            }

            if !adapter.consume_one(|msg: P2pSend, producers| {
                let result = match msg {
                    P2pSend::Gossip(gossip_msg_out) => {
                        gossips += 1;
                        silver_log::debug!(peer=gossip_msg_out.peer_id, "send gossip");
                        self.inner.enqueue_gossip(gossip_msg_out)
                    },
                    P2pSend::SegmentedGossip { peer_id, frame, partial_cells } => {
                        gossips += 1;
                        self.inner.p2p_endpoint.enqueue_segmented_gossip(
                            peer_id, frame, partial_cells, &mut self.inner.context,
                        )
                    }
                    P2pSend::Identify(peer) => {
                        self.inner.p2p_endpoint.enqueue_identify(peer)
                    }
                    P2pSend::Rpc(rpc_outbound) => {
                        rpcs += 1;
                        self.inner.enqueue_rpc_out(rpc_outbound)
                    },
                };
                let dropped = match result {
                    SendResult::Ok => None,
                    SendResult::Dropped(Some(msg)) => Some(msg),
                    SendResult::Dropped(None) => {
                        silver_log::error!(
                            peer = msg.peer_id(),
                            protocol = ?msg.protocol(),
                            "endpoint dropped a message without identifying it"
                        );
                        None
                    }
                    SendResult::StreamCreationError | SendResult::StreamGone => {
                        producers.produce(PeerEvent::P2pCannotCreateStream {
                            p2p_peer: msg.peer_id(),
                            protocol: msg.protocol(),
                            stream_gone: matches!(result, SendResult::StreamGone),
                        });
                        Some(msg)
                    }
                    SendResult::ConnectionClosing => {
                        silver_log::debug!(
                            peer = msg.peer_id(),
                            protocol = ?msg.protocol(),
                            "send refused: connection closing"
                        );
                        Some(msg)
                    }
                    SendResult::UnknownPeer => {
                        // Can happen if peer has disconnected.
                        silver_log::debug!(peer=msg.peer_id(), protocol=?msg.protocol(), "Tried to send to unknown peer");
                        Some(msg)
                    }
                };
                if let Some(msg) = dropped {
                    producers.produce(PeerEvent::P2pOutboundMessageDropped {
                        p2p_peer: msg.peer_id(),
                        protocol: msg.protocol(),
                        msg,
                    });
                }
            }) {
                self.inner.send_drained = true;
                break;
            };
        }
        network_work
    }
}

#[timed]
fn on_event(event: Event, adapter: &mut SpineAdapter<SilverSpine>) {
    adapter.set_ingestion_time(IngestionTime::now());
    match event {
        Event::P2pNet(net_event) => match net_event {
            NetEvent::PeerConnected { peer, addr, local_dialler } => {
                let port = addr.port();
                adapter.produce(PeerEvent::P2pNewConnection {
                    p2p_peer_id: peer.connection,
                    peer_id_full: peer.peer_id,
                    ip: addr.ip().into(),
                    port,
                    local_dial: local_dialler,
                });
            }
            NetEvent::PeerIdentify { peer, identify } => {
                adapter.produce(PeerEvent::P2pPeerIdentity { p2p_peer: peer, identify });
            }
            NetEvent::PeerDisconnected { peer } => {
                adapter.produce(PeerEvent::P2pDisconnect {
                    p2p_peer: peer.connection,
                    peer_id: peer.peer_id,
                });
            }
            NetEvent::StreamReady { stream: _ } => {
                // TODO notifiy new stream?
            }
            NetEvent::StreamClosed { stream } => {
                adapter.produce(PeerEvent::P2pStreamClosed { stream_id: stream });
            }
            NetEvent::RpcInbound(rpc_inbound) => {
                adapter.produce(rpc_inbound);
            }
            NetEvent::RpcMisbehaviour { p2p_peer, severity } => {
                adapter.produce(PeerEvent::RpcMisbehaviour { p2p_peer, severity });
            }
            NetEvent::Gossip { stream, msg } => {
                //let ts = adapter.producers.timestamp().
                // with_ingestion_t(IngestionTime::now()); let msg =
                // InternalMessage::new(ts, GossipMsgIn { p2p_id: stream, tcache: msg });
                adapter.produce(GossipMsgIn { p2p_id: stream, tcache: msg });
            }
            NetEvent::Cluster { stream: _, raft_id, msg } => {
                adapter.produce(ClusterIn::Msg(ClusterMsgIn { from: raft_id, data: msg }));
            }
        },
        Event::Discovery(disc_event) => match disc_event {
            DiscoveryEvent::NodeFound(enr) => {
                adapter.produce(PeerEvent::DiscNodeFound { enr, reload: false });
            }
            DiscoveryEvent::ExternalAddrChanged(socket_addr, seq) => {
                adapter
                    .produce(PeerEvent::DiscExternalAddress { address: socket_addr, seq });
            }
            _ => {} // no-ops
        },
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Event {
    P2pNet(NetEvent),
    Discovery(DiscoveryEvent),
}

impl NetworkTile {
    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.inner.context.open_tcaches()
    }
}

impl Tile<SilverSpine> for NetworkTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // Snapshot before checking any spine queue; a racing producer must prevent
        // sleep.
        self.inner.io.start_loop();
        let network_work = self.body(adapter);
        if !network_work && !adapter.did_work() {
            let timeout =
                self.inner.p2p_endpoint.timeout().unwrap_or(POLL_TIMEOUT).min(POLL_TIMEOUT);
            if let Err(error) = self.inner.io.wait(timeout) {
                silver_log::error!(?error, "network wait failed");
            }
        }
    }

    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        #[cfg(feature = "thread_park")]
        self.inner.io.register_spine_waker().expect("failed to create network waker");
        true
    }

    fn teardown(mut self, _adapter: &mut SpineAdapter<SilverSpine>) {
        // Enqueue goodbyes
        self.inner.goodbye_all();
        self.inner.p2p_endpoint.poll(
            Instant::now(),
            &mut self.inner.io,
            &mut self.inner.context,
            &mut |_| {},
        );

        // Close all p2p connections
        self.p2p_mut().shutdown();
        self.inner.p2p_endpoint.poll(
            Instant::now(),
            &mut self.inner.io,
            &mut self.inner.context,
            &mut |_| {},
        );
    }
}

pub struct NetworkTileInner<D>
where
    D: Discovery,
{
    io: NetworkIo,
    p2p_endpoint: P2p,
    context: Context,
    discovery: D,
    // The last send pass ran the `P2pSend` queue empty; licenses snapshots.
    send_drained: bool,
}

impl<D> NetworkTileInner<D>
where
    D: Discovery,
{
    pub fn new(
        p2p_addr: SocketAddr,
        p2p_endpoint: P2p,
        context: Context,
        discovery_addr: SocketAddr,
        discovery: D,
        config: &NetworkConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            io: NetworkIo::new(p2p_addr, discovery_addr, config)?,
            p2p_endpoint,
            context,
            discovery,
            send_drained: true,
        })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        &mut self.p2p_endpoint
    }

    pub fn update_enr_fork_id(&mut self, eth2: [u8; 16]) {
        self.discovery.update_enr_fork_id(eth2);
    }

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }

    pub fn enqueue_gossip(&mut self, msg: GossipMsgOut) -> SendResult {
        self.p2p_endpoint.enqueue_gossip(msg, &mut self.context)
    }

    pub fn enqueue_rpc_out(&mut self, msg: RpcOutbound) -> SendResult {
        self.p2p_endpoint.enqueue_rpc_out(msg, &mut self.context)
    }

    pub fn enqueue_cluster_out(&mut self, msg: ClusterMsgOut) -> SendResult {
        self.p2p_endpoint.enqueue_cluster_out(msg, &mut self.context)
    }

    pub fn goodbye_all(&mut self) {
        self.p2p_endpoint.goodbye_all(&mut self.context);
    }

    pub fn spin<E>(&mut self, on_event: &mut E) -> bool
    where
        E: FnMut(Event) + Send,
    {
        let mut did_work = false;

        let now = Instant::now();

        if let Err(error) = self.io.recv(|socket, data, remote, scratch| {
            did_work = true;
            match socket {
                SocketId::Discovery => {
                    NetworkCounters::DiscBytesRecv.add(data.len() as u64);
                    self.discovery.handle(remote, &data, now);
                    None
                }
                SocketId::Quic => {
                    NetworkCounters::P2pBytesRecv.add(data.len() as u64);
                    self.p2p_endpoint.recv(now, data, remote, scratch)
                }
            }
        }) {
            silver_log::error!(?error, "network receive failed");
        }

        did_work |= self
            .p2p_endpoint
            .poll(now, &mut self.io, &mut self.context, &mut |evt| on_event(Event::P2pNet(evt)));

        self.io.flush(SocketId::Discovery);
        self.discovery.poll(|disc_event| match disc_event {
            DiscoveryEvent::SendMessage { to, data } => {
                did_work = true;
                NetworkCounters::DiscBytesSent.add(data.len() as u64);
                self.io.send(SocketId::Discovery, |buffer| {
                    buffer.extend_from_slice(&data);
                    Some(Transmit {
                        destination: to,
                        ecn: None,
                        size: data.len(),
                        segment_size: None,
                        src_ip: None,
                    })
                });
            }
            DiscoveryEvent::ExternalAddrChanged(addr, seq) => {
                did_work = true;

                if let Some(identify) = self.context.identify.as_mut() {
                    match self.p2p_endpoint.update_identify_record(identify, addr.ip()) {
                        Ok(new_identify) => *identify = new_identify,
                        Err(e) => {
                            silver_log::error!(?addr, ?e, "failed to update identify record ip");
                        }
                    }
                }
                on_event(Event::Discovery(DiscoveryEvent::ExternalAddrChanged(addr, seq)));
            }
            other => on_event(Event::Discovery(other)),
        });

        self.io.flush(SocketId::Discovery);

        if self.send_drained {
            self.context.reader.free();
        } else {
            self.context.reader.free_undrained();
        }
        did_work
    }
}
