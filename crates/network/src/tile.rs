use std::{
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use flux_profiler::timed;
use mio::{Events, Poll, Token};
use quinn_proto::Transmit;
use secp256k1::PublicKey;
use silver_common::{
    BeaconStateEvent, GossipMsgIn, GossipMsgOut, P2pSend, PeerControl, PeerEvent, PeerStats,
    RpcInbound, RpcOutbound, SilverSpine,
};
use silver_discovery::{DiscV5, Discovery, DiscoveryEvent};

use crate::{
    NetEvent, NetworkCounters, SendResult,
    p2p::{self, Context, P2p},
    socket::Socket,
};

const MAX_PENDING_OUTBOUND_GOSSIP_MSGS: usize = 1024;
const MAX_PENDING_OUTBOUND_RPC_MSGS: usize = 128;
const P2P_SOCKET_TOKEN: Token = Token(0);
const DISC_SOCKET_TOKEN: Token = Token(1);

#[cfg(feature = "thread_park")]
const POLL_TIMEOUT: Duration = Duration::from_millis(10);
#[cfg(not(feature = "thread_park"))]
const POLL_TIMEOUT: Duration = Duration::ZERO;

const PEER_STATS_INTERVAL: Duration = Duration::from_millis(100);
const PEER_STATS_BATCH: usize = 8;

pub struct NetworkTile {
    inner: NetworkTileInner<DiscV5>,
    last_peer_stats: Instant,
}

impl NetworkTile {
    pub fn new(
        discv5_addr: SocketAddr,
        discv5: DiscV5,
        p2p_addr: SocketAddr,
        p2p_endpoint: P2p,
        p2p_context: Context,
    ) -> Result<Self, Error> {
        let inner =
            NetworkTileInner::new(p2p_addr, p2p_endpoint, p2p_context, discv5_addr, discv5)?;
        Ok(Self { inner, last_peer_stats: Instant::now() })
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
                self.inner.p2p_socket.ban(ip);
                self.inner.disc_socket.ban(ip);
            }
            PeerControl::UnbanIp { ip } => {
                self.inner.p2p_socket.unban(ip);
                self.inner.disc_socket.unban(ip);
            }
            PeerControl::DiscoverNodes => self.inner.discovery.find_nodes(),
            PeerControl::P2pDial { p2p, enr } => {
                let addr = enr.quic4_socket().or(enr.quic6_socket());
                if let Some(addr) = addr {
                    crate::NetworkCounters::DialAttempts.inc();
                    tracing::info!(peer_id=?p2p, ?addr, "dialling p2p peer");
                    if let Err(e) = self.inner.p2p_endpoint.connect(p2p, addr, now) {
                        tracing::error!(?e, ?p2p, ?addr, "failed to initiate p2p to peer");
                    }
                } else {
                    tracing::warn!(?enr, "cannot dial peer with no quic endpoint");
                }
            }
            PeerControl::P2pDisconnect { p2p: _, p2p_connection } => {
                self.inner.p2p_endpoint.disconnect(p2p_connection, now);
            }
            _ => {} // no-ops for this tile
        }
    }

    fn body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // Consume peer control messages
        let now = Instant::now();
        adapter.consume(|peer_control: PeerControl, _producers| {
            self.handle_peer_control(peer_control, now);
        });

        adapter.consume(|beacon_event: BeaconStateEvent, _producers| {
            if let BeaconStateEvent::Status { enr_fork_id, .. } = beacon_event {
                self.inner.update_enr_fork_id(enr_fork_id);
            }
        });

        if now.duration_since(self.last_peer_stats) >= PEER_STATS_INTERVAL {
            self.last_peer_stats = now;
            self.inner.p2p_endpoint.sample_stats(now, PEER_STATS_BATCH, &mut |stats| {
                adapter.produce(PeerStats::P2p(stats));
            });
        }

        let mut on_event = |event| match event {
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
                    let stream_id = match &rpc_inbound {
                        RpcInbound::Request(req) => req.stream_id,
                        RpcInbound::Response(rsp) => rsp.stream_id,
                    };
                    tracing::debug!(?stream_id, "network: incoming rpc");
                    adapter.produce(rpc_inbound);
                }
                NetEvent::RpcMisbehaviour { p2p_peer, severity } => {
                    adapter.produce(PeerEvent::RpcMisbehaviour { p2p_peer, severity });
                }
                NetEvent::Gossip { stream, msg } => {
                    adapter.produce(GossipMsgIn { p2p_id: stream, tcache: msg });
                }
            },
            Event::Discovery(disc_event) => match disc_event {
                DiscoveryEvent::NodeFound(enr) => {
                    adapter.produce(PeerEvent::DiscNodeFound { enr, reload: false });
                }
                DiscoveryEvent::ExternalAddrChanged(socket_addr, seq) => {
                    adapter.produce(PeerEvent::DiscExternalAddress { address: socket_addr, seq });
                }
                _ => {} // no-ops
            },
        };

        self.inner.spin(&mut on_event);

        let mut rpcs = 0;
        let mut gossips = 0;

        loop {
            if rpcs > MAX_PENDING_OUTBOUND_RPC_MSGS || gossips > MAX_PENDING_OUTBOUND_GOSSIP_MSGS {
                break;
            }

            if !adapter.consume_one(|msg: P2pSend, producers| {
                let rpc_request = matches!(&msg, P2pSend::Rpc(RpcOutbound::Request(_)));
                let result = match msg {
                    P2pSend::Gossip(gossip_msg_out) => {
                        gossips += 1;
                        tracing::debug!(peer=gossip_msg_out.peer_id, "send gossip");
                        self.inner.enqueue_gossip(gossip_msg_out)
                    },
                    P2pSend::Identify(peer) => {
                        self.inner.p2p_endpoint.enqueue_identify(peer)
                    }
                    P2pSend::Rpc(rpc_outbound) => {
                        rpcs += 1;
                        self.inner.enqueue_rpc_out(rpc_outbound)
                    },
                };
                match result {
                    p2p::SendResult::Ok => {}
                    p2p::SendResult::StreamCreationError => {
                        producers.peer_events.produce(
                            &(PeerEvent::P2pCannotCreateStream {
                                p2p_peer: msg.peer_id(),
                                protocol: msg.protocol(),
                                rpc_request,
                            }
                            .into()),
                        );
                    }
                    p2p::SendResult::MessageDropped => {
                        producers.peer_events.produce(
                            &(PeerEvent::P2pOutboundMessageDropped {
                                p2p_peer: msg.peer_id(),
                                protocol: msg.protocol(),
                                rpc_request,
                            }
                            .into()),
                        );
                    }
                    p2p::SendResult::UnknownPeer => {
                        // Can happen if peer has disconnected.
                        tracing::warn!(peer=msg.peer_id(), protocol=?msg.protocol(), "Tried to send to unknown peer");
                    },
                }
            }) {
                break;
            };
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Event {
    P2pNet(NetEvent),
    Discovery(DiscoveryEvent),
}

impl Tile<SilverSpine> for NetworkTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.body(adapter);
    }

    #[cfg(feature = "thread_park")]
    fn try_init(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        const WAKER_TOKEN: Token = Token(3);

        let waker = mio::Waker::new(self.inner.poll.registry(), WAKER_TOKEN)
            .expect("failed to create network waker");
        adapter.register_waker(waker);
        true
    }

    fn teardown(mut self, _adapter: &mut SpineAdapter<SilverSpine>) {
        // Enqueue goodbyes
        self.inner.goodbye_all();
        p2p::p2p_spin(
            &self.inner.poll,
            &mut self.inner.p2p_endpoint,
            &mut self.inner.p2p_socket,
            &mut self.inner.context,
            Instant::now(),
            &mut |_| {},
        );
        self.inner.p2p_socket.flush(&self.inner.poll);

        // Close all p2p connections
        self.p2p_mut().shutdown();
        p2p::p2p_spin(
            &self.inner.poll,
            &mut self.inner.p2p_endpoint,
            &mut self.inner.p2p_socket,
            &mut self.inner.context,
            Instant::now(),
            &mut |_| {},
        );
        self.inner.p2p_socket.flush(&self.inner.poll);
    }
}

pub struct NetworkTileInner<D>
where
    D: Discovery,
{
    p2p_socket: Socket,
    p2p_endpoint: P2p,
    poll: Poll,
    events: Events,
    context: Context,
    disc_socket: Socket,
    discovery: D,
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
    ) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let p2p_socket = Socket::new(p2p_addr, &poll, P2P_SOCKET_TOKEN)?;
        let disc_socket = Socket::new(discovery_addr, &poll, DISC_SOCKET_TOKEN)?;
        Ok(Self {
            p2p_socket,
            p2p_endpoint,
            poll,
            events: Events::with_capacity(8),
            context,
            disc_socket,
            discovery,
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

    pub fn goodbye_all(&mut self) {
        self.p2p_endpoint.goodbye_all(&mut self.context);
    }

    fn poll(&mut self) -> Result<(), Error> {
        let timeout =
            self.p2p_endpoint.timeout().map(|d| d.min(POLL_TIMEOUT)).or(Some(POLL_TIMEOUT));
        self.poll.poll(&mut self.events, timeout)
    }

    pub fn spin<E>(&mut self, on_event: &mut E) -> bool
    where
        E: FnMut(Event) + Send,
    {
        let mut did_work = false;

        if let Err(e) = self.poll() {
            tracing::error!(error=?e, "poll");
            return false;
        }

        let now = Instant::now();

        for evt in &self.events {
            if evt.token() == DISC_SOCKET_TOKEN && evt.is_readable() {
                self.disc_socket.recv(|data, remote, _scratch, _socket| {
                    did_work = true;
                    NetworkCounters::DiscBytesRecv.add(data.len() as u64);
                    self.discovery.handle(remote, &data[..], now);
                    true
                });
            } else if evt.token() == P2P_SOCKET_TOKEN && evt.is_readable() {
                self.p2p_socket.recv(|data, remote, scratch, socket| {
                    did_work = true;
                    NetworkCounters::P2pBytesRecv.add(data.len() as u64);
                    self.p2p_endpoint.recv(now, data, remote, scratch, socket)
                });
            }
        }

        did_work |= p2p::p2p_spin(
            &self.poll,
            &mut self.p2p_endpoint,
            &mut self.p2p_socket,
            &mut self.context,
            now,
            &mut |evt| on_event(Event::P2pNet(evt)),
        );

        self.disc_socket.flush(&self.poll);
        self.discovery.poll(|disc_event| match disc_event {
            DiscoveryEvent::SendMessage { to, data } => {
                did_work = true;
                NetworkCounters::DiscBytesSent.add(data.len() as u64);
                self.disc_socket.send(&self.poll, |buffer| {
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
                            tracing::error!(?addr, ?e, "failed to update identify record ip");
                        }
                    }
                }
                on_event(Event::Discovery(DiscoveryEvent::ExternalAddrChanged(addr, seq)));
            }
            other => on_event(Event::Discovery(other)),
        });

        self.context.gossip_consumer.free();
        self.context.rpc_consumer.free();
        did_work
    }
}
