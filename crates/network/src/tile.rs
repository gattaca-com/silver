use std::{
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use mio::{Events, Poll, Token};
use quinn_proto::Transmit;
use secp256k1::PublicKey;
use silver_common::{
    GossipMsgOut, P2pSend, PeerControl, PeerEvent, RpcInbound, RpcOutbound, SilverSpine,
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

pub struct NetworkTile {
    inner: NetworkTileInner<DiscV5>,
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
        Ok(Self { inner })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        self.inner.p2p_mut()
    }

    fn handle_peer_control(&mut self, peer_control: PeerControl, now: Instant) {
        match peer_control {
            PeerControl::Ban { p2p, p2p_connection: _ } => {
                if let Ok(pubkey) = PublicKey::from_slice(p2p.pubkey()) {
                    self.inner.discovery.ban_node(pubkey.into());
                }
                self.inner.p2p_endpoint.ban_peer(p2p);
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
                    tracing::debug!(?addr, "dialling p2p peer");
                    if let Err(e) = self.inner.p2p_endpoint.connect(p2p, addr, now) {
                        tracing::error!(?e, ?p2p, ?addr, "failed to initiate p2p to peer");
                    }
                } else {
                    tracing::warn!(?enr, "cannot dial peer with no quic endpoint");
                }
            }
            _ => {} // no-ops for this tile
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
        // Consume peer control messages
        let now = Instant::now();
        adapter.consume(|peer_control: PeerControl, _producers| {
            self.handle_peer_control(peer_control, now);
        });

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
            },
            Event::Discovery(disc_event) => match disc_event {
                DiscoveryEvent::NodeFound(enr) => {
                    adapter.produce(PeerEvent::DiscNodeFound { enr });
                }
                DiscoveryEvent::ExternalAddrChanged(socket_addr) => {
                    adapter.produce(PeerEvent::DiscExternalAddress { address: socket_addr });
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
                let result = match msg {
                    P2pSend::Gossip(gossip_msg_out) => {
                        gossips += 1;
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
                            }
                            .into()),
                        );
                    }
                    p2p::SendResult::MessageDropped => {
                        producers.peer_events.produce(
                            &(PeerEvent::P2pOutboundMessageDropped {
                                p2p_peer: msg.peer_id(),
                                protocol: msg.protocol(),
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

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }

    pub fn enqueue_gossip(&mut self, msg: GossipMsgOut) -> SendResult {
        self.p2p_endpoint.enqueue_gossip(msg, &mut self.context)
    }

    pub fn enqueue_rpc_out(&mut self, msg: RpcOutbound) -> SendResult {
        self.p2p_endpoint.enqueue_rpc_out(msg, &mut self.context)
    }

    pub fn spin<E>(&mut self, on_event: &mut E)
    where
        E: FnMut(Event) + Send,
    {
        if let Err(e) = self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            tracing::error!(error=?e, "poll");
            return;
        }

        let now = Instant::now();

        for evt in &self.events {
            if evt.token() == DISC_SOCKET_TOKEN && evt.is_readable() {
                self.disc_socket.recv(|data, remote, _scratch, _socket| {
                    NetworkCounters::DiscBytesRecv.add(data.len() as u64);
                    self.discovery.handle(remote, &data[..], now);
                    true
                });
            } else if evt.token() == P2P_SOCKET_TOKEN && evt.is_readable() {
                self.p2p_socket.recv(|data, remote, scratch, socket| {
                    NetworkCounters::P2pBytesRecv.add(data.len() as u64);
                    self.p2p_endpoint.recv(now, data, remote, scratch, socket)
                });
            }
        }

        p2p::p2p_spin(
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
            DiscoveryEvent::ExternalAddrChanged(addr) => {
                if let Some(identify) = self.context.identify.as_mut() {
                    match self.p2p_endpoint.update_identify_record(identify, addr.ip()) {
                        Ok(new_identify) => *identify = new_identify,
                        Err(e) => {
                            tracing::error!(?addr, ?e, "failed to update identify record ip");
                        }
                    }
                }
            }
            other => on_event(Event::Discovery(other)),
        });

        self.context.gossip_consumer.free();
        self.context.rpc_consumer.free();
    }
}
