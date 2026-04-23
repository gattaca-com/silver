use std::{
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use mio::{Events, Poll, Token};
use quinn_proto::Transmit;
use silver_common::{
    GossipMsgOut, P2pStreamId, PeerEvent, RpcMsgOut, RpcOutType, SilverSpine, StreamProtocol,
};
use silver_discovery::{DiscV5, Discovery, DiscoveryEvent, DiscoveryNetworking};

use crate::{
    NetEvent, StreamData, TCacheStreamData,
    p2p::{self, MAX_PENDING_OUTBOUND_MSGS, P2p},
    socket::Socket,
};

const P2P_SOCKET_TOKEN: Token = Token(0);
const DISC_SOCKET_TOKEN: Token = Token(1);

pub struct NetworkTile {
    inner: NetworkTileInner<TCacheStreamData, DiscV5>,
}

impl NetworkTile {
    pub fn new(
        discv5_addr: SocketAddr,
        discv5: DiscV5,
        p2p_addr: SocketAddr,
        p2p_endpoint: P2p,
        p2p_stream_handler: TCacheStreamData,
    ) -> Result<Self, Error> {
        let inner =
            NetworkTileInner::new(p2p_addr, p2p_endpoint, p2p_stream_handler, discv5_addr, discv5)?;
        Ok(Self { inner })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        self.inner.p2p_mut()
    }

    pub fn stream_data_mut(&mut self) -> &mut TCacheStreamData {
        self.inner.data_mut()
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Event {
    P2pNet(NetEvent),
    Discovery(DiscoveryEvent),
}

impl Tile<SilverSpine> for NetworkTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // TODO consume peer 'control' messages
        // - ban
        // - ban ip
        // - request more peers

        let mut on_event = |event| match event {
            Event::P2pNet(net_event) => match net_event {
                NetEvent::PeerConnected { peer, addr } => {
                    // TODO start identity exchange
                    // TODO start status exchange?
                    let port = addr.port();
                    adapter.produce(PeerEvent::P2pNewConnection {
                        p2p_peer_id: peer.connection,
                        peer_id_full: peer.peer_id,
                        ip: addr.ip().into(),
                        port,
                    });
                }
                NetEvent::PeerDisconnected { peer } => {
                    adapter.produce(PeerEvent::P2pDisconnect { p2p_peer: peer.connection });
                }
                NetEvent::StreamReady { stream: _ } => {
                    // TODO notifiy new stream
                }
                NetEvent::StreamClosed { stream: _ } => {
                    // TODO notify stream end
                }
            },
            Event::Discovery(disc_event) => match disc_event {
                DiscoveryEvent::SendMessage { to, data } => todo!(),
                DiscoveryEvent::NodeFound(enr) => todo!(),
                DiscoveryEvent::ExternalAddrChanged(socket_addr) => todo!(),
            },
        };

        self.inner.spin(&mut on_event);
        self.inner.stream_data.update_tail();

        for _ in 0..MAX_PENDING_OUTBOUND_MSGS {
            // TCacheMxBuffered
            if !adapter.consume_one(|msg: GossipMsgOut, producers| {
                if let Some(p2p_stream_id) =
                    match self.inner.stream_data.gossip_stream_id(msg.peer_id) {
                        Some(id) => Some(*id),
                        None => match self
                            .inner
                            .p2p_endpoint
                            .open_stream(msg.peer_id, StreamProtocol::GossipSub)
                        {
                            Some(stream_id) => Some(P2pStreamId::new(
                                msg.peer_id,
                                stream_id.into(),
                                StreamProtocol::GossipSub,
                            )),
                            None => {
                                // cannot create new stream - peer at capacity
                                producers.peer_events.produce(
                                    &(PeerEvent::P2pCannotCreateStream {
                                        p2p_peer: msg.peer_id,
                                        protocol: StreamProtocol::GossipSub,
                                    }
                                    .into()),
                                );
                                None
                            }
                        },
                    }
                {
                    if !self.inner.stream_data.enqueue_gossip(&p2p_stream_id, msg) {
                        producers.peer_events.produce(
                            &(PeerEvent::P2pOutboundMessageDropped {
                                p2p_peer: msg.peer_id,
                                protocol: StreamProtocol::GossipSub,
                            }
                            .into()),
                        );
                    }
                }
            }) {
                break;
            }
        }

        for _ in 0..MAX_PENDING_OUTBOUND_MSGS {
            // TCacheMxBuffered
            if !adapter.consume_one(|msg: RpcMsgOut, producers| {
                if let Some(p2p_stream_id) = match &msg.msg_type {
                    RpcOutType::Request(peer, protocol) => {
                        match self.inner.p2p_endpoint.open_stream(*peer, *protocol) {
                            Some(stream_id) => Some(P2pStreamId::new(
                                *peer,
                                stream_id.into(),
                                StreamProtocol::GossipSub,
                            )),
                            None => {
                                // cannot create new stream - peer at capacity
                                producers.peer_events.produce(
                                    &(PeerEvent::P2pCannotCreateStream {
                                        p2p_peer: *peer,
                                        protocol: *protocol,
                                    }
                                    .into()),
                                );
                                None
                            }
                        }
                    }
                    RpcOutType::Response(p2p_stream_id) => Some(*p2p_stream_id),
                } {
                    if !self.inner.stream_data.enqueue_rpc_out(&p2p_stream_id, msg) {
                        producers.peer_events.produce(
                            &(PeerEvent::P2pOutboundMessageDropped {
                                p2p_peer: p2p_stream_id.peer(),
                                protocol: p2p_stream_id.protocol(),
                            }
                            .into()),
                        );
                    }
                }
            }) {
                break;
            }
        }
    }
}

pub struct NetworkTileInner<S, D>
where
    S: StreamData,
    D: Discovery + DiscoveryNetworking,
{
    p2p_socket: Socket,
    p2p_endpoint: P2p,
    poll: Poll,
    events: Events,
    stream_data: S,
    disc_socket: Socket,
    discovery: D,
}

impl<S, D> NetworkTileInner<S, D>
where
    S: StreamData,
    D: Discovery + DiscoveryNetworking,
{
    pub fn new(
        p2p_addr: SocketAddr,
        p2p_endpoint: P2p,
        stream_data: S,
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
            events: Events::with_capacity(16 * 1024),
            stream_data,
            disc_socket,
            discovery,
        })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        &mut self.p2p_endpoint
    }

    pub fn data_mut(&mut self) -> &mut S {
        &mut self.stream_data
    }

    pub fn spin<E>(&mut self, on_event: &mut E)
    where
        E: FnMut(Event) + Send,
    {
        if let Err(e) = self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            tracing::error!(error=?e, "poll");
            return;
        }

        p2p::p2p_spin(
            &self.poll,
            &mut self.p2p_endpoint,
            &mut self.p2p_socket,
            &mut self.stream_data,
            &mut |evt| on_event(Event::P2pNet(evt)),
        );

        let now = Instant::now();

        self.disc_socket.flush(&self.poll);
        self.disc_socket.recv(|data, remote, scratch, socket| {
            self.discovery.handle(remote, &data[..], now);
            true
        });
        self.discovery.poll(|disc_event| match disc_event {
            DiscoveryEvent::SendMessage { to, data } => {
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
            other => on_event(Event::Discovery(other)),
        });
    }
}
