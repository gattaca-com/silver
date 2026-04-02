use std::{io::Error, net::SocketAddr, time::Duration};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use mio::{Events, Poll, Token};
use silver_common::{
    GossipMsgOut, P2pStreamId, PeerEvent, RpcMsgOut, RpcOutType, SilverSpine, StreamProtocol,
};

use crate::{
    NetEvent, StreamData, TCacheStreamData,
    p2p::{self, P2p},
    socket::Socket,
};

const SOCKET_TOKEN: Token = Token(0);

pub struct NetworkTile {
    p2p_stream_handler: TCacheStreamData,
    inner: NetworkTileInner<TCacheStreamData>,
}

impl Tile<SilverSpine> for NetworkTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let mut on_event = |net_event| match net_event {
            NetEvent::PeerConnected { peer, addr } => {
                // TODO start identity exchange
                // TODO start status exchange?
                adapter.produce(PeerEvent::NewP2pConnection { p2p_peer: peer.connection, addr });
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
        };

        self.inner.spin(&mut on_event);
        self.p2p_stream_handler.update_tail();

        for _ in 0..64 {
            // TCacheMxBuffered
            if !adapter.consume_one(|msg: GossipMsgOut, producers| {
                if let Some(p2p_stream_id) =
                    match self.p2p_stream_handler.gossip_stream_id(msg.peer_id) {
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
                                    &(PeerEvent::CannotCreateStream {
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
                    if !self.p2p_stream_handler.enqueue_gossip(&p2p_stream_id, msg) {
                        producers.peer_events.produce(
                            &(PeerEvent::OutboundMessageDropped {
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

        for _ in 0..64 {
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
                                    &(PeerEvent::CannotCreateStream {
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
                    if !self.p2p_stream_handler.enqueue_rpc_out(&p2p_stream_id, msg) {
                        producers.peer_events.produce(
                            &(PeerEvent::OutboundMessageDropped {
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

pub struct NetworkTileInner<D>
where
    D: StreamData,
{
    p2p_socket: Socket,
    p2p_endpoint: P2p,
    poll: Poll,
    events: Events,
    data: D,
}

impl<D> NetworkTileInner<D>
where
    D: StreamData,
{
    pub fn new(p2p_addr: SocketAddr, p2p_endpoint: P2p, data: D) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let p2p_socket = Socket::new(p2p_addr, &poll, SOCKET_TOKEN)?;
        Ok(Self { p2p_socket, p2p_endpoint, poll, events: Events::with_capacity(16 * 1024), data })
    }

    pub fn p2p_mut(&mut self) -> &mut P2p {
        &mut self.p2p_endpoint
    }

    pub fn spin<E: FnMut(NetEvent) + Send>(&mut self, on_event: &mut E) {
        if let Err(e) = self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            tracing::error!(error=?e, "poll");
            return;
        }

        p2p::p2p_spin(
            &self.poll,
            &mut self.p2p_endpoint,
            &mut self.p2p_socket,
            &mut self.data,
            on_event,
        );
    }
}
