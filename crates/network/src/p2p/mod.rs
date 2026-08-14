mod context;
mod quic;
mod streams;
pub(crate) mod tls;

use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use buffa::{Message, MessageView};
pub use context::Context;
use fxhash::{FxHashMap, FxHashSet};
use mio::{Poll, net::UdpSocket};
pub(crate) use quic::{Peer, create_client_config};
pub use quic::{SendResult, create_endpoint, create_server_config};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint};
use silver_common::{
    GossipMsgOut, Identify, Keypair, P2pConnectionStats, P2pStreamId, PeerId, ProtoIdentify,
    ProtoIdentifyView, RpcOutbound, RpcRequestOutbound, TCacheRead,
};

use crate::{
    NetworkCounters, RemotePeer,
    p2p::streams::AcquiredRpcOutbound,
    socket::{MAX_GSO_SEGMENTS, Socket},
};

/// Function to spin the P2p stack - invoked from tile main loop.
pub fn p2p_spin<F: FnMut(NetEvent)>(
    poll: &Poll,
    p2p_endpoint: &mut P2p,
    p2p_socket: &mut Socket,
    context: &mut Context,
    now: Instant,
    on_event: &mut F,
) -> bool {
    p2p_socket.flush(poll);
    let mut did_work = false;
    did_work |= p2p_endpoint.poll(now, poll, p2p_socket, context, &mut |evt| {
        did_work = true;
        on_event(evt);
    });
    p2p_socket.flush(poll);
    did_work
}

/// Lifecycle events surfaced by the network layer during `poll()`. The
/// application handles these inline via the callback passed to `poll`.
///
/// `RpcInbound(_)` carries up to 4 KB of inline payload (BlocksByRoot
/// request) which dwarfs the other variants — same trade-off as
/// `PeerControl::P2pDial`. Boxing would defeat the inline-payload win;
/// the spine slot already pays the largest-variant cost per event so
/// allow it here too.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NetEvent {
    /// A peer connection has been established and its PeerId verified.
    PeerConnected {
        peer: RemotePeer,
        addr: SocketAddr,
        local_dialler: bool,
    },
    /// Peer Identify response
    PeerIdentify {
        peer: usize,
        identify: Identify,
    },
    /// A peer connection has been lost or the underlying QUIC connection
    /// drained.
    PeerDisconnected {
        peer: RemotePeer,
    },
    /// A stream has completed multistream-select negotiation and is ready
    /// for application traffic.
    StreamReady {
        stream: P2pStreamId,
    },
    /// A stream was closed or rejected.
    StreamClosed {
        stream: P2pStreamId,
    },
    /// A complete inbound RPC chunk has been decoded into a typed
    /// `RpcInbound`. Network tile produces this onto the `rpc_inbound`
    /// spine queue. Inline-payload variants (every `RpcRequest` variant
    /// plus small `RpcResponse` variants like Status/Ping/MetaData/Error)
    /// carry their bytes directly; large-payload variants such as
    /// `RpcResponse::BeaconBlock` and `DataColumnSidecar` carry a
    /// `TCacheRead` ref into the `rpc_in` TCache.
    RpcInbound(silver_common::RpcInbound),
    /// SSZ-shape / chunk-framing violation observed on an RPC stream.
    /// Network tile translates this into `PeerEvent::RpcMisbehaviour`
    /// onto `peer_events`. The peer manager applies the P5 score delta.
    RpcMisbehaviour {
        p2p_peer: usize,
        severity: silver_common::RpcSeverity,
    },
    Gossip {
        stream: P2pStreamId,
        msg: TCacheRead,
    },
}

pub struct P2p {
    keypair: Keypair,
    endpoint: Endpoint,
    peers: FxHashMap<ConnectionHandle, Peer>,
    banned: FxHashSet<PeerId>,
    timeout: Option<Duration>,
    recv_count: usize,
    stats_cursor: usize,
}

impl P2p {
    pub fn new(keypair: Keypair, endpoint: Endpoint) -> Self {
        Self {
            keypair,
            endpoint,
            peers: FxHashMap::default(),
            banned: FxHashSet::default(),
            timeout: Some(Duration::ZERO),
            recv_count: 0,
            stats_cursor: 0,
        }
    }

    /// Round-robin by connection handle from the last sampled position, so
    /// periodic small batches cover every peer without a full sweep.
    pub fn sample_stats(
        &mut self,
        now: Instant,
        batch: usize,
        emit: &mut impl FnMut(P2pConnectionStats),
    ) {
        for _ in 0..batch.min(self.peers.len()) {
            let next = self
                .peers
                .iter()
                .filter(|(h, _)| h.0 > self.stats_cursor)
                .min_by_key(|(h, _)| h.0)
                .or_else(|| self.peers.iter().min_by_key(|(h, _)| h.0));
            let Some((handle, peer)) = next else {
                return;
            };
            self.stats_cursor = handle.0;
            if let Some(stats) = peer.stats(now) {
                emit(stats);
            }
        }
    }

    /// Request an outbound connection to a peer.
    pub fn connect(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        now: Instant,
    ) -> Result<(), Error> {
        let client_config = create_client_config(&self.keypair, Some(peer_id))?;
        let (handle, connection) =
            self.endpoint.connect(now, client_config, addr, "x").map_err(Error::other)?;

        let peer = Peer::new(handle, connection, peer_id);
        self.peers.insert(handle, peer);
        Ok(())
    }

    // TODO supply disconnect reason
    pub fn disconnect(&mut self, peer: usize, now: Instant) {
        // Close but keep the peer: the poll loop must keep driving the
        // connection through its drain (CONNECTION_CLOSE retransmits,
        // endpoint events) until the drained reap removes it.
        if let Some(p) = self.peers.get_mut(&ConnectionHandle(peer)) {
            p.shutdown(now);
        }
    }

    // /// Open a new bidirectional stream on the given peer connection with the
    // /// specified protocol. Multistream-select negotiation runs internally;
    // /// `NetEvent::StreamReady` is delivered via the event callback once it
    // /// completes. Returns `None` if the connection isn't ready yet.
    // pub fn open_stream(&mut self, peer: usize, protocol: StreamProtocol) ->
    // Option<StreamId> {     let peer_obj =
    // self.peers.get_mut(&ConnectionHandle(peer))?;     peer_obj.
    // open_stream(protocol) }

    pub fn ban_peer(&mut self, peer_id: PeerId) {
        self.banned.insert(peer_id);
    }

    pub fn unban_peer(&mut self, peer_id: PeerId) {
        self.banned.remove(&peer_id);
    }

    pub(crate) fn recv(
        &mut self,
        now: Instant,
        data: bytes::BytesMut,
        remote: SocketAddr,
        scratch: &mut Vec<u8>,
        socket: &UdpSocket,
    ) -> bool {
        self.recv_count += data.len();

        let Some(event) = self.endpoint.handle(now, remote, None, None, data, scratch) else {
            return false;
        };
        match event {
            DatagramEvent::ConnectionEvent(handle, conn_event) => {
                if let Some(peer) = self.peers.get_mut(&handle) {
                    peer.event(conn_event);
                }
            }
            DatagramEvent::NewConnection(incoming) => {
                match self.endpoint.accept(incoming, now, scratch, None) {
                    Ok((handle, conn)) => {
                        crate::NetworkCounters::InboundAccepted.inc();
                        let peer = Peer::new(handle, conn, PeerId::default());

                        self.peers.insert(handle, peer);
                    }
                    Err(e) => {
                        tracing::error!(cause=?e.cause, "accept");
                        if let Some(rsp) = e.response {
                            let _ = socket.send_to(&scratch[..rsp.size], rsp.destination);
                        }
                    }
                }
            }
            DatagramEvent::Response(rsp) => {
                let _ = socket.send_to(&scratch[..rsp.size], rsp.destination);
            }
        }
        true
    }

    /// Drive the network. `data` handles byte movement for streams;
    /// `on_event` is called inline for lifecycle events.
    pub fn poll<E>(
        &mut self,
        now: Instant,
        poll: &Poll,
        socket: &mut Socket,
        context: &mut Context,
        on_event: &mut E,
    ) -> bool
    where
        E: FnMut(NetEvent),
    {
        let mut did_work = false;
        let mut ep_callback = |handle, ep_event| self.endpoint.handle_event(handle, ep_event);

        let mut any_dirty = false;
        let mut min_wake: Option<Instant> = None;
        let fold_wake = |min_wake: &mut Option<Instant>, t: Option<Instant>| {
            if let Some(t) = t {
                *min_wake = Some(min_wake.map_or(t, |cur| cur.min(t)));
            }
        };

        let mut dead_peers = vec![];
        for peer in self.peers.values_mut() {
            if !peer.due(now) {
                fold_wake(&mut min_wake, peer.wake_at());
                continue;
            }

            // N.B. peer transmit MUST be called before peer.spin();
            did_work |= drain_transmits(peer, socket, poll, now);
            peer.spin(now, &mut ep_callback, context, on_event, &self.banned);
            // Send what spin produced this pass — a settled peer gets no
            // further visit to flush it.
            did_work |= drain_transmits(peer, socket, poll, now);
            peer.settle(socket.is_blocked());

            if peer.due(now) {
                any_dirty = true;
            } else {
                fold_wake(&mut min_wake, peer.wake_at());
            }

            if peer.is_drained() {
                tracing::debug!(peer_id=?peer.id().peer_id, addr=?peer.id().addr, "peer is drained");
                dead_peers.push(peer.id().clone());
                on_event(NetEvent::PeerDisconnected { peer: peer.id().clone() });
            }
        }

        for dead_peer in dead_peers {
            self.peers.remove(&ConnectionHandle(dead_peer.connection));
        }

        // Still-dirty peers need an immediate re-poll; otherwise sleep until
        // the earliest wake deadline (the tile clamps this to its tick).
        self.timeout = if any_dirty {
            Some(Duration::ZERO)
        } else {
            min_wake.map(|t| t.saturating_duration_since(now))
        };

        NetworkCounters::P2pConnections.set(self.peers.len() as u64);
        did_work
    }

    pub fn enqueue_gossip(&mut self, msg: GossipMsgOut, context: &mut Context) -> SendResult {
        match self.peers.get_mut(&ConnectionHandle(msg.peer_id)) {
            Some(peer) => {
                let acquired = context.gossip_consumer.acquire(msg.into());
                peer.send_gossip(acquired)
            }
            None => SendResult::UnknownPeer,
        }
    }

    pub fn enqueue_rpc_out(&mut self, msg: RpcOutbound, context: &mut Context) -> SendResult {
        match self.peers.get_mut(&ConnectionHandle(msg.peer_id())) {
            Some(peer) => {
                tracing::debug!(protocol=?msg.protocol(), peer=msg.peer_id(), "enqueue outbound rpc request");
                let acquired_msg = AcquiredRpcOutbound::from((msg, &mut context.rpc_consumer));
                peer.send_rpc(acquired_msg)
            }
            None => SendResult::UnknownPeer,
        }
    }

    pub fn enqueue_identify(&mut self, peer: usize) -> SendResult {
        match self.peers.get_mut(&ConnectionHandle(peer)) {
            Some(peer) => peer.send_identify(),
            None => SendResult::UnknownPeer,
        }
    }

    pub fn has_pending_outbound(&self, peer: usize) -> bool {
        self.peers
            .get(&ConnectionHandle(peer))
            .map(|p| p.has_pending_outbound())
            .unwrap_or_default()
    }

    pub fn pending(&self, peer: usize) -> usize {
        self.peers.get(&ConnectionHandle(peer)).map(|p| p.pending()).unwrap_or_default()
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn update_identify_record(
        &self,
        identify: &ProtoIdentify,
        new_addr: IpAddr,
    ) -> Result<ProtoIdentify, Error> {
        let proto_bytes = identify.encode_to_vec();
        let view = ProtoIdentifyView::decode_view(proto_bytes.as_slice()).map_err(Error::other)?;
        let mut identify = Identify::try_from(view).map_err(Error::other)?;

        if new_addr.is_ipv4() {
            if let Some(tcp_v4) = &mut identify.tcp_ipv4 {
                tcp_v4.set_ip(new_addr);
            }
            if let Some(udp_v4) = &mut identify.udp_ipv4 {
                udp_v4.set_ip(new_addr);
            }
        } else {
            if let Some(tcp_v6) = &mut identify.tcp_ipv6 {
                tcp_v6.set_ip(new_addr);
            }
            if let Some(udp_v6) = &mut identify.udp_ipv6 {
                udp_v6.set_ip(new_addr);
            }
        }

        // Rebuild and resign identify proto.
        Ok(ProtoIdentify::from((&identify, &self.keypair)))
    }

    pub fn goodbye_all(&mut self, context: &mut Context) {
        let peer_ids = self.peers.values().map(|p| p.id().connection).collect::<Vec<_>>();
        for id in peer_ids {
            let goodbye = RpcOutbound::Request(RpcRequestOutbound {
                application_id: 0,
                peer: id,
                request: silver_common::RpcRequest::Goodbye(1u64.to_le_bytes()),
            });
            self.enqueue_rpc_out(goodbye, context);
        }
    }

    pub fn shutdown(&mut self) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            peer.shutdown(now);
        }
    }
}

/// Drain the peer's pending quinn transmits onto the socket until it has
/// nothing to send, the pacer defers, or the socket blocks.
fn drain_transmits(peer: &mut Peer, socket: &mut Socket, poll: &Poll, now: Instant) -> bool {
    let mut did_work = false;
    while !socket.is_blocked() &&
        socket.send(poll, |buf| {
            let transmit = peer.transmit(now, MAX_GSO_SEGMENTS, buf);
            if let Some(t) = &transmit {
                did_work = true;
                NetworkCounters::P2pBytesSent.add(t.size as u64);
            }
            transmit
        })
    {}
    did_work
}
