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
    GossipMsgOut, Identify, Keypair, P2pStreamId, PeerId, ProtoIdentify, ProtoIdentifyView,
    RpcOutbound,
};
use silver_metrics::timed;

use crate::{
    NetworkCounters, RemotePeer,
    p2p::streams::AcquiredRpcOutbound,
    socket::{MAX_GSO_SEGMENTS, Socket},
};

/// Function to spin the P2p stack - invoked from tile main loop.
#[timed]
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
    PeerConnected { peer: RemotePeer, addr: SocketAddr, local_dialler: bool },
    /// Peer Identify response
    PeerIdentify { peer: usize, identify: Identify },
    /// A peer connection has been lost or the underlying QUIC connection
    /// drained.
    PeerDisconnected { peer: RemotePeer },
    /// A stream has completed multistream-select negotiation and is ready
    /// for application traffic.
    StreamReady { stream: P2pStreamId },
    /// A stream was closed or rejected.
    StreamClosed { stream: P2pStreamId },
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
    RpcMisbehaviour { p2p_peer: usize, severity: silver_common::RpcSeverity },
}

pub struct P2p {
    keypair: Keypair,
    endpoint: Endpoint,
    peers: FxHashMap<ConnectionHandle, Peer>,
    dialled: FxHashSet<PeerId>,
    banned: FxHashSet<PeerId>,
    timeout: Option<Duration>,
    recv_count: usize,
}

impl P2p {
    pub fn new(keypair: Keypair, endpoint: Endpoint) -> Self {
        Self {
            keypair,
            endpoint,
            peers: FxHashMap::default(),
            dialled: FxHashSet::default(),
            banned: FxHashSet::default(),
            timeout: Some(Duration::ZERO),
            recv_count: 0,
        }
    }

    /// Request an outbound connection to a peer.
    pub fn connect(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        now: Instant,
    ) -> Result<(), Error> {
        if self.dialled.insert(peer_id) {
            let client_config = create_client_config(&self.keypair, Some(peer_id))?;
            let (handle, connection) =
                self.endpoint.connect(now, client_config, addr, "x").map_err(Error::other)?;
            let peer = Peer::new(handle, connection);
            self.peers.insert(handle, peer);
        }
        Ok(())
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
                        let peer = Peer::new(handle, conn);

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

        self.timeout = Some(Duration::ZERO);

        let mut dead_peers = vec![];
        for peer in self.peers.values_mut() {
            // N.B. peer transmit MUST be called before peer.spin();
            while !socket.is_blocked() &&
                socket.send(poll, |buf| {
                    did_work = true;
                    let transmit = peer.transmit(now, MAX_GSO_SEGMENTS, buf);
                    NetworkCounters::P2pBytesSent
                        .add(transmit.as_ref().map(|t| t.size as u64).unwrap_or_default());
                    transmit
                })
            {}

            let next_timeout = peer.spin(now, &mut ep_callback, context, on_event, &self.banned);
            if let Some(t) = next_timeout {
                let dur = t.saturating_duration_since(now);
                self.timeout = Some(self.timeout.map_or(dur, |cur| cur.min(dur)));
            }

            if peer.is_drained() {
                tracing::debug!(peer_id=?peer.id().peer_id, addr=?peer.id().addr, "peer is drained");
                dead_peers.push(peer.id().clone());
                on_event(NetEvent::PeerDisconnected { peer: peer.id().clone() });
            }
        }

        for dead_peer in dead_peers {
            self.peers.remove(&ConnectionHandle(dead_peer.connection));
            self.dialled.remove(&dead_peer.peer_id);
        }

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
                tracing::debug!(protocol=?msg.protocol(), "enqueue outbound rpc request");
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
}
