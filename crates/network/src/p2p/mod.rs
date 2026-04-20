mod handlers;
mod quic;
mod stream;
pub(crate) mod tls;

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

pub use handlers::{StreamData, TCacheStreamData};
use mio::{Poll, net::UdpSocket};
pub(crate) use quic::{Peer, create_client_config};
pub use quic::{create_endpoint, create_server_config};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, StreamId};
use silver_common::{Keypair, P2pStreamId, PeerId, StreamProtocol};

use crate::{
    RemotePeer,
    socket::{MAX_GSO_SEGMENTS, Socket},
};

/// Function to spin the P2p stack - invoked from tile main loop.
pub fn p2p_spin<D: StreamData, F: FnMut(NetEvent)>(
    poll: &Poll,
    p2p_endpoint: &mut P2p,
    p2p_socket: &mut Socket,
    stream_data: &mut D,
    on_event: &mut F,
) {
    let now = Instant::now();

    p2p_socket.flush(poll);
    p2p_socket.recv(|data, remote, scratch, socket| {
        p2p_endpoint.recv(now, data, remote, scratch, socket)
    });
    p2p_endpoint.poll(now, poll, p2p_socket, stream_data, on_event);
    p2p_socket.flush(poll);
}

/// Lifecycle events surfaced by the network layer during `poll()`. The
/// application handles these inline via the callback passed to `poll`.
#[derive(Debug, Clone)]
pub enum NetEvent {
    /// A peer connection has been established and its PeerId verified.
    PeerConnected { peer: RemotePeer, addr: SocketAddr },
    /// A peer connection has been lost or the underlying QUIC connection
    /// drained.
    PeerDisconnected { peer: RemotePeer },
    /// A stream has completed multistream-select negotiation and is ready
    /// for application traffic.
    StreamReady { stream: P2pStreamId },
    /// A stream was closed or rejected.
    StreamClosed { stream: P2pStreamId },
}

pub struct P2p {
    keypair: Keypair,
    endpoint: Endpoint,
    peers: HashMap<ConnectionHandle, Peer>,
    timeout: Option<Duration>,
    recv_count: usize,
    /// Pending outbound connections (queued via `connect`).
    pending_connect: Vec<(PeerId, SocketAddr)>,
}

impl P2p {
    pub fn new(keypair: Keypair, endpoint: Endpoint) -> Self {
        Self {
            keypair,
            endpoint,
            peers: HashMap::with_capacity(1024),
            timeout: Some(Duration::ZERO),
            recv_count: 0,
            pending_connect: Vec::new(),
        }
    }

    /// Request an outbound connection to a peer. Processed during the next
    /// `poll()` cycle.
    pub fn connect(&mut self, peer_id: PeerId, addr: SocketAddr) {
        self.pending_connect.push((peer_id, addr));
    }

    /// Open a new bidirectional stream on the given peer connection with the
    /// specified protocol. Multistream-select negotiation runs internally;
    /// `NetEvent::StreamReady` is delivered via the event callback once it
    /// completes. Returns `None` if the connection isn't ready yet.
    pub fn open_stream(&mut self, peer: usize, protocol: StreamProtocol) -> Option<StreamId> {
        let peer_obj = self.peers.get_mut(&ConnectionHandle(peer))?;
        peer_obj.open_stream(protocol)
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
    pub fn poll<S, E>(
        &mut self,
        now: Instant,
        poll: &Poll,
        socket: &mut Socket,
        data: &mut S,
        on_event: &mut E,
    ) where
        S: StreamData,
        E: FnMut(NetEvent),
    {
        // New outbound connections from queued connect requests.
        for (id, addr) in self.pending_connect.drain(..) {
            let client_config = create_client_config(&self.keypair, Some(id)).unwrap(); // TODO
            let (handle, connection) =
                self.endpoint.connect(now, client_config, addr, "x").unwrap(); // TODO
            let peer = Peer::new(handle, connection);
            self.peers.insert(handle, peer);
        }

        let mut ep_callback = |handle, ep_event| self.endpoint.handle_event(handle, ep_event);

        self.timeout = Some(Duration::ZERO);

        let mut dead_peers = vec![];
        for peer in self.peers.values_mut() {
            // N.B. peer transmit MUST be called before peer.spin();
            while !socket.is_blocked() &&
                socket.send(poll, |buf| peer.transmit(now, MAX_GSO_SEGMENTS, buf))
            {}

            let next_timeout = peer.spin(now, &mut ep_callback, data, on_event);
            if let Some(t) = next_timeout {
                let dur = t.saturating_duration_since(now);
                self.timeout = Some(self.timeout.map_or(dur, |cur| cur.min(dur)));
            }

            if peer.is_drained() {
                tracing::info!("peer is drained");
                dead_peers.push(peer.id().connection);
                on_event(NetEvent::PeerDisconnected { peer: peer.id().clone() });
            }
        }

        for dead_peer in dead_peers {
            self.peers.remove(&ConnectionHandle(dead_peer));
        }
    }
}
