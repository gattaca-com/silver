mod handlers;
mod quic;
mod stream;
pub(crate) mod tls;

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

pub use handlers::{PeerHandler, StreamHandler};
use mio::{Poll, net::UdpSocket};
pub(crate) use quic::{Peer, create_client_config};
pub use quic::{create_endpoint, create_server_config};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint};
use silver_common::Keypair;

use crate::socket::{MAX_GSO_SEGMENTS, Socket};

pub struct P2p<P: PeerHandler, S: StreamHandler> {
    keypair: Keypair,
    endpoint: Endpoint,
    peers: HashMap<ConnectionHandle, Peer<S>>,
    timeout: Option<Duration>,
    recv_count: usize,
    peer_handler: P,
    stream_handler: S,
}

impl<P: PeerHandler, S: StreamHandler> P2p<P, S> {
    pub fn new(keypair: Keypair, endpoint: Endpoint, peer_handler: P, stream_handler: S) -> Self {
        Self {
            keypair,
            endpoint,
            peers: HashMap::with_capacity(1024),
            timeout: Some(Duration::ZERO),
            peer_handler,
            stream_handler,
            recv_count: 0,
        }
    }

    pub(crate) fn recv(
        &mut self,
        now: Instant,
        data: &[u8],
        remote: SocketAddr,
        scratch: &mut Vec<u8>,
        socket: &UdpSocket,
    ) -> bool {
        self.recv_count += data.len();
        //tracing::info!(?remote, count=self.recv_count, "recv count");
        let data: bytes::BytesMut = data.into();

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

    pub(crate) fn poll(&mut self, now: Instant, poll: &Poll, socket: &mut Socket) {
        // New outbound connections
        while let Some((id, addr)) = self.peer_handler.poll_new_peer() {
            let client_config = create_client_config(&self.keypair, Some(id.clone())).unwrap(); // TODO
            let (handle, connection) =
                self.endpoint.connect(now, client_config, addr, "x").unwrap(); // TODO
            let peer = Peer::new(handle, connection);
            self.peers.insert(handle, peer);
        }

        let mut ep_callback = |handle, ep_event| self.endpoint.handle_event(handle, ep_event);

        self.timeout = Some(Duration::ZERO);

        let mut dead_peers = vec![]; // todo
        for peer in self.peers.values_mut() {
            // N.B. peer transmit MUST be called before peer.spin();
            while !socket.is_blocked() &&
                socket.send(poll, |buf| peer.transmit(now, MAX_GSO_SEGMENTS, buf))
            {
                //tracing::info!("socket send");
            }

            let next_timeout =
                peer.spin(now, &mut ep_callback, &mut self.stream_handler, &mut self.peer_handler);
            if let Some(t) = next_timeout {
                let dur = t.saturating_duration_since(now);
                self.timeout = Some(self.timeout.map_or(dur, |cur| cur.min(dur)));
            }

            if peer.is_drained() {
                tracing::info!("peer is drained");
                dead_peers.push(peer.id().connection);
            }
        }

        for dead_peer in dead_peers {
            self.peers.remove(&ConnectionHandle(dead_peer));
        }
    }
}
