mod quic;
mod stream;
pub(crate) mod tls;

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use mio::{Poll, net::UdpSocket};
pub(crate) use quic::{Peer, create_client_config};
pub use quic::{create_endpoint, create_server_config};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint};
use silver_common::Keypair;

use crate::{
    NetworkRecv, NetworkSend,
    socket::{MAX_GSO_SEGMENTS, Socket},
};

pub struct P2p<H: NetworkSend + NetworkRecv> {
    keypair: Keypair,
    endpoint: Endpoint,
    peers: HashMap<ConnectionHandle, Peer>,
    timeout: Option<Duration>,
    handler: H,
    recv_count: usize,
}

impl<H: NetworkSend + NetworkRecv> P2p<H> {
    pub fn new(keypair: Keypair, endpoint: Endpoint, handler: H) -> Self {
        Self {
            keypair,
            endpoint,
            peers: HashMap::with_capacity(1024),
            timeout: Some(Duration::ZERO),
            handler,
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
        while let Some((id, addr)) = self.handler.new_peer() {
            let client_config = create_client_config(&self.keypair, Some(id.clone())).unwrap(); // TODO
            let (handle, connection) =
                self.endpoint.connect(now, client_config, addr, "x").unwrap(); // TODO
            let peer = Peer::new(handle, connection);
            self.peers.insert(handle, peer);
        }

        // New outbound streams
        while let Some((id, dir)) = self.handler.new_streams() {
            if let Some(peer) = self.peers.get_mut(&ConnectionHandle(id.connection)) {
                peer.new_stream(dir, &mut self.handler);
            }
        }

        // Things to send.
        while let Some((connection_id, stream, data)) = self.handler.to_send() {
            let peer = self.peers.get_mut(&ConnectionHandle(connection_id)).unwrap(); // TODO
            let wrote = peer.send(stream, data).unwrap(); // TODO
            if wrote < data.len() {
                break;
            }
            self.handler.sent(peer.id(), &stream, wrote);
        }

        self.timeout = Some(Duration::ZERO);
        // if collect_transmits {
        //     self.tx_batch.clear();
        // }

        let mut ep_callback = |handle, ep_event| self.endpoint.handle_event(handle, ep_event);

        for peer in self.peers.values_mut() {

            // N.B. peer transmit MUST be called before peer.spin();
            if !socket.is_blocked() {
                while !socket.is_blocked() && socket.send(poll, |buf| peer.transmit(now, MAX_GSO_SEGMENTS, buf)) {
                    //tracing::info!("socket send");
                }
            } else {
                tracing::warn!(local=?socket.udp_socket().local_addr(), "socket blocked");
            }

            let next_timeout = peer.spin(now, &mut ep_callback, &mut self.handler);
            let drained = peer.is_drained();

            if let Some(t) = next_timeout {
                let dur = t.saturating_duration_since(now);
                self.timeout = Some(self.timeout.map_or(dur, |cur| cur.min(dur)));
            }

            if drained {
                tracing::info!("peer is drained");
                //self.connections.remove(&peer.);
            }
        }
    }
}
