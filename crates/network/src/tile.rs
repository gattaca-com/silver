use std::{
    collections::HashMap,
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
    usize,
};

use flux::{tile::Tile, tracing};
use mio::{Events, Interest, Poll, Token, net::UdpSocket};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint};
use silver_common::{Keypair, SilverSpine};

#[cfg(not(target_os = "linux"))]
use crate::portable::{RX_BATCH_MAX, RxBatch, SCRATCH, TxBatch};
#[cfg(target_os = "linux")]
use crate::unix::{RX_BATCH_MAX, RxBatch, SCRATCH, TxBatch};
use crate::{
    NetworkRecv, NetworkSend,
    p2p::{self, Peer},
};

const MAX_GSO_SEGMENTS: usize = 10;
const SOCKET_TOKEN: Token = Token(0);

pub struct NetworkTile<H: NetworkSend + NetworkRecv> {
    keypair: Keypair,
    endpoint: Endpoint,
    socket: UdpSocket,
    peers: HashMap<ConnectionHandle, Peer>,
    poll: Poll,
    events: Events,
    timeout: Option<Duration>,
    rx_batch: RxBatch,
    tx_batch: TxBatch,
    writable: bool,
    handler: H,
}

impl<H: NetworkSend + NetworkRecv> NetworkTile<H> {
    pub fn new(
        keypair: Keypair,
        endpoint: Endpoint,
        addr: SocketAddr,
        handler: H,
    ) -> Result<Self, Error> {
        let mut socket = UdpSocket::bind(addr)?;
        let poll = Poll::new()?;
        poll.registry().register(&mut socket, SOCKET_TOKEN, Interest::READABLE)?;

        Ok(Self {
            keypair,
            endpoint,
            socket,
            peers: HashMap::with_capacity(1024),
            poll,
            events: Events::with_capacity(16 * 1024),
            timeout: Some(Duration::ZERO),
            rx_batch: RxBatch::new(),
            tx_batch: TxBatch::new(),
            writable: false,
            handler,
        })
    }

    fn set_writable(&mut self, want: bool) {
        if self.writable == want {
            return;
        }
        let interest =
            if want { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
        if let Err(e) = self.poll.registry().reregister(&mut self.socket, SOCKET_TOKEN, interest) {
            tracing::error!(error=?e, "reregister");
        }
        self.writable = want;
    }
}

impl<H: NetworkSend + NetworkRecv> Tile<SilverSpine> for NetworkTile<H> {
    fn loop_body(&mut self, _adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        self.spin();
    }
}

impl<H: NetworkSend + NetworkRecv> NetworkTile<H> {
    pub fn spin(&mut self) {
        if let Err(e) = self.poll.poll(&mut self.events, self.timeout) {
            tracing::error!(error=?e, "poll");
            return;
        }

        let now = Instant::now();

        // New outbound connections
        while let Some((id, addr)) = self.handler.new_peer() {
            let client_config = p2p::create_client_config(&self.keypair, Some(id.clone())).unwrap(); // TODO
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
        while let Some((remote_peer, stream, data)) = self.handler.to_send() {
            let peer = self.peers.get_mut(&ConnectionHandle(remote_peer.connection)).unwrap(); // TODO
            let wrote = peer.send(stream, data).unwrap(); // TODO
            if wrote == 0 {
                break;
            }
            self.handler.sent(&remote_peer, &stream, wrote);
        }

        // Retry pending sends from previous iteration.
        if self.tx_batch.has_pending() {
            tracing::info!("tx batch pending");
            if self.tx_batch.flush(&self.socket) {
                self.tx_batch.clear();
                self.set_writable(false);
            } else {
                self.drain_inbound(now);
                self.drive_connections(now, false);
                return;
            }
        }

        self.drain_inbound(now);
        self.drive_connections(now, true);

        if !self.tx_batch.flush(&self.socket) {
            tracing::warn!("flush failed");
            self.set_writable(true);
        }
    }

    fn drain_inbound(&mut self, now: Instant) {
        loop {
            let n = self.rx_batch.recv(&self.socket);
            if n == 0 {
                break;
            }

            for i in 0..n {
                let (data, remote) = self.rx_batch.get(i);
                let data: bytes::BytesMut = data.into();

                let scratch = &mut self.rx_batch.bufs[SCRATCH];
                let Some(event) = self.endpoint.handle(now, remote, None, None, data, scratch)
                else {
                    continue;
                };
                match event {
                    DatagramEvent::ConnectionEvent(handle, conn_event) => {
                        if let Some(peer) = self.peers.get_mut(&handle) {
                            peer.event(conn_event);
                        }
                    }
                    DatagramEvent::NewConnection(incoming) => {
                        let scratch = &mut self.rx_batch.bufs[SCRATCH];

                        match self.endpoint.accept(incoming, now, scratch, None) {
                            Ok((handle, conn)) => {
                                let peer = Peer::new(handle, conn);
                                self.peers.insert(handle, peer);
                            }
                            Err(e) => {
                                tracing::error!(cause=?e.cause, "accept");
                                if let Some(rsp) = e.response {
                                    let _ = self.socket.send_to(
                                        &self.rx_batch.bufs[SCRATCH][..rsp.size],
                                        rsp.destination,
                                    );
                                }
                            }
                        }
                    }
                    DatagramEvent::Response(rsp) => {
                        let _ = self
                            .socket
                            .send_to(&self.rx_batch.bufs[SCRATCH][..rsp.size], rsp.destination);
                    }
                }
            }

            if n < RX_BATCH_MAX {
                break;
            }
        }
    }

    fn drive_connections(&mut self, now: Instant, collect_transmits: bool) {
        self.timeout = Some(Duration::ZERO);
        if collect_transmits {
            self.tx_batch.clear();
        }

        let mut ep_callback = |handle, ep_event| self.endpoint.handle_event(handle, ep_event);

        for peer in self.peers.values_mut() {
            // N.B. peer transmit MUST be called before peer.spin();
            if collect_transmits {
                loop {
                    let buf_idx = self.tx_batch.entries.len();
                    self.tx_batch.bufs[buf_idx].clear();
                    let Some(tx) =
                        peer.transmit(now, MAX_GSO_SEGMENTS, &mut self.tx_batch.bufs[buf_idx])
                    else {
                        break;
                    };
                    self.tx_batch.commit(&tx);

                    if self.tx_batch.is_full() {
                        if !self.tx_batch.flush(&self.socket) {
                            self.set_writable(true);
                            return;
                        }
                        self.tx_batch.clear();
                    }
                }
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
