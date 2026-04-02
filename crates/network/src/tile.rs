use std::{
    io::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};

use flux::{tile::Tile, tracing};
use mio::{Events, Poll, Token};
use silver_common::SilverSpine;

use crate::{NetworkRecv, NetworkSend, p2p::P2p, socket::Socket};

const SOCKET_TOKEN: Token = Token(0);

pub struct NetworkTile<H: NetworkSend + NetworkRecv> {
    p2p_socket: Socket,
    p2p_endpoint: P2p<H>,
    poll: Poll,
    events: Events,
}

impl<H: NetworkSend + NetworkRecv> NetworkTile<H> {
    pub fn new(p2p_addr: SocketAddr, p2p_endpoint: P2p<H>) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let p2p_socket = Socket::new(p2p_addr, &poll, SOCKET_TOKEN)?;
        Ok(Self { p2p_socket, p2p_endpoint, poll, events: Events::with_capacity(16 * 1024) })
    }
}

impl<H: NetworkSend + NetworkRecv> Tile<SilverSpine> for NetworkTile<H> {
    fn loop_body(&mut self, _adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        self.spin();
    }
}

impl<H: NetworkSend + NetworkRecv> NetworkTile<H> {
    pub fn spin(&mut self) {
        if let Err(e) = self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            tracing::error!(error=?e, "poll");
            return;
        }

        let now = Instant::now();

        self.p2p_socket.flush(&self.poll);
        self.p2p_socket.recv(|data, remote, scratch, socket| {
            self.p2p_endpoint.recv(now, data, remote, scratch, socket)
        });
        self.p2p_endpoint.poll(now, &self.poll, &mut self.p2p_socket);
        self.p2p_socket.flush(&self.poll);
    }
}
