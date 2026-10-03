use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bytes::BytesMut;
#[cfg(feature = "thread_park")]
use flux::park::SIGNAL;
#[cfg(feature = "thread_park")]
use mio::Waker;
use mio::{Events, Poll, Token};
use quinn_proto::Transmit;

use super::SocketId;
use crate::socket::{RX_BUF_SIZE, Socket};

pub(crate) struct MioIo {
    poll: Poll,
    events: Events,
    sockets: [Socket; 2],
    scratch: Vec<u8>,
}

impl MioIo {
    pub(crate) fn new(quic_addr: SocketAddr, discovery_addr: SocketAddr) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let sockets = [
            Socket::new(quic_addr, &poll, Token(SocketId::Quic as usize))?,
            Socket::new(discovery_addr, &poll, Token(SocketId::Discovery as usize))?,
        ];
        Ok(Self {
            poll,
            events: Events::with_capacity(8),
            sockets,
            scratch: Vec::with_capacity(RX_BUF_SIZE),
        })
    }

    #[cfg(feature = "thread_park")]
    pub(crate) fn register_spine_waker(&self) -> Result<(), Error> {
        let waker = Waker::new(self.poll.registry(), Token(self.sockets.len()))?;
        SIGNAL.register_waker(waker);
        Ok(())
    }

    pub(crate) fn poll(&mut self, timeout: Duration) -> Result<(), Error> {
        if self.events.is_empty() {
            self.poll.poll(&mut self.events, Some(timeout))?;
        }
        Ok(())
    }

    pub(crate) fn recv<F>(&mut self, mut receive: F)
    where
        F: FnMut(SocketId, BytesMut, SocketAddr, &mut Vec<u8>) -> Option<Transmit>,
    {
        for event in &self.events {
            if !event.is_readable() {
                continue;
            }
            let socket = match event.token() {
                Token(0) => SocketId::Quic,
                Token(1) => SocketId::Discovery,
                _ => continue,
            };
            self.sockets[socket as usize].recv(
                &self.poll,
                &mut self.scratch,
                |data, remote, scratch| receive(socket, data, remote, scratch),
            );
        }
        self.events.clear();
    }

    pub(crate) fn is_blocked(&self, socket: SocketId) -> bool {
        self.sockets[socket as usize].is_blocked()
    }

    pub(crate) fn flush(&mut self, socket: SocketId) -> bool {
        self.sockets[socket as usize].flush(&self.poll)
    }

    /// The producer is called only after a transmit buffer is available.
    pub(crate) fn send<F>(&mut self, socket: SocketId, produce: F) -> bool
    where
        F: FnOnce(&mut Vec<u8>) -> Option<Transmit>,
    {
        self.sockets[socket as usize].send(&self.poll, produce)
    }

    pub(crate) fn ban(&mut self, ip: IpAddr) {
        for socket in &mut self.sockets {
            socket.ban(ip);
        }
    }

    pub(crate) fn unban(&mut self, ip: IpAddr) {
        for socket in &mut self.sockets {
            socket.unban(ip);
        }
    }
}
