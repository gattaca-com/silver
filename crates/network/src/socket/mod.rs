#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod udp;
#[cfg(not(target_os = "linux"))]
#[path = "portable.rs"]
mod udp;

#[cfg(test)]
mod tests;

use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket as StdUdpSocket},
};

use bytes::BytesMut;
use flux_profiler::timed;
use fxhash::FxHasher;
use mio::{Interest, Poll, Token, net::UdpSocket};
use quinn_proto::Transmit;
use silver_common::WitherFilter;
pub(crate) use udp::{RX_BATCH_MAX, RX_BUF_SIZE, RxBatch, TxBatch};

pub(crate) const MAX_GSO_SEGMENTS: usize = 10;

pub(crate) struct Socket {
    socket: UdpSocket,
    token: Token,
    rx_batch: RxBatch,
    tx_batch: TxBatch,
    blocked: bool,
    banned_ips: WitherFilter<IpAddr, FxHasher, 1024>,
}

impl Socket {
    pub(crate) fn new(addr: SocketAddr, poll: &Poll, token: Token) -> Result<Self, Error> {
        let mut socket = UdpSocket::from_std(bind_udp(addr)?);
        poll.registry().register(&mut socket, token, Interest::READABLE)?;

        Ok(Self {
            socket,
            token,
            rx_batch: RxBatch::new(),
            tx_batch: TxBatch::new(),
            blocked: false,
            banned_ips: WitherFilter::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        })
    }

    fn re_register(&mut self, poll: &Poll, interest: Interest) -> Result<(), Error> {
        poll.registry().reregister(&mut self.socket, self.token, interest)
    }

    /// Returns true if writable value was changed
    fn set_blocked(&mut self, blocked: bool, poll: &Poll) -> Result<bool, Error> {
        if self.blocked != blocked {
            self.blocked = blocked;
            let interest =
                if blocked { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
            self.re_register(poll, interest)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn is_blocked(&self) -> bool {
        self.blocked
    }

    #[timed]
    pub(crate) fn flush(&mut self, poll: &Poll) -> bool {
        if !self.tx_batch.entries.is_empty() {
            if self.tx_batch.flush(&self.socket) {
                self.tx_batch.clear();
                let _ = self.set_blocked(false, poll);
                true
            } else {
                let _ = self.set_blocked(true, poll);
                false
            }
        } else {
            true
        }
    }

    #[timed]
    pub(crate) fn send<F>(&mut self, poll: &Poll, f: F) -> bool
    where
        F: FnOnce(&mut Vec<u8>) -> Option<Transmit>,
    {
        let buf_idx = self.tx_batch.entries.len();
        if self.blocked || buf_idx >= self.tx_batch.bufs.len() {
            return false;
        }
        self.tx_batch.bufs[buf_idx].clear();

        let Some(tx) = f(&mut self.tx_batch.bufs[buf_idx]) else {
            return false;
        };

        self.tx_batch.commit(&tx);

        if self.tx_batch.is_full() {
            if !self.tx_batch.flush(&self.socket) {
                let _ = self.set_blocked(true, poll);
                return false;
            }
            self.tx_batch.clear();
        }
        true
    }

    #[timed]
    pub(crate) fn recv<F>(&mut self, poll: &Poll, scratch: &mut Vec<u8>, mut f: F)
    where
        F: FnMut(BytesMut, SocketAddr, &mut Vec<u8>) -> Option<Transmit>,
    {
        loop {
            let n = self.rx_batch.recv(&self.socket);
            if n == 0 {
                break;
            }

            for i in 0..n {
                let (data, remote) = self.rx_batch.take(i);

                if !self.banned_ips.contains(&remote.ip()) {
                    scratch.clear();
                    if let Some(response) = f(data, remote, scratch) {
                        self.send(poll, |buffer| {
                            buffer.extend_from_slice(&scratch[..response.size]);
                            Some(response)
                        });
                    }
                }
            }

            if n < RX_BATCH_MAX {
                break;
            }
        }
    }

    pub(crate) fn ban(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip);
    }

    pub(crate) fn unban(&mut self, ip: IpAddr) {
        self.banned_ips.remove(&ip);
    }
}

pub(crate) fn bind_udp(addr: SocketAddr) -> Result<StdUdpSocket, Error> {
    silver_log::debug!("bind to: {addr:?}");
    let bind_addr = match addr {
        SocketAddr::V4(v4) => {
            let ip = if v4.ip().is_unspecified() {
                Ipv6Addr::UNSPECIFIED
            } else {
                v4.ip().to_ipv6_mapped()
            };
            SocketAddr::V6(SocketAddrV6::new(ip, v4.port(), 0, 0))
        }
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    };

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(false)?;
    const BUFFER_SIZE: usize = 32 * 1024 * 1024;
    socket.set_recv_buffer_size(BUFFER_SIZE)?;
    socket.set_send_buffer_size(BUFFER_SIZE)?;
    // Linux silently caps these at net.core.rmem_max / wmem_max.
    let (recv, send) = (socket.recv_buffer_size()?, socket.send_buffer_size()?);
    if recv < BUFFER_SIZE || send < BUFFER_SIZE {
        silver_log::warn!(
            ?addr,
            recv,
            send,
            requested = BUFFER_SIZE,
            "UDP socket buffers capped; raise net.core.rmem_max / wmem_max"
        );
    }
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}
