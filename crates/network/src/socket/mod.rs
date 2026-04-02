#[cfg(not(target_os = "linux"))]
#[path = "portable.rs"]
mod udp;
#[cfg(target_os = "linux")]
#[path = "unix.rs"]
mod udp;

use std::{io::Error, net::SocketAddr};

use mio::{Interest, Poll, Token, net::UdpSocket};
use quinn_proto::Transmit;
pub(crate) use udp::{RX_BATCH_MAX, RX_BUF_SIZE, RxBatch, TxBatch};

pub(crate) const MAX_GSO_SEGMENTS: usize = 10;

pub struct Socket {
    socket: UdpSocket,
    token: Token,
    rx_batch: RxBatch,
    tx_batch: TxBatch,
    blocked: bool,
    scratch_buffer: Vec<u8>,
}

impl Socket {
    pub(crate) fn new(addr: SocketAddr, poll: &Poll, token: Token) -> Result<Self, Error> {
        let mut socket = UdpSocket::bind(addr)?;
        poll.registry().register(&mut socket, token, Interest::READABLE)?;

        Ok(Self {
            socket,
            token,
            rx_batch: RxBatch::new(),
            tx_batch: TxBatch::new(),
            blocked: false,
            scratch_buffer: vec![0u8; RX_BUF_SIZE],
        })
    }

    fn re_register(&mut self, poll: &Poll, interest: Interest) -> Result<(), Error> {
        poll.registry().reregister(&mut self.socket, self.token, interest)
    }

    /// Returns true if writable value was changed
    fn set_writable(&mut self, writable: bool, poll: &Poll) -> Result<bool, Error> {
        if self.blocked != writable {
            self.blocked = writable;
            let interest =
                if writable { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
            self.re_register(poll, interest)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn is_blocked(&self) -> bool {
        self.blocked
    }

    pub(crate) fn flush(&mut self, poll: &Poll) -> bool {
        if !self.tx_batch.entries.is_empty() {
            if self.tx_batch.flush(&self.socket) {
                self.tx_batch.clear();
                let _ = self.set_writable(false, poll);
                true
            } else {
                let _ = self.set_writable(true, poll); // TODO
                false
            }
        } else {
            true
        }
    }

    pub(crate) fn send<F>(&mut self, poll: &Poll, mut f: F) -> bool
    where
        F: FnMut(&mut Vec<u8>) -> Option<Transmit>,
    {
        // TODO
        let buf_idx = self.tx_batch.entries.len();
        self.tx_batch.bufs[buf_idx].clear();

        let Some(tx) = f(&mut self.tx_batch.bufs[buf_idx]) else {
            return false;
        };

        self.tx_batch.commit(&tx);

        if self.tx_batch.is_full() {
            if !self.tx_batch.flush(&self.socket) {
                let _ = self.set_writable(true, poll); // TODO
                return false;
            }
            self.tx_batch.clear();
        }
        true
    }

    pub(crate) fn recv<F>(&mut self, mut f: F)
    where
        F: FnMut(bytes::BytesMut, SocketAddr, &mut Vec<u8>, &UdpSocket) -> bool,
    {
        loop {
            let n = self.rx_batch.recv(&self.socket);
            if n == 0 {
                break;
            }

            for i in 0..n {
                let (data, remote) = self.rx_batch.take(i);
                self.scratch_buffer.clear();
                f(data, remote, &mut self.scratch_buffer, &self.socket);
            }

            if n < RX_BATCH_MAX {
                break;
            }
        }
    }
}
