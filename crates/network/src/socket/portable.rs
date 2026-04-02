use std::net::SocketAddr;

use bytes::BytesMut;
use flux::tracing;
use mio::net::UdpSocket;

pub(crate) const RX_BATCH_MAX: usize = 32;
pub(crate) const RX_BUF_SIZE: usize = 2048;
const TX_BATCH_MAX: usize = 256;
const MAX_GSO_SEGMENTS: usize = 10;

// --- RxBatch ----------------------------------------------------------------

pub(crate) struct RxBatch {
    /// Per-slot backing buffers. Each slot hands off a split to quinn on
    /// receive; reclaimed via `try_reclaim` on the next recv round.
    bufs: Vec<BytesMut>,
    datagrams: Vec<(usize, usize, SocketAddr)>, // (buf_index, len, remote)
}

impl RxBatch {
    pub(crate) fn new() -> Self {
        let bufs = (0..RX_BATCH_MAX).map(|_| BytesMut::with_capacity(RX_BUF_SIZE)).collect();
        Self { bufs, datagrams: Vec::with_capacity(RX_BATCH_MAX) }
    }

    /// Receive up to RX_BATCH_MAX datagrams via individual recv_from calls.
    pub(crate) fn recv(&mut self, socket: &UdpSocket) -> usize {
        // Reclaim only slots that were used last round.
        for &(buf_idx, _len, _addr) in &self.datagrams {
            if !self.bufs[buf_idx].try_reclaim(RX_BUF_SIZE) {
                self.bufs[buf_idx] = BytesMut::with_capacity(RX_BUF_SIZE);
            }
            // SAFETY: capacity is RX_BUF_SIZE; recv_from overwrites.
            unsafe { self.bufs[buf_idx].set_len(RX_BUF_SIZE) };
        }
        self.datagrams.clear();

        for i in 0..RX_BATCH_MAX {
            // First time init: slots not yet set_len'd still have len=0.
            // Subsequent rounds: used slots were reclaimed above; unused
            // slots still have RX_BUF_SIZE len from prior round.
            if self.bufs[i].len() < RX_BUF_SIZE {
                unsafe { self.bufs[i].set_len(RX_BUF_SIZE) };
            }

            match socket.recv_from(&mut self.bufs[i]) {
                Ok((len, remote)) => {
                    self.datagrams.push((i, len, remote));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::error!(error=?e, "recv_from");
                    break;
                }
            }
        }

        self.datagrams.len()
    }

    /// Take the i-th received datagram as an owned `BytesMut` plus source
    /// address.
    pub(crate) fn take(&mut self, i: usize) -> (BytesMut, SocketAddr) {
        let (buf_idx, len, addr) = self.datagrams[i];
        let packet = self.bufs[buf_idx].split_to(len);
        (packet, addr)
    }
}

// --- TxBatch ----------------------------------------------------------------

pub(crate) struct TxEntry {
    buf_idx: usize,
    size: usize,
    segment_size: Option<usize>,
    dst: SocketAddr,
}

pub(crate) struct TxBatch {
    pub(crate) bufs: Vec<Vec<u8>>,
    pub(crate) entries: Vec<TxEntry>,
    send_idx: usize,
}

impl TxBatch {
    pub(crate) fn new() -> Self {
        let bufs = (0..TX_BATCH_MAX).map(|_| Vec::with_capacity(MAX_GSO_SEGMENTS * 1500)).collect();
        Self { bufs, entries: Vec::with_capacity(TX_BATCH_MAX), send_idx: 0 }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.send_idx = 0;
    }

    pub(crate) fn is_full(&self) -> bool {
        self.entries.len() >= TX_BATCH_MAX
    }

    /// Record a transmit after poll_transmit wrote into bufs[entries.len()].
    pub(crate) fn commit(&mut self, tx: &quinn_proto::Transmit) {
        let buf_idx = self.entries.len();
        self.entries.push(TxEntry {
            buf_idx,
            size: tx.size,
            segment_size: tx.segment_size,
            dst: tx.destination,
        });
    }

    pub(crate) fn flush(&mut self, socket: &UdpSocket) -> bool {
        while self.send_idx < self.entries.len() {
            let entry = &self.entries[self.send_idx];
            let buf = &self.bufs[entry.buf_idx];
            // No GSO — split segments into individual sends.
            match entry.segment_size {
                None => match socket.send_to(&buf[..entry.size], entry.dst) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                    Err(_) => {}
                },
                Some(segment_size) => {
                    let mut off = 0;
                    while off < entry.size {
                        let end = (off + segment_size).min(entry.size);
                        match socket.send_to(&buf[off..end], entry.dst) {
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                            Err(_) => {}
                        }
                        off = end;
                    }
                }
            }
            self.send_idx += 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    #[test]
    fn buf() {
        let mut bytes_mut = BytesMut::zeroed(1024);
        assert_eq!(1024, bytes_mut.len());
        let other = bytes_mut.split();
        assert_eq!(0, bytes_mut.len());
        drop(other);
        assert!(bytes_mut.try_reclaim(1024));
        unsafe {
            bytes_mut.set_len(1024);
        }
        println!("{} / {}", bytes_mut.len(), bytes_mut.capacity());
    }
}
