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
    /// Per-datagram buffers. 
    pub(crate) bufs: Vec<BytesMut>,
    datagrams: Vec<(usize, usize, SocketAddr)>, // (buf_index, len, remote)
}

impl RxBatch {
    pub(crate) fn new() -> Self {
        let bufs = (0..RX_BATCH_MAX).map(|_| BytesMut::zeroed(RX_BUF_SIZE)).collect();
        Self { bufs, datagrams: Vec::with_capacity(RX_BATCH_MAX) }
    }

    /// Receive up to RX_BATCH_MAX datagrams via individual recv_from calls.
    pub(crate) fn recv(&mut self, socket: &UdpSocket) -> usize {
        self.datagrams.clear();

        for i in 0..RX_BATCH_MAX {
            debug_assert!(self.bufs[i].try_reclaim(RX_BUF_SIZE));
            unsafe { self.bufs[i].set_len(RX_BUF_SIZE);}

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

    /// Get the i-th received datagram as (data, source_addr).
    pub(crate) fn get(&self, i: usize) -> (&[u8], SocketAddr) {
        let (buf_idx, len, addr) = self.datagrams[i];
        (&self.bufs[buf_idx][..len], addr)
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
        unsafe { bytes_mut.set_len(1024);}
        println!("{} / {}", bytes_mut.len(), bytes_mut.capacity());
    }
}