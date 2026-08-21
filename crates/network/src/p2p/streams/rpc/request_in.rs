use std::io::ErrorKind;

use silver_common::{P2pStreamId, RpcRequest, TProducer, decode_varint};

use crate::p2p::streams::{
    StreamError, StreamIo,
    rpc::{Rpc, RpcReservation, alloc_incoming_rpc},
    snappy::SnappyDecoder,
};

/// State machine for reading a single length-prefixed, snappy-compressed SSZ
/// chunk.
#[derive(Debug)]
pub enum RpcReadRequest {
    /// Reading the varint length prefix of the SSZ chunk
    ReadingLength { buf: [u8; 10], read: usize },
    /// Alocating
    AllocBody { length: usize, buf: [u8; 10], buf_start: usize, buf_end: usize },
    /// Stream Snappy decompressing the chunk payload into a handler buffer.
    ReadingBody { reservation: RpcReservation, remaining: usize },
    /// Request read completed
    Complete { msg: RpcRequest },
}

impl Default for RpcReadRequest {
    fn default() -> Self {
        Self::ReadingLength { buf: [0; 10], read: 0 }
    }
}

enum Spin {
    Ok(RpcReadRequest),
    Next(RpcReadRequest),
}

impl RpcReadRequest {
    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
        producer: &mut TProducer,
        decoder: &mut SnappyDecoder,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id, producer, decoder)? {
                Spin::Ok(read_state) => return Ok(read_state),
                Spin::Next(read_state) => {
                    self = read_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(
        self,
        io: &mut S,
        p2p_id: &P2pStreamId,
        producer: &mut TProducer,
        decoder: &mut SnappyDecoder,
    ) -> Result<Spin, StreamError> {
        match self {
            RpcReadRequest::ReadingLength { mut buf, mut read } => {
                read += io.read_from_stream(p2p_id.stream_id(), &mut buf[read..])?;

                for pos in 0..read {
                    if buf[pos] & 0x80 == 0 {
                        // last byte of varint.
                        let (length, offset) = decode_varint(&buf[..read], 0)?;
                        if length == 0 {
                            tracing::warn!(
                                ?p2p_id,
                                prefix = ?&buf[..read],
                                "rpc request chunk with zero varint length"
                            );
                        }
                        return Ok(Spin::Next(Self::AllocBody {
                            length: length as usize,
                            buf,
                            buf_start: offset,
                            buf_end: read,
                        }));
                    }
                }

                Ok(Spin::Ok(Self::ReadingLength { buf, read }))
            }
            RpcReadRequest::AllocBody { length, buf, buf_start, buf_end } => {
                let mut reservation = match alloc_incoming_rpc(producer, p2p_id, length) {
                    Ok(reservation) => reservation,
                    Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                        return Ok(Spin::Ok(Self::AllocBody { length, buf, buf_start, buf_end }));
                    }
                    Err(e) => return Err(e.into()),
                };

                // Decode any body bytes read along with the prefix. Output
                // must be the full remaining buffer — see response_in.
                let mut remaining = length;
                if buf_end > buf_start {
                    let out_buf = reservation.remaining_buffer()?;
                    let (_, decoded_bytes) =
                        decoder.decompress(&buf[buf_start..buf_end], out_buf)?;

                    reservation.increment_offset(decoded_bytes)?;
                    remaining -= decoded_bytes;
                }

                Ok(Spin::Next(Self::ReadingBody { reservation, remaining }))
            }
            RpcReadRequest::ReadingBody { mut reservation, mut remaining } => {
                // Short-circuit BEFORE attempting another read — once the
                // SSZ payload is fully decoded the peer's already FIN'd
                // (single-chunk request) and reading would surface
                // `ClosedStream`.
                if remaining == 0 {
                    match reservation.into_rpc() {
                        Rpc::Request(rpc_request) => {
                            return Ok(Spin::Ok(Self::Complete { msg: rpc_request }));
                        }
                        Rpc::Response(_) => return Err(StreamError::InvalidRpc),
                    }
                }
                let decompress_buffer = decoder.decompress_buffer();
                if !decompress_buffer.is_empty() {
                    let written = io.read_from_stream(p2p_id.stream_id(), decompress_buffer)?;
                    if written == 0 {
                        return Ok(Spin::Ok(Self::ReadingBody { reservation, remaining }));
                    }
                    let decoded =
                        decoder.decompress_written(written, reservation.remaining_buffer()?)?;
                    // Advance the reservation past the decoded bytes — a
                    // tcache-backed request (by-root) only commits via this,
                    // and without the commit the consumer acquires an empty
                    // buffer.
                    reservation.increment_offset(decoded)?;
                    remaining -= decoded;
                }
                Ok(Spin::Next(Self::ReadingBody { reservation, remaining }))
            }
            RpcReadRequest::Complete { msg } => Ok(Spin::Ok(Self::Complete { msg })),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TCache, TCacheProducer, TRead};

    use super::*;
    use crate::p2p::streams::{
        StreamIo,
        rpc::AcquiredRpcOutbound,
        snappy::{SnappyDecoder, SnappyEncoder},
    };

    /// Serves a fixed byte stream in `cap`-sized reads; sinks writes.
    struct WireIo {
        data: Vec<u8>,
        pos: usize,
        cap: usize,
    }

    impl StreamIo for WireIo {
        fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
            Ok(data.len())
        }

        fn read_from_stream(
            &mut self,
            _id: StreamId,
            out: &mut [u8],
        ) -> Result<usize, StreamError> {
            let n = out.len().min(self.cap).min(self.data.len() - self.pos);
            out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }

        fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
            Ok(())
        }

        fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
            None
        }

        fn gossip_next(&mut self) -> Option<TRead> {
            None
        }

        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
    }

    /// Regression: a by-root request body flows through `ReadingBody` into a
    /// tcache reservation; without `increment_offset` per decode the
    /// reservation never commits and the consumer acquires an empty buffer —
    /// live symptom was count=0 for every by-root request from every client.
    #[test]
    fn by_root_request_body_commits_tcache() {
        let mut ssz = Vec::new();
        ssz.extend_from_slice(&[0xAB; 32]);
        ssz.extend_from_slice(&[0xCD; 32]);

        let mut body = Vec::new();
        let mut enc = SnappyEncoder::new();
        let (consumed, pending) = enc.compress(&ssz, &mut body).unwrap();
        assert_eq!((consumed, pending), (ssz.len(), 0));
        let mut wire = vec![ssz.len() as u8]; // single-byte varint (64)
        wire.extend_from_slice(&body);

        let mut producer = TCache::producer("test_rpc_by_root_req", 1 << 16);
        let mut consumer =
            producer.cache_ref().random_access("test_rpc_by_root_req", false).unwrap();
        let p2p_id = P2pStreamId::new(0, 16, StreamProtocol::BeaconBlocksByRoot, true);

        // Full-buffer reads, byte-by-byte, and odd-sized.
        for cap in [usize::MAX, 1, 7] {
            let mut dec = SnappyDecoder::default();
            let mut io = WireIo { data: wire.clone(), pos: 0, cap };
            let mut state = RpcReadRequest::default();
            let mut spins = 0;
            let msg = loop {
                state = state.spin(&mut io, &p2p_id, &mut producer, &mut dec).unwrap();
                if let RpcReadRequest::Complete { msg } = state {
                    break msg;
                }
                spins += 1;
                assert!(spins < 1000, "cap {cap}: state machine did not complete");
            };
            let RpcRequest::BlockByRoot(read) = msg else { panic!("wrong request kind") };
            let acquired = consumer.acquire(read);
            let (buf, _) = acquired.buffer().unwrap();
            assert_eq!(buf, &ssz[..], "cap {cap}: committed body mismatch");
        }
    }
}
