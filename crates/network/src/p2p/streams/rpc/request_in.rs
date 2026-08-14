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
                    remaining -=
                        decoder.decompress_written(written, reservation.remaining_buffer()?)?;
                }
                Ok(Spin::Next(Self::ReadingBody { reservation, remaining }))
            }
            RpcReadRequest::Complete { msg } => Ok(Spin::Ok(Self::Complete { msg })),
        }
    }
}
