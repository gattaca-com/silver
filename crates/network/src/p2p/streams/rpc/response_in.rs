use std::io::ErrorKind;

use silver_common::{P2pStreamId, RpcResponse, TProducer, decode_varint};

use crate::p2p::streams::{
    StreamError, StreamIo,
    rpc::{
        Rpc, RpcReservation, alloc_incoming_rpc,
        reservation::{alloc_error_response, rpc_response_context_length},
    },
    snappy::SnappyDecoder,
};

/// State machine for reading a single length-prefixed, snappy-compressed SSZ
/// chunk.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcReadResponse {
    /// Reading the response status, possible prefix and varint length of the
    /// SSZ chunk
    ReadingPrefix { app_id: u64, decoder: SnappyDecoder, buf: [u8; 15], read: usize },
    /// Allocating
    AllocBody {
        app_id: u64,
        decoder: SnappyDecoder,
        length: usize,
        buf: [u8; 15],
        buf_start: usize,
        buf_end: usize,
    },
    /// Stream Snappy decompressing the chunk payload into a handler buffer.
    ReadingBody {
        app_id: u64,
        decoder: SnappyDecoder,
        reservation: RpcReservation,
        remaining: usize,
    },
    /// Request read completed
    Complete { app_id: u64, msg: RpcResponse },
}

enum Spin {
    Ok(RpcReadResponse),
    Next(RpcReadResponse),
}

impl RpcReadResponse {
    pub fn new(app_id: u64) -> Self {
        Self::ReadingPrefix { app_id, decoder: SnappyDecoder::default(), buf: [0; 15], read: 0 }
    }

    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
        producer: &mut TProducer,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id, producer)? {
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
    ) -> Result<Spin, StreamError> {
        match self {
            RpcReadResponse::ReadingPrefix { app_id, mut decoder, mut buf, mut read } => {
                read += io.read_from_stream(p2p_id.stream_id(), &mut buf[read..])?;

                let prefix_length = rpc_response_context_length(p2p_id.protocol());
                if read > prefix_length {
                    // status and any prefix have been read, check for complete length.
                    let start = if buf[0] == 0 {
                        prefix_length + 1
                    } else {
                        // error response
                        1
                    };

                    for pos in start..read {
                        if buf[pos] & 0x80 == 0 {
                            // last byte of varint.
                            let (length, offset) = decode_varint(&buf[..read], start)?;
                            return Ok(Spin::Next(Self::AllocBody {
                                app_id,
                                decoder,
                                length: length as usize,
                                buf,
                                buf_start: offset,
                                buf_end: read,
                            }));
                        }
                    }
                }
                Ok(Spin::Ok(Self::ReadingPrefix { app_id, decoder, buf, read }))
            }
            RpcReadResponse::AllocBody { app_id, mut decoder, length, buf, buf_start, buf_end } => {
                let status = buf[0];

                let mut reservation = if buf[0] == 0 {
                    match alloc_incoming_rpc(producer, p2p_id, length) {
                        Ok(reservation) => reservation,
                        Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                            return Ok(Spin::Ok(Self::AllocBody {
                                app_id,
                                decoder,
                                length,
                                buf,
                                buf_start,
                                buf_end,
                            }));
                        }
                        Err(e) => return Err(e.into()),
                    }
                } else {
                    alloc_error_response(buf[0])
                };

                // write any remaining bytes to decoder -> output
                let mut remaining = length;
                if buf_end > buf_start {
                    let len = buf_end - buf_start;
                    let out_buf = reservation.remaining_buffer()?;
                    let out_limit = len.min(out_buf.len());
                    let (consumed, decoded_bytes) =
                        decoder.decompress(&buf[buf_start..buf_end], &mut out_buf[..out_limit])?;

                    reservation.increment_offset(decoded_bytes)?;
                    remaining -= decoded_bytes;
                }

                Ok(Spin::Next(Self::ReadingBody { app_id, decoder, reservation, remaining }))
            }
            RpcReadResponse::ReadingBody {
                app_id,
                mut decoder,
                mut reservation,
                mut remaining,
            } => {
                let mut decompress_buffer = decoder.decompress_buffer();
                if !decompress_buffer.is_empty() {
                    let written = io.read_from_stream(p2p_id.stream_id(), decompress_buffer)?;
                    if written == 0 {
                        return Ok(Spin::Ok(Self::ReadingBody {
                            app_id,
                            decoder,
                            reservation,
                            remaining,
                        }));
                    }
                    remaining -=
                        decoder.decompress_written(written, reservation.remaining_buffer()?)?;
                }
                if remaining == 0 {
                    match reservation.into_rpc() {
                        Rpc::Request(_) => return Err(StreamError::InvalidRpc),
                        Rpc::Response(rpc_response) => {
                            return Ok(Spin::Ok(Self::Complete { app_id, msg: rpc_response }))
                        }
                    }
                }
                Ok(Spin::Next(Self::ReadingBody { app_id, decoder, reservation, remaining }))
            }
            RpcReadResponse::Complete { app_id, msg } => {
                Ok(Spin::Ok(Self::Complete { app_id, msg }))
            }
        }
    }
}
