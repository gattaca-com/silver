use std::io::ErrorKind;

use silver_common::{P2pStreamId, RpcResponse, TProducer, decode_varint};

use crate::p2p::streams::{
    StreamError, StreamIo,
    rpc::{
        Rpc, RpcReservation, alloc_incoming_rpc,
        reservation::{alloc_error_response, rpc_response_context_length},
    },
    snappy::{SnappyDecoder, SnappyError},
};

/// State machine for reading a single length-prefixed, snappy-compressed SSZ
/// chunk.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcReadResponse {
    /// Reading the response status, possible prefix and varint length of the
    /// SSZ chunk
    ReadingPrefix { app_id: u64, chunk: u32, decoder: SnappyDecoder, buf: [u8; 15], read: usize },
    /// Allocating
    AllocBody {
        app_id: u64,
        chunk: u32,
        decoder: SnappyDecoder,
        length: usize,
        buf: [u8; 15],
        buf_start: usize,
        buf_end: usize,
    },
    /// Stream Snappy decompressing the chunk payload into a handler buffer.
    ReadingBody {
        app_id: u64,
        chunk: u32,
        decoder: SnappyDecoder,
        reservation: RpcReservation,
        remaining: usize,
    },
    /// Request read completed
    Complete { app_id: u64, chunk: u32, msg: RpcResponse },
}

enum Spin {
    Ok(RpcReadResponse),
    Next(RpcReadResponse),
}

impl RpcReadResponse {
    /// `chunk` is the zero-based index within a multipart response, for
    /// diagnostics.
    pub fn new(app_id: u64, chunk: u32) -> Self {
        Self::ReadingPrefix {
            app_id,
            chunk,
            // Responses carry the bulk inbound payload (BeaconBlock /
            // DataColumnSidecar). KZG cells are incompressible ⇒ peers emit
            // CHUNK_UNCOMPRESSED frames; stream those straight into the tcache.
            // The earlier hang (a frame overshooting the declared chunk length
            // stalled on zero-length reads, pinning the reservation) is fixed by
            // the bounds guard in `ReadingBody` — see `direct_remaining` there.
            decoder: SnappyDecoder::new_direct(),
            buf: [0; 15],
            read: 0,
        }
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
            RpcReadResponse::ReadingPrefix { app_id, chunk, decoder, mut buf, mut read } => {
                match io.read_from_stream(p2p_id.stream_id(), &mut buf[read..]) {
                    Ok(r) => read += r,
                    Err(StreamError::StreamEOF)
                        if read == 0 && p2p_id.protocol().has_multipart_response() =>
                    {
                        // Normal termination for a multipart response TODO if received > 1 response
                        return Ok(Spin::Ok(Self::Complete {
                            app_id,
                            chunk,
                            msg: RpcResponse::Complete,
                        }));
                    }
                    Err(e) => return Err(e),
                }

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
                                chunk,
                                decoder,
                                length: length as usize,
                                buf,
                                buf_start: offset,
                                buf_end: read,
                            }));
                        }
                    }
                }
                Ok(Spin::Ok(Self::ReadingPrefix { app_id, chunk, decoder, buf, read }))
            }
            RpcReadResponse::AllocBody {
                app_id,
                chunk,
                mut decoder,
                length,
                buf,
                buf_start,
                buf_end,
            } => {
                // Raw prefix capture: status byte, context bytes, varint and
                // any body leftover, exactly as read off the wire.
                tracing::debug!(
                    ?p2p_id,
                    chunk,
                    length,
                    buf_start,
                    prefix = ?&buf[..buf_end],
                    "rpc response chunk prefix"
                );
                let mut reservation = if buf[0] == 0 {
                    match alloc_incoming_rpc(producer, p2p_id, length) {
                        Ok(reservation) => reservation,
                        Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                            return Ok(Spin::Ok(Self::AllocBody {
                                app_id,
                                chunk,
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
                    alloc_error_response(buf[0], length)
                };

                // Plumb the wire fork_digest from the prefix into the
                // response's 4-byte fork_digest slot. `RpcReservation`
                // models BeaconBlock / DataColumnSidecar with offset 0..4
                // pointing at `fork_digest` and offset 4+ pointing at the
                // tcache-backed SSZ payload; writing fork_digest here is
                // the only path that populates it.
                let prefix_length = rpc_response_context_length(p2p_id.protocol());
                if buf[0] == 0 && prefix_length > 0 {
                    let out_buf = reservation.remaining_buffer()?;
                    let n = prefix_length.min(out_buf.len());
                    out_buf[..n].copy_from_slice(&buf[1..1 + n]);
                    reservation.increment_offset(n)?;
                }

                // Decode any body bytes read along with the prefix. Output
                // must be the full remaining buffer: a short slice makes the
                // decoder's output-full early-exit fire and silently drop
                // buffered frame bytes (seen live: zero-length error
                // reservations desynced the frame stream on rate-limited
                // peers).
                let mut remaining = length;
                if buf_end > buf_start {
                    let out_buf = reservation.remaining_buffer()?;
                    let (_, decoded_bytes) =
                        decoder.decompress(&buf[buf_start..buf_end], out_buf)?;

                    reservation.increment_offset(decoded_bytes)?;
                    remaining -= decoded_bytes;
                }

                Ok(Spin::Next(Self::ReadingBody { app_id, chunk, decoder, reservation, remaining }))
            }
            RpcReadResponse::ReadingBody {
                app_id,
                chunk,
                mut decoder,
                mut reservation,
                mut remaining,
            } => {
                if decoder.direct_remaining() > 0 {
                    // Uncompressed frame: read its data straight into the tcache.
                    let out = reservation.remaining_buffer()?;
                    // Bounds guard: the frame's remaining data must fit the
                    // reservation's remaining room. If it overshoots, the peer
                    // sent more bytes than the declared chunk length — error
                    // (which tears the stream down and frees the reservation)
                    // rather than capping the read at a zero-length slice and
                    // spinning forever on zero-progress reads.
                    if decoder.direct_remaining() > out.len() {
                        tracing::error!(
                            ?p2p_id,
                            chunk,
                            direct_remaining = decoder.direct_remaining(),
                            out = out.len(),
                            remaining,
                            "rpc response uncompressed frame overshoots reservation"
                        );
                        return Err(StreamError::SnappyError(SnappyError::OutputTooSmall));
                    }
                    let want = decoder.direct_remaining();
                    let written = io.read_from_stream(p2p_id.stream_id(), &mut out[..want])?;
                    if written == 0 {
                        return Ok(Spin::Ok(Self::ReadingBody {
                            app_id,
                            chunk,
                            decoder,
                            reservation,
                            remaining,
                        }));
                    }
                    let decoded = decoder.advance_direct(written);
                    reservation.increment_offset(decoded)?;
                    remaining -= decoded;
                } else {
                    let decompress_buffer = decoder.decompress_buffer();
                    if !decompress_buffer.is_empty() {
                        let written = io.read_from_stream(p2p_id.stream_id(), decompress_buffer)?;
                        if written == 0 {
                            return Ok(Spin::Ok(Self::ReadingBody {
                                app_id,
                                chunk,
                                decoder,
                                reservation,
                                remaining,
                            }));
                        }
                        let decoded = decoder
                            .decompress_written(written, reservation.remaining_buffer()?)
                            .inspect_err(|e| {
                                tracing::error!(
                                    ?e,
                                    ?p2p_id,
                                    chunk,
                                    remaining,
                                    ?decoder,
                                    "rpc response body decode failed"
                                );
                            })?;
                        reservation.increment_offset(decoded)?;
                        remaining -= decoded;
                    }
                }
                if remaining == 0 {
                    match reservation.into_rpc() {
                        Rpc::Request(_) => return Err(StreamError::InvalidRpc),
                        Rpc::Response(rpc_response) => {
                            tracing::trace!(?p2p_id, chunk, "response complete");
                            return Ok(Spin::Ok(Self::Complete {
                                app_id,
                                chunk,
                                msg: rpc_response,
                            }));
                        }
                    }
                }
                Ok(Spin::Next(Self::ReadingBody { app_id, chunk, decoder, reservation, remaining }))
            }
            RpcReadResponse::Complete { app_id, chunk, msg } => {
                tracing::debug!(?p2p_id, chunk, "read response");
                Ok(Spin::Ok(Self::Complete { app_id, chunk, msg }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TCache, TRead};

    use super::*;
    use crate::p2p::streams::{rpc::AcquiredRpcOutbound, snappy::SnappyEncoder};

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

    /// Error chunk wire shape: `[code][varint len][snappy frames(msg)]` — no
    /// context bytes. Regression: a rate-limiting lighthouse answers
    /// columns-by-range with ResourceUnavailable(3); the zero-length error
    /// reservation made the decoder's output-full early-exit drop buffered
    /// frame bytes and desync (FrameTooLarge on the message CRC).
    #[test]
    fn error_chunk_roundtrip() {
        let msg = b"data unavailable for range 123"; // 30 bytes, as seen live
        let mut body = Vec::new();
        let mut enc = SnappyEncoder::new();
        let (consumed, pending) = enc.compress(msg, &mut body).unwrap();
        assert_eq!(consumed, msg.len());
        assert_eq!(pending, 0);

        let mut wire = vec![3u8, msg.len() as u8];
        wire.extend_from_slice(&body);

        let mut producer = TCache::producer("test_rpc_error_chunk", 1 << 16);
        let p2p_id = P2pStreamId::new(0, 16, StreamProtocol::DataColumnSidecarsByRange, false);

        // Full-buffer reads (the live failure shape), byte-by-byte, and odd.
        for cap in [usize::MAX, 1, 7] {
            let mut io = WireIo { data: wire.clone(), pos: 0, cap };
            let mut state = RpcReadResponse::new(7, 0);
            let mut spins = 0;
            let out = loop {
                state = state.spin(&mut io, &p2p_id, &mut producer).unwrap();
                if let RpcReadResponse::Complete { app_id, msg, .. } = state {
                    assert_eq!(app_id, 7);
                    break msg;
                }
                spins += 1;
                assert!(spins < 1000, "cap {cap}: state machine did not complete");
            };
            match out {
                RpcResponse::Error { error, msg: m, len } => {
                    assert_eq!(error, 3, "cap {cap}");
                    assert_eq!(len, msg.len(), "cap {cap}");
                    assert_eq!(&m[..len], msg, "cap {cap}");
                }
                other => panic!("cap {cap}: expected error response, got {other:?}"),
            }
        }
    }

    /// Direct-decode bounds guard. A `CHUNK_UNCOMPRESSED` frame whose data
    /// exceeds the declared chunk length must error (tearing the stream down
    /// and freeing the reservation), not stall on zero-length reads. Regression
    /// for the inbound-RPC hang that got the direct path disabled: an over-long
    /// frame pinned its `rpc_in` reservation forever.
    #[test]
    fn direct_decode_overshoot_errors_not_hangs() {
        const CHUNK_UNCOMPRESSED: u8 = 0x01;
        const CHECKSUM_LEN: usize = 4;
        const STREAM_IDENTIFIER: [u8; 10] =
            [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

        let declared = 8usize; // SSZ length advertised to the reader
        let data_len = 100usize; // actual uncompressed frame data — overshoots

        // [status=0][fork_digest:4][varint declared][stream id][uncompressed frame]
        let mut wire = vec![0u8];
        wire.extend_from_slice(&[0xAB; 4]);
        wire.push(declared as u8); // single-byte varint (< 0x80)
        wire.extend_from_slice(&STREAM_IDENTIFIER);
        let chunk_len = CHECKSUM_LEN + data_len;
        wire.push(CHUNK_UNCOMPRESSED);
        wire.push((chunk_len & 0xff) as u8);
        wire.push(((chunk_len >> 8) & 0xff) as u8);
        wire.push(((chunk_len >> 16) & 0xff) as u8);
        wire.extend_from_slice(&[0u8; CHECKSUM_LEN]); // crc (unchecked)
        wire.extend(std::iter::repeat_n(0xCD, data_len));

        let mut producer = TCache::producer("test_rpc_direct_overshoot", 1 << 16);
        let p2p_id = P2pStreamId::new(0, 16, StreamProtocol::DataColumnSidecarsByRange, false);

        // Whole-buffer, byte-by-byte, and odd reads — the boundary the bug hid at.
        for cap in [usize::MAX, 1, 7] {
            let mut io = WireIo { data: wire.clone(), pos: 0, cap };
            let mut state = RpcReadResponse::new(7, 0);
            let mut spins = 0;
            let err = loop {
                match state.spin(&mut io, &p2p_id, &mut producer) {
                    Ok(s) => state = s,
                    Err(e) => break e,
                }
                if let RpcReadResponse::Complete { .. } = state {
                    panic!("cap {cap}: overshoot completed instead of erroring");
                }
                spins += 1;
                assert!(spins < 1000, "cap {cap}: state machine hung instead of erroring");
            };
            assert!(
                matches!(err, StreamError::SnappyError(_)),
                "cap {cap}: expected SnappyError, got {err:?}"
            );
        }
    }
}
