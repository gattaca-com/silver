use std::io::{Error as IoError, Write};

use silver_common::{P2pStreamId, decode_varint, encode_varint};
use snap::write::FrameEncoder;

use super::super::{StreamEvent, snappy::SnappyDecoder};
use crate::StreamData;

/// State machine for reading a single length-prefixed, snappy-compressed SSZ
/// chunk.
#[derive(Debug)]
pub enum RpcFrameState {
    /// Reading the varint length prefix of the SSZ chunk
    ReadingLength { buf: [u8; 10], read: usize },
    /// Stream Snappy decompressing the chunk payload into a handler buffer.
    ReadingBody { remaining: usize },
}

impl Default for RpcFrameState {
    fn default() -> Self {
        Self::ReadingLength { buf: [0; 10], read: 0 }
    }
}

impl RpcFrameState {
    /// Feeds bytes into the payload state machine.
    /// Returns `Ok((is_complete, bytes_decoded))`.
    pub fn feed_chunk<S: StreamData>(
        &mut self,
        chunk: &mut &[u8],
        decoder: &mut SnappyDecoder,
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> Result<(bool, usize), IoError> {
        let start = chunk.len();

        while !chunk.is_empty() {
            match self {
                Self::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    *chunk = &chunk[1..];

                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;

                        data.alloc_recv(stream_id, length as usize)?;
                        *self = Self::ReadingBody { remaining: length as usize };
                    }
                }
                Self::ReadingBody { remaining } => {
                    let out_buf = data.recv_buf(stream_id)?;
                    let out_limit = (*remaining).min(out_buf.len());
                    let (consumed, decoded_bytes) = decoder
                        .decompress(chunk, &mut out_buf[..out_limit])
                        .map_err(|e| IoError::other(format!("snappy error: {e:?}")))?;

                    data.recv_advance(stream_id, decoded_bytes)?;

                    *remaining -= decoded_bytes;
                    *chunk = &chunk[consumed..];

                    if *remaining == 0 {
                        decoder.reset();
                        return Ok((true, start - chunk.len()));
                    }
                    if consumed == 0 {
                        // No progress possible — handler buffer full or input
                        // exhausted. Bail out.
                        break;
                    }
                }
            }
        }
        Ok((false, start - chunk.len()))
    }
}

/// State machine for handling an incoming request-response RPC stream.
#[derive(Debug)]
pub enum RpcInboundState {
    /// Reading the request chunk
    ReadingRequest(RpcFrameState),
    /// Request fully received, writing response code and payload chunks.
    /// `current` tracks `(length, offset)` for the current outbound message.
    WritingResponse { current: Option<(usize, usize)> },
    /// Stream gracefully closed
    #[allow(dead_code)]
    AwaitingClose, // TODO: required state?
}

impl RpcInboundState {
    pub fn new() -> Self {
        Self::ReadingRequest(RpcFrameState::default())
    }

    pub fn feed_chunk<S: StreamData>(
        &mut self,
        mut chunk: &[u8],
        decoder: &mut SnappyDecoder,
        data: &mut S,
        stream_id: &P2pStreamId,
    ) -> Result<usize, IoError> {
        let start = chunk.len();
        while !chunk.is_empty() {
            match self {
                Self::ReadingRequest(frame) => {
                    let (done, _decoded) =
                        frame.feed_chunk(&mut chunk, decoder, stream_id, data)?;
                    if done {
                        *self = Self::WritingResponse { current: None };
                    }
                }
                Self::WritingResponse { .. } => break,
                Self::AwaitingClose => break,
            }
        }
        Ok(start - chunk.len())
    }

    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> StreamEvent {
        match self {
            Self::WritingResponse { current } => {
                super::drive_send_loop(current, send, stream_id, data)
            }
            _ => StreamEvent::Pending,
        }
    }
}

/// Helper function to zero-copy compress an entire outbound SSZ payload.
#[allow(dead_code)]
pub fn encode_rpc_payload(
    uncompressed_ssz: &[u8],
    out_buffer: &mut Vec<u8>,
) -> Result<(), IoError> {
    let mut prefix_buf = [0u8; 10];
    let prefix_len = encode_varint(uncompressed_ssz.len() as u64, &mut prefix_buf)
        .map_err(|_| IoError::other("varint buffer too small"))?;

    out_buffer.write_all(&prefix_buf[..prefix_len])?;
    let mut encoder = FrameEncoder::new(out_buffer);
    encoder.write_all(uncompressed_ssz)?;
    encoder.into_inner().map_err(|e| e.into_error())?;
    Ok(())
}

/// Helper function to zero-copy compress an entire outbound SSZ response
/// payload.
#[allow(dead_code)]
pub fn encode_rpc_response(
    response_code: u8,
    uncompressed_ssz: &[u8],
    out_buffer: &mut Vec<u8>,
) -> Result<(), IoError> {
    out_buffer.push(response_code);
    encode_rpc_payload(uncompressed_ssz, out_buffer)
}

/// State machine for initiating and tracking an outgoing request-response RPC.
#[derive(Debug)]
pub enum RpcOutboundState {
    /// Writing the SSZ+Snappy encoded request to the peer.
    /// `current` tracks `(length, offset)` for the current outbound message.
    WritingRequest {
        current: Option<(usize, usize)>,
    },
    /// Reading the 1-byte response code
    ReadingResponseCode,
    /// Reading the response chunk
    ReadingResponse(RpcFrameState),
    /// Reading the raw UTF-8 Error Message string (no snappy)
    ReadingErrorMessageLen {
        buf: [u8; 10],
        read: usize,
    },
    ReadingErrorMessageData {
        remaining: usize,
    },
    /// Awaiting final stream closure or next chunk
    Done,
}

impl RpcOutboundState {
    pub fn new() -> Self {
        Self::WritingRequest { current: None }
    }

    pub fn feed_chunk<S: StreamData>(
        &mut self,
        mut chunk: &[u8],
        decoder: &mut SnappyDecoder,
        mut out_buf: &mut [u8],
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> Result<usize, IoError> {
        let start = chunk.len();
        while !chunk.is_empty() {
            match self {
                Self::WritingRequest { .. } => break,
                Self::ReadingResponseCode => {
                    let code = chunk[0];
                    chunk = &chunk[1..];
                    if code == 0 {
                        *self = Self::ReadingResponse(RpcFrameState::default());
                    } else {
                        *self = Self::ReadingErrorMessageLen { buf: [0; 10], read: 0 };
                    }
                }
                Self::ReadingErrorMessageLen { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    chunk = &chunk[1..];
                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;
                        *self = Self::ReadingErrorMessageData { remaining: length as usize };
                    }
                }
                Self::ReadingErrorMessageData { remaining } => {
                    if out_buf.is_empty() {
                        break;
                    }
                    let transfer = chunk.len().min(*remaining).min(out_buf.len());
                    out_buf[..transfer].copy_from_slice(&chunk[..transfer]);
                    *remaining -= transfer;
                    chunk = &chunk[transfer..];
                    out_buf = &mut out_buf[transfer..];
                    if *remaining == 0 {
                        *self = Self::Done;
                    }
                }
                Self::ReadingResponse(frame) => {
                    let (done, _decoded) =
                        frame.feed_chunk(&mut chunk, decoder, stream_id, data)?;
                    if done {
                        *self = Self::ReadingResponseCode;
                    }
                }
                Self::Done => break,
            }
        }
        Ok(start - chunk.len())
    }

    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> StreamEvent {
        match self {
            Self::WritingRequest { current } => {
                let (total, result) = super::drive_send(current, send, stream_id, data);
                match result {
                    super::WriteResult::Done => {
                        *self = Self::ReadingResponseCode;

                        // Finished writing request. Close the outbound channel.
                        if let Err(e) = send.finish() {
                            tracing::warn!(?e, ?stream_id, "error finishing outbound stream");
                        }
                        if total > 0 { StreamEvent::Sent(total) } else { StreamEvent::Pending }
                    }
                    super::WriteResult::Failed => StreamEvent::Failed,
                    _ => {
                        if total > 0 {
                            StreamEvent::Sent(total)
                        } else {
                            StreamEvent::Pending
                        }
                    }
                }
            }
            _ => StreamEvent::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use silver_common::StreamProtocol;

    use super::*;
    use crate::RemotePeer;

    /// Test handler that accumulates received data.
    struct TestHandler {
        received: Vec<u8>,
        offset: usize,
    }

    impl TestHandler {
        fn new() -> Self {
            Self { received: Vec::new(), offset: 0 }
        }
    }

    impl StreamData for TestHandler {
        fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
        fn stream_closed(&mut self, _stream: &P2pStreamId) {}

        fn alloc_recv(&mut self, _stream: &P2pStreamId, length: usize) -> Result<(), IoError> {
            self.received.resize(length, 0u8);
            self.offset = 0;
            Ok(())
        }

        fn recv_buf(&mut self, _stream: &P2pStreamId) -> Result<&mut [u8], IoError> {
            Ok(&mut self.received[self.offset..])
        }

        fn recv_advance(&mut self, _stream: &P2pStreamId, written: usize) -> Result<(), IoError> {
            self.offset += written;
            Ok(())
        }

        fn poll_send(&mut self, _stream: &P2pStreamId) -> Option<usize> {
            None
        }

        fn send_data(&mut self, _stream: &P2pStreamId, _offset: usize) -> Option<&[u8]> {
            None
        }

        fn send_complete(&mut self, _stream: &P2pStreamId) {}
    }

    #[test]
    fn test_rpc_state_machines() {
        let mut rng = rand::thread_rng();
        let stream_id = P2pStreamId::new(0, 0, StreamProtocol::Ping);

        // 1. Generate a random SSZ request
        let mut original_request = vec![0u8; 125 * 1024];
        rng.fill_bytes(&mut original_request);

        // 2. Outbound encodes request
        let mut req_encoded = Vec::new();
        encode_rpc_payload(&original_request, &mut req_encoded).unwrap();

        // 3. Inbound receives request via chunked driving
        let mut inbound = RpcInboundState::new();
        let mut inbound_decoder = SnappyDecoder::new();
        let mut handler = TestHandler::new();

        let mut network_stream = req_encoded.as_slice();
        while !network_stream.is_empty() {
            let chunk_sz = (rng.next_u32() as usize % 4096 + 1).min(network_stream.len());
            let chunk = &network_stream[..chunk_sz];
            let consumed =
                inbound.feed_chunk(chunk, &mut inbound_decoder, &mut handler, &stream_id).unwrap();
            network_stream = &network_stream[consumed..];
        }

        assert!(matches!(inbound, RpcInboundState::WritingResponse { .. }));
        assert_eq!(handler.received, original_request);

        // 4. Inbound responds with an echo
        let mut resp_encoded = Vec::new();
        encode_rpc_response(0, &original_request, &mut resp_encoded).unwrap();

        // 5. Outbound processes the response
        let mut outbound = RpcOutboundState::ReadingResponseCode;
        let mut outbound_decoder = SnappyDecoder::new();
        let mut out_handler = TestHandler::new();
        let mut out_buf = vec![0u8; 65536];

        let mut network_stream = resp_encoded.as_slice();
        while !network_stream.is_empty() {
            let chunk_sz = (rng.next_u32() as usize % 4096 + 1).min(network_stream.len());
            let chunk = &network_stream[..chunk_sz];
            let consumed = outbound
                .feed_chunk(
                    chunk,
                    &mut outbound_decoder,
                    &mut out_buf,
                    &stream_id,
                    &mut out_handler,
                )
                .unwrap();
            network_stream = &network_stream[consumed..];
        }

        assert!(matches!(outbound, RpcOutboundState::ReadingResponseCode));
        assert_eq!(out_handler.received, original_request);
    }
}
