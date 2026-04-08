use std::io::Error as IoError;

use silver_common::{decode_varint, encode_varint};
use snap::write::FrameEncoder;
use std::io::Write;

use super::super::snappy::SnappyDecoder;

/// State machine for reading a single length-prefixed, snappy-compressed SSZ chunk.
#[derive(Debug)]
pub enum RpcFrameState {
    /// Reading the varint length prefix of the SSZ chunk
    ReadingLength { buf: [u8; 10], read: usize },
    /// Stream Snappy decompressing the chunk payload
    ReadingBody { remaining: usize },
}

impl Default for RpcFrameState {
    fn default() -> Self {
        Self::ReadingLength {
            buf: [0; 10],
            read: 0,
        }
    }
}

impl RpcFrameState {
    /// Feeds bytes into the payload state machine.
    /// Returns `Ok((is_complete, bytes_decoded))`
    pub fn feed_chunk(
        &mut self,
        chunk: &mut &[u8],
        decoder: &mut SnappyDecoder,
        mut out_buf: &mut [u8],
    ) -> Result<(bool, usize), IoError> {
        let mut total_decoded = 0;
        while !chunk.is_empty() {
            match self {
                Self::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    *chunk = &chunk[1..];

                    // Check continuation bit
                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;
                        *self = Self::ReadingBody {
                            remaining: length as usize,
                        };
                    }
                }
                Self::ReadingBody { remaining } => {
                    if out_buf.is_empty() {
                        break;
                    }
                    let out_limit = (*remaining).min(out_buf.len());
                    let (consumed, decoded_bytes) = decoder
                        .decompress(chunk, &mut out_buf[..out_limit])
                        .map_err(|e| IoError::other(format!("snappy error: {e:?}")))?;

                    *remaining -= decoded_bytes;
                    *chunk = &chunk[consumed..];
                    out_buf = &mut out_buf[decoded_bytes..];
                    total_decoded += decoded_bytes;

                    if *remaining == 0 {
                        decoder.reset();
                        return Ok((true, total_decoded));
                    }
                }
            }
        }
        Ok((false, total_decoded))
    }
}

/// State machine for handling an incoming request-response RPC stream.
#[derive(Debug)]
pub enum RpcInboundState {
    /// Reading the request chunk
    ReadingRequest(RpcFrameState),
    /// Request fully received, writing response code and payload chunks
    WritingResponse { current: Option<(super::super::DCacheRef, usize)> },
    /// Stream gracefully closed
    AwaitingClose,
}

impl RpcInboundState {
    pub fn new() -> Self {
        Self::ReadingRequest(RpcFrameState::default())
    }

    pub fn feed_chunk(
        &mut self,
        mut chunk: &[u8],
        decoder: &mut SnappyDecoder,
        mut out_buf: &mut [u8],
    ) -> Result<usize, IoError> {
        let mut total_decoded = 0;
        while !chunk.is_empty() {
            match self {
                Self::ReadingRequest(frame) => {
                    let (done, decoded) = frame.feed_chunk(&mut chunk, decoder, out_buf)?;
                    total_decoded += decoded;
                    out_buf = &mut out_buf[decoded..];
                    if done {
                        *self = Self::WritingResponse { current: None };
                    }
                }
                Self::WritingResponse { .. } => break,
                Self::AwaitingClose => break,
            }
        }
        Ok(total_decoded)
    }

    pub(crate) fn drive_write(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        outbound_queue: &mut std::collections::VecDeque<super::super::DCacheRef>,
    ) -> super::super::StreamEvent {
        match self {
            Self::WritingResponse { current } => {
                let mut bytes_written = 0;
                loop {
                    // Try to load next message if we don't have a current one
                    if current.is_none() {
                        if let Some(msg) = outbound_queue.pop_front() {
                            *current = Some((msg, 0));
                        } else {
                            break;
                        }
                    }

                    if let Some((msg, offset)) = current.as_mut() {
                        let chunk = &msg.payload[*offset..];
                        if chunk.is_empty() {
                            *current = None;
                            continue;
                        }

                        match send.write(chunk) {
                            Ok(written) => {
                                bytes_written += written;
                                *offset += written;
                                if *offset >= msg.payload.len() {
                                    *current = None;
                                } else {
                                    // Quinn buffer full
                                    break;
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => break,
                            Err(_) => return super::super::StreamEvent::Failed,
                        }
                    }
                }
                if bytes_written > 0 {
                    super::super::StreamEvent::Sent(bytes_written)
                } else {
                    super::super::StreamEvent::Pending
                }
            }
            _ => super::super::StreamEvent::Pending,
        }
    }
}

/// Helper function to zero-copy compress an entire outbound SSZ payload.
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

/// Helper function to zero-copy compress an entire outbound SSZ response payload.
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
    /// Writing the SSZ+Snappy encoded request to the peer
    WritingRequest { current: Option<(super::super::DCacheRef, usize)> },
    /// Reading the 1-byte response code
    ReadingResponseCode,
    /// Reading the response chunk
    ReadingResponse(RpcFrameState),
    /// Reading the raw UTF-8 Error Message string (no snappy)
    ReadingErrorMessageLen { buf: [u8; 10], read: usize },
    ReadingErrorMessageData { remaining: usize },
    /// Awaiting final stream closure or next chunk
    Done,
}

impl RpcOutboundState {
    pub fn new() -> Self {
        Self::WritingRequest { current: None }
    }

    pub fn feed_chunk(
        &mut self,
        mut chunk: &[u8],
        decoder: &mut SnappyDecoder,
        mut out_buf: &mut [u8],
    ) -> Result<usize, IoError> {
        let mut total_decoded = 0;
        while !chunk.is_empty() {
            match self {
                Self::WritingRequest { .. } => break,
                Self::ReadingResponseCode => {
                    let code = chunk[0];
                    chunk = &chunk[1..];
                    if code == 0 {
                        *self = Self::ReadingResponse(RpcFrameState::default());
                    } else {
                        // Non-zero response codes mean the payload is an uncompressed string error message
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
                    if out_buf.is_empty() { break; }
                    let transfer = chunk.len().min(*remaining).min(out_buf.len());
                    out_buf[..transfer].copy_from_slice(&chunk[..transfer]);
                    *remaining -= transfer;
                    chunk = &chunk[transfer..];
                    out_buf = &mut out_buf[transfer..];
                    total_decoded += transfer;
                    if *remaining == 0 {
                        // We extracted the full error string. Discard it or send it as StreamEvent Data and return to start.
                        *self = Self::Done; 
                    }
                }
                Self::ReadingResponse(frame) => {
                    let (done, decoded) = frame.feed_chunk(&mut chunk, decoder, out_buf)?;
                    total_decoded += decoded;
                    out_buf = &mut out_buf[decoded..];
                    if done {
                        *self = Self::ReadingResponseCode;
                    }
                }
                Self::Done => break,
            }
        }
        Ok(total_decoded)
    }

    pub(crate) fn drive_write(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        outbound_queue: &mut std::collections::VecDeque<super::super::DCacheRef>,
    ) -> super::super::StreamEvent {
        match self {
            Self::WritingRequest { current } => {
                let mut bytes_written = 0;
                loop {
                    if current.is_none() {
                        if let Some(msg) = outbound_queue.pop_front() {
                            *current = Some((msg, 0));
                        } else {
                            break;
                        }
                    }

                    if let Some((msg, offset)) = current.as_mut() {
                        let chunk = &msg.payload[*offset..];
                        if chunk.is_empty() {
                            *current = None;
                            // If we finished writing our one request, immediately flip state!
                            *self = Self::ReadingResponseCode;
                            break;
                        }

                        match send.write(chunk) {
                            Ok(written) => {
                                bytes_written += written;
                                *offset += written;
                                if *offset >= msg.payload.len() {
                                    *current = None;
                                    *self = Self::ReadingResponseCode;
                                    break;
                                } else {
                                    break;
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => break,
                            Err(_) => return super::super::StreamEvent::Failed,
                        }
                    }
                }

                if bytes_written > 0 {
                    super::super::StreamEvent::Sent(bytes_written)
                } else {
                    super::super::StreamEvent::Pending
                }
            }
            _ => super::super::StreamEvent::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_rpc_state_machines() {
        let mut rng = rand::thread_rng();

        // 1. Generate a random SSZ request
        let mut original_request = vec![0u8; 125 * 1024];
        rng.fill_bytes(&mut original_request);

        // 2. Outbound encodes request
        let mut req_encoded = Vec::new();
        encode_rpc_payload(&original_request, &mut req_encoded).unwrap();

        // 3. Inbound receives request via chunked driving
        let mut inbound = RpcInboundState::new();
        let mut inbound_decoder = SnappyDecoder::new();
        let mut inbound_received = vec![0u8; original_request.len() + 8192];
        let mut decoded_offset = 0;

        let mut network_stream = req_encoded.as_slice();
        while !network_stream.is_empty() {
            let chunk_sz = (rng.next_u32() as usize % 4096 + 1).min(network_stream.len());
            let chunk = &network_stream[..chunk_sz];
            let decoded = inbound
                .feed_chunk(chunk, &mut inbound_decoder, &mut inbound_received[decoded_offset..])
                .unwrap();
            decoded_offset += decoded;
            network_stream = &network_stream[chunk_sz..];
        }

        assert!(matches!(inbound, RpcInboundState::WritingResponse { .. }));
        assert_eq!(&inbound_received[..original_request.len()], original_request.as_slice());

        // 4. Inbound responds with an echo 
        let mut resp_encoded = Vec::new();
        encode_rpc_response(0, &original_request, &mut resp_encoded).unwrap();

        // 5. Outbound processes the response 
        let mut outbound = RpcOutboundState::ReadingResponseCode; // manually step to reading reading
        let mut outbound_decoder = SnappyDecoder::new();
        let mut outbound_received = vec![0u8; original_request.len() + 8192];
        let mut out_decoded_offset = 0;

        let mut network_stream = resp_encoded.as_slice();
        while !network_stream.is_empty() {
            let chunk_sz = (rng.next_u32() as usize % 4096 + 1).min(network_stream.len());
            let chunk = &network_stream[..chunk_sz];
            let decoded = outbound
                .feed_chunk(
                    chunk,
                    &mut outbound_decoder,
                    &mut outbound_received[out_decoded_offset..],
                )
                .unwrap();
            out_decoded_offset += decoded;
            network_stream = &network_stream[chunk_sz..];
        }

        assert!(matches!(outbound, RpcOutboundState::ReadingResponseCode));
        assert_eq!(&outbound_received[..original_request.len()], original_request.as_slice());
    }
}
