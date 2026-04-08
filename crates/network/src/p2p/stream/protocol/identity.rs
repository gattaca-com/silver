use std::io::Error as IoError;
use silver_common::decode_varint;

/// State machine for an incoming Identity protocol stream (/ipfs/id/1.0.0).
/// When a peer opens an Identity stream to us, there is no request message!
/// We simply immediately write our node's Identify protobuf message and close the stream.
#[derive(Debug)]
pub enum IdentifyInboundState {
    /// Write our local node's identify payload back to the peer.
    WritingResponse {
        current: Option<(super::super::DCacheRef, usize)>,
    },
    /// Finished writing, stream cleanly closing.
    Done,
}

impl IdentifyInboundState {
    pub fn new() -> Self {
        Self::WritingResponse { current: None }
    }

    /// No incoming data is expected for an inbound identify stream.
    /// If the peer sends any bytes, it's technically a protocol violation.
    pub fn feed_chunk(&mut self, _chunk: &[u8]) -> Result<(), IoError> {
        Ok(())
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
                            *self = Self::Done;
                            break;
                        }

                        match send.write(chunk) {
                            Ok(written) => {
                                bytes_written += written;
                                *offset += written;
                                if *offset >= msg.payload.len() {
                                    *current = None;
                                    *self = Self::Done;
                                    break; // Identify only sends one message
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

/// State machine for an outbound Identity protocol stream.
/// When we open this stream to a peer, we send nothing, and immediately await
/// the peer's length-prefixed protobuf Identify message.
#[derive(Debug)]
pub enum IdentifyOutboundState {
    /// Reading the varint length of the peer's identify protobuf.
    ReadingLength {
        buf: [u8; 10],
        read: usize,
    },
    /// Reading the raw, uncompressed protobuf payload.
    ReadingBody {
        remaining: usize,
    },
    Done,
}

impl IdentifyOutboundState {
    pub fn new() -> Self {
        Self::ReadingLength {
            buf: [0; 10],
            read: 0,
        }
    }

    pub fn feed_chunk(&mut self, mut chunk: &[u8], mut out_buf: &mut [u8]) -> Result<usize, IoError> {
        let mut total_decoded = 0;
        
        while !chunk.is_empty() {
            match self {
                Self::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    chunk = &chunk[1..];

                    // Check continuation bit top bit
                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;
                        *self = Self::ReadingBody { remaining: length as usize };
                    }
                }
                Self::ReadingBody { remaining } => {
                    if out_buf.is_empty() {
                        break;
                    }
                    let out_limit = (*remaining).min(out_buf.len());
                    let transfer = chunk.len().min(out_limit);
                    
                    // Identify is NOT compressed! We just copy the raw protobuf bytes directly.
                    out_buf[..transfer].copy_from_slice(&chunk[..transfer]);

                    *remaining -= transfer;
                    chunk = &chunk[transfer..];
                    out_buf = &mut out_buf[transfer..];
                    total_decoded += transfer;

                    if *remaining == 0 {
                        *self = Self::Done;
                    }
                }
                Self::Done => break,
            }
        }
        Ok(total_decoded)
    }

    pub(crate) fn drive_write(
        &mut self,
        _send: &mut quinn_proto::SendStream<'_>,
        _outbound_queue: &mut std::collections::VecDeque<super::super::DCacheRef>,
    ) -> super::super::StreamEvent {
        super::super::StreamEvent::Pending
    }
}
